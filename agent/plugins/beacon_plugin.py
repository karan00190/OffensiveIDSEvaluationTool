#!/usr/bin/env python3
# agent/plugins/beacon_plugin.py
# =============================================================================
#  MIAT Plugin — C2 Beacon Simulation
#
#  Simulates the periodic "call home" behaviour of real C2 malware
#  (Cobalt Strike, Emotet, APT implants).  The agent sends N HTTP or DNS
#  requests to a configurable target at a configurable interval, with
#  per-beacon jitter randomisation to evade timing-based IDS rules.
#
#  This is a pure OFFENSIVE simulation — no detection logic runs here.
#  The ids_signatures array in the result is informational only (documents
#  what a real IDS would look for) and does not imply MIAT is detecting
#  anything.
#
#  Server command format:
#  {
#    "command": "beacon",
#    "args": {
#      "target":           "192.168.1.100",
#      "port":             80,
#      "protocol":         "http_get",   # http_get | http_post | dns
#      "count":            20,
#      "interval_sec":     60.0,
#      "jitter_pct":       10,           # ± % of interval_sec
#      "encoding":         "base64",     # plain | base64 | xor
#      "xor_key":          0x5A,         # only used when encoding=xor
#      "user_agent_rotate": true,
#      "task_id":          "uuid-string"
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


_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36',
]

_IDS_SIGNATURES = [
    'Repeated HTTP connections to same host at near-regular intervals',
    'Base64/XOR-encoded value in URL query parameter or POST body',
    'Rotating User-Agent strings from same source IP',
    'DNS TXT queries with high-entropy label at regular intervals',
    'Low-entropy beacon payload size consistency across requests',
]


def _encode(payload: str, encoding: str, xor_key: int = 0x5A) -> str:
    raw = payload.encode('utf-8')
    if encoding == 'base64':
        return base64.b64encode(raw).decode('ascii')
    if encoding == 'xor':
        xored = bytes(b ^ xor_key for b in raw)
        return base64.b64encode(xored).decode('ascii')
    return payload  # plain


class BeaconPlugin(MIATPlugin):

    @property
    def name(self) -> str:    return 'beacon'

    @property
    def version(self) -> str: return '1.0.0'

    @property
    def description(self) -> str:
        return 'C2 Beacon Simulation — periodic call-home with jitter and encoding'

    # =========================================================================
    # EXECUTE
    # =========================================================================

    async def execute(self, args: dict) -> None:
        target          = str(args.get('target',          '127.0.0.1'))
        port            = int(args.get('port',            80))
        protocol        = str(args.get('protocol',        'http_get')).lower()
        count           = int(args.get('count',           20))
        interval_sec    = float(args.get('interval_sec',  60.0))
        jitter_pct      = int(args.get('jitter_pct',      10))
        encoding        = str(args.get('encoding',        'base64')).lower()
        xor_key         = int(args.get('xor_key',         0x5A))
        ua_rotate       = bool(args.get('user_agent_rotate', True))
        task_id         = str(args.get('task_id',         ''))

        # ── Availability guards ───────────────────────────────────────────────
        if protocol in ('http_get', 'http_post') and not REQUESTS_AVAILABLE:
            await self._emit(
                data={'error': 'pip install requests required for HTTP beacon',
                      'task_id': task_id},
                success=False,
                endpoint='/api/agent/beacon/results/')
            return

        if protocol == 'dns' and not DNS_AVAILABLE:
            await self._emit(
                data={'error': 'pip install dnspython required for DNS beacon',
                      'task_id': task_id},
                success=False,
                endpoint='/api/agent/beacon/results/')
            return

        # ── Session ID — unique identifier for this beacon campaign ──────────
        session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        await self._emit_live(
            f'BEACON [{protocol.upper()}][{encoding.upper()}] — '
            f'target={target}:{port}  count={count}  '
            f'interval={interval_sec}s ±{jitter_pct}%  session={session_id}'
        )

        # ── Beacon loop ───────────────────────────────────────────────────────
        loop       = asyncio.get_event_loop()
        beacons    = []
        successful = 0
        failed     = 0
        intervals  = []
        start_time = time.time()

        for i in range(1, count + 1):
            if self._stop_event.is_set():
                break

            payload    = f'{session_id}:{int(time.time())}:miat-agent'
            encoded    = _encode(payload, encoding, xor_key)
            beacon_ts  = datetime.now(tz=timezone.utc).isoformat()

            result = await loop.run_in_executor(
                None,
                lambda enc=encoded, ua_r=ua_rotate, seq=i:
                    self._send_beacon(protocol, target, port, enc, ua_r, seq, xor_key)
            )

            result['sequence']  = i
            result['timestamp'] = beacon_ts
            result['encoding']  = encoding
            beacons.append(result)

            if result.get('sent'):
                successful += 1
            else:
                failed += 1

            status_str = (
                f"{result.get('http_status', 'DNS')}"
                if result.get('sent')
                else f"ERR: {result.get('error', '?')[:40]}"
            )
            latency_ms = result.get('latency_ms', 0)

            await self._emit_live(
                f'[BEACON {i:02d}/{count:02d}] '
                f'{protocol.upper()} → {target}:{port} → '
                f'{status_str}  ({latency_ms}ms)'
            )

            if i < count and not self._stop_event.is_set():
                jitter_fraction = jitter_pct / 100.0
                jitter_delta    = interval_sec * jitter_fraction
                actual_sleep    = random.uniform(
                    max(0.1, interval_sec - jitter_delta),
                    interval_sec + jitter_delta,
                )
                beacons[-1]['actual_interval_sec'] = round(actual_sleep, 2)
                intervals.append(actual_sleep)
                await asyncio.sleep(actual_sleep)

        duration   = round(time.time() - start_time, 2)
        avg_lat    = round(
            sum(b.get('latency_ms', 0) for b in beacons) / max(len(beacons), 1), 1
        )
        std_dev    = 0.0
        if intervals:
            mean   = sum(intervals) / len(intervals)
            std_dev = round(
                (sum((x - mean) ** 2 for x in intervals) / len(intervals)) ** 0.5, 2
            )

        summary = {
            'task_id':          task_id,
            'session_id':       session_id,
            'protocol':         protocol,
            'encoding':         encoding,
            'target':           f'{target}:{port}',
            'total_beacons':    len(beacons),
            'successful':       successful,
            'failed':           failed,
            'interval_sec':     interval_sec,
            'jitter_pct':       jitter_pct,
            'avg_latency_ms':   avg_lat,
            'std_dev_sec':      std_dev,
            'duration_sec':     duration,
            'ids_signatures':   _IDS_SIGNATURES[:3 if protocol == 'dns' else 4],
            'beacons':          beacons,
        }

        await self._emit_live(
            f'Beacon campaign complete — '
            f'{successful}/{len(beacons)} sent  avg_latency={avg_lat}ms  '
            f'jitter_std={std_dev}s  session={session_id}'
        )
        await self._emit(data=summary, endpoint='/api/agent/beacon/results/')

    # =========================================================================
    # TRANSPORT HELPERS
    # =========================================================================

    def _send_beacon(self, protocol, target, port, encoded, ua_rotate, seq, xor_key):
        t0 = time.time()
        try:
            if protocol == 'http_get':
                return self._beacon_http_get(target, port, encoded, ua_rotate, seq, t0)
            elif protocol == 'http_post':
                return self._beacon_http_post(target, port, encoded, ua_rotate, seq, t0)
            elif protocol == 'dns':
                return self._beacon_dns(target, encoded, seq, t0)
            else:
                return {'sent': False, 'error': f'Unknown protocol: {protocol}',
                        'latency_ms': 0}
        except Exception as exc:
            return {'sent': False, 'error': str(exc),
                    'latency_ms': round((time.time() - t0) * 1000)}

    def _beacon_http_get(self, target, port, encoded, ua_rotate, seq, t0):
        ua = _USER_AGENTS[seq % len(_USER_AGENTS)] if ua_rotate else _USER_AGENTS[0]
        url = f'http://{target}:{port}/update?v={encoded}&seq={seq}'
        try:
            resp = requests.get(
                url,
                headers={'User-Agent': ua, 'X-Session': encoded[:16]},
                timeout=10, verify=False, allow_redirects=True,
            )
            return {
                'sent': True, 'protocol': 'http_get',
                'url': url[:100], 'http_status': resp.status_code,
                'latency_ms': round((time.time() - t0) * 1000),
            }
        except Exception as exc:
            return {'sent': False, 'protocol': 'http_get', 'url': url[:100],
                    'error': str(exc), 'latency_ms': round((time.time() - t0) * 1000)}

    def _beacon_http_post(self, target, port, encoded, ua_rotate, seq, t0):
        ua = _USER_AGENTS[seq % len(_USER_AGENTS)] if ua_rotate else _USER_AGENTS[0]
        url = f'http://{target}:{port}/check'
        try:
            resp = requests.post(
                url,
                json={'d': encoded, 'seq': seq},
                headers={'User-Agent': ua},
                timeout=10, verify=False, allow_redirects=True,
            )
            return {
                'sent': True, 'protocol': 'http_post',
                'url': url[:100], 'http_status': resp.status_code,
                'latency_ms': round((time.time() - t0) * 1000),
            }
        except Exception as exc:
            return {'sent': False, 'protocol': 'http_post', 'url': url[:100],
                    'error': str(exc), 'latency_ms': round((time.time() - t0) * 1000)}

    def _beacon_dns(self, target, encoded, seq, t0):
        label = encoded[:40].lower().replace('+', 'a').replace('/', 'b').replace('=', '')
        query = f'{label}.{seq:03d}.beacon.{target}'
        r = dns.resolver.Resolver()
        r.timeout = r.lifetime = 5
        try:
            r.resolve(query, 'TXT')
            outcome = 'RESOLVED'
        except dns.resolver.NXDOMAIN:
            outcome = 'NXDOMAIN'
        except dns.exception.Timeout:
            outcome = 'TIMEOUT'
        except Exception as exc:
            return {'sent': False, 'protocol': 'dns', 'query': query[:80],
                    'error': str(exc), 'latency_ms': round((time.time() - t0) * 1000)}
        return {
            'sent': True, 'protocol': 'dns',
            'query': query[:80], 'outcome': outcome,
            'latency_ms': round((time.time() - t0) * 1000),
        }
