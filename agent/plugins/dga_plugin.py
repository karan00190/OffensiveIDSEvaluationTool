#!/usr/bin/env python3
# agent/plugins/dga_plugin.py
# =============================================================================
#  MIAT Plugin — Domain Generation Algorithm
#
#  Change from original:
#    execute() now extracts task_id from args and includes it in the
#    summary dict posted to /api/agent/dga/results/.  This allows
#    api_dga_results() on the server to look up the matching ModuleTask
#    and call mark_complete(result.pk), closing the web-dispatch loop.
#
#  Server command format:
#  {
#    "command": "dga",
#    "args": {
#      "algorithm":   "date_seed",
#      "count":       50,
#      "rate":        1.0,
#      "seed_secret": "BARC-MIAT",
#      "tld":         ".com",
#      "dns_server":  null,
#      "task_id":     "uuid-string"   ← injected by dispatch_dga_task
#    }
#  }
# =============================================================================

import asyncio
import base64
import hashlib
import math
import random
import time
from datetime import date, datetime, timezone

from plugin_base import MIATPlugin

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def shannon_entropy(domain: str) -> float:
    label = domain.split('.')[0]
    if not label:
        return 0.0
    freq = {}
    for c in label:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(label)
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class DGAPlugin(MIATPlugin):

    DOMAIN_CHARS = 'abcdefghijklmnopqrstuvwxyz'

    WORDLIST = [
        'cloud', 'secure', 'data', 'sync', 'net', 'link', 'hub',
        'core', 'node', 'host', 'web', 'api', 'cdn', 'edge', 'gate',
        'proxy', 'cache', 'store', 'vault', 'key', 'auth', 'access',
        'global', 'fast', 'smart', 'safe', 'trust', 'open', 'base',
    ]

    @property
    def name(self) -> str:
        return 'dga'

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def description(self) -> str:
        return 'Domain Generation Algorithm — IDS detection testing'

    async def execute(self, args: dict) -> None:
        if not DNS_AVAILABLE:
            await self._emit(
                data={'error': 'dnspython not installed. pip install dnspython'},
                success=False,
            )
            return

        algorithm   = args.get('algorithm',   'date_seed')
        count       = int(args.get('count',    50))
        rate        = float(args.get('rate',   1.0))
        secret      = args.get('seed_secret',  'BARC-MIAT')
        tld         = args.get('tld',          '.com')
        dns_server  = args.get('dns_server',   None)
        randomise   = args.get('randomise',    True)
        timeout_sec = int(args.get('timeout',  3))

        # ── task_id forwarded from dispatch_dga_task via channel_layer ────────
        # Included verbatim in the summary so api_dga_results() can look up
        # the ModuleTask and call mark_complete(result.pk).
        task_id = str(args.get('task_id', ''))

        delay = 1.0 / rate if rate > 0 else 1.0

        await self._emit_live(
            f"DGA [{algorithm.upper()}] starting — "
            f"{count} domains @ {rate}/s, tld={tld}"
        )

        loop    = asyncio.get_event_loop()
        domains = await loop.run_in_executor(
            None,
            lambda: self._generate(algorithm, count, secret, tld),
        )

        if randomise:
            random.shuffle(domains)

        resolver          = dns.resolver.Resolver()
        resolver.timeout  = timeout_sec
        resolver.lifetime = timeout_sec
        if dns_server:
            resolver.nameservers = [dns_server]

        results    = []
        nxdomain   = 0
        resolved   = 0
        timeouts   = 0
        errors     = 0
        start_time = time.time()

        for i, domain in enumerate(domains, start=1):
            if self._stop_event.is_set():
                break

            entropy = shannon_entropy(domain)
            outcome = await loop.run_in_executor(
                None, lambda d=domain: self._query(resolver, d),
            )

            if outcome == 'NXDOMAIN':
                nxdomain += 1
            elif outcome == 'RESOLVED':
                resolved += 1
            elif outcome == 'TIMEOUT':
                timeouts += 1
            else:
                errors += 1

            results.append({
                'domain':    domain,
                'outcome':   outcome,
                'entropy':   entropy,
                'timestamp': datetime.now(tz=timezone.utc).isoformat(),
            })

            await self._emit_live(
                f"[{i:3d}/{count}] {domain:<35} → {outcome:<10} "
                f"(H={entropy})"
            )

            if i < count and not self._stop_event.is_set():
                await asyncio.sleep(delay)

        duration  = round(time.time() - start_time, 2)
        ratio     = round(nxdomain / max(len(results), 1), 4)
        entropies = [r['entropy'] for r in results]

        summary = {
            'algorithm':      algorithm,
            'total_queries':  len(results),
            'nxdomain':       nxdomain,
            'resolved':       resolved,
            'timeout':        timeouts,
            'errors':         errors,
            'nxdomain_ratio': ratio,
            'avg_entropy':    round(sum(entropies) / len(entropies), 3) if entropies else 0,
            'max_entropy':    max(entropies) if entropies else 0,
            'min_entropy':    min(entropies) if entropies else 0,
            'duration_sec':   duration,
            'rate_per_sec':   rate,
            'dns_server':     dns_server or 'system',
            'domains':        results,
            # ── NEW ──────────────────────────────────────────────────────────
            # Carry task_id through to api_dga_results() so it can close the
            # ModuleTask tracking loop via _close_moduletask_loop().
            'task_id':        task_id,
        }

        await self._emit_live(
            f"DGA complete — {nxdomain}/{len(results)} NXDOMAIN "
            f"({ratio * 100:.1f}%), avg entropy={summary['avg_entropy']}"
        )

        await self._emit(data=summary, endpoint='/api/agent/dga/results/')

    # ── Domain generators ─────────────────────────────────────────────────────

    def _generate(self, algorithm: str, count: int,
                  secret: str, tld: str) -> list:
        seed_date = date.today()
        if algorithm == 'date_seed':
            return self._gen_date_seed(count, secret, tld, seed_date)
        elif algorithm == 'xor_lcg':
            return self._gen_xor_lcg(count, secret, tld, seed_date)
        elif algorithm == 'wordlist':
            return self._gen_wordlist(count, secret, tld, seed_date)
        return self._gen_date_seed(count, secret, tld, seed_date)

    def _gen_date_seed(self, count, secret, tld, seed_date):
        domains      = []
        seed_str     = f"{seed_date.isoformat()}:{secret}"
        current_hash = hashlib.sha256(seed_str.encode()).digest()
        for i in range(count):
            name = ''.join(
                self.DOMAIN_CHARS[b % 26] for b in current_hash[:10]
            )
            domains.append(name + tld)
            current_hash = hashlib.sha256(
                current_hash + i.to_bytes(4, 'big')
            ).digest()
        return domains

    def _gen_xor_lcg(self, count, secret, tld, seed_date):
        domains  = []
        seed_str = f"{seed_date.isoformat()}:{secret}"
        seed_num = int.from_bytes(
            hashlib.md5(seed_str.encode()).digest()[:4], 'big'
        )
        xor_key  = int.from_bytes(
            hashlib.md5(secret.encode()).digest()[:4], 'big'
        )
        current  = seed_num ^ xor_key
        for _ in range(count):
            current = (1664525 * current + 1013904223) % (2 ** 32)
            name = ''
            v    = current
            for _ in range(8):
                name += self.DOMAIN_CHARS[v % 26]
                v    //= 26
            domains.append(name + tld)
        return domains

    def _gen_wordlist(self, count, secret, tld, seed_date):
        domains  = []
        seed_str = f"{seed_date.isoformat()}:{secret}"
        seed_int = int.from_bytes(
            hashlib.sha256(seed_str.encode()).digest(), 'big'
        )
        rng = random.Random(seed_int)
        for _ in range(count):
            w1     = rng.choice(self.WORDLIST)
            w2     = rng.choice(self.WORDLIST)
            suffix = str(rng.randint(1, 99)) if rng.random() < 0.3 else ''
            domains.append(f"{w1}{w2}{suffix}{tld}")
        return domains

    def _query(self, resolver, domain: str) -> str:
        try:
            resolver.resolve(domain, 'A')
            return 'RESOLVED'
        except dns.resolver.NXDOMAIN:
            return 'NXDOMAIN'
        except dns.exception.Timeout:
            return 'TIMEOUT'
        except Exception:
            return 'ERROR'