#!/usr/bin/env python3
# agent/modules/dga_module.py
# =============================================================================
#  MIAT — DGA (Domain Generation Algorithm) Module
#
#  PURPOSE:
#    Simulate malware DGA behaviour to test whether the BARC IDS detects it.
#    Real malware (Conficker, GameOver Zeus, Mirai) uses DGA to find its C2
#    server without using a hardcoded domain that can be blocked.
#
#  WHAT THIS MODULE DOES:
#    1. Generates pseudo-random domain names using 3 algorithms
#    2. Queries DNS for each domain — most return NXDOMAIN
#    3. Streams every result live to the server dashboard via WebSocket
#    4. Posts a full summary report to the server when complete
#
#  THREE ALGORITHMS:
#    date_seed   — SHA-256(date + secret) → domains. Changes every day.
#    xor_lcg     — Linear Congruential Generator. Simulates Conficker-style.
#    wordlist    — Combines dictionary words. Low entropy — harder to detect.
#
#  INSTALL:
#    pip install dnspython
#
#  USAGE (from agent.py):
#    runner = DGARunner(agent_ref=self, config={
#        'algorithm':   'date_seed',
#        'count':       50,
#        'rate':        1.0,          # queries per second
#        'seed_secret': 'BARC-MIAT',
#        'tld':         '.com',
#        'dns_server':  '8.8.8.8',    # or your lab DNS
#    })
#    runner.run()
# =============================================================================

import hashlib
import math
import time
import random
import logging
import threading
from datetime import date, datetime, timezone

# dnspython — pip install dnspython
try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print('[WARN] dnspython not installed. Run: pip install dnspython')

logger = logging.getLogger('MIAT-DGA')


# =============================================================================
# DGA GENERATOR — produces domain names using different algorithms
# =============================================================================

class DGAGenerator:
    """
    Generates pseudo-random domain names.

    All three algorithms are DETERMINISTIC — same input always gives
    same output. This is essential for real DGA: both the malware and
    the attacker's C2 server run the same algorithm to agree on domains.
    """

    # Wordlist for the wordlist algorithm
    # Short common words produce lower-entropy domains (harder for IDS to detect)
    WORDLIST = [
        'cloud', 'secure', 'data', 'sync', 'net', 'link', 'hub',
        'core', 'node', 'host', 'web', 'api', 'cdn', 'edge', 'gate',
        'proxy', 'cache', 'store', 'vault', 'key', 'auth', 'access',
        'global', 'fast', 'smart', 'safe', 'trust', 'open', 'base',
    ]

    # Alphabet used for domain name characters (no digits at start)
    DOMAIN_CHARS = 'abcdefghijklmnopqrstuvwxyz'

    def generate(self, algorithm: str, count: int,
                 seed_secret: str = 'BARC-MIAT',
                 tld: str = '.com',
                 seed_date: date = None) -> list[str]:
        """
        Main entry point. Returns a list of generated domain names.

        Args:
            algorithm:   'date_seed' | 'xor_lcg' | 'wordlist'
            count:       number of domains to generate
            seed_secret: shared secret mixed into the seed
            tld:         '.com' | '.net' | '.org' etc.
            seed_date:   date to use as seed (default: today)
        """
        if seed_date is None:
            seed_date = date.today()

        if algorithm == 'date_seed':
            return self._date_seed(count, seed_secret, tld, seed_date)
        elif algorithm == 'xor_lcg':
            return self._xor_lcg(count, seed_secret, tld, seed_date)
        elif algorithm == 'wordlist':
            return self._wordlist(count, seed_secret, tld, seed_date)
        else:
            raise ValueError(f'Unknown algorithm: {algorithm}')

    # ── Algorithm 1: Date-seeded SHA-256 ─────────────────────────────────────
    # Most common in real malware. Changes every day automatically.
    # Same date + same secret = same domain list (deterministic).

    def _date_seed(self, count: int, secret: str,
                   tld: str, seed_date: date) -> list[str]:
        """
        SHA-256(date_string + secret) → stream of bytes → domain names.

        The SHA-256 output is 32 bytes. We keep hashing the output
        (SHA-256 chaining) to produce as many domains as needed.
        """
        domains = []

        # Initial seed: "2026-05-13:BARC-MIAT"
        seed_str = f"{seed_date.isoformat()}:{secret}"
        current_hash = hashlib.sha256(seed_str.encode()).digest()

        for i in range(count):
            # Take first 10 bytes of the hash → map to letters → domain name
            domain_bytes = current_hash[:10]
            name = ''.join(
                self.DOMAIN_CHARS[b % len(self.DOMAIN_CHARS)]
                for b in domain_bytes
            )
            domains.append(name + tld)

            # Chain: next hash = SHA-256(current hash + index)
            # This ensures each domain is different even with same seed
            current_hash = hashlib.sha256(
                current_hash + i.to_bytes(4, 'big')
            ).digest()

        return domains

    # ── Algorithm 2: XOR + Linear Congruential Generator (LCG) ──────────────
    # Simulates Conficker worm's approach. Uses a simple mathematical formula.
    # Fast to compute, hard to predict without knowing the seed.

    def _xor_lcg(self, count: int, secret: str,
                 tld: str, seed_date: date) -> list[str]:
        """
        Linear Congruential Generator — same formula used by Conficker.
        seed → multiply → add → modulo → repeat
        The XOR with the secret hash makes it unique per deployment.
        """
        domains = []

        # Derive numeric seed from date + secret
        seed_str  = f"{seed_date.isoformat()}:{secret}"
        seed_hash = hashlib.md5(seed_str.encode()).digest()
        seed_num  = int.from_bytes(seed_hash[:4], 'big')

        # XOR key from secret (adds the "mutual secret" layer)
        xor_hash  = hashlib.md5(secret.encode()).digest()
        xor_key   = int.from_bytes(xor_hash[:4], 'big')

        # LCG parameters (same as used in many real DGA implementations)
        A = 1664525       # multiplier
        C = 1013904223    # increment
        M = 2**32         # modulus

        current = seed_num ^ xor_key   # XOR with secret key

        for _ in range(count):
            # LCG formula
            current = (A * current + C) % M

            # Convert to domain name
            # Take 8 characters: each 4 bits → letter index
            name = ''
            value = current
            for _ in range(8):
                name += self.DOMAIN_CHARS[value % 26]
                value //= 26

            domains.append(name + tld)

        return domains

    # ── Algorithm 3: Wordlist combination ────────────────────────────────────
    # Harder for IDS to detect because domains look more legitimate.
    # Tests whether the IDS uses Shannon entropy analysis (it should).

    def _wordlist(self, count: int, secret: str,
                  tld: str, seed_date: date) -> list[str]:
        """
        Combines two words from a wordlist to create plausible-looking domains.
        Example: 'cloudsync.com', 'datasecure.com', 'netcore.com'

        These have LOWER Shannon entropy than pure random strings,
        so they test whether the IDS can detect DGA at this level.
        """
        domains = []

        seed_str    = f"{seed_date.isoformat()}:{secret}"
        seed_bytes  = hashlib.sha256(seed_str.encode()).digest()
        seed_int    = int.from_bytes(seed_bytes, 'big')

        # Seeded random number generator (reproducible)
        rng = random.Random(seed_int)

        for _ in range(count):
            w1 = rng.choice(self.WORDLIST)
            w2 = rng.choice(self.WORDLIST)
            # Occasionally add a number suffix to vary the pattern
            suffix = str(rng.randint(1, 99)) if rng.random() < 0.3 else ''
            domain = f"{w1}{w2}{suffix}{tld}"
            domains.append(domain)

        return domains


# =============================================================================
# ENTROPY CALCULATOR — measures how random a domain name looks
# =============================================================================

def shannon_entropy(domain: str) -> float:
    """
    Calculate Shannon entropy of the domain name (excluding TLD).

    High entropy (> 3.5) → likely DGA (random characters)
    Low entropy  (< 2.5) → likely legitimate (readable words)

    Real IDS systems use this to flag suspicious domains.
    We calculate it so we can report what the IDS should be seeing.

    Formula: H = -sum(p * log2(p)) for each unique character
    """
    # Use only the domain label, not the TLD
    label = domain.split('.')[0]
    if not label:
        return 0.0

    freq = {}
    for char in label:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length  = len(label)
    for count in freq.values():
        p        = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


# =============================================================================
# DGA REPORTER — collects results and sends to server
# =============================================================================

class DGAReporter:
    """
    Collects query results and builds the summary report.
    Sends results to the Django server via the agent's HTTP client.
    Also streams live output via WebSocket.
    """

    def __init__(self, agent_ref, algorithm: str, config: dict):
        self.agent_ref  = agent_ref    # MIATAgent instance
        self.algorithm  = algorithm
        self.config     = config
        self.results    = []           # list of per-domain result dicts
        self.start_time = None
        self.end_time   = None

    def record(self, domain: str, outcome: str,
               entropy: float, response_time_ms: float) -> None:
        """Record the result of one DNS query."""
        self.results.append({
            'domain':          domain,
            'outcome':         outcome,    # NXDOMAIN | RESOLVED | TIMEOUT | ERROR
            'entropy':         entropy,
            'response_ms':     round(response_time_ms, 2),
            'timestamp':       datetime.now(tz=timezone.utc).isoformat(),
        })

    def stream_live(self, domain: str, outcome: str, entropy: float) -> None:
        """
        Send a single query result to the dashboard in real time via WebSocket.
        The browser sees a live terminal feed while DGA is running.
        """
        if self.agent_ref and hasattr(self.agent_ref, 'ws_thread'):
            ws = self.agent_ref.ws_thread
            if ws and ws.connected:
                icon = '✓' if outcome == 'RESOLVED' else '✗'
                line = (
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    f"{domain:<30} → {outcome:<10} "
                    f"(entropy: {entropy})"
                )
                ws.send_module_output('dga', line)

    def build_summary(self) -> dict:
        """Build the complete summary report for this DGA test run."""
        total    = len(self.results)
        nxdomain = sum(1 for r in self.results if r['outcome'] == 'NXDOMAIN')
        resolved = sum(1 for r in self.results if r['outcome'] == 'RESOLVED')
        timeout  = sum(1 for r in self.results if r['outcome'] == 'TIMEOUT')
        errors   = sum(1 for r in self.results if r['outcome'] == 'ERROR')

        entropies   = [r['entropy'] for r in self.results]
        avg_entropy = round(sum(entropies) / len(entropies), 3) if entropies else 0
        max_entropy = max(entropies) if entropies else 0
        min_entropy = min(entropies) if entropies else 0

        duration = 0.0
        if self.start_time and self.end_time:
            duration = round(self.end_time - self.start_time, 2)

        return {
            'algorithm':     self.algorithm,
            'total_queries': total,
            'nxdomain':      nxdomain,
            'resolved':      resolved,
            'timeout':       timeout,
            'errors':        errors,
            'nxdomain_ratio': round(nxdomain / total, 4) if total else 0,
            'avg_entropy':   avg_entropy,
            'max_entropy':   max_entropy,
            'min_entropy':   min_entropy,
            'duration_sec':  duration,
            'rate_per_sec':  self.config.get('rate', 1.0),
            'dns_server':    self.config.get('dns_server', 'system'),
            'domains':       self.results,
        }

    def post_to_server(self) -> None:
        """Post the complete DGA report to the Django server."""
        if not self.agent_ref:
            return

        summary = self.build_summary()

        logger.info(
            f"DGA complete — "
            f"{summary['total_queries']} queries, "
            f"{summary['nxdomain']} NXDOMAIN "
            f"({summary['nxdomain_ratio']*100:.1f}%), "
            f"avg entropy: {summary['avg_entropy']}"
        )

        # Stream final summary line to dashboard
        if hasattr(self.agent_ref, 'ws_thread'):
            ws = self.agent_ref.ws_thread
            if ws and ws.connected:
                ws.send_module_output(
                    'dga',
                    f"{'─'*60}\n"
                    f"SUMMARY: {summary['total_queries']} queries | "
                    f"{summary['nxdomain']} NXDOMAIN "
                    f"({summary['nxdomain_ratio']*100:.1f}%) | "
                    f"avg entropy: {summary['avg_entropy']}"
                )

        # Post to server via authenticated HTTP
        try:
            self.agent_ref.post_results(
                module   = 'dga',
                target   = self.config.get('dns_server', 'lab-dns'),
                findings = summary['domains'],
                summary  = str(summary),
            )
        except Exception as exc:
            logger.error(f"Failed to post DGA results: {exc}")


# =============================================================================
# DGA RUNNER — orchestrates the full test run
# =============================================================================

class DGARunner:
    """
    Main controller for a DGA test run.

    Orchestrates:
      1. Domain generation (DGAGenerator)
      2. DNS querying with rate limiting
      3. Live streaming (DGAReporter.stream_live)
      4. Result collection and final report

    Can be stopped mid-run via stop() — useful for agent shutdown.
    """

    def __init__(self, agent_ref, config: dict):
        """
        Args:
            agent_ref: MIATAgent instance (for HTTP + WebSocket)
            config: {
                'algorithm':   'date_seed' | 'xor_lcg' | 'wordlist'
                'count':       number of domains to query (default 50)
                'rate':        queries per second (default 1.0)
                'seed_secret': shared secret string (default 'BARC-MIAT')
                'tld':         top-level domain (default '.com')
                'dns_server':  DNS server IP (default: system resolver)
                'randomise':   shuffle domain order (default True)
                'timeout':     DNS query timeout in seconds (default 3)
            }
        """
        self.agent_ref = agent_ref
        self.config    = config
        self.running   = False
        self._stop_event = threading.Event()

        self.generator = DGAGenerator()
        self.reporter  = DGAReporter(agent_ref, config.get('algorithm', 'date_seed'), config)

    def run(self) -> dict:
        """
        Execute the full DGA test run synchronously.
        Returns the summary dict when complete.
        Call in a background thread from agent.py.
        """
        if not DNS_AVAILABLE:
            logger.error("dnspython not installed. Run: pip install dnspython")
            return {}

        algorithm   = self.config.get('algorithm',   'date_seed')
        count       = self.config.get('count',        50)
        rate        = self.config.get('rate',          1.0)
        secret      = self.config.get('seed_secret',  'BARC-MIAT')
        tld         = self.config.get('tld',           '.com')
        dns_server  = self.config.get('dns_server',    None)
        randomise   = self.config.get('randomise',     True)
        timeout     = self.config.get('timeout',       3)

        delay = 1.0 / rate if rate > 0 else 1.0   # seconds between queries

        logger.info(
            f"DGA run starting — algorithm={algorithm}, "
            f"count={count}, rate={rate}/s, tld={tld}"
        )

        # ── Step 1: Generate domains ──────────────────────────────────────────
        try:
            domains = self.generator.generate(
                algorithm   = algorithm,
                count       = count,
                seed_secret = secret,
                tld         = tld,
            )
        except Exception as exc:
            logger.error(f"Domain generation failed: {exc}")
            return {}

        # Shuffle order so it doesn't always query in same sequence
        if randomise:
            random.shuffle(domains)

        logger.info(f"Generated {len(domains)} domains. Starting DNS queries...")

        # Notify dashboard that DGA is starting
        if hasattr(self.agent_ref, 'ws_thread'):
            ws = self.agent_ref.ws_thread
            if ws and ws.connected:
                ws.send_module_output(
                    'dga',
                    f"DGA [{algorithm.upper()}] starting — "
                    f"{count} domains @ {rate}/s"
                )

        # ── Step 2: Configure DNS resolver ───────────────────────────────────
        resolver = dns.resolver.Resolver()
        resolver.timeout        = timeout
        resolver.lifetime       = timeout

        if dns_server:
            # Use specific DNS server (e.g. lab DNS inside IDS-monitored network)
            resolver.nameservers = [dns_server]
            logger.info(f"Using DNS server: {dns_server}")
        else:
            logger.info("Using system DNS resolver")

        # ── Step 3: Query each domain ─────────────────────────────────────────
        self.running = True
        self.reporter.start_time = time.time()

        for i, domain in enumerate(domains, start=1):

            # Check if stop was requested (e.g. agent shutting down)
            if self._stop_event.is_set():
                logger.info("DGA run stopped by request")
                break

            entropy   = shannon_entropy(domain)
            outcome   = self._query_domain(resolver, domain)
            query_ms  = 0.0   # response time captured inside _query_domain

            self.reporter.record(domain, outcome, entropy, query_ms)
            self.reporter.stream_live(domain, outcome, entropy)

            logger.debug(f"[{i:3d}/{count}] {domain:<30} → {outcome} (H={entropy})")

            # Rate limiting — wait before next query
            if i < len(domains) and not self._stop_event.is_set():
                time.sleep(delay)

        self.reporter.end_time = time.time()
        self.running = False

        # ── Step 4: Post results to server ────────────────────────────────────
        self.reporter.post_to_server()

        return self.reporter.build_summary()

    def stop(self) -> None:
        """Signal the run loop to stop after the current query."""
        self._stop_event.set()
        logger.info("DGA stop requested")

    def _query_domain(self, resolver: 'dns.resolver.Resolver',
                      domain: str) -> str:
        """
        Perform a single DNS A-record lookup.

        Returns:
            'RESOLVED'  — domain exists and returned an IP
            'NXDOMAIN'  — domain does not exist (most common for DGA)
            'TIMEOUT'   — DNS server did not respond in time
            'ERROR'     — other DNS error
        """
        start = time.monotonic()
        try:
            resolver.resolve(domain, 'A')
            elapsed = (time.monotonic() - start) * 1000
            logger.debug(f"RESOLVED: {domain} ({elapsed:.1f}ms)")
            return 'RESOLVED'

        except dns.resolver.NXDOMAIN:
            return 'NXDOMAIN'

        except dns.resolver.NoAnswer:
            # Domain exists but no A record — treat as partial resolve
            return 'RESOLVED'

        except dns.exception.Timeout:
            return 'TIMEOUT'

        except dns.resolver.NoNameservers:
            return 'ERROR'

        except Exception as exc:
            logger.debug(f"DNS error for {domain}: {exc}")
            return 'ERROR'