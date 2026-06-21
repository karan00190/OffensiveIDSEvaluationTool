#!/usr/bin/env python3
# agent/payload_buffer.py
# =============================================================================
#  MIAT — Payload Buffer Abstraction
#
#  Provides a single uniform interface for both payload sources:
#    • Machine-generated: synthesised from a template string, instant, no I/O
#    • Manual pull:       fetched from the C2 server via authenticated HTTPS,
#                         held entirely in RAM (io.BytesIO), never written to disk
#
#  Both modes expose the same .chunks(technique) method so the three transport
#  classes (DNS, HTTP, ICMP) require zero changes.
#
#  Chunk sizes per transport constraint:
#    DNS  : 20 raw bytes → Base32 → ~32-char label (safe under 63-char DNS limit)
#    HTTP : 100 raw bytes → Base64 → header value chunk
#    ICMP : 64 raw bytes → raw binary → ICMP echo payload beyond standard 8 bytes
# =============================================================================

import asyncio
import hashlib
import io
import logging
from typing import Optional

logger = logging.getLogger('MIAT.PayloadBuffer')

# ── Per-technique raw byte chunk sizes ───────────────────────────────────────
CHUNK_SIZES: dict[str, int] = {
    'dns':  20,    # 20 raw bytes → Base32 → ~32-char label ≤ 63-char DNS limit
    'http': 100,   # 100 raw bytes → Base64 → manageable header value length
    'icmp': 64,    # 64 raw bytes → fits within safe ICMP echo payload window
    # 32 raw bytes → 64 hex chars.  A UNION SELECT injection string stays well
    # under 2 000-char URL limits, and hex uses only [0-9a-f] so no percent-
    # encoding is needed.  Keeps each GET request small enough to look like
    # ordinary traffic while still moving data efficiently.
    'sqli': 32,
}

# ── Machine-generated payload templates ──────────────────────────────────────
# Sized to 300–350 bytes so every technique produces multiple chunks:
#   HTTP (100 B/chunk) → 3-4 chunks  → header name rotates through all 4 values
#   ICMP (64 B/chunk)  → 5-6 chunks  → sustained echo sequence
#   DNS  (20 B/chunk)  → 15-18 DNS queries
#   SQLI (32 B/chunk)  → 9-11 injection requests
_TEMPLATES: dict[str, bytes] = {
    'credentials': (
        b"username=admin&password=Str0ng!P@ss#2024&mfa_code=847291\r\n"
        b"token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.sig\r\n"
        b"session_id=SID_abc123XYZ789&csrf_token=csrf_8f4a9b2c1d7e5f\r\n"
        b"last_login=2024-01-15T08:30:00Z&login_ip=192.168.1.50\r\n"
        b"user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"role=superadmin&permissions=read,write,delete,admin,sudo\r\n"
    ),
    'pii': (
        b"full_name=John Michael Doe&dob=1990-01-15&ssn=123-45-6789\r\n"
        b"email=john.doe@example.com&phone=+1-555-0123&mobile=+1-555-9876\r\n"
        b"address=123 Main Street,Springfield,IL 62701,US\r\n"
        b"passport=P12345678&drv_lic=D1234567890&cc_tail=4532\r\n"
        b"bank_acct=****3891&annual_salary=85000&tax_id=98-7654321\r\n"
        b"employer=Acme Corporation&employee_id=EMP-00456&dept=Engineering\r\n"
    ),
    'api_key': (
        b"AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\r\n"
        b"AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"
        b"STRIPE_SECRET=sk_live_51xyzABCDEFGHIJKLMNOPQRST\r\n"
        b"GITHUB_PAT=ghp_16C7e42F292c6912cE1C9bkk0abcde12345\r\n"
        b"SENDGRID_KEY=SG.abc123xyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n"
        b"DB_PASS=S3cr3tP@ss!2024&REDIS_AUTH=r3d1s_xyz789abc\r\n"
    ),
    'db_dump': (
        b"id,username,email,pwd_hash,role,last_login\r\n"
        b"1,alice,alice@corp.com,$2b$12$LQv3c1yqBWVHxkd0abc,admin,2024-01-10\r\n"
        b"2,bob,bob@corp.com,$2b$12$eImiTXuWVxfM37uY4def,user,2024-01-14\r\n"
        b"3,carol,carol@corp.com,$2b$12$DT5NqPPi3eTbkgPghi,user,2024-01-05\r\n"
        b"4,dave,dave@corp.com,$2b$12$abcdefghijklmnojkl,mod,2024-01-20\r\n"
        b"5,eve,eve@corp.com,$2b$12$mno345pqrstuvwxmno,user,2024-01-11\r\n"
    ),
    'config': (
        b"DB_HOST=db-prod-01.internal&DB_PORT=5432&DB_NAME=proddb\r\n"
        b"DB_USER=svc_account&DB_PASS=SuperSecret!2024&DB_SSL=require\r\n"
        b"DJANGO_SECRET=50-random-chars-xYz9Kl3Mn7Pq2Rs5Tv8Uw1Ax4Bq\r\n"
        b"JWT_SECRET=jwt-key-AbCdEf123GhIjKl456MnOpQr789StUvWxYz\r\n"
        b"REDIS_URL=redis://:r3d1s_pass@10.0.0.5:6379/0\r\n"
        b"S3_BUCKET=prod-backups&S3_KEY=AKIABCDEFGHIJKLMNOPQ\r\n"
    ),
}

# 35 MB hard ceiling — prevents runaway memory on the agent
MAX_PAYLOAD_BYTES: int = 35 * 1024 * 1024


class PayloadBuffer:
    """
    Uniform in-memory byte buffer regardless of payload source.

    Usage:

        # Generated mode (sync, instant)
        buf = PayloadBuffer.from_generated('credentials', run_id='abc123')

        # Pull mode (async, fetches from C2 server)
        buf = await PayloadBuffer.from_remote_pull(
            transport          = transport_instance,
            payload_url        = '/api/agent/payload/7/download/',
            expected_checksum  = 'sha256:deadbeef...',
            expected_size      = 65536,
        )

        # Both modes expose the same slicing interface
        for chunk in buf.chunks('dns'):
            # chunk is a bytes object sized for DNS Base32 encoding
            ...
    """

    def __init__(self, raw: bytes, source: str = 'unknown') -> None:
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(f'PayloadBuffer expects bytes, got {type(raw).__name__}')
        self._raw    = bytes(raw)
        self._source = source   # 'generated' | 'manual' — used for telemetry only

    # =========================================================================
    # CONSTRUCTORS
    # =========================================================================

    @classmethod
    def from_generated(
        cls,
        payload_type: str = 'credentials',
        run_id:       str = '',
    ) -> 'PayloadBuffer':
        """
        Synthesise a payload string from a built-in template.
        Instant — no network I/O, no disk access.

        Args:
            payload_type: Template key ('credentials', 'pii', 'api_key',
                          'db_dump', 'config').  Defaults to 'credentials'.
            run_id:       Short identifier prepended to the payload so each
                          run produces a unique byte sequence.
        """
        template = _TEMPLATES.get(payload_type, _TEMPLATES['credentials'])
        prefix   = f'[MIAT-SIM][{run_id}] '.encode('utf-8') if run_id else b''
        raw      = prefix + template
        logger.debug(
            f"Generated payload: type={payload_type} size={len(raw)}B"
        )
        return cls(raw, source='generated')

    @classmethod
    async def from_remote_pull(
        cls,
        transport,
        payload_url:       str,
        expected_checksum: str,
        expected_size:     int = 0,
    ) -> 'PayloadBuffer':
        """
        Pull the uploaded file from the C2 server download endpoint.

        Security properties enforced:
          1. Authenticated via transport.get_raw_bytes() — same mTLS + JWT +
             HMAC stack used by every other agent endpoint.
          2. Size gate: rejects payloads above MAX_PAYLOAD_BYTES before fetching
             to prevent the agent from being instructed to download arbitrarily
             large data that could exhaust RAM.
          3. Integrity gate: SHA-256 checksum of received bytes is compared
             against the value the server sent in the WebSocket command.
             Any mismatch (network corruption, truncation, tampering) raises
             ValueError and aborts the task before execution begins.
          4. No disk access: bytes accumulate in an io.BytesIO object that
             lives entirely in the agent process's heap.

        Args:
            transport:         SecureTransport instance with get_raw_bytes().
            payload_url:       Path relative to server root, e.g.
                               '/api/agent/payload/7/download/'.
            expected_checksum: 'sha256:<hex>' string sent in WS command args.
            expected_size:     File size in bytes from WS command args.
                               Used only for the pre-flight size gate; 0 = skip.

        Returns:
            PayloadBuffer backed by the fetched bytes.

        Raises:
            ValueError:   Checksum mismatch or size limit exceeded.
            RuntimeError: Network or auth failure from transport layer.
        """
        # ── Pre-flight size gate ──────────────────────────────────────────────
        if expected_size > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload too large: server reported {expected_size} bytes "
                f"which exceeds the {MAX_PAYLOAD_BYTES // (1024*1024)} MB limit."
            )

        logger.info(f"Pulling payload from {payload_url} ...")

        loop  = asyncio.get_event_loop()
        raw_b = await loop.run_in_executor(
            None,
            lambda: transport.get_raw_bytes(payload_url),
        )

        # ── Post-fetch size check ─────────────────────────────────────────────
        if len(raw_b) > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Downloaded payload ({len(raw_b)} B) exceeds "
                f"{MAX_PAYLOAD_BYTES // (1024*1024)} MB limit."
            )

        # ── Integrity verification ────────────────────────────────────────────
        received = 'sha256:' + hashlib.sha256(raw_b).hexdigest()
        if expected_checksum and received != expected_checksum:
            raise ValueError(
                f"Payload integrity check FAILED.\n"
                f"  Expected : {expected_checksum}\n"
                f"  Received : {received}\n"
                f"Aborting task — payload may have been tampered with or corrupted."
            )

        logger.info(
            f"Payload pull complete: {len(raw_b)} B "
            f"checksum verified ({received[:24]}…)"
        )
        return cls(raw_b, source='manual')

    # =========================================================================
    # SLICING INTERFACE
    # =========================================================================

    def chunks(self, technique: str) -> list[bytes]:
        """
        Slice the buffer into byte chunks sized for the given transport.

        This is the single method all three transport helpers call.
        chunk size is determined entirely by protocol constraints:
          • DNS : 20 B raw → Base32 → ~32-char label ≤ 63-char DNS limit
          • HTTP: 100 B raw → Base64 → manageable header value length
          • ICMP: 64 B raw → fits within safe ICMP echo payload window

        Args:
            technique: 'dns' | 'http' | 'icmp'

        Returns:
            List of bytes objects.  Last chunk may be shorter than chunk_size.
        """
        size   = CHUNK_SIZES.get(technique, CHUNK_SIZES['dns'])
        data   = self._raw
        result = [data[i:i + size] for i in range(0, len(data), size)]
        logger.debug(
            f"Sliced {len(data)} B into {len(result)} chunks "
            f"of {size} B for technique={technique}"
        )
        return result

    # =========================================================================
    # METADATA
    # =========================================================================

    @property
    def size(self) -> int:
        """Raw byte count."""
        return len(self._raw)

    @property
    def source(self) -> str:
        """'generated' or 'manual' — included in telemetry summary."""
        return self._source

    def checksum(self) -> str:
        """SHA-256 hex digest prefixed with 'sha256:'."""
        return 'sha256:' + hashlib.sha256(self._raw).hexdigest()

    def checksum_short(self) -> str:
        """First 16 hex chars + ellipsis — for log messages."""
        return self.checksum()[:23] + '…'

    def chunk_count(self, technique: str) -> int:
        """Number of chunks that will be produced for a given technique."""
        size = CHUNK_SIZES.get(technique, CHUNK_SIZES['dns'])
        return (len(self._raw) + size - 1) // size

    def __repr__(self) -> str:
        return (
            f"PayloadBuffer(source={self._source!r}, "
            f"size={self.size} B, checksum={self.checksum_short()})"
        )