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
    'dns':  20,
    'http': 100,
    'icmp': 64,
}

# ── Machine-generated payload templates ──────────────────────────────────────
_TEMPLATES: dict[str, bytes] = {
    'credentials': b"username=admin&password=P@ssw0rd123&token=eyJhbGciOiJSUzI1NiJ9",
    'pii':         b"name=John Doe,dob=1990-01-15,ssn=123-45-6789,email=john@example.com",
    'api_key':     b"api_key=AKIA1234567890ABCDEF&secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCY",
    'db_dump':     b"id,name,email\n1,Alice,alice@ex.com\n2,Bob,bob@ex.com",
    'config':      b"DB_HOST=192.168.1.100\nDB_PASS=SuperSecret!\nSECRET_KEY=abc123",
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