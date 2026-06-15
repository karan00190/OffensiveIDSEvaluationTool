#!/usr/bin/env python3
# agent/transport.py
# =============================================================================
#  MIAT — Secure Transport Layer
#
#  Handles ALL network I/O:
#    SecureTransport  → mTLS HTTP (JWT + HMAC signed)
#    WebSocketThread  → persistent WebSocket with mTLS + auto-reconnect
#
#  Nothing else in the agent touches the network.
#  Orchestrator uses SecureTransport for HTTP.
#  TelemetryEngine uses SecureTransport for result POSTs.
#  WebSocketThread is started by Orchestrator and passed to TelemetryEngine.
# =============================================================================

import hashlib
import hmac
import json
import logging
import ssl
import threading
import time
from pathlib import Path
from typing  import Optional

logger = logging.getLogger('MIAT.Transport')

try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import websocket
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False

TOKEN_REFRESH_BUFFER = 60   # seconds before expiry to refresh


# =============================================================================
# SSL CONTEXT — mutual TLS
# =============================================================================

def build_ssl_context(ca_cert: Path, agent_cert: Path, agent_key: Path) -> ssl.SSLContext:
    """
    Build an SSLContext that enforces mutual TLS.
    Both sides present and verify certificates.
    Used for BOTH HTTP and WebSocket connections.
    """
    for f, name in [(ca_cert,'CA cert'),(agent_cert,'Agent cert'),(agent_key,'Agent key')]:
        if not f.exists():
            raise FileNotFoundError(f"{name} not found at {f}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_cert))
    ctx.load_cert_chain(certfile=str(agent_cert), keyfile=str(agent_key))
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


# =============================================================================
# SECURE HTTP TRANSPORT — mTLS + JWT + HMAC
# =============================================================================

class SecureTransport:
    """
    Synchronous HTTP client.
    Every request is signed with:
      Authorization: Bearer <jwt>      — identity + expiry
      X-Timestamp:   <unix_float>      — replay prevention
      X-Signature:   <hmac_sha256>     — body integrity
    """

    def __init__(self, server_url: str, config: dict, ssl_ctx: ssl.SSLContext):
        self.server_url     = server_url.rstrip('/')
        self.config         = config
        self.ssl_ctx        = ssl_ctx
        self._access_token  : Optional[str] = None
        self._refresh_token : Optional[str] = None
        self._token_exp     = 0.0
        self._lock          = threading.Lock()

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """POST to /api/agent/token/ → store JWT access + refresh tokens."""
        logger.info("Authenticating — requesting JWT tokens...")
        data = self._raw_post('/api/agent/token/', {
            'agent_id':         self.config['agent_id'],
            'registration_key': self.config['registration_key'],
        })
        self._access_token  = data['access_token']
        self._refresh_token = data['refresh_token']
        self._token_exp     = self._parse_exp(self._access_token)
        logger.info(f"JWT obtained — expires in {int(self._token_exp - time.time())}s")

    def _refresh(self) -> None:
        data = self._raw_post('/api/agent/token/refresh/',
                              {'refresh_token': self._refresh_token})
        self._access_token = data['access_token']
        self._token_exp    = self._parse_exp(self._access_token)
        logger.info(f"JWT refreshed — expires in {int(self._token_exp - time.time())}s")

    def _ensure_token(self) -> None:
        with self._lock:
            if not self._access_token:
                self.authenticate()
                return
            if self._token_exp - time.time() < TOKEN_REFRESH_BUFFER:
                try:    self._refresh()
                except: self.authenticate()

    @staticmethod
    def _parse_exp(token: str) -> float:
        if not JWT_AVAILABLE:
            return time.time() + 840
        try:
            p = pyjwt.decode(token, options={"verify_signature": False})
            return float(p.get('exp', time.time() + 840))
        except Exception:
            return time.time() + 840

    # ── HMAC signing ──────────────────────────────────────────────────────────

    def _sign(self, body: str) -> tuple:
        """Returns (timestamp_str, hmac_hex)."""
        ts  = str(time.time())
        sig = hmac.new(
            self.config['secret_key'].encode('utf-8'),
            f"{ts}:{body}".encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return ts, sig

    # ── HTTP methods ──────────────────────────────────────────────────────────

    def _raw_post(self, path: str, data: dict) -> dict:
        """POST without JWT — used only for token endpoints."""
        import urllib.request
        body = json.dumps(data).encode('utf-8')
        req  = urllib.request.Request(
            f"{self.server_url}{path}", data=body,
            headers={'Content-Type': 'application/json'}, method='POST',
        )
        with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=10) as r:
            return json.loads(r.read())

    def post(self, path: str, data: dict = None) -> dict:
        """Authenticated POST — mTLS + JWT + HMAC."""
        import urllib.request, urllib.error
        self._ensure_token()
        body    = json.dumps(data or {})
        ts, sig = self._sign(body)
        req = urllib.request.Request(
            f"{self.server_url}{path}",
            data    = body.encode('utf-8'),
            headers = {
                'Content-Type':  'application/json',
                'Authorization': f'Bearer {self._access_token}',
                'X-Timestamp':   ts,
                'X-Signature':   sig,
            },
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=15) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            raw    = exc.read().decode()
            detail = json.loads(raw).get('detail', raw) if raw.startswith('{') else raw
            raise RuntimeError(f"HTTP {exc.code}: {detail}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Network error: {exc.reason}")

    def get(self, path: str) -> dict:
        """Authenticated GET — mTLS + JWT + HMAC."""
        import urllib.request
        self._ensure_token()
        ts, sig = self._sign('')
        req = urllib.request.Request(
            f"{self.server_url}{path}",
            headers={
                'Authorization': f'Bearer {self._access_token}',
                'X-Timestamp': ts, 'X-Signature': sig,
            },
            method='GET',
        )
        with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=15) as r:
            return json.loads(r.read())

    @property
    def access_token(self) -> Optional[str]:
        return self._access_token


# =============================================================================
# WEBSOCKET THREAD — persistent connection with mTLS + auto-reconnect
# =============================================================================

class WebSocketThread(threading.Thread):
    """
    Background thread maintaining a persistent WebSocket connection.
    Receives commands from server → dispatches to orchestrator callback.
    Sends live output from plugins to browser dashboard.
    Uses same SSL context as HTTP — mTLS on WebSocket too.
    """

    def __init__(
        self,
        server_url    : str,
        agent_id      : str,
        auth_token    : str,
        ssl_ctx       : ssl.SSLContext,
        on_command    : callable,   # orchestrator.dispatch_command callback
    ):
        super().__init__(daemon=True, name='ws-thread')
        ws_base       = server_url.replace('https://','wss://').replace('http://','ws://')
        self.ws_url   = f"{ws_base}/ws/agent/{agent_id}/?token={auth_token}"
        self.ssl_ctx  = ssl_ctx
        self.on_command = on_command
        self.ws         = None
        self.running    = True
        self.connected  = False

    def run(self) -> None:
        if not WS_AVAILABLE:
            logger.error("websocket-client not installed — pip install websocket-client")
            return

        while self.running:
            try:
                logger.info("WebSocket connecting...")
                self.ws = websocket.WebSocketApp(
                    self.ws_url,
                    on_open    = self._on_open,
                    on_message = self._on_message,
                    on_error   = self._on_error,
                    on_close   = self._on_close,
                )
                self.ws.run_forever(
                    sslopt        = {"context": self.ssl_ctx},
                    ping_interval = 30,
                    ping_timeout  = 10,
                )
            except Exception as exc:
                logger.error(f"WebSocket run error: {exc}")
            if self.running:
                logger.info("WebSocket disconnected — reconnecting in 5s...")
                time.sleep(5)

    def stop(self) -> None:
        self.running   = False
        self.connected = False
        if self.ws:
            self.ws.close()

    def _on_open(self, ws) -> None:
        self.connected = True
        logger.info("WebSocket connected — bidirectional channel open")
        self.send({'type': 'connected_ack', 'status': 'ready'})

    def _on_message(self, ws, message: str) -> None:
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            logger.warning(f"Unparseable WS message: {message[:80]}")
            return

        msg_type = data.get('type', '')

        if msg_type == 'connected':
            logger.info(f"Server: {data.get('message','')}")
        elif msg_type == 'heartbeat_ack':
            logger.debug("Heartbeat ACK")
        elif msg_type == 'command':
            # Hand off to orchestrator — never block here
            t = threading.Thread(
                target=self.on_command, args=(data,), daemon=True
            )
            t.start()
        elif msg_type == 'error':
            logger.error(f"Server WS error: {data.get('message','')}")

    def _on_error(self, ws, error) -> None:
        self.connected = False
        logger.error(f"WebSocket error: {error}")

    def _on_close(self, ws, code, msg) -> None:
        self.connected = False
        logger.warning(f"WebSocket closed (code={code})")

    def send(self, data: dict) -> None:
        if self.ws and self.connected:
            try:
                self.ws.send(json.dumps(data))
            except Exception as exc:
                logger.error(f"WS send failed: {exc}")

    def send_module_output(self, module: str, output: str) -> None:
        """Stream live plugin output to server dashboard."""
        self.send({'type': 'module_output', 'module': module, 'output': output})

    def send_heartbeat(self, plugins: list) -> None:
        self.send({'type': 'heartbeat', 'plugins_loaded': plugins})

    def send_ids_alert(self, message: str) -> None:
        self.send({'type': 'ids_alert', 'message': message})