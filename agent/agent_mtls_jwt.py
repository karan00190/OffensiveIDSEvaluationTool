#!/usr/bin/env python3
# agent_mtls_jwt.py
# ─────────────────────────────────────────────────────────────────────────────
#  MIAT Agent — Mutual TLS + JWT Authentication
#
#  This replaces the basic HTTP client in agent.py.
#  Every request now:
#    1. Uses client certificate (mTLS) — proves machine identity
#    2. Sends JWT Bearer token — proves agent identity
#    3. Auto-refreshes the JWT when it's about to expire
#
#  Files needed on the agent machine (copy from server after cert generation):
#    certs/ca.crt     ← to verify the SERVER's certificate
#    certs/agent.crt  ← the AGENT's certificate (proves its identity)
#    certs/agent.key  ← the AGENT's private key (keep SECRET)
#
#  Usage:
#    pip install requests PyJWT
#    python agent_mtls_jwt.py --register --agent-id barc-lab-01 --reg-key KEY
#    python agent_mtls_jwt.py
# ─────────────────────────────────────────────────────────────────────────────

import json
import time
import logging
import os
import sys
import argparse
import threading
from pathlib import Path

import requests           # pip install requests
import jwt as pyjwt       # pip install PyJWT

logging.basicConfig(
    level   = logging.INFO,
    format  = '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt = '%H:%M:%S',
)
logger = logging.getLogger('MIAT-Agent')

CONFIG_FILE = 'agent_config.json'
CERT_DIR    = Path('certs')

# These three files must exist on the agent machine
CA_CERT    = CERT_DIR / 'ca.crt'      # verifies server's certificate
AGENT_CERT = CERT_DIR / 'agent.crt'   # agent's certificate
AGENT_KEY  = CERT_DIR / 'agent.key'   # agent's private key


# ─────────────────────────────────────────────────────────────────────────────
# Secure HTTP Client with mTLS + JWT
# ─────────────────────────────────────────────────────────────────────────────

class SecureAgentClient:
    """
    HTTP client that authenticates every request with:
      - mTLS:  presents agent.crt + agent.key (proves machine identity)
               verifies server using ca.crt (proves server identity)
      - JWT:   Bearer token in Authorization header (proves agent identity)
               auto-refreshes when token is about to expire

    This is the core of the mutual TLS + JWT authentication system.
    """

    # Refresh the access token when less than this many seconds remain
    TOKEN_REFRESH_BUFFER_SECONDS = 60

    def __init__(
        self,
        server_url:    str,
        agent_id:      str,
        reg_key:       str,
        ca_cert:       Path = CA_CERT,
        agent_cert:    Path = AGENT_CERT,
        agent_key:     Path = AGENT_KEY,
    ):
        self.server_url    = server_url.rstrip('/')
        self.agent_id      = agent_id
        self.reg_key       = reg_key
        self._access_token  = None
        self._refresh_token = None
        self._token_exp     = 0
        self._token_lock    = threading.Lock()   # thread-safe token refresh

        # ── Validate cert files exist ─────────────────────────────────────
        for f, name in [(ca_cert, 'CA cert'), (agent_cert, 'Agent cert'), (agent_key, 'Agent key')]:
            if not Path(f).exists():
                raise FileNotFoundError(
                    f'{name} not found: {f}\n'
                    f'Copy from server: ca.crt, agent.crt, agent.key → {CERT_DIR}/'
                )

        # ── requests SSL configuration ────────────────────────────────────
        # verify = ca.crt   → requests uses this to verify the SERVER's cert
        # cert   = (agent.crt, agent.key) → sent to server as CLIENT cert (mTLS)
        self._ssl_verify = str(ca_cert)
        self._ssl_cert   = (str(agent_cert), str(agent_key))

        # Build a session object (reuses TCP connections efficiently)
        self._session = requests.Session()
        self._session.verify = self._ssl_verify
        self._session.cert   = self._ssl_cert

        logger.info(f'SecureAgentClient initialized for {agent_id}')
        logger.info(f'  mTLS: presenting {agent_cert} to server')
        logger.info(f'  mTLS: verifying server with {ca_cert}')

    # ── Token management ──────────────────────────────────────────────────────

    def authenticate(self):
        """
        Log in and get JWT access + refresh tokens.
        Called once at startup and after token refresh fails.
        """
        logger.info('Obtaining JWT tokens...')
        resp = self._session.post(
            f'{self.server_url}/api/agent/token/',
            json={
                'agent_id':         self.agent_id,
                'registration_key': self.reg_key,
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        self._access_token  = data['access_token']
        self._refresh_token = data['refresh_token']
        self._token_exp     = self._decode_expiry(self._access_token)

        logger.info(
            f'JWT obtained. Expires in '
            f'{int(self._token_exp - time.time())}s'
        )

    def _refresh_access_token(self):
        """
        Exchange the refresh token for a new access token.
        Called automatically before the access token expires.
        """
        logger.info('Refreshing JWT access token...')
        resp = self._session.post(
            f'{self.server_url}/api/agent/token/refresh/',
            json={'refresh_token': self._refresh_token},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        self._access_token = data['access_token']
        self._token_exp    = self._decode_expiry(self._access_token)
        logger.info(
            f'JWT refreshed. Expires in '
            f'{int(self._token_exp - time.time())}s'
        )

    def _ensure_valid_token(self):
        """
        Check if access token is about to expire — refresh if needed.
        Called before every request. Thread-safe via lock.
        """
        with self._token_lock:
            if not self._access_token:
                self.authenticate()
                return

            remaining = self._token_exp - time.time()
            if remaining < self.TOKEN_REFRESH_BUFFER_SECONDS:
                try:
                    self._refresh_access_token()
                except Exception as exc:
                    logger.warning(f'Token refresh failed ({exc}) — re-authenticating')
                    self.authenticate()

    @staticmethod
    def _decode_expiry(token: str) -> float:
        """Extract expiry timestamp from JWT without verification (already verified by server)."""
        try:
            payload = pyjwt.decode(token, options={"verify_signature": False})
            return float(payload.get('exp', 0))
        except Exception:
            return time.time() + 60   # fallback: assume 60 seconds

    # ── HTTP methods ──────────────────────────────────────────────────────────

    def _headers(self) -> dict:
        """Build auth headers for a request."""
        self._ensure_valid_token()
        return {
            'Authorization': f'Bearer {self._access_token}',
            'Content-Type':  'application/json',
        }

    def get(self, path: str) -> dict:
        """Authenticated GET request."""
        resp = self._session.get(
            f'{self.server_url}{path}',
            headers=self._headers(),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, data: dict = None) -> dict:
        """Authenticated POST request."""
        resp = self._session.post(
            f'{self.server_url}{path}',
            json=data or {},
            headers=self._headers(),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()


# ─────────────────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────────────────

def register_agent(server_url, agent_id, name, reg_key):
    """
    Register a new agent with the server using mTLS.
    Uses the same secure client — even registration is done over mTLS.
    """
    logger.info(f'Registering agent "{agent_id}" via mTLS...')

    # For registration we use requests directly with mTLS
    resp = requests.post(
        f'{server_url.rstrip("/")}/api/agent/register/',
        json={
            'agent_id':         agent_id,
            'name':             name or agent_id,
            'registration_key': reg_key,
        },
        verify = str(CA_CERT),
        cert   = (str(AGENT_CERT), str(AGENT_KEY)),
        timeout = 10,
    )

    if resp.status_code != 201:
        logger.error(f'Registration failed: {resp.status_code} {resp.text}')
        sys.exit(1)

    data   = resp.json()
    config = {
        'server_url':         server_url,
        'agent_id':           data['agent_id'],
        'registration_key':   reg_key,
        'auth_token':         data['auth_token'],
        'secret_key':         data['secret_key'],
    }

    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

    logger.info(f'Registered! Config saved to {CONFIG_FILE}')
    logger.info(f'Agent ID: {config["agent_id"]}')


# ─────────────────────────────────────────────────────────────────────────────
# Agent main class
# ─────────────────────────────────────────────────────────────────────────────

class SecureMIATAgent:
    """
    Persistent agent using mTLS + JWT for every server interaction.
    """

    def __init__(self, config: dict):
        self.config  = config
        self.running = False
        self.client  = SecureAgentClient(
            server_url = config['server_url'],
            agent_id   = config['agent_id'],
            reg_key    = config['registration_key'],
        )

    def start(self):
        self.running = True
        logger.info(f"Secure agent starting — ID: {self.config['agent_id']}")

        # Authenticate (get JWT) before starting any threads
        self.client.authenticate()

        # Start heartbeat thread
        t = threading.Thread(target=self._heartbeat_loop, daemon=True)
        t.start()

        logger.info('Agent running securely (mTLS + JWT). Press Ctrl+C to stop.')
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        logger.info('Agent stopped.')

    def _heartbeat_loop(self):
        while self.running:
            try:
                resp = self.client.post('/api/agent/heartbeat/', {
                    'status':         'running',
                    'modules_active': [],
                })
                logger.debug(f"Heartbeat: {resp.get('server_time')}")
            except Exception as exc:
                logger.warning(f'Heartbeat failed: {exc}')
            time.sleep(30)

    def submit_scan(self, target: str, profile: str = 'default') -> dict:
        logger.info(f'Submitting scan: {target} ({profile})')
        try:
            resp = self.client.post('/api/agent/scan/submit/', {
                'target':       target,
                'scan_profile': profile,
            })
            logger.info(f'Scan queued: #{resp.get("scan_id")}')
            return resp
        except Exception as exc:
            logger.error(f'Scan submission failed: {exc}')
            return {}


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='MIAT Secure Agent (mTLS + JWT)')
    parser.add_argument('--register',   action='store_true')
    parser.add_argument('--agent-id',   help='Agent ID for registration')
    parser.add_argument('--agent-name', help='Display name')
    parser.add_argument('--reg-key',    help='Registration key from settings.py')
    parser.add_argument('--server',     default='https://127.0.0.1:8443')
    parser.add_argument('--scan',       help='Scan a single target and exit')
    parser.add_argument('--profile',    default='default')
    args = parser.parse_args()

    if args.register:
        if not args.agent_id or not args.reg_key:
            parser.error('--register requires --agent-id and --reg-key')
        register_agent(args.server, args.agent_id, args.agent_name, args.reg_key)
        return

    if not Path(CONFIG_FILE).exists():
        logger.error(f'{CONFIG_FILE} not found. Run --register first.')
        sys.exit(1)

    with open(CONFIG_FILE) as f:
        config = json.load(f)

    if args.server:
        config['server_url'] = args.server

    agent = SecureMIATAgent(config)

    if args.scan:
        agent.client.authenticate()
        result = agent.submit_scan(args.scan, args.profile)
        print(json.dumps(result, indent=2))
        return

    agent.start()


if __name__ == '__main__':
    main()