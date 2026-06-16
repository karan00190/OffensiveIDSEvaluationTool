# scanner/authentication.py
import hashlib, hmac, logging, time
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions     import AuthenticationFailed
from .jwt_auth                     import verify_token
from .models                       import Agent

logger = logging.getLogger('MIAT.Auth')

REPLAY_WINDOW = 300   # seconds — reject requests older than 5 minutes


class _AgentProxy:
    """Lightweight stand-in for request.user so DRF permission checks work."""
    def __init__(self, agent: Agent):
        self._agent      = agent
        self.agent_id    = agent.agent_id
        self.is_active   = agent.is_active
        self.is_anonymous= False

    def __getattr__(self, name):
        return getattr(self._agent, name)


class AgentAuthentication(BaseAuthentication):
    """
    Triple-layer authentication for agent-facing API endpoints:
      1. JWT Bearer token — verifies agent identity, 15-min expiry
      2. X-Timestamp header — validates request recency (replay window)
      3. X-Signature header — HMAC-SHA256 of f'{timestamp}:{body}' using
         the agent's per-row secret_key

    All three must pass.  Failure on any layer raises AuthenticationFailed.
    """

    def authenticate(self, request):
        # ── 1. JWT ────────────────────────────────────────────────────────────
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return None   # not our auth scheme — let other backends try
        token = auth_header[7:].strip()
        payload = verify_token(token)
        if not payload:
            raise AuthenticationFailed('JWT invalid or expired.')

        agent_id = payload.get('agent_id', '')
        try:
            agent = Agent.objects.get(agent_id=agent_id, is_active=True)
        except Agent.DoesNotExist:
            raise AuthenticationFailed(f'Agent "{agent_id}" not found or inactive.')

        # ── 2. Timestamp replay window ────────────────────────────────────────
        ts_header = request.headers.get('X-Timestamp', '')
        if not ts_header:
            raise AuthenticationFailed('X-Timestamp header missing.')
        try:
            req_time = int(ts_header)
        except ValueError:
            raise AuthenticationFailed('X-Timestamp must be a Unix integer.')
        age = abs(time.time() - req_time)
        if age > REPLAY_WINDOW:
            raise AuthenticationFailed(
                f'Request timestamp too old ({int(age)}s > {REPLAY_WINDOW}s window).'
            )

        # ── 3. HMAC-SHA256 body signature ─────────────────────────────────────
        sig_header = request.headers.get('X-Signature', '')
        if not sig_header:
            raise AuthenticationFailed('X-Signature header missing.')

        body = request.body.decode('utf-8', errors='replace')
        expected = hmac.new(
            agent.secret_key.encode('utf-8'),
            f'{ts_header}:{body}'.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected, sig_header):
            raise AuthenticationFailed('HMAC signature mismatch.')

        # Mark the agent as seen (updates last_seen_at + total_requests)
        agent.mark_seen(
            ip_address=request.META.get('REMOTE_ADDR')
        )
        logger.debug(f'Auth OK: agent={agent_id}')
        return _AgentProxy(agent), token