# scanner/authentication.py
# =============================================================================
#  MIAT — Final Authentication Class
#  Combines JWT (identity + expiry) + HMAC (body integrity) in one class.
#
#  This REPLACES the old authentication.py completely.
#  Every authenticated API request must pass BOTH checks:
#
#    Check 1 — JWT Bearer token
#      Proves:  "I am agent barc-lab-01 and my session is valid"
#      Fails:   if token expired, tampered, or signed by wrong key
#
#    Check 2 — HMAC-SHA256 signature
#      Proves:  "This exact request body was sent by the real agent"
#      Fails:   if body was modified in transit or timestamp is stale
#
#  Header requirements on every request:
#    Authorization: Bearer <jwt_access_token>
#    X-Timestamp:   <unix_timestamp_float>
#    X-Signature:   <hmac_sha256_hex(secret_key, "timestamp:body")>
# =============================================================================

import time
import hmac
import hashlib
import logging
from pathlib import Path

from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions     import AuthenticationFailed

from .models import Agent

logger = logging.getLogger(__name__)

TIMESTAMP_TOLERANCE = 300   # 5 minutes — reject requests older than this


def _load_public_key() -> str:
    """
    Load the RSA public key used to verify JWT signatures.
    This key can ONLY verify — it cannot sign new tokens.
    Path set in settings.py as JWT_PUBLIC_KEY_PATH.
    """
    key_path = getattr(settings, 'JWT_PUBLIC_KEY_PATH', 'certs/server_pub.key')
    path = Path(key_path)
    if not path.exists():
        raise RuntimeError(
            f"JWT public key not found at '{key_path}'.\n"
            f"Run: openssl x509 -pubkey -noout -in certs/server.crt > certs/server_pub.key\n"
            f"Then set JWT_PUBLIC_KEY_PATH in settings.py"
        )
    return path.read_text()


class AgentAuthentication(BaseAuthentication):
    """
    Final DRF authentication class combining JWT + HMAC.

    Use on any agent-facing API view:

        @api_view(['POST'])
        @authentication_classes([AgentAuthentication])
        @permission_classes([IsAuthenticated])
        def my_view(request):
            agent = request.user   # authenticated Agent object
    """

    def authenticate(self, request):
        # ── Check 1: JWT Bearer token ─────────────────────────────────────────
        auth_header = request.headers.get('Authorization', '')

        if not auth_header:
            return None    # no auth attempted

        if not auth_header.startswith('Bearer '):
            return None    # wrong scheme

        token = auth_header[7:].strip()
        if not token:
            raise AuthenticationFailed('Empty Bearer token.')

        # Verify JWT — import here to avoid circular imports
        try:
            import jwt as pyjwt
        except ImportError:
            raise AuthenticationFailed(
                'PyJWT not installed on server. Run: pip install PyJWT'
            )

        public_key = _load_public_key()

        try:
            payload = pyjwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                options={'verify_exp': True},
            )
        except pyjwt.ExpiredSignatureError:
            raise AuthenticationFailed(
                'JWT token expired. '
                'POST to /api/agent/token/refresh/ with your refresh token.'
            )
        except pyjwt.InvalidSignatureError:
            raise AuthenticationFailed('JWT signature invalid.')
        except pyjwt.DecodeError as exc:
            raise AuthenticationFailed(f'JWT decode error: {exc}')

        if payload.get('type') != 'access':
            raise AuthenticationFailed(
                f"Wrong token type '{payload.get('type')}'. Need 'access' token."
            )

        agent_id = payload.get('agent_id')
        if not agent_id:
            raise AuthenticationFailed('JWT missing agent_id claim.')

        # Load agent from database
        try:
            agent = Agent.objects.get(agent_id=agent_id, is_active=True)
        except Agent.DoesNotExist:
            raise AuthenticationFailed(f'Agent "{agent_id}" not found or disabled.')

        # ── Check 2: HMAC-SHA256 body signature ───────────────────────────────
        timestamp_str = request.headers.get('X-Timestamp', '')
        signature     = request.headers.get('X-Signature', '')

        if not timestamp_str:
            raise AuthenticationFailed(
                'Missing X-Timestamp header. '
                'Agent must sign every request with HMAC.'
            )

        if not signature:
            raise AuthenticationFailed(
                'Missing X-Signature header. '
                'Agent must sign every request with HMAC.'
            )

        # Check timestamp freshness — prevents replay attacks
        try:
            request_time = float(timestamp_str)
        except ValueError:
            raise AuthenticationFailed('X-Timestamp must be a float (Unix time).')

        age = abs(time.time() - request_time)
        if age > TIMESTAMP_TOLERANCE:
            raise AuthenticationFailed(
                f'Request timestamp is {int(age)}s old. '
                f'Max allowed: {TIMESTAMP_TOLERANCE}s. '
                f'Check system clock on agent.'
            )

        # Compute expected HMAC and compare
        try:
            body = request.body.decode('utf-8')
        except Exception:
            body = ''

        expected_sig = hmac.new(
            agent.secret_key.encode('utf-8'),
            f"{timestamp_str}:{body}".encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # compare_digest is safe against timing attacks
        if not hmac.compare_digest(expected_sig, signature):
            logger.warning(
                f'HMAC mismatch for agent {agent_id} '
                f'from {self._get_ip(request)}'
            )
            raise AuthenticationFailed(
                'HMAC signature mismatch. '
                'Request body may have been tampered with.'
            )

        # ── Both checks passed ────────────────────────────────────────────────
        agent.mark_seen(ip_address=self._get_ip(request))
        logger.info(f'Agent {agent_id} authenticated (JWT + HMAC)')

        return (agent, token)

    def authenticate_header(self, request):
        return 'Bearer realm="MIAT-Agent-API"'

    @staticmethod
    def _get_ip(request) -> str:
        fwd = request.META.get('HTTP_X_FORWARDED_FOR')
        if fwd:
            return fwd.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')