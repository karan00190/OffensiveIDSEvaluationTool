# scanner/jwt_auth.py
# ─────────────────────────────────────────────────────────────────────────────
#  MIAT — JWT Authentication System
#
#  JWT = JSON Web Token. It's a self-contained token that carries:
#    - WHO you are (agent_id)
#    - WHEN it expires (exp)
#    - WHAT you're allowed to do (role)
#    - A SIGNATURE that proves nobody tampered with it
#
#  Structure of a JWT:
#    eyJhbGci...   ← Header (base64): { "alg": "RS256", "typ": "JWT" }
#    .eyJhZ2Vu...  ← Payload (base64): { "agent_id": "barc-lab-01", "exp": ... }
#    .SIGNATURE    ← RSA signature using server's private key
#
#  Why RS256 (RSA) and not HS256 (HMAC)?
#    HS256 uses the same secret to sign AND verify — so the agent needs
#    the secret, which means if the agent is compromised, the attacker
#    can forge tokens.
#    RS256 uses a PRIVATE key to sign (server only) and a PUBLIC key to
#    verify (anyone). The agent can verify tokens without being able to
#    create them. This is the right choice for this architecture.
#
#  Flow:
#    1. Agent sends its client cert (mTLS already verifies the machine)
#    2. Agent POSTs to /api/agent/token/ with agent_id
#    3. Server verifies agent exists → issues JWT signed with RS256
#    4. Agent includes JWT in every subsequent request
#    5. JWT expires in 15 minutes → agent refreshes automatically
# ─────────────────────────────────────────────────────────────────────────────

import jwt
import time
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib   import Path

from django.conf             import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions     import AuthenticationFailed

from .models import Agent

logger = logging.getLogger(__name__)

# JWT settings — these come from settings.py
JWT_ACCESS_EXPIRY_MINUTES  = getattr(settings, 'JWT_ACCESS_EXPIRY_MINUTES',  15)
JWT_REFRESH_EXPIRY_MINUTES = getattr(settings, 'JWT_REFRESH_EXPIRY_MINUTES', 1440)  # 24 hours
JWT_ALGORITHM              = 'RS256'


# ─────────────────────────────────────────────────────────────────────────────
# Key loading helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_private_key() -> str:
    """
    Load the RSA private key used to SIGN JWT tokens.
    Only the server has this — agents cannot forge tokens.
    Path configured in settings.py as JWT_PRIVATE_KEY_PATH.
    """
    key_path = getattr(settings, 'JWT_PRIVATE_KEY_PATH', 'certs/server.key')
    try:
        return Path(key_path).read_text()
    except FileNotFoundError:
        raise RuntimeError(
            f"JWT private key not found at '{key_path}'. "
            f"Run generate_certs.sh first, then set JWT_PRIVATE_KEY_PATH in settings.py"
        )


def _load_public_key() -> str:
    """
    Load the RSA public key used to VERIFY JWT tokens.
    The public key can be shared — it only verifies, not signs.
    """
    key_path = getattr(settings, 'JWT_PUBLIC_KEY_PATH', 'certs/server_pub.key')

    # If a separate public key file doesn't exist, extract from the certificate
    if not Path(key_path).exists():
        cert_path = getattr(settings, 'JWT_CERT_PATH', 'certs/server.crt')
        try:
            import subprocess
            result = subprocess.run(
                ['openssl', 'x509', '-pubkey', '-noout', '-in', cert_path],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass

    try:
        return Path(key_path).read_text()
    except FileNotFoundError:
        raise RuntimeError(
            f"JWT public key not found at '{key_path}'. "
            f"Run generate_certs.sh and set JWT_PUBLIC_KEY_PATH in settings.py"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Token creation
# ─────────────────────────────────────────────────────────────────────────────

def create_access_token(agent: Agent) -> str:
    """
    Create a short-lived JWT access token for an agent.
    Expires in JWT_ACCESS_EXPIRY_MINUTES (default 15 minutes).

    Payload:
        agent_id  — who this token belongs to
        role      — what they're allowed to do
        iat       — issued at (unix timestamp)
        exp       — expires at (unix timestamp)
        type      — "access" (distinguishes from refresh token)
    """
    now     = datetime.now(tz=timezone.utc)
    payload = {
        'agent_id': agent.agent_id,
        'role':     'agent',
        'iat':      int(now.timestamp()),
        'exp':      int((now + timedelta(minutes=JWT_ACCESS_EXPIRY_MINUTES)).timestamp()),
        'type':     'access',
    }
    private_key = _load_private_key()
    return jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM)


def create_refresh_token(agent: Agent) -> str:
    """
    Create a long-lived JWT refresh token.
    Expires in JWT_REFRESH_EXPIRY_MINUTES (default 24 hours).
    Used to get a new access token without re-authenticating.
    """
    now     = datetime.now(tz=timezone.utc)
    payload = {
        'agent_id': agent.agent_id,
        'iat':      int(now.timestamp()),
        'exp':      int((now + timedelta(minutes=JWT_REFRESH_EXPIRY_MINUTES)).timestamp()),
        'type':     'refresh',
    }
    private_key = _load_private_key()
    return jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM)


# ─────────────────────────────────────────────────────────────────────────────
# Token verification
# ─────────────────────────────────────────────────────────────────────────────

def verify_token(token: str, expected_type: str = 'access') -> dict:
    """
    Verify and decode a JWT token.
    Returns the payload dict if valid.
    Raises AuthenticationFailed if invalid, expired, or wrong type.

    This is called on every authenticated request.
    """
    public_key = _load_public_key()

    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[JWT_ALGORITHM],
            options={'verify_exp': True},
        )
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed(
            'JWT token has expired. '
            'Agent must refresh the token via POST /api/agent/token/refresh/'
        )
    except jwt.InvalidSignatureError:
        raise AuthenticationFailed('JWT signature is invalid.')
    except jwt.DecodeError as exc:
        raise AuthenticationFailed(f'JWT decode error: {exc}')
    except jwt.InvalidTokenError as exc:
        raise AuthenticationFailed(f'Invalid JWT: {exc}')

    if payload.get('type') != expected_type:
        raise AuthenticationFailed(
            f'Wrong token type. Expected "{expected_type}", '
            f'got "{payload.get("type")}".'
        )

    return payload


# ─────────────────────────────────────────────────────────────────────────────
# DRF Authentication class — plugs into @authentication_classes
# ─────────────────────────────────────────────────────────────────────────────

class MutualTLSJWTAuthentication(BaseAuthentication):
    """
    Combined mTLS + JWT authentication for DRF views.

    Checks two things on every request:
      1. mTLS client certificate (verified at TLS layer by daphne/nginx)
         Django reads the result from the HTTP header SSL_CLIENT_VERIFY
      2. JWT Bearer token in Authorization header

    Both must pass. mTLS alone proves "valid machine".
    JWT proves "valid identity with unexpired session".

    Usage on any view:
        @api_view(['POST'])
        @authentication_classes([MutualTLSJWTAuthentication])
        @permission_classes([IsAuthenticated])
        def my_view(request):
            agent = request.user  # the authenticated Agent object
    """

    def authenticate(self, request):
        # ── Step 1: Verify mTLS client certificate ────────────────────────
        # When daphne/nginx terminates TLS, it injects headers:
        #   SSL_CLIENT_VERIFY: SUCCESS or FAILED or NONE
        #   SSL_CLIENT_S_DN:   subject DN from the client cert
        #
        # In development (runserver without TLS), we skip this check.
        # In production (daphne with certs), we enforce it.

        tls_verify = request.META.get('HTTP_SSL_CLIENT_VERIFY', 'NONE')
        debug_mode = getattr(settings, 'DEBUG', False)

        if not debug_mode:
            # Production: require valid client certificate
            if tls_verify != 'SUCCESS':
                raise AuthenticationFailed(
                    'mTLS client certificate required. '
                    f'SSL_CLIENT_VERIFY={tls_verify}. '
                    'Agent must present a valid certificate signed by the MIAT CA.'
                )

            # Extract agent_id from certificate subject
            # Subject looks like: CN=miat-agent,O=BARC-MIAT,...
            cert_subject = request.META.get('HTTP_SSL_CLIENT_S_DN', '')
            if cert_subject:
                logger.debug(f'Client cert subject: {cert_subject}')

        # ── Step 2: Extract JWT from Authorization header ──────────────────
        auth_header = request.headers.get('Authorization', '')

        if not auth_header:
            return None   # no auth attempted — let other authenticators try

        if not auth_header.startswith('Bearer '):
            return None

        token = auth_header[7:].strip()
        if not token:
            raise AuthenticationFailed('Empty Bearer token.')

        # ── Step 3: Verify JWT ─────────────────────────────────────────────
        payload = verify_token(token, expected_type='access')

        agent_id = payload.get('agent_id')
        if not agent_id:
            raise AuthenticationFailed('JWT missing agent_id claim.')

        # ── Step 4: Load agent from database ──────────────────────────────
        try:
            agent = Agent.objects.get(agent_id=agent_id, is_active=True)
        except Agent.DoesNotExist:
            raise AuthenticationFailed(
                f'Agent "{agent_id}" not found or disabled.'
            )

        # ── Step 5: Update activity ────────────────────────────────────────
        agent.mark_seen(ip_address=self._get_ip(request))
        logger.info(f'Agent {agent_id} authenticated via mTLS+JWT')

        return (agent, token)

    def authenticate_header(self, request):
        return 'Bearer realm="MIAT-Agent" error="invalid_token"'

    @staticmethod
    def _get_ip(request) -> str:
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')