# scanner/jwt_auth.py
# =============================================================================
#  MIAT — JWT Token Management
#  Uses symmetric HS256 for simplicity in the lab environment.
#  Production deployments should swap to RS256 (asymmetric key pair).
# =============================================================================

import time
import logging
from typing import Optional

import jwt
from django.conf import settings

logger = logging.getLogger('MIAT.JWTAuth')

ACCESS_EXPIRY  = getattr(settings, 'JWT_ACCESS_EXPIRY_MINUTES',  15)   * 60
REFRESH_EXPIRY = getattr(settings, 'JWT_REFRESH_EXPIRY_MINUTES', 1440) * 60

_SECRET = getattr(settings, 'MIAT_JWT_SECRET', settings.SECRET_KEY)
_ALGO   = 'HS256'


def create_access_token(agent_id: str) -> str:
    payload = {
        'agent_id': agent_id,
        'type':     'access',
        'iat':      int(time.time()),
        'exp':      int(time.time()) + ACCESS_EXPIRY,
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGO)


def create_refresh_token(agent_id: str) -> str:
    payload = {
        'agent_id': agent_id,
        'type':     'refresh',
        'iat':      int(time.time()),
        'exp':      int(time.time()) + REFRESH_EXPIRY,
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGO)


def verify_token(token: str) -> Optional[dict]:
    """
    Returns the decoded payload dict if the token is valid and unexpired.
    Returns None on any failure — callers must treat None as authentication failure.
    """
    try:
        return jwt.decode(token, _SECRET, algorithms=[_ALGO])
    except jwt.ExpiredSignatureError:
        logger.debug('JWT expired')
        return None
    except jwt.InvalidTokenError as exc:
        logger.debug(f'JWT invalid: {exc}')
        return None


def rotate_tokens(refresh_token: str) -> Optional[tuple[str, str]]:
    """
    Exchange a valid refresh token for a new (access, refresh) pair.
    Returns None if the refresh token is invalid or expired.
    """
    payload = verify_token(refresh_token)
    if not payload or payload.get('type') != 'refresh':
        return None
    agent_id = payload.get('agent_id', '')
    return create_access_token(agent_id), create_refresh_token(agent_id)