# scanner/token_views.py
# ─────────────────────────────────────────────────────────────────────────────
#  MIAT — JWT Token Endpoints
#
#  Endpoints:
#    POST /api/agent/token/          → agent logs in, gets access + refresh token
#    POST /api/agent/token/refresh/  → agent uses refresh token to get new access token
#    POST /api/agent/token/verify/   → check if a token is still valid
# ─────────────────────────────────────────────────────────────────────────────

import logging
from django.conf             import settings
from rest_framework.decorators  import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.response    import Response
from rest_framework             import status

from .models    import Agent
from .jwt_auth  import (
    create_access_token,
    create_refresh_token,
    verify_token,
    MutualTLSJWTAuthentication,
    JWT_ACCESS_EXPIRY_MINUTES,
    JWT_REFRESH_EXPIRY_MINUTES,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT 1 — Get tokens (login)
# POST /api/agent/token/
#
# The agent calls this after the TLS handshake succeeds.
# mTLS has already proven the machine identity at the network layer.
# Now the agent identifies itself at the application layer.
#
# Request body:
#   { "agent_id": "barc-lab-01", "registration_key": "your-admin-key" }
#
# Response:
#   {
#     "access_token":  "eyJ...",   ← use on every API request (15 min)
#     "refresh_token": "eyJ...",   ← use to get new access token (24 hr)
#     "expires_in":    900         ← seconds until access token expires
#   }
# ─────────────────────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([AllowAny])   # no auth needed — this IS the auth endpoint
def obtain_token(request):
    """Agent logs in and receives JWT access + refresh tokens."""

    agent_id         = request.data.get('agent_id', '').strip()
    registration_key = request.data.get('registration_key', '').strip()
    expected_key     = getattr(settings, 'AGENT_REGISTRATION_KEY', '')

    if not agent_id:
        return Response(
            {'error': 'agent_id is required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    if registration_key != expected_key:
        logger.warning(f'Token request failed: wrong registration_key for {agent_id}')
        return Response(
            {'error': 'Invalid registration key.'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        agent = Agent.objects.get(agent_id=agent_id, is_active=True)
    except Agent.DoesNotExist:
        # Use same error as above — don't reveal whether agent exists
        return Response(
            {'error': 'Invalid credentials.'},
            status=status.HTTP_403_FORBIDDEN
        )

    access_token  = create_access_token(agent)
    refresh_token = create_refresh_token(agent)

    logger.info(f'JWT tokens issued to agent: {agent_id}')

    return Response({
        'access_token':  access_token,
        'refresh_token': refresh_token,
        'expires_in':    JWT_ACCESS_EXPIRY_MINUTES * 60,  # in seconds
        'token_type':    'Bearer',
        'agent_id':      agent.agent_id,
    })


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT 2 — Refresh token
# POST /api/agent/token/refresh/
#
# When the access token expires (15 min), the agent calls this with the
# refresh token to get a new access token — without re-entering credentials.
#
# Request body:
#   { "refresh_token": "eyJ..." }
#
# Response:
#   { "access_token": "eyJ...", "expires_in": 900 }
# ─────────────────────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token_view(request):
    """Exchange a refresh token for a new access token."""

    refresh_token = request.data.get('refresh_token', '').strip()

    if not refresh_token:
        return Response(
            {'error': 'refresh_token is required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Verify the refresh token
    payload  = verify_token(refresh_token, expected_type='refresh')
    agent_id = payload.get('agent_id')

    try:
        agent = Agent.objects.get(agent_id=agent_id, is_active=True)
    except Agent.DoesNotExist:
        return Response(
            {'error': f'Agent "{agent_id}" not found or disabled.'},
            status=status.HTTP_403_FORBIDDEN
        )

    new_access_token = create_access_token(agent)

    logger.info(f'Access token refreshed for agent: {agent_id}')

    return Response({
        'access_token': new_access_token,
        'expires_in':   JWT_ACCESS_EXPIRY_MINUTES * 60,
        'token_type':   'Bearer',
    })


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT 3 — Verify token
# POST /api/agent/token/verify/
#
# Lets the agent check if its current access token is still valid
# before attempting an authenticated request.
# ─────────────────────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_token_view(request):
    """Check if a token is valid without performing any action."""

    token = request.data.get('token', '').strip()

    if not token:
        return Response(
            {'error': 'token is required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    payload = verify_token(token)   # raises AuthenticationFailed if invalid

    return Response({
        'valid':     True,
        'agent_id':  payload.get('agent_id'),
        'exp':       payload.get('exp'),
        'token_type': payload.get('type'),
    })