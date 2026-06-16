# scanner/token_views.py
import logging
from django.conf                import settings
from rest_framework.decorators  import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response    import Response
from rest_framework             import status

from .jwt_auth import create_access_token, create_refresh_token, verify_token, rotate_tokens
from .models   import Agent

logger = logging.getLogger('MIAT.TokenViews')

REG_KEY = getattr(settings, 'MIAT_REGISTRATION_KEY', 'change-this-to-something-strong')


@api_view(['POST'])
@permission_classes([AllowAny])
def obtain_token(request):
    """
    POST /api/agent/token/
    Body: { "agent_id": "...", "reg_key": "..." }
    Returns: { "access": "...", "refresh": "..." }
    """
    agent_id = request.data.get('agent_id', '').strip()
    reg_key  = request.data.get('reg_key',  '').strip()

    if not agent_id or not reg_key:
        return Response(
            {'error': 'agent_id and reg_key are required.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if reg_key != REG_KEY:
        logger.warning(f'Bad registration key from agent {agent_id}')
        return Response(
            {'error': 'Invalid registration key.'},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        agent = Agent.objects.get(agent_id=agent_id, is_active=True)
    except Agent.DoesNotExist:
        return Response(
            {'error': f'Agent "{agent_id}" not found. Register first.'},
            status=status.HTTP_404_NOT_FOUND,
        )

    access  = create_access_token(agent.agent_id)
    refresh = create_refresh_token(agent.agent_id)
    logger.info(f'Token issued for agent {agent_id}')
    return Response({'access': access, 'refresh': refresh})


@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token_view(request):
    """
    POST /api/agent/token/refresh/
    Body: { "refresh": "..." }
    Returns: { "access": "...", "refresh": "..." }
    """
    refresh = request.data.get('refresh', '').strip()
    if not refresh:
        return Response({'error': 'refresh token required.'}, status=400)

    result = rotate_tokens(refresh)
    if not result:
        return Response({'error': 'Refresh token invalid or expired.'}, status=401)

    access_new, refresh_new = result
    return Response({'access': access_new, 'refresh': refresh_new})


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_token_view(request):
    """
    POST /api/agent/token/verify/
    Body: { "token": "..." }
    Returns: { "valid": true/false, "agent_id": "...", "exp": ... }
    """
    token = request.data.get('token', '').strip()
    payload = verify_token(token)
    if not payload:
        return Response({'valid': False}, status=200)
    return Response({
        'valid':    True,
        'agent_id': payload.get('agent_id'),
        'exp':      payload.get('exp'),
    })