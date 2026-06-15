# scanner/agent_views.py
# =============================================================================
#  MIAT — Agent API Endpoints (Final)
#  Registration now issues JWT tokens immediately on success.
#  All other endpoints use the combined AgentAuthentication (JWT + HMAC).
# =============================================================================

import logging
from django.utils  import timezone
from django.conf   import settings

from rest_framework.decorators  import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response    import Response
from rest_framework             import status

from .models         import Agent, ScanRequest, ScanStatus
from .authentication import AgentAuthentication

logger = logging.getLogger(__name__)


# =============================================================================
# ENDPOINT 1 — Register agent + immediately issue JWT
# POST /api/agent/register/
# No auth required (this creates the auth credentials)
# =============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def agent_register(request):
    """
    Register a new agent.
    On success returns auth_token, secret_key, AND initial JWT tokens.
    Agent can start making authenticated calls immediately — no second step.

    Request:
        { "agent_id": "barc-lab-01", "name": "...", "registration_key": "..." }

    Response:
        {
            "agent_id":      "barc-lab-01",
            "auth_token":    "abc...",      ← for HMAC signing
            "secret_key":    "xyz...",      ← for HMAC signing
            "access_token":  "eyJ...",      ← JWT, expires 15 min
            "refresh_token": "eyJ...",      ← JWT, expires 24 hr
            "expires_in":    900
        }
    """
    from .jwt_auth import create_access_token, create_refresh_token, JWT_ACCESS_EXPIRY_MINUTES

    registration_key = request.data.get('registration_key', '')
    expected_key     = getattr(settings, 'AGENT_REGISTRATION_KEY', '')

    if not expected_key:
        return Response(
            {'error': 'AGENT_REGISTRATION_KEY not set in settings.py'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    if registration_key != expected_key:
        logger.warning(
            f'Failed registration from {request.META.get("REMOTE_ADDR")} '
            f'— wrong key'
        )
        return Response(
            {'error': 'Invalid registration key.'},
            status=status.HTTP_403_FORBIDDEN
        )

    agent_id = request.data.get('agent_id', '').strip()
    name     = request.data.get('name', agent_id)

    if not agent_id:
        return Response(
            {'error': 'agent_id is required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    if Agent.objects.filter(agent_id=agent_id).exists():
        return Response(
            {'error': f'Agent "{agent_id}" already registered.'},
            status=status.HTTP_409_CONFLICT
        )

    # Create agent with generated credentials
    auth_token = Agent.generate_auth_token()
    secret_key = Agent.generate_secret_key()

    agent = Agent.objects.create(
        agent_id   = agent_id,
        name       = name,
        auth_token = auth_token,
        secret_key = secret_key,
    )

    # Issue JWT tokens immediately — agent doesn't need a second login call
    access_token  = create_access_token(agent)
    refresh_token = create_refresh_token(agent)

    logger.info(f'Agent registered and JWT issued: {agent_id}')

    return Response({
        # Credentials for HMAC signing (save permanently)
        'agent_id':   agent.agent_id,
        'auth_token': auth_token,
        'secret_key': secret_key,

        # JWT tokens (access expires in 15 min, refresh in 24hr)
        'access_token':  access_token,
        'refresh_token': refresh_token,
        'expires_in':    JWT_ACCESS_EXPIRY_MINUTES * 60,

        'message': (
            'Agent registered. Save auth_token and secret_key permanently. '
            'Use access_token for immediate API calls.'
        ),
    }, status=status.HTTP_201_CREATED)


# =============================================================================
# ENDPOINT 2 — Heartbeat
# POST /api/agent/heartbeat/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def agent_heartbeat(request):
    """Agent sends this every 30s to confirm it's alive."""
    agent = request.user

    return Response({
        'acknowledged':  True,
        'server_time':   timezone.now().isoformat(),
        'agent_id':      agent.agent_id,
        'commands':      [],   # future: pending commands from server
    })


# =============================================================================
# ENDPOINT 3 — Submit scan
# POST /api/agent/scan/submit/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def agent_submit_scan(request):
    """Agent submits a scan request. Server queues via django-q2."""
    from django_q.tasks  import async_task
    from datetime        import timedelta

    agent        = request.user
    target       = request.data.get('target', '').strip()
    scan_profile = request.data.get('scan_profile', 'default')

    if not target:
        return Response(
            {'error': 'target is required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Token cache check
    token      = ScanRequest.generate_token(target, scan_profile)
    ttl        = getattr(settings, 'SCAN_CACHE_TTL', 3600)
    cutoff     = timezone.now() - timedelta(seconds=ttl)
    cached     = ScanRequest.objects.filter(
        token=token,
        status=ScanStatus.COMPLETE,
        completed_at__gte=cutoff
    ).first()

    if cached:
        return Response({
            'scan_id':   cached.pk,
            'status':    'complete',
            'cache_hit': True,
            'token':     token,
        })

    scan = ScanRequest.objects.create(
        target       = target,
        scan_profile = scan_profile,
        status       = ScanStatus.PENDING,
    )

    async_task(
        'scanner.tasks.run_scan_task',
        scan.pk,
        task_name = f'miat_scan_{scan.pk}',
    )

    logger.info(f'Agent {agent.agent_id} queued scan #{scan.pk} for {target}')

    return Response({
        'scan_id':    scan.pk,
        'status':     scan.status,
        'cache_hit':  False,
        'token':      token,
        'status_url': f'/api/scan/{scan.pk}/status/',
    }, status=status.HTTP_202_ACCEPTED)


# =============================================================================
# ENDPOINT 4 — Post results
# POST /api/agent/results/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def agent_post_results(request):
    """Agent posts findings from any module (DGA, exfil, etc.)"""
    agent    = request.user
    module   = request.data.get('module', 'unknown')
    target   = request.data.get('target', '')
    findings = request.data.get('findings', [])

    logger.info(
        f'Agent {agent.agent_id} posted {len(findings)} '
        f'results for module={module} target={target}'
    )

    return Response({
        'acknowledged':   True,
        'module':         module,
        'findings_count': len(findings),
    })


# =============================================================================
# ENDPOINT 5 — Poll commands
# GET /api/agent/status/
# =============================================================================

@api_view(['GET'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def agent_poll_commands(request):
    """Agent polls for pending commands (fallback if WebSocket unavailable)."""
    agent = request.user
    return Response({
        'agent_id':  agent.agent_id,
        'commands':  [],
        'timestamp': timezone.now().isoformat(),
    })