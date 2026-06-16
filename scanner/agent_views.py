# scanner/agent_views.py
import logging
from django.conf                    import settings
from rest_framework.decorators      import api_view, authentication_classes, permission_classes
from rest_framework.permissions     import IsAuthenticated, AllowAny
from rest_framework.response        import Response
from rest_framework                 import status

from .authentication import AgentAuthentication
from .models         import Agent, ScanRequest, ScanProfile, ScanStatus
from .jwt_auth       import create_access_token, create_refresh_token

logger  = logging.getLogger('MIAT.AgentViews')
REG_KEY = getattr(settings, 'MIAT_REGISTRATION_KEY', 'changeme-set-in-settings')


# =============================================================================
# REGISTRATION
# POST /api/agent/register/
# =============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def agent_register(request):
    """
    First-time agent registration.
    Creates the Agent row and issues the auth_token + secret_key pair.
    """
    agent_id = request.data.get('agent_id', '').strip()
    name     = request.data.get('name', '').strip()
    reg_key  = request.data.get('registration_key', '').strip()

    if not agent_id or not reg_key:
        return Response({'error': 'agent_id and registration_key required.'}, status=400)

    if reg_key != REG_KEY:
        return Response({'error': 'Invalid registration key.'}, status=401)

    agent, created = Agent.objects.get_or_create(
        agent_id=agent_id,
        defaults={
            'name':       name or agent_id,
            'auth_token': Agent.generate_auth_token(),
            'secret_key': Agent.generate_secret_key(),
            'is_active':  True,
        },
    )

    if not created and not agent.is_active:
        return Response({'error': f'Agent "{agent_id}" exists but is disabled.'}, status=403)

    action = 'registered' if created else 're-authenticated'
    logger.info(f'Agent {action}: {agent_id}')

    return Response({
        'agent_id':   agent.agent_id,
        'auth_token': agent.auth_token,
        'secret_key': agent.secret_key,
        'access':     create_access_token(agent.agent_id),
        'refresh':    create_refresh_token(agent.agent_id),
        'action':     action,
    }, status=201 if created else 200)


# =============================================================================
# HEARTBEAT
# POST /api/agent/heartbeat/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def agent_heartbeat(request):
    """
    Periodic keep-alive.  Updates last_seen_at, optionally updates capabilities.
    Called every HEARTBEAT_INTERVAL seconds by the orchestrator.
    """
    agent_proxy  = request.user
    capabilities = request.data.get('capabilities', [])
    plugins      = request.data.get('plugins', [])

    try:
        agent = Agent.objects.get(agent_id=agent_proxy.agent_id)
        if capabilities:
            agent.capabilities = capabilities
            agent.save(update_fields=['capabilities'])
    except Agent.DoesNotExist:
        pass

    return Response({
        'status':  'alive',
        'plugins': plugins,
    })


# =============================================================================
# CAPABILITY REGISTRATION
# POST /api/agent/capabilities/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def agent_capabilities(request):
    """
    Called by the orchestrator after all plugins are loaded.
    Stores capability metadata in the Agent row.
    """
    capabilities = request.data.get('capabilities', [])
    try:
        agent = Agent.objects.get(agent_id=request.user.agent_id)
        agent.capabilities = capabilities
        agent.save(update_fields=['capabilities'])
        logger.info(
            f"Capabilities stored for {agent.agent_id}: "
            f"{[c.get('name') for c in capabilities]}"
        )
    except Agent.DoesNotExist:
        pass
    return Response({'stored': len(capabilities)})


# =============================================================================
# AGENT-SUBMITTED SCAN
# POST /api/agent/scan/submit/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def agent_submit_scan(request):
    """
    Agent submits a scan request on behalf of a web-initiated nmap task.
    Creates a ScanRequest row tied to the submitting agent.
    """
    target  = request.data.get('target', '').strip()
    profile = request.data.get('scan_profile', ScanProfile.DEFAULT)

    if not target:
        return Response({'error': 'target is required.'}, status=400)

    try:
        agent = Agent.objects.get(agent_id=request.user.agent_id)
    except Agent.DoesNotExist:
        agent = None

    scan = ScanRequest.objects.create(
        target       = target,
        scan_profile = profile,
        agent        = agent,
        status       = ScanStatus.PENDING,
    )

    logger.info(f'Agent {request.user.agent_id} submitted scan #{scan.pk} → {target}')
    return Response({'scan_id': scan.pk, 'status': scan.status}, status=201)


# =============================================================================
# GENERIC RESULT INGESTION
# POST /api/agent/results/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def agent_post_results(request):
    """
    Generic catch-all result endpoint.
    Plugin-specific results should go to their dedicated endpoints:
      /api/agent/dga/results/   → dga_views.api_dga_results
      /api/agent/exfil/results/ → exfil_views.api_exfil_results
    This endpoint handles nmap PortFindings and any future plugin results.
    """
    plugin  = request.data.get('plugin', 'unknown')
    success = request.data.get('success', True)
    data    = request.data.get('data', {})

    logger.info(
        f"Result received from agent {request.user.agent_id}: "
        f"plugin={plugin} success={success}"
    )
    return Response({'received': True, 'plugin': plugin})


# =============================================================================
# COMMAND POLL (fallback — primary path is WebSocket)
# GET /api/agent/status/
# =============================================================================

@api_view(['GET'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def agent_poll_commands(request):
    """
    HTTP fallback for agents that cannot maintain a WebSocket connection.
    Returns any pending commands for this agent.
    Primary command delivery is via WebSocket (AgentConsumer).
    """
    from .models import ModuleTask, TaskStatus
    pending = (
        ModuleTask.objects
        .filter(agent__agent_id=request.user.agent_id, status=TaskStatus.PENDING)
        .values('task_id', 'module', 'config_json')
        .order_by('dispatched_at')[:5]
    )

    commands = []
    for t in pending:
        commands.append({
            'task_id': str(t['task_id']),
            'command': t['module'],
            'args':    {**t['config_json'], 'task_id': str(t['task_id'])},
        })

    return Response({'commands': commands, 'count': len(commands)})