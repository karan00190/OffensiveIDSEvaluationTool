# scanner/beacon_views.py
# =============================================================================
#  MIAT — C2 Beacon Simulation Views
#
#  Browser views:
#    dispatch_beacon_task  POST /api/modules/beacon/dispatch/
#    beacon_dashboard      GET  /beacon/
#    beacon_detail         GET  /beacon/<pk>/
#    beacon_mark_detected  POST /beacon/<pk>/mark/
#
#  Agent-facing view (AgentAuthentication — mTLS + JWT + HMAC):
#    api_beacon_results    POST /api/agent/beacon/results/
# =============================================================================

import json
import logging

from django.contrib.auth.decorators import login_required
from django.contrib                 import messages
from django.http                    import JsonResponse
from django.shortcuts               import render, get_object_or_404, redirect
from django.views.decorators.http   import require_http_methods

from asgiref.sync    import async_to_sync
from channels.layers import get_channel_layer

from rest_framework.decorators  import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response    import Response
from rest_framework             import status as drf_status

from .authentication import AgentAuthentication
from .dga_views      import _close_moduletask_loop
from .models         import Agent, BeaconResult, ModuleTask, ModuleChoice

logger = logging.getLogger(__name__)


# =============================================================================
# API VIEW — agent posts beacon results here
# POST /api/agent/beacon/results/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def api_beacon_results(request):
    """
    Agent POSTs the complete beacon campaign summary here after the run ends.
    The body must include 'task_id' so the ModuleTask loop can be closed.
    """
    agent = request.user
    data  = request.data

    if data.get('error'):
        _close_moduletask_loop(
            task_id_str=str(data.get('task_id', '')),
            result_pk=0,
            module='beacon',
            failed=True,
            error_message=str(data['error']),
        )
        return Response({'received': True, 'error': data['error']}, status=200)

    agent_model = None
    if hasattr(agent, 'agent_id'):
        try:
            agent_model = Agent.objects.get(agent_id=agent.agent_id)
        except Agent.DoesNotExist:
            pass

    result = BeaconResult.objects.create(
        agent           = agent_model,
        session_id      = data.get('session_id',     ''),
        protocol        = data.get('protocol',       'http_get'),
        encoding        = data.get('encoding',       'base64'),
        target          = data.get('target',         ''),
        total_beacons   = data.get('total_beacons',  0),
        successful      = data.get('successful',     0),
        failed          = data.get('failed',         0),
        interval_sec    = data.get('interval_sec',   60.0),
        jitter_pct      = data.get('jitter_pct',     10),
        avg_latency_ms  = data.get('avg_latency_ms', 0.0),
        std_dev_sec     = data.get('std_dev_sec',    0.0),
        ids_signatures  = data.get('ids_signatures', []),
        beacons_json    = data.get('beacons',        []),
    )

    logger.info(
        f"Beacon results saved: #{result.pk} "
        f"protocol={result.protocol} "
        f"sent={result.successful}/{result.total_beacons} "
        f"target={result.target}"
    )

    _close_moduletask_loop(
        task_id_str = str(data.get('task_id', '')),
        result_pk   = result.pk,
        module      = 'beacon',
    )

    return Response({
        'result_id': result.pk,
        'message':   f'Beacon results saved (ID: {result.pk})',
        'summary': {
            'protocol':      result.protocol,
            'total_beacons': result.total_beacons,
            'successful':    result.successful,
            'success_rate':  result.success_rate,
        },
    }, status=drf_status.HTTP_201_CREATED)


# =============================================================================
# DISPATCH VIEW — browser submits beacon task
# POST /api/modules/beacon/dispatch/
# =============================================================================

@login_required
@require_http_methods(['POST'])
def dispatch_beacon_task(request):
    """
    Validate beacon parameters, create a ModuleTask, and push the command
    to the target agent via the WebSocket channel layer.
    """
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Request body must be valid JSON.'}, status=400)

    # ── Agent ────────────────────────────────────────────────────────────────
    agent_id = str(body.get('agent_id', '')).strip()
    if not agent_id:
        return JsonResponse({'error': 'agent_id is required.'}, status=400)
    try:
        agent = Agent.objects.get(agent_id=agent_id, is_active=True)
    except Agent.DoesNotExist:
        return JsonResponse(
            {'error': f'No active agent with ID "{agent_id}".'}, status=404)

    # ── Protocol ─────────────────────────────────────────────────────────────
    VALID_PROTOCOLS = {'http_get', 'http_post', 'dns'}
    protocol = str(body.get('protocol', 'http_get')).strip().lower()
    if protocol not in VALID_PROTOCOLS:
        return JsonResponse(
            {'error': f'Invalid protocol. Choose: {", ".join(sorted(VALID_PROTOCOLS))}.'},
            status=400)

    # ── Target ───────────────────────────────────────────────────────────────
    target = str(body.get('target', '')).strip()
    if not target:
        return JsonResponse({'error': 'target is required (IP or hostname).'}, status=400)

    # ── Port ─────────────────────────────────────────────────────────────────
    try:
        port = int(body.get('port', 80))
        if not (1 <= port <= 65535):
            raise ValueError('out of range')
    except (TypeError, ValueError):
        return JsonResponse(
            {'error': 'port must be an integer between 1 and 65535.'}, status=400)

    # ── Count ────────────────────────────────────────────────────────────────
    try:
        count = int(body.get('count', 20))
        if not (1 <= count <= 200):
            raise ValueError('out of range')
    except (TypeError, ValueError):
        return JsonResponse(
            {'error': 'count must be an integer between 1 and 200.'}, status=400)

    # ── Interval ─────────────────────────────────────────────────────────────
    try:
        interval_sec = float(body.get('interval_sec', 60.0))
        if not (1.0 <= interval_sec <= 3600.0):
            raise ValueError('out of range')
    except (TypeError, ValueError):
        return JsonResponse(
            {'error': 'interval_sec must be a number between 1.0 and 3600.0.'}, status=400)

    # ── Jitter ───────────────────────────────────────────────────────────────
    try:
        jitter_pct = int(body.get('jitter_pct', 10))
        if not (0 <= jitter_pct <= 50):
            raise ValueError('out of range')
    except (TypeError, ValueError):
        return JsonResponse(
            {'error': 'jitter_pct must be an integer between 0 and 50.'}, status=400)

    # ── Encoding ─────────────────────────────────────────────────────────────
    VALID_ENCODINGS = {'plain', 'base64', 'xor'}
    encoding = str(body.get('encoding', 'base64')).strip().lower()
    if encoding not in VALID_ENCODINGS:
        return JsonResponse(
            {'error': f'Invalid encoding. Choose: {", ".join(sorted(VALID_ENCODINGS))}.'},
            status=400)

    xor_key      = int(body.get('xor_key', 90)) & 0xFF
    ua_rotate    = bool(body.get('user_agent_rotate', True))

    config_json = {
        'target':            target,
        'port':              port,
        'protocol':          protocol,
        'count':             count,
        'interval_sec':      interval_sec,
        'jitter_pct':        jitter_pct,
        'encoding':          encoding,
        'xor_key':           xor_key,
        'user_agent_rotate': ua_rotate,
    }

    task = ModuleTask.objects.create(
        agent        = agent,
        initiated_by = request.user,
        module       = ModuleChoice.BEACON,
        config_json  = config_json,
    )

    dispatch_args = {**config_json, 'task_id': str(task.task_id)}

    agent_online = agent.is_online
    try:
        layer = get_channel_layer()
        if layer is None:
            raise RuntimeError('Channel layer not configured.')
        async_to_sync(layer.group_send)(
            f'agent_{agent.agent_id}',
            {'type': 'agent.command', 'command': 'beacon', 'args': dispatch_args},
        )
        task.mark_dispatched()
        logger.info(
            f"Beacon task {task.task_id_short} dispatched → "
            f"agent:{agent.agent_id} | "
            f"protocol:{protocol} | count:{count} | "
            f"interval:{interval_sec}s ±{jitter_pct}% | "
            f"online:{agent_online}"
        )
    except Exception as exc:
        task.mark_failed(str(exc))
        logger.error(f"Beacon task {task.task_id_short} dispatch FAILED: {exc}")
        return JsonResponse(
            {'error': 'Failed to push command to agent.', 'detail': str(exc)},
            status=500)

    return JsonResponse({
        'task_id':       str(task.task_id),
        'task_id_short': task.task_id_short,
        'status':        task.status,
        'module':        task.module,
        'agent_id':      agent.agent_id,
        'agent_name':    agent.name or agent.agent_id,
        'agent_online':  agent_online,
        'config':        config_json,
        'poll_url':      f'/api/modules/task/{task.task_id}/status/',
        'warning': (
            'Agent appears offline. Command queued for when agent reconnects.'
            if not agent_online else None
        ),
    }, status=202)


# =============================================================================
# BROWSER VIEWS
# =============================================================================

@login_required
def beacon_dashboard(request):
    results = BeaconResult.objects.select_related('agent').order_by('-created_at')

    total_runs    = results.count()
    detected_runs = results.filter(ids_detected=True).count()
    evaded_runs   = results.filter(ids_detected=False).count()
    unknown_runs  = results.filter(ids_detected__isnull=True).count()

    return render(request, 'scanner/beacon_dashboard.html', {
        'results':      results,
        'total_runs':   total_runs,
        'detected_runs': detected_runs,
        'evaded_runs':  evaded_runs,
        'unknown_runs': unknown_runs,
        'page':         'beacon',
    })


@login_required
def beacon_detail(request, pk):
    result  = get_object_or_404(BeaconResult, pk=pk)
    beacons = result.beacons_json or []
    return render(request, 'scanner/beacon_detail.html', {
        'result':  result,
        'beacons': beacons,
        'page':    'beacon',
    })


@login_required
@require_http_methods(['POST'])
def beacon_mark_detected(request, pk):
    result   = get_object_or_404(BeaconResult, pk=pk)
    detected = request.POST.get('detected') == 'true'
    notes    = request.POST.get('notes', '')

    result.ids_detected        = detected
    result.ids_detection_notes = notes
    result.save(update_fields=['ids_detected', 'ids_detection_notes'])

    status_str = 'DETECTED by IDS' if detected else 'EVADED IDS'
    messages.success(request, f'Beacon Run #{pk} marked as: {status_str}')
    return redirect('scanner:beacon_detail', pk=pk)
