# scanner/dga_views.py
# Changes from original:
#   api_dga_results() — after DGAResult.create(), look up the ModuleTask by
#   task_id from the POST body, call mark_complete(result.pk), and push a
#   'task.complete' event to the dashboard WebSocket group so the browser
#   control panel redirects automatically.

import logging
from datetime import date

from django.shortcuts               import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http   import require_http_methods
from django.contrib                 import messages

from rest_framework.decorators  import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response    import Response
from rest_framework             import status

from .models         import DGAResult, DGAAlgorithm, Agent, ModuleTask
from .authentication import AgentAuthentication

logger = logging.getLogger(__name__)


# =============================================================================
# PRIVATE HELPER — close ModuleTask loop
# =============================================================================

def _close_moduletask_loop(
    task_id_str: str,
    result_pk: int,
    module: str,
    failed: bool = False,
    error_message: str = '',
) -> None:
    """
    Called after a result row is committed (or on agent-reported failure).
    On success: marks ModuleTask COMPLETE and pushes a 'task.complete' WS event.
    On failure: marks ModuleTask FAILED — no WS push, no result_url.
    Designed to be silent on error — never propagates exceptions to API callers.
    """
    if not task_id_str:
        return

    # ── Mark the task in the DB ───────────────────────────────────────────────
    task = None
    try:
        task = ModuleTask.objects.get(task_id=task_id_str)
        if failed:
            task.mark_failed(error_message or 'Agent reported execution failure')
            logger.info(
                f"ModuleTask {task.task_id_short} → FAILED "
                f"(module={module}, reason={error_message!r})"
            )
            return
        task.mark_complete(result_pk)
        logger.info(
            f"ModuleTask {task.task_id_short} → COMPLETE "
            f"(module={module}, result_pk={result_pk})"
        )
    except (ModuleTask.DoesNotExist, ValueError) as exc:
        # task_id from old agent.py (now deleted) or a race condition — ignore
        logger.debug(
            f"_close_moduletask_loop: no ModuleTask for task_id={task_id_str}: {exc}"
        )
        return
    except Exception as exc:
        logger.error(f"_close_moduletask_loop: unexpected error: {exc}")
        return

    # ── Push real-time notification to browser dashboards ────────────────────
    result_url_map = {
        'dga':    f'/dga/{result_pk}/',
        'exfil':  f'/exfil/{result_pk}/',
        'nmap':   f'/scan/{result_pk}/report/',
        'beacon': f'/beacon/{result_pk}/',
    }
    result_url = result_url_map.get(module, f'/{module}/{result_pk}/')

    try:
        from channels.layers import get_channel_layer
        from asgiref.sync    import async_to_sync

        channel_layer = get_channel_layer()
        if channel_layer is None:
            logger.warning('_close_moduletask_loop: channel layer not configured')
            return

        async_to_sync(channel_layer.group_send)(
            'dashboard',
            {
                'type':          'task.complete',    # → DashboardConsumer.task_complete()
                'task_id':       str(task.task_id),
                'task_id_short': task.task_id_short,
                'module':        module,
                'result_url':    result_url,
                'result_pk':     result_pk,
            },
        )
        logger.info(
            f"WebSocket push: task_complete {task.task_id_short} → {result_url}"
        )
    except Exception as exc:
        # WS push failure must never surface as an API error
        logger.warning(
            f"_close_moduletask_loop: WebSocket push failed for "
            f"task {task.task_id_short}: {exc}"
        )


# =============================================================================
# API VIEW — agent posts DGA results here
# POST /api/agent/dga/results/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def api_dga_results(request):
    """
    Agent posts the complete DGA test summary here after a run finishes.
    The POST body must include 'task_id' (injected by module_views.dispatch_dga_task
    and forwarded through dga_plugin.py) so we can close the ModuleTask tracking loop.

    Request body (JSON):
    {
        "task_id":       "<uuid-string>",   ← injected by dispatch_dga_task
        "algorithm":     "date_seed",
        "total_queries": 50,
        "nxdomain":      48,
        "resolved":      2,
        "timeout":       0,
        "errors":        0,
        "nxdomain_ratio": 0.96,
        "avg_entropy":   3.91,
        "max_entropy":   3.97,
        "min_entropy":   3.82,
        "duration_sec":  52.3,
        "rate_per_sec":  1.0,
        "dns_server":    "192.168.1.1",
        "domains":       [...]
    }
    """
    agent = request.user
    data  = request.data

    # If the orchestrator sent a failure report, mark the task failed — no result row.
    if data.get('error'):
        _close_moduletask_loop(
            task_id_str=str(data.get('task_id', '')),
            result_pk=0,
            module='dga',
            failed=True,
            error_message=str(data['error']),
        )
        return Response({'received': True, 'error': data['error']}, status=200)

    # Look up the agent model instance
    agent_model = None
    if hasattr(agent, 'agent_id'):
        try:
            agent_model = Agent.objects.get(agent_id=agent.agent_id)
        except Agent.DoesNotExist:
            pass

    # Map algorithm string to DGAAlgorithm choice
    algo_map = {
        'date_seed': DGAAlgorithm.DATE_SEED,
        'xor_lcg':   DGAAlgorithm.XOR_LCG,
        'wordlist':  DGAAlgorithm.WORDLIST,
    }
    algorithm = algo_map.get(
        data.get('algorithm', 'date_seed'),
        DGAAlgorithm.DATE_SEED,
    )

    # Create DGAResult record
    result = DGAResult.objects.create(
        agent          = agent_model,
        algorithm      = algorithm,
        total_queries  = data.get('total_queries', 0),
        rate_per_sec   = data.get('rate_per_sec',  1.0),
        dns_server     = data.get('dns_server',    'system'),
        seed_date      = date.today(),
        nxdomain_count = data.get('nxdomain',      0),
        resolved_count = data.get('resolved',      0),
        timeout_count  = data.get('timeout',       0),
        error_count    = data.get('errors',         0),
        nxdomain_ratio = data.get('nxdomain_ratio', 0.0),
        avg_entropy    = data.get('avg_entropy',    0.0),
        max_entropy    = data.get('max_entropy',    0.0),
        min_entropy    = data.get('min_entropy',    0.0),
        duration_sec   = data.get('duration_sec',  0.0),
        domains_json   = data.get('domains',       []),
    )

    logger.info(
        f"DGA results saved: #{result.pk} "
        f"algorithm={algorithm} "
        f"NXDOMAIN={result.nxdomain_count}/{result.total_queries} "
        f"ratio={result.nxdomain_ratio}"
    )

    # ── Close ModuleTask loop ─────────────────────────────────────────────────
    # task_id was injected into the plugin args by dispatch_dga_task and
    # forwarded through dga_plugin.py's summary dict.
    _close_moduletask_loop(
        task_id_str = str(data.get('task_id', '')),
        result_pk   = result.pk,
        module      = 'dga',
    )

    return Response({
        'result_id': result.pk,
        'message':   f'DGA results saved (ID: {result.pk})',
        'summary': {
            'algorithm':      result.algorithm,
            'total_queries':  result.total_queries,
            'nxdomain_ratio': result.nxdomain_ratio,
            'avg_entropy':    result.avg_entropy,
            'risk_level':     result.risk_level,
        },
    }, status=status.HTTP_201_CREATED)


# =============================================================================
# BROWSER VIEWS
# =============================================================================

@login_required
def dga_dashboard(request):
    results = DGAResult.objects.select_related('agent').order_by('-created_at')

    total_runs       = results.count()
    detected_runs    = results.filter(ids_detected=True).count()
    evaded_runs      = results.filter(ids_detected=False).count()
    unknown_runs     = results.filter(ids_detected__isnull=True).count()
    high_risk_runs   = [r for r in results if r.risk_level == 'HIGH']

    context = {
        'results':         results,
        'total_runs':      total_runs,
        'detected_runs':   detected_runs,
        'evaded_runs':     evaded_runs,
        'unknown_runs':    unknown_runs,
        'high_risk_count': len(high_risk_runs),
        'page':            'dga',
    }
    return render(request, 'scanner/dga_dashboard.html', context)


@login_required
def dga_detail(request, pk):
    result  = get_object_or_404(DGAResult, pk=pk)
    domains = result.domains_json or []

    nxdomains = [d for d in domains if d.get('outcome') == 'NXDOMAIN']
    resolved  = [d for d in domains if d.get('outcome') == 'RESOLVED']
    timeouts  = [d for d in domains if d.get('outcome') == 'TIMEOUT']

    context = {
        'result':    result,
        'domains':   domains,
        'nxdomains': nxdomains,
        'resolved':  resolved,
        'timeouts':  timeouts,
        'page':      'dga',
    }
    return render(request, 'scanner/dga_detail.html', context)


@login_required
@require_http_methods(['POST'])
def dga_mark_detected(request, pk):
    result    = get_object_or_404(DGAResult, pk=pk)
    detected  = request.POST.get('detected') == 'true'
    notes     = request.POST.get('notes', '')

    result.ids_detected        = detected
    result.ids_detection_notes = notes
    result.save(update_fields=['ids_detected', 'ids_detection_notes'])

    status_str = 'DETECTED by IDS' if detected else 'EVADED IDS'
    messages.success(request, f'DGA Run #{pk} marked as: {status_str}')

    return redirect('scanner:dga_detail', pk=pk)