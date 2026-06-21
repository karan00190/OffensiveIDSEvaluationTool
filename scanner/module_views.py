# scanner/module_views.py
# =============================================================================
#  MIAT — Module Dispatch Views
#
#  These views form the Django-side half of the web-driven C2 dispatch loop.
#  They handle the path from browser form submission to WebSocket delivery:
#
#    Browser POST → dispatch_*_task()
#                 → validate params
#                 → ModuleTask.objects.create()   (DB record opened)
#                 → channel_layer.group_send()    (command pushed to agent WS)
#                 → task.mark_dispatched()        (DB record updated)
#                 → JsonResponse(task_id)         (browser starts polling)
#
#    Browser GET  → get_task_status(task_id)
#                 → ModuleTask.objects.get()
#                 → JsonResponse(status + result_url when complete)
#
#  The agent side closes the loop by:
#    1. Receiving the command in AgentConsumer.agent_command()
#    2. Orchestrator routing to the correct plugin
#    3. Plugin POSTing results to /api/agent/dga/results/ or /api/agent/exfil/results/
#    4. Those result views calling task.mark_complete(result_pk) + WS push
#
#  CSRF NOTE:
#    The dispatch endpoints are standard Django views (not DRF) and therefore
#    subject to CSRF protection. JavaScript callers must send the CSRF token
#    in the X-CSRFToken request header. Retrieve it from the cookie named
#    'csrftoken' or from the {% csrf_token %} template tag value.
#    Example fetch call:
#      fetch(url, {
#          method: 'POST',
#          headers: {
#              'Content-Type': 'application/json',
#              'X-CSRFToken': getCookie('csrftoken'),
#          },
#          body: JSON.stringify(payload),
#      });
# =============================================================================

import json
import logging

from asgiref.sync             import async_to_sync
from channels.layers          import get_channel_layer
from django.contrib.auth.decorators import login_required
from django.http              import JsonResponse
from django.shortcuts         import render, get_object_or_404
from django.utils             import timezone
from django.views.decorators.http import require_http_methods

from .models import Agent, ModuleTask, ModuleChoice, TaskStatus

logger = logging.getLogger(__name__)


# =============================================================================
# SHARED PRIVATE HELPERS
# =============================================================================

def _get_channel_layer_or_error():
    """
    Return the configured channel layer or raise RuntimeError.
    Centralises the 'is channel layer configured?' check so both
    dispatch views fail with the same clear message.
    """
    layer = get_channel_layer()
    if layer is None:
        raise RuntimeError(
            'Channel layer is not configured. '
            'Verify CHANNEL_LAYERS in settings.py and that daphne is running.'
        )
    return layer


def _push_command_to_agent(agent: Agent, command: str, args: dict) -> None:
    """
    Deliver a command JSON payload to a specific agent via the channel layer.

    The group name mirrors what AgentConsumer sets on connect:
        self.group_name = f"agent_{self.agent_id}"

    The event type 'agent.command' maps to AgentConsumer.agent_command()
    (Django Channels converts dots to underscores when routing to handlers).

    channel_layer.group_send is an async coroutine — async_to_sync() bridges
    it into this synchronous Django view context. It does NOT block until the
    agent receives the message; it only blocks until the message is accepted
    by the channel layer's internal buffer. If no consumer is listening on
    this group (agent offline), the InMemoryChannelLayer silently drops the
    message. The task remains in DISPATCHED state; the polling endpoint
    surfaces this to the browser.

    Args:
        agent:   The Agent instance whose WebSocket group to target.
        command: Plugin name string ('dga', 'exfil', 'nmap').
        args:    Full argument dict, including task_id as a string key.

    Raises:
        RuntimeError: If the channel layer is not configured.
        Exception:    Any channel layer internal error propagates up so
                      the calling view can catch it and mark the task FAILED.
    """
    layer = _get_channel_layer_or_error()
    async_to_sync(layer.group_send)(
        f"agent_{agent.agent_id}",
        {
            'type':    'agent.command',  # → AgentConsumer.agent_command()
            'command': command,
            'args':    args,
        },
    )


# =============================================================================
# VIEW 1 — Unified Module Control Panel
# GET /modules/
# =============================================================================

@login_required
def module_control_view(request):
    """
    Render the unified execution control panel.

    Passes all active agents to the template so the agent-selector
    dropdown is populated. The template annotates each agent card with
    live online/offline status derived from agent.is_online (last heartbeat
    within 90 seconds). Offline agents remain selectable — the dispatch
    view sends a warning in the response but still creates the task, since
    the agent may reconnect before the command TTL expires.

    Context variables:
        agents          QuerySet[Agent]  — all is_active=True agents
        recent_tasks    QuerySet[ModuleTask] — last 20 tasks for the sidebar
        module_choices  list[(value, label)] — for template display helpers
        page            str — active nav-link highlighter
    """
    agents = (
        Agent.objects
        .filter(is_active=True)
        .order_by('agent_id')
    )

    recent_tasks = (
        ModuleTask.objects
        .select_related('agent')
        .order_by('-dispatched_at')[:20]
    )

    return render(request, 'scanner/module_control.html', {
        'agents':         agents,
        'recent_tasks':   recent_tasks,
        'module_choices': ModuleChoice.choices,
        'page':           'modules',
    })


# =============================================================================
# VIEW 2 — Dispatch DGA Task
# POST /api/modules/dga/dispatch/
# =============================================================================

@login_required
@require_http_methods(['POST'])
def dispatch_dga_task(request):
    """
    Validate DGA parameters, create a ModuleTask, and push the execution
    command to the target agent via the WebSocket channel layer.

    Expected JSON body fields:
        agent_id     (str, required)  — agent.agent_id string identifier
        algo_type    (str, required)  — 'date_seed' | 'xor_lcg' | 'wordlist'
        domain_count (int, required)  — number of domains to generate (1–500)
        query_rate   (float,required) — DNS queries per second (0.1–10.0)
        dns_server   (str, optional)  — specific DNS server IP; null uses system resolver

    The config_json stored in ModuleTask uses the plugin's own key names
    (e.g. 'algorithm' not 'algo_type', 'count' not 'domain_count') so that
    it can be forwarded verbatim as the orchestrator dispatch args without
    any translation layer on the agent side.

    Returns HTTP 202 Accepted with:
        task_id        (str)  — UUID to poll via get_task_status
        task_id_short  (str)  — first 8 chars for UI display
        status         (str)  — 'dispatched'
        agent_online   (bool) — whether the agent was online at dispatch time
        warning        (str|null) — set if agent appeared offline
    """

    # ── Parse body ─────────────────────────────────────────────────────────
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse(
            {'error': 'Request body must be valid JSON.'},
            status=400,
        )

    # ── Validate agent ──────────────────────────────────────────────────────
    agent_id = str(body.get('agent_id', '')).strip()
    if not agent_id:
        return JsonResponse(
            {'error': 'agent_id is required.'},
            status=400,
        )

    try:
        agent = Agent.objects.get(agent_id=agent_id, is_active=True)
    except Agent.DoesNotExist:
        return JsonResponse(
            {'error': f'No active agent found with ID "{agent_id}".'},
            status=404,
        )

    # ── Validate algorithm ──────────────────────────────────────────────────
    VALID_ALGORITHMS = {'date_seed', 'xor_lcg', 'wordlist'}
    algorithm = str(body.get('algo_type', '')).strip().lower()
    if algorithm not in VALID_ALGORITHMS:
        return JsonResponse(
            {
                'error': (
                    f'Invalid algo_type "{algorithm}". '
                    f'Valid values: {", ".join(sorted(VALID_ALGORITHMS))}.'
                )
            },
            status=400,
        )

    # ── Validate domain_count ───────────────────────────────────────────────
    try:
        domain_count = int(body.get('domain_count', 0))
        if not (1 <= domain_count <= 500):
            raise ValueError('out of range')
    except (TypeError, ValueError):
        return JsonResponse(
            {'error': 'domain_count must be an integer between 1 and 500.'},
            status=400,
        )

    # ── Validate query_rate ─────────────────────────────────────────────────
    try:
        query_rate = float(body.get('query_rate', 0))
        if not (0.1 <= query_rate <= 10.0):
            raise ValueError('out of range')
    except (TypeError, ValueError):
        return JsonResponse(
            {'error': 'query_rate must be a number between 0.1 and 10.0.'},
            status=400,
        )

    # ── Optional: DNS server ────────────────────────────────────────────────
    dns_server = str(body.get('dns_server', '')).strip() or None

    # ── Build plugin-compatible config dict ────────────────────────────────
    # Keys match what dga_plugin.py reads from args in execute().
    # Storing these under plugin key names means the dict can be forwarded
    # to the agent without any translation on either side.
    config_json = {
        'algorithm':   algorithm,     # algo_type form field → algorithm plugin key
        'count':       domain_count,  # domain_count form field → count plugin key
        'rate':        query_rate,    # query_rate form field → rate plugin key
        'dns_server':  dns_server,    # same key on both sides
        'seed_secret': 'BARC-MIAT',  # fixed lab secret; not exposed to UI
        'tld':         '.com',        # fixed for lab tests
        'randomise':   True,          # shuffle domain order to vary query patterns
        'timeout':     3,             # DNS query timeout in seconds
    }

    # ── Create the tracking record ──────────────────────────────────────────
    task = ModuleTask.objects.create(
        agent        = agent,
        initiated_by = request.user,
        module       = ModuleChoice.DGA,
        config_json  = config_json,
    )

    # Inject task_id into the dispatch args so the agent can echo it back
    # in the telemetry POST body, allowing api_dga_results to call
    # task.mark_complete(result_pk) and close the tracking loop.
    dispatch_args = {**config_json, 'task_id': str(task.task_id)}

    # ── Push command to agent via channel layer ─────────────────────────────
    agent_online = agent.is_online
    try:
        _push_command_to_agent(agent, 'dga', dispatch_args)
        task.mark_dispatched()
        logger.info(
            f"DGA task {task.task_id_short} dispatched → "
            f"agent:{agent.agent_id} | "
            f"algorithm:{algorithm} | "
            f"count:{domain_count} | "
            f"rate:{query_rate}/s | "
            f"online:{agent_online}"
        )
    except Exception as exc:
        error_reason = f'Channel layer dispatch failed: {exc}'
        task.mark_failed(error_reason)
        logger.error(
            f"DGA task {task.task_id_short} dispatch FAILED "
            f"for agent {agent.agent_id}: {exc}"
        )
        return JsonResponse(
            {
                'error': (
                    'Failed to push command to the agent channel. '
                    'Check that Daphne is running and CHANNEL_LAYERS is configured.'
                ),
                'detail': str(exc),
            },
            status=500,
        )

    return JsonResponse(
        {
            'task_id':        str(task.task_id),
            'task_id_short':  task.task_id_short,
            'status':         task.status,
            'module':         task.module,
            'agent_id':       agent.agent_id,
            'agent_name':     agent.name or agent.agent_id,
            'agent_online':   agent_online,
            'config':         config_json,
            'poll_url':       f'/api/modules/task/{task.task_id}/status/',
            'warning': (
                'Agent appears offline. The command has been queued and will '
                'execute automatically when the agent reconnects.'
                if not agent_online else None
            ),
        },
        status=202,
    )


# =============================================================================
# VIEW 3 — Dispatch Exfil Task
# POST /api/modules/exfil/dispatch/
# =============================================================================

@login_required
@require_http_methods(['POST'])
def dispatch_exfil_task(request):
    """
    Validate Exfil parameters, create a ModuleTask, and push the execution
    command to the target agent via the WebSocket channel layer.

    Expected JSON body fields:
        agent_id       (str,   required) — agent.agent_id string identifier
        technique      (str,   required) — 'dns' | 'http' | 'icmp'
        profile        (str,   required) — 'burst' | 'slow_drip' | 'jitter'
        target         (str,   required) — target IP or hostname
        payload_type   (str,   required) — 'credentials'|'pii'|'api_key'|
                                           'db_dump'|'config'|'custom'
        dns_domain     (str,   optional) — parent domain for DNS tunnel
                                           (default: 'exfil-test.local')
        dns_server     (str,   optional) — specific DNS server IP
        drip_interval  (float, optional) — seconds between chunks for
                                           slow_drip profile (1.0–300.0)
        jitter_min     (float, optional) — min seconds for jitter profile
        jitter_max     (float, optional) — max seconds for jitter profile
                                           (must be > jitter_min, max 120.0)

    Returns HTTP 202 Accepted — same shape as dispatch_dga_task.
    """

    # ── Parse body ─────────────────────────────────────────────────────────
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse(
            {'error': 'Request body must be valid JSON.'},
            status=400,
        )

    # ── Validate agent ──────────────────────────────────────────────────────
    agent_id = str(body.get('agent_id', '')).strip()
    if not agent_id:
        return JsonResponse(
            {'error': 'agent_id is required.'},
            status=400,
        )

    try:
        agent = Agent.objects.get(agent_id=agent_id, is_active=True)
    except Agent.DoesNotExist:
        return JsonResponse(
            {'error': f'No active agent found with ID "{agent_id}".'},
            status=404,
        )

    # ── Validate technique ──────────────────────────────────────────────────
    VALID_TECHNIQUES = {'dns', 'http', 'icmp', 'sqli'}
    technique = str(body.get('technique', '')).strip().lower()
    if technique not in VALID_TECHNIQUES:
        return JsonResponse(
            {
                'error': (
                    f'Invalid technique "{technique}". '
                    f'Valid values: {", ".join(sorted(VALID_TECHNIQUES))}.'
                )
            },
            status=400,
        )

    # ── Validate profile ────────────────────────────────────────────────────
    VALID_PROFILES = {'burst', 'slow_drip', 'jitter'}
    profile = str(body.get('profile', '')).strip().lower()
    if profile not in VALID_PROFILES:
        return JsonResponse(
            {
                'error': (
                    f'Invalid profile "{profile}". '
                    f'Valid values: {", ".join(sorted(VALID_PROFILES))}.'
                )
            },
            status=400,
        )

    # ── Payload mode (generated vs manual pull) ─────────────────────────────
    payload_mode = str(body.get('payload_mode', 'generated')).strip().lower()
    if payload_mode not in ('generated', 'manual'):
        payload_mode = 'generated'

    # ── Validate payload_type (only required for generated mode) ────────────
    VALID_PAYLOADS = {'credentials', 'pii', 'api_key', 'db_dump', 'config', 'custom'}
    payload_type = str(body.get('payload_type', '')).strip().lower()
    if payload_mode == 'generated' and payload_type not in VALID_PAYLOADS:
        return JsonResponse(
            {
                'error': (
                    f'Invalid payload_type "{payload_type}". '
                    f'Valid values: {", ".join(sorted(VALID_PAYLOADS))}.'
                )
            },
            status=400,
        )

    # ── Manual pull-model payload fields ────────────────────────────────────
    payload_url      = str(body.get('payload_url',      '')).strip()
    payload_checksum = str(body.get('payload_checksum', '')).strip()
    payload_size     = int(body.get('payload_size',     0) or 0)
    payload_id       = body.get('payload_id')

    # ── Validate target ─────────────────────────────────────────────────────
    target = str(body.get('target', '')).strip()
    if not target:
        return JsonResponse(
            {'error': 'target (IP address or hostname) is required.'},
            status=400,
        )

    # ── Validate drip_interval (only meaningful for slow_drip profile) ──────
    try:
        drip_interval = float(body.get('drip_interval', 10.0))
        if not (1.0 <= drip_interval <= 300.0):
            raise ValueError('out of range')
    except (TypeError, ValueError):
        return JsonResponse(
            {'error': 'drip_interval must be a number between 1.0 and 300.0 seconds.'},
            status=400,
        )

    # ── Validate jitter bounds (only meaningful for jitter profile) ─────────
    try:
        jitter_min = float(body.get('jitter_min', 1.0))
        jitter_max = float(body.get('jitter_max', 8.0))
        if jitter_min < 0.1:
            raise ValueError('jitter_min below 0.1')
        if jitter_max > 120.0:
            raise ValueError('jitter_max above 120.0')
        if jitter_min >= jitter_max:
            raise ValueError('jitter_min must be less than jitter_max')
    except (TypeError, ValueError) as exc:
        return JsonResponse(
            {
                'error': (
                    f'Invalid jitter bounds: {exc}. '
                    'jitter_min and jitter_max must satisfy: '
                    '0.1 ≤ jitter_min < jitter_max ≤ 120.0.'
                )
            },
            status=400,
        )

    # ── Optional string fields with safe defaults ───────────────────────────
    dns_domain = str(body.get('dns_domain', 'exfil-test.local')).strip() or 'exfil-test.local'
    dns_server = str(body.get('dns_server', '')).strip() or None

    sqli_param   = str(body.get('sqli_param',   'id')).strip() or 'id'
    sqli_columns = int(body.get('sqli_columns', 3))
    if sqli_columns < 1 or sqli_columns > 20:
        sqli_columns = 3

    # Build HTTP target URL
    http_target = str(body.get('http_target', '')).strip()
    if not http_target:
        http_target = target if target.startswith('http') else f'http://{target}'

    config_json = {
        'technique':        technique,
        'profile':          profile,
        'target':           target,
        'payload_mode':     payload_mode,
        'payload_type':     payload_type,
        'payload_url':      payload_url,
        'payload_checksum': payload_checksum,
        'payload_size':     payload_size,
        'payload_id':       payload_id,
        'dns_domain':       dns_domain,
        'dns_server':       dns_server,
        'http_target':      http_target,
        'drip_interval':    drip_interval,
        'jitter_min':       jitter_min,
        'jitter_max':       jitter_max,
        'sqli_param':       sqli_param,
        'sqli_columns':     sqli_columns,
    }

    # ── Create the tracking record ──────────────────────────────────────────
    task = ModuleTask.objects.create(
        agent        = agent,
        initiated_by = request.user,
        module       = ModuleChoice.EXFIL,
        config_json  = config_json,
    )

    dispatch_args = {**config_json, 'task_id': str(task.task_id)}

    # ── Push command to agent via channel layer ─────────────────────────────
    agent_online = agent.is_online
    try:
        _push_command_to_agent(agent, 'exfil', dispatch_args)
        task.mark_dispatched()
        logger.info(
            f"Exfil task {task.task_id_short} dispatched → "
            f"agent:{agent.agent_id} | "
            f"technique:{technique} | "
            f"profile:{profile} | "
            f"target:{target} | "
            f"online:{agent_online}"
        )
    except Exception as exc:
        error_reason = f'Channel layer dispatch failed: {exc}'
        task.mark_failed(error_reason)
        logger.error(
            f"Exfil task {task.task_id_short} dispatch FAILED "
            f"for agent {agent.agent_id}: {exc}"
        )
        return JsonResponse(
            {
                'error': (
                    'Failed to push command to the agent channel. '
                    'Check that Daphne is running and CHANNEL_LAYERS is configured.'
                ),
                'detail': str(exc),
            },
            status=500,
        )

    return JsonResponse(
        {
            'task_id':        str(task.task_id),
            'task_id_short':  task.task_id_short,
            'status':         task.status,
            'module':         task.module,
            'agent_id':       agent.agent_id,
            'agent_name':     agent.name or agent.agent_id,
            'agent_online':   agent_online,
            'config':         config_json,
            'poll_url':       f'/api/modules/task/{task.task_id}/status/',
            'warning': (
                'Agent appears offline. The command has been queued and will '
                'execute automatically when the agent reconnects.'
                if not agent_online else None
            ),
        },
        status=202,
    )


# =============================================================================
# VIEW 4 — Task Status Polling Endpoint
# GET /api/modules/task/<uuid:task_id>/status/
# =============================================================================

@login_required
@require_http_methods(['GET'])
def get_task_status(request, task_id):
    """
    Return the current lifecycle state of a ModuleTask.

    Called by the browser JavaScript panel every two seconds after a
    dispatch view returns a task_id. Polling stops once is_terminal=True.

    The result_url field is only populated when status='complete' AND
    result_pk is set. Its path depends on the module field:
        dga   → /dga/<result_pk>/
        exfil → /exfil/<result_pk>/
        nmap  → /scan/<result_pk>/report/

    The task_id in the URL is typed as uuid by Django's URL converter,
    which means Django validates the UUID format before this view runs —
    malformed UUIDs return 404 automatically without reaching this code.

    There is intentionally no user-ownership filter on the lookup.
    Task IDs are UUIDs (128-bit random, unguessable), and this is an
    internal admin tool where any authenticated staff member may monitor
    any active task.

    Response fields:
        task_id          str       UUID string
        task_id_short    str       First 8 chars for compact UI display
        module           str       'dga' | 'exfil' | 'nmap'
        module_display   str       Human-readable module name
        status           str       TaskStatus value
        status_display   str       Human-readable status
        agent_id         str       Agent identifier string
        agent_name       str       Agent display name
        agent_online     bool      Whether agent is currently heartbeating
        config           dict      Parameters that were dispatched
        dispatched_at    str       ISO 8601 timestamp
        completed_at     str|null  ISO 8601 timestamp when terminal state reached
        duration_seconds float|null Wall-clock seconds, null if not yet terminal
        result_pk        int|null  PK of the result row in DGAResult/ExfilResult
        result_url       str|null  Browser URL to the result detail page
        has_result       bool      True once result_pk is populated
        is_terminal      bool      True when status is 'complete' or 'failed'
        error_message    str|null  Populated only when status='failed'
    """
    task = get_object_or_404(ModuleTask, task_id=task_id)

    # Build the result deep-link only once both conditions are met:
    # the task is complete AND the result row has been written and linked.
    result_url = None
    if task.result_pk is not None and task.status == TaskStatus.COMPLETE:
        if task.module == ModuleChoice.DGA:
            result_url = f'/dga/{task.result_pk}/'
        elif task.module == ModuleChoice.EXFIL:
            result_url = f'/exfil/{task.result_pk}/'
        elif task.module == ModuleChoice.NMAP:
            result_url = f'/scan/{task.result_pk}/report/'

    return JsonResponse({
        'task_id':          str(task.task_id),
        'task_id_short':    task.task_id_short,
        'module':           task.module,
        'module_display':   task.get_module_display(),
        'status':           task.status,
        'status_display':   task.get_status_display(),
        'agent_id':         task.agent.agent_id,
        'agent_name':       task.agent.name or task.agent.agent_id,
        'agent_online':     task.agent.is_online,
        'config':           task.config_json,
        'dispatched_at':    task.dispatched_at.isoformat(),
        'completed_at':     task.completed_at.isoformat() if task.completed_at else None,
        'duration_seconds': task.duration_seconds,
        'result_pk':        task.result_pk,
        'result_url':       result_url,
        'has_result':       task.result_pk is not None,
        'is_terminal':      task.is_terminal,
        'error_message':    task.error_message or None,
    })