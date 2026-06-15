# scanner/views.py
# ─────────────────────────────────────────────────────────────────────────────
#  MIAT — Views
#
#  A Django view is a Python function that:
#    1. Receives an HTTP request
#    2. Does some work (query DB, run logic, etc.)
#    3. Returns an HTTP response (HTML page or JSON)
#
#  URL → View → Template is the full Django request cycle.
#
#  Our views:
#    dashboard()       →  home page, scan history list
#    submit_scan()     →  form to submit a new scan (token/cache logic here)
#    scan_status()     →  polling page — "is my scan done yet?"
#    scan_report()     →  full results page for a completed scan
#    api_scan_status() →  JSON endpoint polled by JavaScript every 2 seconds
#    api_submit_scan() →  JSON endpoint to submit a scan via API/DRF
# ─────────────────────────────────────────────────────────────────────────────

import json
import logging
from datetime import timedelta

from django.shortcuts        import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils            import timezone
from django.http             import JsonResponse
from django.conf             import settings
from django.views.decorators.http import require_http_methods
from django.contrib          import messages

from django_q.tasks          import async_task

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response    import Response
from rest_framework             import status as drf_status

from .models  import ScanRequest, HostResult, PortFinding, ScanStatus, Severity
from .forms   import ScanForm

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# HELPER — Token / Cache lookup
#
# This is what your sir described as "tokens":
#   Same target + same profile → same token → return old result instantly.
#   The cache TTL is controlled by SCAN_CACHE_TTL in settings.py (default 1hr).
# ─────────────────────────────────────────────────────────────────────────────

def _get_cached_scan(target: str, scan_profile: str):
    """
    Look for a completed scan with the same token that is still fresh.

    Returns a ScanRequest if a valid cache hit exists, otherwise None.

    How it works:
      1. Generate the token for this target + profile combination
      2. Query DB for any COMPLETE scan with that token
      3. Check if it was completed within the TTL window
      4. If yes → return it (cache HIT, skip nmap)
      5. If no  → return None (cache MISS, run nmap)
    """
    token      = ScanRequest.generate_token(target, scan_profile)
    ttl_seconds = getattr(settings, 'SCAN_CACHE_TTL', 3600)
    cutoff      = timezone.now() - timedelta(seconds=ttl_seconds)

    cached = ScanRequest.objects.filter(
        token        = token,
        status       = ScanStatus.COMPLETE,
        completed_at__gte = cutoff,   # completed within the TTL window
        cache_hit    = False,         # don't chain cache hits
    ).order_by('-completed_at').first()

    return cached


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 1 — Dashboard
# URL: /
# Shows scan history and quick stats.
# ─────────────────────────────────────────────────────────────────────────────

@login_required   # redirect to /accounts/login/ if not logged in
def dashboard(request):
    """
    Home page.
    Shows the user's recent scans and aggregate stats.
    @login_required means only authenticated users can see this.
    """
    # .select_related('user') fetches user in the same DB query — more efficient
    scans = (
        ScanRequest.objects
        .filter(user=request.user)
        .select_related('user')
        .order_by('-created_at')[:20]   # latest 20 scans
    )

    # Aggregate stats for the dashboard cards
    all_scans   = ScanRequest.objects.filter(user=request.user)
    total_scans = all_scans.count()
    high_risk   = all_scans.filter(overall_risk=Severity.HIGH).count()
    cache_hits  = all_scans.filter(cache_hit=True).count()
    running     = all_scans.filter(
        status__in=[ScanStatus.PENDING, ScanStatus.RUNNING]
    ).count()

    context = {
        'scans':       scans,
        'total_scans': total_scans,
        'high_risk':   high_risk,
        'cache_hits':  cache_hits,
        'running':     running,
        'page':        'dashboard',
    }
    return render(request, 'scanner/dashboard.html', context)


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 2 — Submit Scan
# URL: /scan/
# GET  → show the scan form
# POST → validate form, check cache, queue task or return cached result
# ─────────────────────────────────────────────────────────────────────────────

@login_required
@require_http_methods(['GET', 'POST'])
def submit_scan(request):
    """
    GET  → render the empty ScanForm
    POST → validate input → check token cache → queue scan or return cache
    """

    if request.method == 'POST':
        form = ScanForm(request.POST)

        if form.is_valid():
            target       = form.cleaned_data['target']
            scan_profile = form.cleaned_data['scan_profile']

            # ── TOKEN / CACHE CHECK ──────────────────────────────────────────
            # This is the core caching logic your sir described.
            cached_scan = _get_cached_scan(target, scan_profile)

            if cached_scan:
                # ── CACHE HIT ────────────────────────────────────────────────
                # A fresh result already exists for this target + profile.
                # Create a lightweight record pointing to the original,
                # then redirect straight to the report — no nmap needed.
                logger.info(
                    f'Cache HIT for {target} ({scan_profile}) '
                    f'— reusing scan #{cached_scan.pk}'
                )

                # Record the cache hit (for audit history + dashboard stats)
                cache_record = ScanRequest.objects.create(
                    user         = request.user,
                    target       = target,
                    scan_profile = scan_profile,
                    status       = ScanStatus.CACHED,
                    cache_hit    = True,
                    cached_from  = cached_scan,
                    # Copy summary from the original scan
                    overall_risk          = cached_scan.overall_risk,
                    total_hosts           = cached_scan.total_hosts,
                    hosts_up              = cached_scan.hosts_up,
                    total_open_ports      = cached_scan.total_open_ports,
                    high_severity_count   = cached_scan.high_severity_count,
                    medium_severity_count = cached_scan.medium_severity_count,
                    completed_at          = timezone.now(),
                )

                messages.success(
                    request,
                    f'Returning cached result for {target} '
                    f'(scanned {_time_ago(cached_scan.completed_at)}). '
                    f'Cache expires in {_ttl_remaining(cached_scan.completed_at)}.'
                )
                # Redirect to the ORIGINAL scan's report — it has all the data
                return redirect('scanner:scan_report', pk=cached_scan.pk)

            else:
                # ── CACHE MISS ───────────────────────────────────────────────
                # No fresh result found. Create a new ScanRequest and queue
                # a background task via django-q2.
                logger.info(
                    f'Cache MISS for {target} ({scan_profile}) — queuing new scan'
                )

                scan = ScanRequest.objects.create(
                    user         = request.user,
                    target       = target,
                    scan_profile = scan_profile,
                    status       = ScanStatus.PENDING,
                )

                # Queue the background task
                # 'scanner.tasks.run_scan_task' is the dotted path to the function
                # scan.pk is passed as the argument to that function
                async_task(
                    'scanner.tasks.run_scan_task',
                    scan.pk,
                    task_name = f'miat_scan_{scan.pk}',
                    # hook = 'scanner.tasks.on_scan_complete',  # optional callback
                )

                logger.info(f'Queued scan #{scan.pk} for {target}')

                messages.info(
                    request,
                    f'Scan started for {target}. '
                    f'Results will appear automatically when complete.'
                )
                return redirect('scanner:scan_status', pk=scan.pk)

        # Form is invalid — re-render with errors
        return render(request, 'scanner/scan_form.html', {'form': form, 'page': 'scan'})

    else:
        # GET request — show empty form
        form = ScanForm()
        return render(request, 'scanner/scan_form.html', {'form': form, 'page': 'scan'})


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 3 — Scan Status (polling page)
# URL: /scan/<pk>/status/
# The user waits here while the scan runs in the background.
# JavaScript on this page calls the API endpoint every 2 seconds.
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def scan_status(request, pk):
    """
    Waiting page shown after submitting a scan.
    The page uses JavaScript to poll /api/scan/<pk>/status/ every 2 seconds.
    When status == 'complete', JS redirects to the report page automatically.
    """
    scan = get_object_or_404(ScanRequest, pk=pk, user=request.user)

    # If already complete, skip the waiting page entirely
    if scan.status in [ScanStatus.COMPLETE, ScanStatus.CACHED]:
        return redirect('scanner:scan_report', pk=pk)

    if scan.status == ScanStatus.FAILED:
        messages.error(request, f'Scan failed: {scan.error_message}')
        return redirect('scanner:dashboard')

    context = {
        'scan':         scan,
        'poll_url':     f'/api/scan/{pk}/status/',
        'report_url':   f'/scan/{pk}/report/',
        'page':         'scan',
    }
    return render(request, 'scanner/scan_status.html', context)


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 4 — Scan Report
# URL: /scan/<pk>/report/
# Full results page — hosts, ports, risk breakdown.
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def scan_report(request, pk):
    """
    Full scan results page.
    Fetches all related HostResult and PortFinding records from the DB.

    select_related and prefetch_related are ORM optimisations:
      select_related  → JOIN for ForeignKey (single object)
      prefetch_related → separate query + Python join for reverse FK (many objects)
    Without these, you'd hit the DB once per host × once per port = N+1 queries.
    With them, it's 3 total queries regardless of how many hosts/ports.
    """
    scan = get_object_or_404(ScanRequest, pk=pk, user=request.user)

    # If the scan isn't done yet, redirect to the status page
    if scan.status in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        return redirect('scanner:scan_status', pk=pk)

    # If it's a cache hit, load from the original scan's data
    source_scan = scan.cached_from if scan.cache_hit else scan

    # Fetch all hosts + their ports in 3 DB queries total
    hosts = (
        HostResult.objects
        .filter(scan=source_scan)
        .prefetch_related('ports')
        .order_by('ip_address')
    )

    # Severity counts for the report summary bar
    severity_counts = {
        'HIGH':   0,
        'MEDIUM': 0,
        'LOW':    0,
        'INFO':   0,
    }
    critical_alerts = []

    for host in hosts:
        for port in host.ports.all():
            sev = port.severity
            if sev in severity_counts:
                severity_counts[sev] += 1
            if port.is_critical_alert:
                critical_alerts.append(port)

    context = {
        'scan':            scan,
        'source_scan':     source_scan,
        'hosts':           hosts,
        'severity_counts': severity_counts,
        'critical_alerts': critical_alerts,
        'page':            'report',
    }
    return render(request, 'scanner/scan_report.html', context)


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 5 — API: Scan Status (JSON)
# URL: /api/scan/<pk>/status/
# Called by JavaScript every 2 seconds from the scan_status page.
# Returns JSON so JS can decide whether to redirect or keep polling.
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def api_scan_status(request, pk):
    """
    Returns JSON with the current scan status.
    JavaScript on scan_status.html calls this every 2 seconds.

    Response shape:
    {
        "status":      "running",
        "progress":    "Scanning 192.168.1.1...",
        "complete":    false,
        "failed":      false,
        "report_url":  null
    }
    """
    scan = get_object_or_404(ScanRequest, pk=pk, user=request.user)

    complete = scan.status in [ScanStatus.COMPLETE, ScanStatus.CACHED]
    failed   = scan.status == ScanStatus.FAILED

    # Human-readable progress message
    if scan.status == ScanStatus.PENDING:
        progress = 'Waiting in queue...'
    elif scan.status == ScanStatus.RUNNING:
        elapsed = (timezone.now() - scan.started_at).seconds if scan.started_at else 0
        progress = f'Scanning {scan.target}... ({elapsed}s elapsed)'
    elif complete:
        progress = f'Complete — found {scan.hosts_up} host(s), {scan.total_open_ports} open port(s)'
    elif failed:
        progress = f'Failed: {scan.error_message}'
    else:
        progress = scan.status

    return JsonResponse({
        'status':     scan.status,
        'progress':   progress,
        'complete':   complete,
        'failed':     failed,
        'report_url': f'/scan/{pk}/report/' if complete else None,
        'overall_risk': scan.overall_risk,
    })


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 6 — DRF API: Submit Scan
# URL: /api/scan/submit/
# Lets other tools (Postman, scripts, other apps) submit scans via API.
# Uses Django REST Framework for clean JSON in/out.
# ─────────────────────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_submit_scan(request):
    """
    DRF endpoint to submit a scan via API.

    Request body (JSON):
    {
        "target":       "192.168.1.1",
        "scan_profile": "default"
    }

    Response (JSON):
    {
        "scan_id":    42,
        "status":     "pending",
        "cache_hit":  false,
        "token":      "a3f9bc...",
        "status_url": "/api/scan/42/status/"
    }
    """
    target       = request.data.get('target', '').strip()
    scan_profile = request.data.get('scan_profile', 'default')

    if not target:
        return Response(
            {'error': 'target is required'},
            status=drf_status.HTTP_400_BAD_REQUEST
        )

    # Validate using our form
    form = ScanForm(data={'target': target, 'scan_profile': scan_profile})
    if not form.is_valid():
        return Response(
            {'error': form.errors},
            status=drf_status.HTTP_400_BAD_REQUEST
        )

    # Cache check
    cached_scan = _get_cached_scan(target, scan_profile)
    if cached_scan:
        return Response({
            'scan_id':    cached_scan.pk,
            'status':     'complete',
            'cache_hit':  True,
            'token':      cached_scan.token,
            'report_url': f'/scan/{cached_scan.pk}/report/',
            'message':    f'Returning cached result from {_time_ago(cached_scan.completed_at)}',
        })

    # Queue new scan
    scan = ScanRequest.objects.create(
        user         = request.user,
        target       = target,
        scan_profile = scan_profile,
        status       = ScanStatus.PENDING,
    )
    async_task(
        'scanner.tasks.run_scan_task',
        scan.pk,
        task_name=f'miat_scan_{scan.pk}',
    )

    return Response({
        'scan_id':    scan.pk,
        'status':     scan.status,
        'cache_hit':  False,
        'token':      scan.token,
        'status_url': f'/api/scan/{scan.pk}/status/',
    }, status=drf_status.HTTP_202_ACCEPTED)


# ─────────────────────────────────────────────────────────────────────────────
# HELPER UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _time_ago(dt) -> str:
    """Returns a human readable string like '5 minutes ago'."""
    if not dt:
        return 'unknown time ago'
    diff = timezone.now() - dt
    secs = int(diff.total_seconds())
    if secs < 60:
        return f'{secs} seconds ago'
    elif secs < 3600:
        return f'{secs // 60} minutes ago'
    else:
        return f'{secs // 3600} hours ago'


def _ttl_remaining(completed_at) -> str:
    """Returns how long until the cache for this scan expires."""
    ttl     = getattr(settings, 'SCAN_CACHE_TTL', 3600)
    expires = completed_at + timedelta(seconds=ttl)
    remaining = expires - timezone.now()
    secs    = int(remaining.total_seconds())
    if secs <= 0:
        return 'expired'
    elif secs < 60:
        return f'{secs}s'
    elif secs < 3600:
        return f'{secs // 60} min'
    else:
        return f'{secs // 3600}h {(secs % 3600) // 60}min'