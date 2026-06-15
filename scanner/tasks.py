# scanner/tasks.py
# =============================================================================
#  MIAT — Background Tasks (django-q2) with Live WebSocket Bridge
#
#  The "live bridge" is the glue between django-q2 and WebSockets:
#
#    run_scan_task() runs inside a django-q2 worker process (sync)
#         ↓  when scan completes
#    notify_scan_complete() uses async_to_sync to call channel_layer
#         ↓  pushes message to 'dashboard' group
#    DashboardConsumer.scan_complete() receives it
#         ↓  forwards to all connected browsers
#    Browser JS receives it → redirects to report page
#
#  No polling. No page refresh. Pure push.
# =============================================================================

import nmap
import logging
from django.utils  import timezone

from .models import (
    ScanRequest, HostResult, PortFinding,
    ScanStatus, Severity
)

logger = logging.getLogger(__name__)

# ── Risk rules ────────────────────────────────────────────────────────────────
RISKY_PORTS = {
    21:    (Severity.HIGH,   'FTP — plaintext credentials'),
    22:    (Severity.MEDIUM, 'SSH — brute-force surface'),
    23:    (Severity.HIGH,   'Telnet — plaintext, legacy protocol'),
    25:    (Severity.MEDIUM, 'SMTP — potential mail relay'),
    80:    (Severity.LOW,    'HTTP — unencrypted web traffic'),
    443:   (Severity.INFO,   'HTTPS — standard encrypted web'),
    445:   (Severity.HIGH,   'SMB — common ransomware vector'),
    1433:  (Severity.HIGH,   'MSSQL — database port exposed'),
    3306:  (Severity.HIGH,   'MySQL — database port exposed'),
    3389:  (Severity.HIGH,   'RDP — brute-force target'),
    5432:  (Severity.HIGH,   'PostgreSQL — database port exposed'),
    5900:  (Severity.HIGH,   'VNC — often unencrypted'),
    6379:  (Severity.HIGH,   'Redis — unauthenticated by default'),
    8080:  (Severity.LOW,    'HTTP-alt — proxy or dev server'),
    27017: (Severity.HIGH,   'MongoDB — often unauthenticated'),
}

CRITICAL_PORTS = {
    21:   'FTP transmits credentials in plaintext',
    23:   'Telnet transmits all data in plaintext',
    445:  'SMB — used by WannaCry/NotPetya ransomware',
    3306: 'MySQL exposed — check for weak/default passwords',
    5432: 'PostgreSQL exposed — check for weak/default passwords',
    3389: 'RDP open — restrict to VPN only',
}

SCAN_PROFILES = {
    'fast':    '-sV -T4 -F',
    'default': '-sV -T4 --top-ports 1000',
    'deep':    '-sS -sV -O -T4 -p-',
    'ping':    '-sn',
}

SEV_ORDER = {
    Severity.HIGH:   0,
    Severity.MEDIUM: 1,
    Severity.LOW:    2,
    Severity.INFO:   3,
    Severity.NONE:   4,
}


def _worse(a, b):
    return a if SEV_ORDER[a] <= SEV_ORDER[b] else b


# =============================================================================
# LIVE BRIDGE — django-q2 worker → WebSocket → browser
# =============================================================================

def notify_scan_complete(scan_id: int, overall_risk: str) -> None:
    """
    Push a 'scan complete' notification to all browser dashboards.

    This runs inside a django-q2 task (synchronous context).
    channel_layer.group_send() is async — we bridge using async_to_sync.

    The DashboardConsumer.scan_complete() method receives this and
    forwards it to every connected browser as JSON.

    Browser JS then redirects to the report page automatically.
    """
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync    import async_to_sync

        channel_layer = get_channel_layer()

        if channel_layer is None:
            logger.warning(
                'Channel layer is None — is CHANNEL_LAYERS set in settings.py?'
            )
            return

        # group_send dispatches to all consumers in the 'dashboard' group.
        # 'type': 'scan.complete' → Django Channels calls scan_complete()
        # on each DashboardConsumer instance (dot → underscore in method name).
        async_to_sync(channel_layer.group_send)(
            'dashboard',
            {
                'type':       'scan.complete',
                'scan_id':    scan_id,
                'risk':       overall_risk,
                'report_url': f'/scan/{scan_id}/report/',
            }
        )
        logger.info(
            f'WebSocket push sent: scan #{scan_id} complete '
            f'(risk={overall_risk})'
        )

    except Exception as exc:
        # Never crash the scan task because of a WebSocket notification failure
        logger.warning(
            f'WebSocket notify failed for scan #{scan_id}: {exc} '
            f'(scan result is still saved — only the push notification failed)'
        )


def notify_dashboard_update(message: str, level: str = 'info') -> None:
    """
    Push a general status message to the dashboard.
    Used for streaming intermediate progress updates.
    level: 'info' | 'warning' | 'error'
    """
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync    import async_to_sync

        channel_layer = get_channel_layer()
        if channel_layer is None:
            return

        async_to_sync(channel_layer.group_send)(
            'dashboard',
            {
                'type':    'dashboard.update',
                'message': message,
                'level':   level,
            }
        )
    except Exception as exc:
        logger.debug(f'Dashboard update push failed: {exc}')


# =============================================================================
# MAIN SCAN TASK — called by django-q2 worker
# =============================================================================

def run_scan_task(scan_id: int) -> None:
    """
    Main background task. django-q2 worker calls this.

    Pipeline:
      1. Load ScanRequest from DB
      2. Mark as RUNNING
      3. Run nmap via python-nmap
      4. For each host → create HostResult
      5. For each open port → create PortFinding + apply risk rules
      6. Update ScanRequest with summary counts
      7. Mark as COMPLETE
      8. *** Push WebSocket notification to browser dashboard ***
    """

    # ── Step 1: Load scan ─────────────────────────────────────────────────────
    try:
        scan = ScanRequest.objects.get(pk=scan_id)
    except ScanRequest.DoesNotExist:
        logger.error(f'ScanRequest #{scan_id} not found')
        return

    logger.info(f'Starting scan #{scan_id}: {scan.target}')

    # ── Step 2: Mark running ──────────────────────────────────────────────────
    scan.status     = ScanStatus.RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=['status', 'started_at'])

    # Push "scan started" to dashboard
    notify_dashboard_update(
        f'Scan #{scan_id} started: {scan.target}',
        level='info'
    )

    try:
        # ── Step 3: Run nmap ──────────────────────────────────────────────────
        nmap_args = SCAN_PROFILES.get(scan.scan_profile, SCAN_PROFILES['default'])
        logger.info(f'nmap args: {nmap_args}')

        nm = nmap.PortScanner()
        nm.scan(hosts=scan.target, arguments=nmap_args)

        # ── Steps 4-5: Process hosts and ports ────────────────────────────────
        total_open_ports = 0
        high_count       = 0
        medium_count     = 0
        hosts_up         = 0
        scan_worst_risk  = Severity.NONE

        for ip in nm.all_hosts():
            host_data  = nm[ip]
            host_state = host_data.state()

            if host_state == 'up':
                hosts_up += 1

            # OS detection
            os_name, os_accuracy = 'N/A', 0
            if 'osmatch' in host_data and host_data['osmatch']:
                best = host_data['osmatch'][0]
                os_name     = best.get('name', 'N/A')
                os_accuracy = int(best.get('accuracy', 0))

            hostname = nm[ip].hostname() or ''

            host_record = HostResult.objects.create(
                scan        = scan,
                ip_address  = ip,
                hostname    = hostname,
                status      = host_state,
                os_detected = os_name,
                os_accuracy = os_accuracy,
                host_risk   = Severity.NONE,
            )

            host_worst = Severity.NONE
            host_open  = 0

            for proto in host_data.all_protocols():
                for port_num, port_info in host_data[proto].items():

                    state = port_info.get('state', 'unknown')
                    if state != 'open':
                        continue

                    host_open        += 1
                    total_open_ports += 1

                    svc_name    = port_info.get('name', '')
                    svc_product = port_info.get('product', '')
                    svc_version = port_info.get('version', '')
                    svc_cpe     = port_info.get('cpe', '')

                    severity, risk_note = RISKY_PORTS.get(
                        port_num, (Severity.INFO, 'Open port — no specific rule')
                    )
                    is_critical = port_num in CRITICAL_PORTS
                    alert_msg   = CRITICAL_PORTS.get(port_num, '')

                    PortFinding.objects.create(
                        host              = host_record,
                        port              = port_num,
                        protocol          = proto,
                        state             = state,
                        service_name      = svc_name,
                        service_product   = svc_product,
                        service_version   = svc_version,
                        service_cpe       = svc_cpe,
                        severity          = severity,
                        risk_note         = risk_note,
                        is_critical_alert = is_critical,
                        alert_message     = alert_msg,
                    )

                    host_worst = _worse(host_worst, severity)

                    if severity == Severity.HIGH:
                        high_count += 1
                    elif severity == Severity.MEDIUM:
                        medium_count += 1

            host_record.host_risk       = host_worst
            host_record.open_port_count = host_open
            host_record.save(update_fields=['host_risk', 'open_port_count'])

            scan_worst_risk = _worse(scan_worst_risk, host_worst)

        # ── Step 6: Update ScanRequest summary ────────────────────────────────
        scan.status                = ScanStatus.COMPLETE
        scan.completed_at          = timezone.now()
        scan.overall_risk          = scan_worst_risk
        scan.total_hosts           = len(nm.all_hosts())
        scan.hosts_up              = hosts_up
        scan.total_open_ports      = total_open_ports
        scan.high_severity_count   = high_count
        scan.medium_severity_count = medium_count
        scan.save(update_fields=[
            'status', 'completed_at', 'overall_risk',
            'total_hosts', 'hosts_up', 'total_open_ports',
            'high_severity_count', 'medium_severity_count',
        ])

        logger.info(
            f'Scan #{scan_id} complete — '
            f'{len(nm.all_hosts())} hosts, '
            f'{total_open_ports} open ports, '
            f'risk={scan_worst_risk}'
        )

        # ── Step 7: Push WebSocket notification ───────────────────────────────
        # This is the LIVE BRIDGE — tells browser "results are ready"
        # without any polling.
        notify_scan_complete(scan_id, scan_worst_risk)

    except nmap.PortScannerError as exc:
        _mark_failed(scan, f'nmap error: {exc}')
        notify_dashboard_update(
            f'Scan #{scan_id} failed: {exc}', level='error'
        )

    except Exception as exc:
        logger.exception(f'Scan #{scan_id} failed unexpectedly')
        _mark_failed(scan, str(exc))
        notify_dashboard_update(
            f'Scan #{scan_id} failed: {exc}', level='error'
        )


def _mark_failed(scan: ScanRequest, reason: str) -> None:
    scan.status        = ScanStatus.FAILED
    scan.completed_at  = timezone.now()
    scan.error_message = reason
    scan.save(update_fields=['status', 'completed_at', 'error_message'])
    logger.error(f'Scan #{scan.pk} failed: {reason}')