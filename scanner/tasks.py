# scanner/tasks.py
import logging
from asgiref.sync  import async_to_sync
from channels.layers import get_channel_layer

logger = logging.getLogger('MIAT.Tasks')


# =============================================================================
# WEBSOCKET NOTIFICATION HELPERS
# Called from both django-q2 background tasks and API result views.
# =============================================================================

def notify_scan_complete(scan_id: int, risk: str, report_url: str) -> None:
    """Push a scan_complete event to all connected browser dashboards."""
    layer = get_channel_layer()
    if layer is None:
        logger.warning('notify_scan_complete: channel layer not configured')
        return
    try:
        async_to_sync(layer.group_send)(
            'dashboard',
            {
                'type':       'scan.complete',
                'scan_id':    scan_id,
                'risk':       risk,
                'report_url': report_url,
            },
        )
    except Exception as exc:
        logger.error(f'notify_scan_complete WS push failed: {exc}')


def notify_dashboard_update(message: str, level: str = 'info') -> None:
    """Push a generic informational message to all connected dashboards."""
    layer = get_channel_layer()
    if layer is None:
        return
    try:
        async_to_sync(layer.group_send)(
            'dashboard',
            {
                'type':    'dashboard.update',
                'message': message,
                'level':   level,
            },
        )
    except Exception as exc:
        logger.error(f'notify_dashboard_update WS push failed: {exc}')


# =============================================================================
# DJANGO-Q2 BACKGROUND TASK — Nmap scan
# =============================================================================

def run_scan_task(scan_pk: int) -> None:
    """
    Background task queued by submit_scan() view via async_task().
    Runs nmap against the target, parses results, writes to DB, and
    pushes a WebSocket notification when done.

    Enqueued with:
        from django_q.tasks import async_task
        async_task('scanner.tasks.run_scan_task', scan.pk)
    """
    from .models import ScanRequest, ScanStatus, HostResult, PortFinding, Severity
    from django.utils import timezone

    try:
        scan = ScanRequest.objects.get(pk=scan_pk)
    except ScanRequest.DoesNotExist:
        logger.error(f'run_scan_task: ScanRequest #{scan_pk} not found')
        return

    scan.status     = ScanStatus.RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=['status', 'started_at'])

    notify_dashboard_update(
        f'Scan #{scan_pk} started → {scan.target}', 'info'
    )

    try:
        import nmap
        nm      = nmap.PortScanner()
        profile = scan.scan_profile

        nmap_args = {
            'fast':    '-T4 -F',
            'default': '-T4 --top-ports 1000',
            'deep':    '-T4 -p- -sV -O',
            'ping':    '-sn',
        }.get(profile, '-T4 --top-ports 1000')

        nm.scan(hosts=scan.target, arguments=nmap_args)

        total_hosts = total_open = high_count = medium_count = 0
        hosts_up    = 0
        overall_sev = Severity.NONE

        for host_ip in nm.all_hosts():
            host_data = nm[host_ip]
            host_status = host_data.state()
            total_hosts += 1
            if host_status == 'up':
                hosts_up += 1

            os_name = 'N/A'
            os_acc  = 0
            if 'osmatch' in host_data and host_data['osmatch']:
                best = host_data['osmatch'][0]
                os_name = best.get('name', 'N/A')
                os_acc  = int(best.get('accuracy', 0))

            host_row = HostResult.objects.create(
                scan        = scan,
                ip_address  = host_ip,
                hostname    = next(iter(host_data.hostname() or []), ''),
                status      = host_status,
                os_detected = os_name,
                os_accuracy = os_acc,
            )

            port_count   = 0
            host_high    = 0
            host_medium  = 0
            host_sev     = Severity.NONE

            for proto in host_data.all_protocols():
                for port_num, port_data in host_data[proto].items():
                    if port_data.get('state') != 'open':
                        continue
                    port_count  += 1
                    total_open  += 1
                    svc_name     = port_data.get('name', '')
                    svc_product  = port_data.get('product', '')
                    svc_version  = port_data.get('version', '')
                    svc_cpe      = port_data.get('cpe', '')
                    sev, note, alert = _assess_port(port_num, svc_name)
                    if sev == Severity.HIGH:
                        host_high   += 1
                        high_count  += 1
                        host_sev     = Severity.HIGH
                        if overall_sev != Severity.HIGH:
                            overall_sev = Severity.HIGH
                    elif sev == Severity.MEDIUM:
                        host_medium += 1
                        medium_count+= 1
                        if host_sev == Severity.NONE:
                            host_sev = Severity.MEDIUM
                        if overall_sev == Severity.NONE:
                            overall_sev = Severity.MEDIUM
                    PortFinding.objects.create(
                        host            = host_row,
                        port            = port_num,
                        protocol        = proto,
                        state           = 'open',
                        service_name    = svc_name,
                        service_product = svc_product,
                        service_version = svc_version,
                        service_cpe     = svc_cpe,
                        severity        = sev,
                        risk_note       = note,
                        is_critical_alert = alert,
                        alert_message   = note if alert else '',
                    )

            host_row.open_port_count = port_count
            host_row.host_risk       = host_sev
            host_row.save(update_fields=['open_port_count', 'host_risk'])

        scan.status               = ScanStatus.COMPLETE
        scan.completed_at         = timezone.now()
        scan.total_hosts          = total_hosts
        scan.hosts_up             = hosts_up
        scan.total_open_ports     = total_open
        scan.high_severity_count  = high_count
        scan.medium_severity_count= medium_count
        scan.overall_risk         = overall_sev
        scan.save(update_fields=[
            'status','completed_at','total_hosts','hosts_up',
            'total_open_ports','high_severity_count',
            'medium_severity_count','overall_risk',
        ])

        report_url = f'/scan/{scan_pk}/report/'
        notify_scan_complete(scan_pk, overall_sev, report_url)
        logger.info(
            f'Scan #{scan_pk} complete: '
            f'{hosts_up}/{total_hosts} hosts up, '
            f'{total_open} open ports, risk={overall_sev}'
        )

    except Exception as exc:
        scan.status        = ScanStatus.FAILED
        scan.error_message = str(exc)
        scan.completed_at  = timezone.now()
        scan.save(update_fields=['status', 'error_message', 'completed_at'])
        notify_dashboard_update(
            f'Scan #{scan_pk} failed: {exc}', 'error'
        )
        logger.error(f'Scan #{scan_pk} failed: {exc}', exc_info=True)


# ── Port risk classifier ──────────────────────────────────────────────────────

_HIGH_PORTS = {
    21: ('FTP — cleartext credentials', True),
    22: ('SSH exposed', False),
    23: ('Telnet — cleartext protocol', True),
    445: ('SMB — ransomware vector', True),
    3389: ('RDP exposed — brute-force target', True),
    1433: ('MSSQL directly exposed', True),
    3306: ('MySQL directly exposed', True),
    5432: ('PostgreSQL directly exposed', True),
    6379: ('Redis — unauthenticated by default', True),
    27017: ('MongoDB — unauthenticated by default', True),
}

_MEDIUM_PORTS = {
    80:   'HTTP — no TLS',
    8080: 'HTTP alternate — no TLS',
    8443: 'HTTPS alternate',
    25:   'SMTP exposed',
    110:  'POP3 exposed',
    143:  'IMAP exposed',
}


def _assess_port(port: int, service: str):
    from .models import Severity
    if port in _HIGH_PORTS:
        note, alert = _HIGH_PORTS[port]
        return Severity.HIGH, note, alert
    if port in _MEDIUM_PORTS:
        return Severity.MEDIUM, _MEDIUM_PORTS[port], False
    return Severity.INFO, f'{service or "unknown"} on port {port}', False