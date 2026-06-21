# scanner/export_views.py
# =============================================================================
#  MIAT — Report Export (CSV + PDF)
#
#  GET /dga/<pk>/export/?format=csv|pdf
#  GET /exfil/<pk>/export/?format=csv|pdf
#  GET /scan/<pk>/export/?format=csv|pdf
#  GET /beacon/<pk>/export/?format=csv|pdf
# =============================================================================

import csv
import io
from datetime import datetime, timezone

from django.contrib.auth.decorators import login_required
from django.http                    import HttpResponse
from django.shortcuts               import get_object_or_404

from reportlab.lib              import colors
from reportlab.lib.pagesizes    import A4
from reportlab.lib.styles       import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units        import mm
from reportlab.platypus         import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

from .models import DGAResult, ExfilResult, ScanRequest, BeaconResult

# ── colour palette (matches MIAT UI) ─────────────────────────────────────────
_CYAN       = colors.HexColor('#00d4ff')
_CYAN_DIM   = colors.HexColor('#0099bb')
_GREEN      = colors.HexColor('#00ff88')
_AMBER      = colors.HexColor('#ffbb33')
_RED        = colors.HexColor('#ff4455')
_BG_VOID    = colors.HexColor('#0a0c0f')
_BG_PANEL   = colors.HexColor('#111418')
_BORDER     = colors.HexColor('#1e2530')
_TEXT_PRI   = colors.HexColor('#e0e8f0')
_TEXT_SEC   = colors.HexColor('#8a9ab5')
_TEXT_DIM   = colors.HexColor('#4a5568')


# =============================================================================
# PDF HELPERS
# =============================================================================

def _styles():
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle(
            'MiatTitle',
            parent=base['Normal'],
            fontSize=18, textColor=_CYAN, fontName='Helvetica-Bold',
            spaceAfter=4,
        ),
        'subtitle': ParagraphStyle(
            'MiatSub',
            parent=base['Normal'],
            fontSize=10, textColor=_TEXT_SEC, fontName='Helvetica',
            spaceAfter=2,
        ),
        'section': ParagraphStyle(
            'MiatSection',
            parent=base['Normal'],
            fontSize=9, textColor=_TEXT_DIM, fontName='Helvetica-Bold',
            spaceBefore=14, spaceAfter=4,
            textTransform='uppercase', letterSpacing=1.5,
        ),
        'body': ParagraphStyle(
            'MiatBody',
            parent=base['Normal'],
            fontSize=8, textColor=_TEXT_SEC, fontName='Helvetica',
            spaceAfter=2,
        ),
        'mono': ParagraphStyle(
            'MiatMono',
            parent=base['Normal'],
            fontSize=7.5, textColor=_TEXT_PRI, fontName='Courier',
        ),
        'sig': ParagraphStyle(
            'MiatSig',
            parent=base['Normal'],
            fontSize=8, textColor=_AMBER, fontName='Helvetica',
            spaceAfter=2, leftIndent=8,
        ),
    }


def _kv_table(rows, col_widths=(70*mm, 100*mm)):
    """Two-column key-value table."""
    data = [[Paragraph(f'<b>{k}</b>', _styles()['mono']),
             Paragraph(str(v), _styles()['mono'])]
            for k, v in rows]
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, -1), _BG_PANEL),
        ('TEXTCOLOR',   (0, 0), (0, -1),  _TEXT_DIM),
        ('TEXTCOLOR',   (1, 0), (1, -1),  _TEXT_PRI),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [_BG_PANEL, colors.HexColor('#141920')]),
        ('GRID',        (0, 0), (-1, -1), 0.3, _BORDER),
        ('FONTNAME',    (0, 0), (-1, -1), 'Courier'),
        ('FONTSIZE',    (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',(0, 0), (-1, -1), 8),
        ('TOPPADDING',  (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING',(0,0), (-1, -1), 5),
    ]))
    return t


def _data_table(headers, rows, page_width=None):
    """Multi-column data table with header row."""
    if page_width is None:
        page_width = A4[0] - 20*mm
    col_w = page_width / max(len(headers), 1)

    data = [[Paragraph(f'<b>{h}</b>', _styles()['mono']) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(c) if c is not None else '—', _styles()['mono'])
                     for c in row])

    t = Table(data, colWidths=[col_w] * len(headers), repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor('#0f1d2a')),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  _CYAN),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [_BG_PANEL, colors.HexColor('#141920')]),
        ('TEXTCOLOR',     (0, 1), (-1, -1), _TEXT_SEC),
        ('GRID',          (0, 0), (-1, -1), 0.25, _BORDER),
        ('FONTNAME',      (0, 0), (-1, -1), 'Courier'),
        ('FONTSIZE',      (0, 0), (-1, -1), 7),
        ('LEFTPADDING',   (0, 0), (-1, -1), 5),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 5),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('WORDWRAP',      (0, 0), (-1, -1), 'CJK'),
    ]))
    return t


def _pdf_response(filename):
    resp = HttpResponse(content_type='application/pdf')
    resp['Content-Disposition'] = f'attachment; filename="{filename}"'
    return resp


def _build_pdf(elements, filename):
    resp = _pdf_response(filename)
    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=12*mm, rightMargin=12*mm,
        topMargin=14*mm, bottomMargin=14*mm,
    )
    doc.build(elements)
    resp.write(buf.getvalue())
    return resp


def _header_block(title_txt, subtitle_txt, meta_pairs):
    s = _styles()
    elems = [
        Paragraph(title_txt,    s['title']),
        Paragraph(subtitle_txt, s['subtitle']),
        HRFlowable(width='100%', thickness=0.5, color=_CYAN_DIM, spaceAfter=8),
    ]
    for key, val in meta_pairs:
        elems.append(
            Paragraph(f'<font color="#4a5568">{key}:</font>&nbsp; '
                      f'<font color="#e0e8f0">{val}</font>', s['mono'])
        )
    elems.append(Spacer(1, 8))
    return elems


# =============================================================================
# DGA EXPORT
# =============================================================================

@login_required
def export_dga(request, pk):
    result = get_object_or_404(DGAResult, pk=pk)
    fmt    = request.GET.get('format', 'csv').lower()
    return _dga_pdf(result) if fmt == 'pdf' else _dga_csv(result)


def _dga_csv(result):
    resp = HttpResponse(content_type='text/csv')
    resp['Content-Disposition'] = f'attachment; filename="dga_run_{result.pk}.csv"'
    w = csv.writer(resp)

    w.writerow(['# MIAT — DGA Simulation Report'])
    w.writerow(['run_id', 'created_at', 'agent_id', 'algorithm',
                'total_queries', 'nxdomain_count', 'resolved_count',
                'timeout_count', 'error_count', 'nxdomain_ratio',
                'avg_entropy', 'max_entropy', 'min_entropy',
                'rate_per_sec', 'duration_sec', 'dns_server',
                'ids_detected', 'ids_detection_notes'])
    w.writerow([
        result.pk,
        result.created_at.isoformat(),
        result.agent.agent_id if result.agent else '',
        result.algorithm,
        result.total_queries,
        result.nxdomain_count,
        result.resolved_count,
        result.timeout_count,
        result.error_count,
        result.nxdomain_ratio,
        result.avg_entropy,
        result.max_entropy,
        result.min_entropy,
        result.rate_per_sec,
        result.duration_sec,
        result.dns_server or 'system',
        result.ids_detected,
        result.ids_detection_notes or '',
    ])

    w.writerow([])
    w.writerow(['# Per-Domain Records'])
    w.writerow(['domain', 'outcome', 'entropy', 'timestamp'])
    for d in (result.domains_json or []):
        w.writerow([
            d.get('domain', ''),
            d.get('outcome', ''),
            d.get('entropy', ''),
            d.get('timestamp', ''),
        ])
    return resp


def _dga_pdf(result):
    s     = _styles()
    elems = _header_block(
        f'DGA Simulation — Run #{result.pk}',
        f'Algorithm: {result.algorithm.upper()}  ·  Agent: {result.agent.agent_id if result.agent else "—"}',
        [
            ('Date',       result.created_at.strftime('%Y-%m-%d %H:%M UTC')),
            ('DNS Server', result.dns_server or 'system'),
        ],
    )

    elems += [Paragraph('SUMMARY', s['section']),
              _kv_table([
                  ('Total Queries',    result.total_queries),
                  ('NXDOMAIN',         f'{result.nxdomain_count} ({result.nxdomain_ratio*100:.1f}%)'),
                  ('Resolved',         result.resolved_count),
                  ('Timeouts',         result.timeout_count),
                  ('Errors',           result.error_count),
                  ('Avg Entropy',      result.avg_entropy),
                  ('Max Entropy',      result.max_entropy),
                  ('Min Entropy',      result.min_entropy),
                  ('Rate (q/s)',        result.rate_per_sec),
                  ('Duration (s)',      result.duration_sec),
                  ('IDS Detected',     result.ids_status),
              ]),
              Spacer(1, 8)]

    domains = result.domains_json or []
    if domains:
        elems += [Paragraph('DOMAIN LOG', s['section']),
                  _data_table(
                      ['Domain', 'Outcome', 'Entropy', 'Timestamp'],
                      [[d.get('domain',''), d.get('outcome',''),
                        d.get('entropy',''), (d.get('timestamp','') or '')[:19]]
                       for d in domains],
                  )]

    return _build_pdf(elems, f'dga_run_{result.pk}.pdf')


# =============================================================================
# EXFIL EXPORT
# =============================================================================

@login_required
def export_exfil(request, pk):
    result = get_object_or_404(ExfilResult, pk=pk)
    fmt    = request.GET.get('format', 'csv').lower()
    return _exfil_pdf(result) if fmt == 'pdf' else _exfil_csv(result)


def _exfil_csv(result):
    resp = HttpResponse(content_type='text/csv')
    resp['Content-Disposition'] = f'attachment; filename="exfil_run_{result.pk}.csv"'
    w = csv.writer(resp)

    w.writerow(['# MIAT — Data Exfiltration Report'])
    w.writerow(['run_id', 'created_at', 'agent_id', 'technique', 'profile',
                'target', 'total_chunks', 'successful', 'errors',
                'duration_sec', 'avg_interval_sec', 'ids_severity',
                'ids_detected', 'ids_detection_notes'])
    w.writerow([
        result.pk,
        result.created_at.isoformat(),
        result.agent.agent_id if result.agent else '',
        result.technique,
        result.profile,
        result.target,
        result.total_chunks,
        result.successful,
        result.errors,
        result.duration_sec,
        result.avg_interval_sec,
        result.ids_severity,
        result.ids_detected,
        result.ids_detection_notes or '',
    ])

    w.writerow([])
    w.writerow(['# Per-Packet Records'])

    packets = result.packets_json or []
    if packets:
        all_keys = set()
        for p in packets:
            all_keys.update(p.keys())
        headers = sorted(all_keys)
        w.writerow(headers)
        for p in packets:
            w.writerow([p.get(k, '') for k in headers])
    return resp


def _exfil_pdf(result):
    s     = _styles()
    elems = _header_block(
        f'Data Exfiltration — Run #{result.pk}',
        f'Technique: {result.technique.upper()}  ·  Profile: {result.profile.upper()}  ·  Agent: {result.agent.agent_id if result.agent else "—"}',
        [
            ('Date',   result.created_at.strftime('%Y-%m-%d %H:%M UTC')),
            ('Target', result.target),
        ],
    )

    elems += [Paragraph('SUMMARY', s['section']),
              _kv_table([
                  ('Technique',       result.technique.upper()),
                  ('Profile',         result.profile.upper()),
                  ('Total Chunks',    result.total_chunks),
                  ('Successful',      result.successful),
                  ('Errors',          result.errors),
                  ('Duration (s)',     result.duration_sec),
                  ('Avg Interval (s)',result.avg_interval_sec),
                  ('IDS Severity',    result.ids_severity),
                  ('IDS Detected',    result.ids_status),
              ]),
              Spacer(1, 8)]

    sigs = result.ids_signatures or []
    if sigs:
        elems += [Paragraph('IDS SIGNATURES', s['section'])]
        for sig in sigs:
            elems.append(Paragraph(f'⚑  {sig}', s['sig']))
        elems.append(Spacer(1, 8))

    packets = result.packets_json or []
    if packets:
        all_keys = sorted({k for p in packets for k in p.keys()})
        elems += [Paragraph('PACKET LOG', s['section']),
                  _data_table(all_keys,
                               [[p.get(k, '') for k in all_keys] for p in packets])]

    return _build_pdf(elems, f'exfil_run_{result.pk}.pdf')


# =============================================================================
# SCAN (NMAP) EXPORT
# =============================================================================

@login_required
def export_scan(request, pk):
    scan = get_object_or_404(ScanRequest, pk=pk)
    fmt  = request.GET.get('format', 'csv').lower()
    return _scan_pdf(scan) if fmt == 'pdf' else _scan_csv(scan)


def _scan_csv(scan):
    resp = HttpResponse(content_type='text/csv')
    resp['Content-Disposition'] = f'attachment; filename="scan_{scan.pk}.csv"'
    w = csv.writer(resp)

    w.writerow(['# MIAT — Nmap Scan Report'])
    w.writerow(['scan_id', 'target', 'profile', 'status', 'completed_at',
                'overall_risk', 'total_hosts', 'hosts_up', 'total_open_ports',
                'high_severity_count', 'medium_severity_count'])
    hosts    = scan.hosts.prefetch_related('ports').all()
    all_ports = [p for h in hosts for p in h.ports.all()]
    high_ct  = sum(1 for p in all_ports if p.severity == 'HIGH')
    med_ct   = sum(1 for p in all_ports if p.severity == 'MEDIUM')
    up_ct    = sum(1 for h in hosts if h.status == 'up')

    w.writerow([
        scan.pk, scan.target, scan.scan_profile, scan.status,
        scan.completed_at.isoformat() if scan.completed_at else '',
        scan.overall_risk or '',
        hosts.count(), up_ct, len(all_ports), high_ct, med_ct,
    ])

    w.writerow([])
    w.writerow(['# Hosts'])
    w.writerow(['host_ip', 'hostname', 'status', 'os_detected',
                'os_accuracy', 'host_risk', 'open_port_count'])
    for h in hosts:
        w.writerow([
            h.ip_address, h.hostname or '', h.status,
            h.os_detected or '', h.os_accuracy or '',
            h.host_risk or '', h.ports.count(),
        ])

    w.writerow([])
    w.writerow(['# Ports'])
    w.writerow(['host_ip', 'port', 'protocol', 'state', 'service_name',
                'service_version', 'severity', 'risk_note',
                'is_critical_alert', 'alert_message'])
    for h in hosts:
        for p in h.ports.all():
            w.writerow([
                h.ip_address, p.port, p.protocol, p.state,
                p.service_name or '', p.service_version or '',
                p.severity or '', p.risk_note or '',
                p.is_critical_alert, p.alert_message or '',
            ])
    return resp


def _scan_pdf(scan):
    s      = _styles()
    hosts  = list(scan.hosts.prefetch_related('ports').all())
    all_p  = [p for h in hosts for p in h.ports.all()]
    high_c = sum(1 for p in all_p if p.severity == 'HIGH')
    med_c  = sum(1 for p in all_p if p.severity == 'MEDIUM')
    up_c   = sum(1 for h in hosts if h.status == 'up')

    elems = _header_block(
        f'Nmap Scan — #{scan.pk}',
        f'Target: {scan.target}  ·  Profile: {scan.scan_profile.upper()}',
        [
            ('Status',    scan.status.upper()),
            ('Completed', scan.completed_at.strftime('%Y-%m-%d %H:%M UTC') if scan.completed_at else '—'),
            ('Risk',      scan.overall_risk or '—'),
        ],
    )

    elems += [Paragraph('SUMMARY', s['section']),
              _kv_table([
                  ('Total Hosts',    len(hosts)),
                  ('Hosts Up',       up_c),
                  ('Open Ports',     len(all_p)),
                  ('HIGH Severity',  high_c),
                  ('MEDIUM Severity',med_c),
              ]),
              Spacer(1, 8)]

    critical = [p for h in hosts for p in h.ports.all() if p.is_critical_alert]
    if critical:
        elems += [Paragraph('CRITICAL ALERTS', s['section'])]
        for p in critical:
            elems.append(
                Paragraph(
                    f'<font color="#ff4455">⚠ {p.host.ip_address}:{p.port}/{p.protocol} — {p.alert_message or p.risk_note or "Critical"}</font>',
                    s['body']
                )
            )
        elems.append(Spacer(1, 8))

    for host in hosts:
        ports = list(host.ports.all())
        elems += [Paragraph(f'HOST: {host.ip_address}', s['section']),
                  _kv_table([
                      ('Hostname',   host.hostname or '—'),
                      ('Status',     host.status),
                      ('OS',         f'{host.os_detected or "Unknown"} ({host.os_accuracy or 0}%)'),
                      ('Risk',       host.host_risk or '—'),
                      ('Open Ports', len(ports)),
                  ], col_widths=(50*mm, 120*mm)),
                  Spacer(1, 5)]
        if ports:
            elems.append(
                _data_table(
                    ['Port', 'Proto', 'State', 'Service', 'Version', 'Severity', 'Risk Note'],
                    [[p.port, p.protocol, p.state,
                      p.service_name or '', (p.service_version or '')[:30],
                      p.severity or '', (p.risk_note or '')[:40]]
                     for p in ports],
                )
            )
        elems.append(Spacer(1, 10))

    return _build_pdf(elems, f'scan_{scan.pk}.pdf')


# =============================================================================
# BEACON EXPORT
# =============================================================================

@login_required
def export_beacon(request, pk):
    result = get_object_or_404(BeaconResult, pk=pk)
    fmt    = request.GET.get('format', 'csv').lower()
    return _beacon_pdf(result) if fmt == 'pdf' else _beacon_csv(result)


def _beacon_csv(result):
    resp = HttpResponse(content_type='text/csv')
    resp['Content-Disposition'] = f'attachment; filename="beacon_run_{result.pk}.csv"'
    w = csv.writer(resp)

    w.writerow(['# MIAT — C2 Beacon Simulation Report'])
    w.writerow(['run_id', 'session_id', 'created_at', 'agent_id',
                'protocol', 'encoding', 'target',
                'total_beacons', 'successful', 'failed',
                'interval_sec', 'jitter_pct', 'avg_latency_ms', 'std_dev_sec',
                'ids_detected', 'ids_detection_notes'])
    w.writerow([
        result.pk,
        result.session_id,
        result.created_at.isoformat(),
        result.agent.agent_id if result.agent else '',
        result.protocol,
        result.encoding,
        result.target,
        result.total_beacons,
        result.successful,
        result.failed,
        result.interval_sec,
        result.jitter_pct,
        result.avg_latency_ms,
        result.std_dev_sec,
        result.ids_detected,
        result.ids_detection_notes or '',
    ])

    w.writerow([])
    w.writerow(['# Per-Beacon Records'])
    w.writerow(['sequence', 'timestamp', 'encoding', 'sent',
                'http_status', 'outcome', 'latency_ms', 'actual_interval_sec', 'error'])
    for b in (result.beacons_json or []):
        w.writerow([
            b.get('sequence', ''),
            b.get('timestamp', ''),
            b.get('encoding', ''),
            b.get('sent', ''),
            b.get('http_status', ''),
            b.get('outcome', ''),
            b.get('latency_ms', ''),
            b.get('actual_interval_sec', ''),
            b.get('error', ''),
        ])
    return resp


def _beacon_pdf(result):
    s     = _styles()
    elems = _header_block(
        f'C2 Beacon — Run #{result.pk}',
        f'Protocol: {result.protocol.upper()}  ·  Encoding: {result.encoding.upper()}  ·  Target: {result.target}',
        [
            ('Date',     result.created_at.strftime('%Y-%m-%d %H:%M UTC')),
            ('Session',  result.session_id),
            ('Agent',    result.agent.agent_id if result.agent else '—'),
        ],
    )

    elems += [Paragraph('SUMMARY', s['section']),
              _kv_table([
                  ('Total Beacons',   result.total_beacons),
                  ('Successful',      result.successful),
                  ('Failed',          result.failed),
                  ('Success Rate',    f'{result.success_rate*100:.1f}%'),
                  ('Avg Latency',     f'{result.avg_latency_ms:.1f} ms'),
                  ('Interval',        f'{result.interval_sec} s'),
                  ('Jitter',          f'±{result.jitter_pct}%'),
                  ('Interval Std Dev',f'{result.std_dev_sec} s'),
                  ('IDS Detected',    result.ids_status),
              ]),
              Spacer(1, 8)]

    sigs = result.ids_signatures or []
    if sigs:
        elems += [Paragraph('IDS SIGNATURES', s['section'])]
        for sig in sigs:
            elems.append(Paragraph(f'⚑  {sig}', s['sig']))
        elems.append(Spacer(1, 8))

    if result.ids_detection_notes:
        elems += [Paragraph('DETECTION NOTES', s['section']),
                  Paragraph(result.ids_detection_notes, s['body']),
                  Spacer(1, 8)]

    beacons = result.beacons_json or []
    if beacons:
        elems += [Paragraph('BEACON TIMELINE', s['section']),
                  _data_table(
                      ['#', 'Timestamp', 'Encoding', 'Sent', 'Status/Outcome', 'Latency (ms)', 'Sleep (s)'],
                      [[b.get('sequence',''), (b.get('timestamp','') or '')[:19],
                        b.get('encoding',''), '✓' if b.get('sent') else '✗',
                        str(b.get('http_status', b.get('outcome', '—'))),
                        b.get('latency_ms',''),
                        b.get('actual_interval_sec','—')]
                       for b in beacons],
                  )]

    return _build_pdf(elems, f'beacon_run_{result.pk}.pdf')
