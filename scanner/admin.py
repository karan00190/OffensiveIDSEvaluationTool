# scanner/admin.py
from django.contrib import admin
from .models import (
    ScanRequest, HostResult, PortFinding,
    Agent, DGAResult, ExfilResult, ModuleTask,
)


# ── Inlines ──────────────────────────────────────────────────────────────────

class PortFindingInline(admin.TabularInline):
    model   = PortFinding
    extra   = 0
    readonly_fields = (
        'port', 'protocol', 'state', 'service_name',
        'service_product', 'service_version', 'severity',
        'risk_note', 'is_critical_alert', 'alert_message',
    )
    can_delete = False


class HostResultInline(admin.TabularInline):
    model   = HostResult
    extra   = 0
    readonly_fields = (
        'ip_address', 'hostname', 'status',
        'os_detected', 'host_risk', 'open_port_count',
    )
    can_delete = False
    show_change_link = True


# ── ScanRequest ───────────────────────────────────────────────────────────────

@admin.register(ScanRequest)
class ScanRequestAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'target', 'scan_profile', 'status',
        'overall_risk', 'total_hosts', 'hosts_up',
        'total_open_ports', 'high_severity_count',
        'cache_hit', 'created_at', 'duration_seconds',
    )
    list_filter   = ('status', 'scan_profile', 'overall_risk', 'cache_hit')
    search_fields = ('target', 'token', 'user__username')
    readonly_fields = (
        'token', 'created_at', 'started_at', 'completed_at',
        'duration_seconds', 'cache_hit', 'cached_from',
        'total_hosts', 'hosts_up', 'total_open_ports',
        'high_severity_count', 'medium_severity_count',
        'overall_risk', 'error_message',
    )
    inlines  = [HostResultInline]
    fieldsets = (
        ('Scan Target', {'fields': ('user', 'agent', 'target', 'scan_profile', 'token')}),
        ('Status',      {'fields': ('status', 'error_message')}),
        ('Cache',       {'fields': ('cache_hit', 'cached_from')}),
        ('Results Summary', {
            'fields': (
                'overall_risk', 'total_hosts', 'hosts_up',
                'total_open_ports', 'high_severity_count', 'medium_severity_count',
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'started_at', 'completed_at', 'duration_seconds')
        }),
    )


# ── HostResult ────────────────────────────────────────────────────────────────

@admin.register(HostResult)
class HostResultAdmin(admin.ModelAdmin):
    list_display  = (
        'ip_address', 'hostname', 'status',
        'os_detected', 'host_risk', 'open_port_count',
        'scan', 'scanned_at',
    )
    list_filter   = ('status', 'host_risk')
    search_fields = ('ip_address', 'hostname', 'scan__target')
    readonly_fields = ('scanned_at',)
    inlines = [PortFindingInline]


# ── PortFinding ───────────────────────────────────────────────────────────────

@admin.register(PortFinding)
class PortFindingAdmin(admin.ModelAdmin):
    list_display  = (
        'port', 'protocol', 'state', 'service_name',
        'service_product', 'service_version',
        'severity', 'is_critical_alert', 'host', 'found_at',
    )
    list_filter   = ('state', 'severity', 'protocol', 'is_critical_alert')
    search_fields = ('service_name', 'service_product', 'host__ip_address')
    readonly_fields = ('found_at', 'full_version')


# ── Agent ─────────────────────────────────────────────────────────────────────

@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    list_display  = (
        'agent_id', 'name', 'is_active',
        'last_seen_at', 'last_seen_ip', 'total_requests',
        'registered_at',
    )
    list_filter   = ('is_active',)
    search_fields = ('agent_id', 'name', 'last_seen_ip')
    readonly_fields = (
        'auth_token', 'secret_key', 'registered_at',
        'last_seen_at', 'last_seen_ip', 'total_requests',
    )
    fieldsets = (
        ('Identity', {
            'fields': ('agent_id', 'name', 'is_active', 'registered_by')
        }),
        ('Credentials (read-only)', {
            'fields': ('auth_token', 'secret_key'),
            'classes': ('collapse',),
        }),
        ('Capabilities', {
            'fields': ('capabilities',),
            'classes': ('collapse',),
        }),
        ('Activity', {
            'fields': (
                'registered_at', 'last_seen_at',
                'last_seen_ip', 'total_requests',
            )
        }),
    )


# ── DGAResult ─────────────────────────────────────────────────────────────────

@admin.register(DGAResult)
class DGAResultAdmin(admin.ModelAdmin):
    list_display  = (
        'pk', 'algorithm', 'total_queries',
        'nxdomain_count', 'nxdomain_ratio',
        'avg_entropy', 'ids_detected', 'risk_level',
        'agent', 'created_at',
    )
    list_filter   = ('algorithm', 'ids_detected')
    search_fields = ('agent__agent_id',)
    readonly_fields = (
        'nxdomain_count', 'resolved_count', 'timeout_count',
        'error_count', 'nxdomain_ratio', 'avg_entropy',
        'max_entropy', 'min_entropy', 'duration_sec',
        'domains_json', 'created_at', 'risk_level',
    )
    fieldsets = (
        ('Configuration', {
            'fields': (
                'agent', 'algorithm', 'total_queries',
                'rate_per_sec', 'dns_server', 'seed_date',
            ),
        }),
        ('Results', {
            'fields': (
                'nxdomain_count', 'resolved_count',
                'timeout_count', 'error_count',
                'nxdomain_ratio', 'duration_sec',
            ),
        }),
        ('Entropy Analysis', {
            'fields': ('avg_entropy', 'max_entropy', 'min_entropy'),
        }),
        ('IDS Tracking', {
            'fields': ('ids_detected', 'ids_detection_notes'),
        }),
        ('Raw Data', {
            'fields': ('domains_json',),
            'classes': ('collapse',),
        }),
    )


# ── ExfilResult ───────────────────────────────────────────────────────────────

@admin.register(ExfilResult)
class ExfilResultAdmin(admin.ModelAdmin):
    list_display  = (
        'pk', 'technique', 'profile', 'target',
        'total_chunks', 'successful', 'errors',
        'duration_sec', 'ids_detected', 'agent', 'created_at',
    )
    list_filter   = ('technique', 'profile', 'ids_detected')
    search_fields = ('target', 'agent__agent_id')
    readonly_fields = (
        'total_chunks', 'successful', 'errors',
        'duration_sec', 'avg_interval_sec',
        'ids_signatures', 'ids_severity',
        'packets_json', 'created_at', 'success_rate',
    )
    fieldsets = (
        ('Configuration', {
            'fields': ('agent', 'technique', 'profile', 'target'),
        }),
        ('Results', {
            'fields': (
                'total_chunks', 'successful', 'errors',
                'duration_sec', 'avg_interval_sec', 'success_rate',
            ),
        }),
        ('Detection Surface', {
            'fields': ('ids_severity', 'ids_signatures'),
        }),
        ('IDS Tracking', {
            'fields': ('ids_detected', 'ids_detection_notes'),
        }),
        ('Raw Packet Log', {
            'fields':  ('packets_json',),
            'classes': ('collapse',),
        }),
    )


# ── ModuleTask ────────────────────────────────────────────────────────────────

@admin.register(ModuleTask)
class ModuleTaskAdmin(admin.ModelAdmin):
    """
    Admin view for the web-orchestrated module task tracking model.
    Shows the full dispatch lifecycle — from web UI submission through
    WebSocket delivery to final result linkage.
    """
    list_display = (
        'task_id_short', 'module', 'status',
        'agent', 'initiated_by',
        'dispatched_at', 'completed_at', 'duration_seconds',
        'result_pk',
    )
    list_filter   = ('module', 'status')
    search_fields = ('agent__agent_id', 'initiated_by__username')
    readonly_fields = (
        'task_id', 'task_id_short', 'dispatched_at',
        'completed_at', 'duration_seconds', 'is_terminal',
    )
    ordering = ('-dispatched_at',)
    fieldsets = (
        ('Identity', {
            'fields': ('task_id', 'task_id_short', 'module', 'status'),
        }),
        ('Relationships', {
            'fields': ('agent', 'initiated_by'),
        }),
        ('Configuration dispatched to agent', {
            'fields': ('config_json',),
        }),
        ('Timing', {
            'fields': (
                'dispatched_at', 'completed_at',
                'duration_seconds', 'is_terminal',
            ),
        }),
        ('Result linkage', {
            'fields': ('result_pk',),
            'description': (
                'result_pk points into DGAResult (module=dga), '
                'ExfilResult (module=exfil), or ScanRequest (module=nmap).'
            ),
        }),
        ('Error detail', {
            'fields': ('error_message',),
            'classes': ('collapse',),
        }),
    )