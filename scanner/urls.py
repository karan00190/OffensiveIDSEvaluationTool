# scanner/urls.py — COMPLETE FINAL VERSION

from django.urls import path
from . import (
    views,
    agent_views,
    agent_frontend_views,
    token_views,
    dga_views,
    exfil_views,
    module_views,
)

app_name = 'scanner'

urlpatterns = [

    # ── Browser pages ─────────────────────────────────────────────────────────
    path('',
         views.dashboard,
         name='dashboard'),

    path('scan/',
         views.submit_scan,
         name='submit_scan'),

    path('scan/<int:pk>/status/',
         views.scan_status,
         name='scan_status'),

    path('scan/<int:pk>/report/',
         views.scan_report,
         name='scan_report'),

    # ── Agent management (browser) ────────────────────────────────────────────
    path('agents/',
         agent_frontend_views.agent_list,
         name='agent_list'),

    path('agents/register/',
         agent_frontend_views.agent_register_view,
         name='agent_register'),

    path('agents/<int:pk>/',
         agent_frontend_views.agent_detail,
         name='agent_detail'),

    path('agents/<int:pk>/toggle/',
         agent_frontend_views.agent_toggle,
         name='agent_toggle'),

    path('agents/<int:pk>/delete/',
         agent_frontend_views.agent_delete,
         name='agent_delete'),

    # ── DGA (browser) ─────────────────────────────────────────────────────────
    path('dga/',
         dga_views.dga_dashboard,
         name='dga_dashboard'),

    path('dga/<int:pk>/',
         dga_views.dga_detail,
         name='dga_detail'),

    path('dga/<int:pk>/mark/',
         dga_views.dga_mark_detected,
         name='dga_mark_detected'),

    # ── Exfiltration (browser) ────────────────────────────────────────────────
    path('exfil/',
         exfil_views.exfil_dashboard,
         name='exfil_dashboard'),

    path('exfil/<int:pk>/',
         exfil_views.exfil_detail,
         name='exfil_detail'),

    path('exfil/<int:pk>/mark/',
         exfil_views.exfil_mark_detected,
         name='exfil_mark_detected'),

    # ── Module control panel & dispatch API ───────────────────────────────────
    path('modules/',
         module_views.module_control_view,
         name='module_control'),

    path('api/modules/dga/dispatch/',
         module_views.dispatch_dga_task,
         name='api_dispatch_dga'),

    path('api/modules/exfil/dispatch/',
         module_views.dispatch_exfil_task,
         name='api_dispatch_exfil'),

    # <uuid:task_id> validates UUID format before the view runs;
    # malformed IDs get an automatic 404 from Django's URL converter.
    path('api/modules/task/<uuid:task_id>/status/',
         module_views.get_task_status,
         name='api_task_status'),

    # ── Scan status JSON (polled by scan_status.html JS) ─────────────────────
    path('api/scan/<int:pk>/status/',
         views.api_scan_status,
         name='api_scan_status'),

    path('api/scan/submit/',
         views.api_submit_scan,
         name='api_submit_scan'),

    # ── JWT token endpoints ───────────────────────────────────────────────────
    path('api/agent/token/',
         token_views.obtain_token,
         name='token_obtain'),

    path('api/agent/token/refresh/',
         token_views.refresh_token_view,
         name='token_refresh'),

    path('api/agent/token/verify/',
         token_views.verify_token_view,
         name='token_verify'),

    # ── Agent API endpoints ───────────────────────────────────────────────────
    path('api/agent/register/',
         agent_views.agent_register,
         name='agent_register_api'),

    path('api/agent/heartbeat/',
         agent_views.agent_heartbeat,
         name='agent_heartbeat'),

    path('api/agent/scan/submit/',
         agent_views.agent_submit_scan,
         name='agent_submit_scan'),

    path('api/agent/results/',
         agent_views.agent_post_results,
         name='agent_post_results'),

    path('api/agent/status/',
         agent_views.agent_poll_commands,
         name='agent_poll_commands'),

    # ── DGA API (agent telemetry) ─────────────────────────────────────────────
    path('api/agent/dga/results/',
         dga_views.api_dga_results,
         name='api_dga_results'),

    # ── Exfil API (agent telemetry) ───────────────────────────────────────────
    path('api/agent/exfil/results/',
         exfil_views.api_exfil_results,
         name='api_exfil_results'),
]