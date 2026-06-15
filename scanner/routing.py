# scanner/routing.py
# ─────────────────────────────────────────────────────────────────────────────
#  MIAT — WebSocket URL Routing
#
#  This is the WebSocket equivalent of urls.py.
#  Regular HTTP URLs go to views.py via urls.py.
#  WebSocket URLs go to consumers.py via routing.py.
#
#  URL patterns:
#    ws://server/ws/agent/<agent_id>/   → AgentConsumer
#    ws://server/ws/dashboard/          → DashboardConsumer
#
#  The <agent_id> part is captured and passed to the consumer
#  as: self.scope['url_route']['kwargs']['agent_id']
# ─────────────────────────────────────────────────────────────────────────────

from django.urls   import re_path
from . import consumers

# These are WebSocket URL patterns — same syntax as urlpatterns in urls.py
# but using re_path with ws:// prefix convention

websocket_urlpatterns = [

    # Agent WebSocket connection
    # Pattern: /ws/agent/<agent_id>/
    # agent_id can contain letters, numbers, and hyphens
    re_path(
        r'^ws/agent/(?P<agent_id>[\w\-]+)/$',
        consumers.AgentConsumer.as_asgi(),
        name='ws_agent',
    ),

    # Browser dashboard WebSocket
    # Pattern: /ws/dashboard/
    re_path(
        r'^ws/dashboard/$',
        consumers.DashboardConsumer.as_asgi(),
        name='ws_dashboard',
    ),
]