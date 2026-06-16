# scanner/routing.py
from django.urls import re_path
from .consumers  import AgentConsumer, DashboardConsumer

websocket_urlpatterns = [
    re_path(r'^ws/agent/(?P<agent_id>[\w\-]+)/$', AgentConsumer.as_asgi()),
    re_path(r'^ws/dashboard/$',                   DashboardConsumer.as_asgi()),
]