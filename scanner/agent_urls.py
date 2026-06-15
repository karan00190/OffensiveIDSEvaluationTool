# scanner/agent_urls.py
# Add these URL patterns to your existing scanner/urls.py
# inside the urlpatterns list

from django.urls import path
from . import agent_views

# Add these lines to your existing scanner/urls.py urlpatterns:
agent_urlpatterns = [
    path('api/agent/register/',      agent_views.agent_register,     name='agent_register'),
    path('api/agent/heartbeat/',     agent_views.agent_heartbeat,    name='agent_heartbeat'),
    path('api/agent/scan/submit/',   agent_views.agent_submit_scan,  name='agent_submit_scan'),
    path('api/agent/results/',       agent_views.agent_post_results, name='agent_post_results'),
    path('api/agent/status/',        agent_views.agent_poll_commands, name='agent_poll_commands'),
]