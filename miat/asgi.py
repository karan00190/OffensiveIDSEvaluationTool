# miat/asgi.py — REPLACE your existing asgi.py with this
import os
import django
from django.core.asgi           import get_asgi_application
from channels.routing           import ProtocolTypeRouter, URLRouter
from channels.auth              import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'miat.settings')
django.setup()

from scanner.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    # All regular HTTP → Django views as normal
    'http': get_asgi_application(),

    # WebSocket → Django Channels consumers
    'websocket': AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(websocket_urlpatterns)
        )
    ),
})