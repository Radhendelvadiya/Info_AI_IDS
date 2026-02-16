"""
ASGI config for ai_ids project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ai_ids.settings')

import intrusion_app.routing

application = ProtocolTypeRouter({
	'http': get_asgi_application(),
	'websocket': URLRouter(intrusion_app.routing.websocket_urlpatterns),
})
