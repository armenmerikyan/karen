# middleware.py
import re
from django.conf import settings

class DynamicSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host().split(':')[0]  # Remove port if present
        if self.is_valid_host(host):
            if host not in settings.ALLOWED_HOSTS:
                settings.ALLOWED_HOSTS.append(host)
            origin = request.headers.get('Origin')
            if origin and self.is_valid_origin(origin):
                if origin not in settings.CSRF_TRUSTED_ORIGINS:
                    settings.CSRF_TRUSTED_ORIGINS.append(origin)
        return self.get_response(request)

    def is_valid_host(self, host):
        # Add your validation logic here
        return re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', host) is not None

    def is_valid_origin(self, origin):
        # Add your validation logic here
        return re.match(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', origin) is not None