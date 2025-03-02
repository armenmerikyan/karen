# store/middleware.py
from django.conf import settings

class DynamicAllowedHostsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host().split(':')[0]  # Remove port if present
        if host not in settings.ALLOWED_HOSTS:
            settings.ALLOWED_HOSTS.append(host)
        return self.get_response(request)