import re
from django.conf import settings

class DynamicAllowedHostsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host().split(':')[0]  # Remove port if present
        if self.is_valid_host(host) and host not in settings.ALLOWED_HOSTS:
            settings.ALLOWED_HOSTS.append(host)
        return self.get_response(request)

    def is_valid_host(self, host):
        # Add your validation logic here
        # Example: Allow only specific domains or subdomains
        return re.match(r'^[a-zA-Z0-9.-]+\.ai$', host) is not None