# your_app/management/commands/update_hosts.py

from django.core.management.base import BaseCommand
from django.conf import settings
import os

class Command(BaseCommand):
    help = 'Update ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS'

    def add_arguments(self, parser):
        parser.add_argument('host', type=str, help='Host to add to ALLOWED_HOSTS')
        parser.add_argument('origin', type=str, help='Origin to add to CSRF_TRUSTED_ORIGINS')

    def handle(self, *args, **kwargs):
        host = kwargs['host']
        origin = kwargs['origin']

        # Add to ALLOWED_HOSTS
        allowed_hosts = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
        if host not in allowed_hosts:
            allowed_hosts.append(host)
            settings.ALLOWED_HOSTS = allowed_hosts
            self.stdout.write(self.style.SUCCESS(f'Host {host} added to ALLOWED_HOSTS'))

        # Add to CSRF_TRUSTED_ORIGINS
        csrf_trusted_origins = os.getenv('CSRF_TRUSTED_ORIGINS', 'http://localhost').split(',')
        if origin not in csrf_trusted_origins:
            csrf_trusted_origins.append(origin)
            settings.CSRF_TRUSTED_ORIGINS = csrf_trusted_origins
            self.stdout.write(self.style.SUCCESS(f'Origin {origin} added to CSRF_TRUSTED_ORIGINS'))
