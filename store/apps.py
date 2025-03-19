# store/apps.py
from django.apps import AppConfig
from django.conf import settings
from django.db.utils import OperationalError, ProgrammingError

class StoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'store'
    '''
    def ready(self):
        """
        This method is called when the application is fully loaded and ready to run.
        It runs every time the server is restarted.
        """
        
        try:
            # Import your model here to avoid circular imports
            from store.models import LandingPage  # Import the LandingPage model

            # Fetch all activated domains from the LandingPage model
            activated_domains = LandingPage.objects.filter(is_activated=True).values_list('domain_name', flat=True)

            # Add domains to CSRF_TRUSTED_ORIGINS and ALLOWED_HOSTS
            for domain in activated_domains:
                # Add https:// to the domain for CSRF_TRUSTED_ORIGINS
                domain_with_scheme = f'https://{domain}'
                if domain_with_scheme not in settings.CSRF_TRUSTED_ORIGINS:
                    settings.CSRF_TRUSTED_ORIGINS.append(domain_with_scheme)

                # Add domain to ALLOWED_HOSTS without the scheme
                if domain not in settings.ALLOWED_HOSTS:
                    settings.ALLOWED_HOSTS.append(domain)

        except (OperationalError, ProgrammingError) as e:
            # Handle cases where the database is not available (e.g., during initial setup or migrations)
            print(f"Could not fetch activated domains: {e}")'
    '''        