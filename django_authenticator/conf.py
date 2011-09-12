"""unifies django settings with an optional additional settings module
and default settings of this application"""
from django.conf import settings as django_settings
from multi_registry import MultiRegistry

settings = MultiRegistry(
    'django.conf.settings',
    'django_authenticator.default_settings'
)

extra_settings_path = getattr(django_settings, 'EXTRA_SETTINGS_MODULE', None)
if extra_settings_path:
    settings.insert(1, extra_settings_path)
