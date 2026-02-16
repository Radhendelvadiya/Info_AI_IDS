from django.apps import AppConfig


class IntrusionAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'intrusion_app'


class CoreConfig(AppConfig):
    name = 'core'

    def ready(self):
        from infoids.network_monitor import start_background
        start_background()