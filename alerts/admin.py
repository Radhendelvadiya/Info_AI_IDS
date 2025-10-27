from django.contrib import admin
from .models import Alert

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'source_ip', 'attack_type', 'severity')
    list_filter = ('attack_type', 'severity')
    search_fields = ('source_ip',)
