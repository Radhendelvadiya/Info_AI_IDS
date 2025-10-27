from django import template

register = template.Library()

@register.filter
def pluck(queryset, key):
    """
    Extracts a list of values for a specific key from a queryset.
    Usage: {{ queryset|pluck:'field_name' }}
    """
    return [item[key] for item in queryset]
