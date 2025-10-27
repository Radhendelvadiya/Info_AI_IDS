from django.shortcuts import render
from .models import Alert
from django.db.models import Count

def dashboard(request):
    # Recent alerts
    recent_alerts = Alert.objects.all().order_by('-timestamp')[:10]

    # Attack distribution as a list of dicts
    attack_distribution = Alert.objects.values('attack_type').annotate(count=Count('attack_type'))

    # Alerts over time
    alerts_over_time = Alert.objects.extra({'day': "date(timestamp)"}).values('day').annotate(count=Count('id')).order_by('day')

    context = {
        'recent_alerts': recent_alerts,
        'attack_distribution': attack_distribution,
        'alerts_over_time': alerts_over_time,
    }

    return render(request, 'dashboard.html', context)
