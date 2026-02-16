from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta

from .infoids.network_monitor import get_dashboard_data
from .models import Alert, TrafficLog
from .ai.predict import predict_intrusion
from intrusion_app.ml.ids_model import predict_packet
import random
from django.db.models import Count, Sum
from django.db.models.functions import TruncHour
from django.contrib.auth.decorators import login_required
from random import randint
from django.views.decorators.http import require_POST
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import platform, subprocess


# -------------------------------
# GLOBAL LIVE STATS (Memory Store)
# -------------------------------
LIVE_STATS = {
    "alerts": 2,
    "traffic": 1.5,
}




# Create your views here.

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')


def dashboard_data(request):
    data = get_dashboard_data()

    attack_distribution = [
        {"attack_type": "AI Anomaly", "count": sum(1 for a in data["alerts"] if a.get("type")=="AI Anomaly")},
        {"attack_type": "Port Scan", "count": sum(1 for a in data["alerts"] if a.get("type")=="Port Scan")},
        {"attack_type": "Suspicious Port", "count": sum(1 for a in data["alerts"] if a.get("type")=="Suspicious Port Access")},
    ]

    # Pull latest model accuracy if available
    try:
        from .models import ModelMetric
        metric = ModelMetric.objects.order_by('-trained_at').first()
        accuracy = round(metric.accuracy * 100, 2) if metric else 0
    except Exception:
        accuracy = 0

    return JsonResponse({
        "active_alerts": data["active_alerts"],
        "traffic_gb": data["traffic_gb"],
        "accuracy": accuracy,
        "uptime": 99.9,
        "attack_distribution": attack_distribution,
        "alerts_over_time": [
            {"hour": "Now", "count": data["active_alerts"]}
        ],
        # Provide recent alerts and blocked IPs for dashboard panels
        "recent_alerts": [
            {"type": a.get('type'), "source": a.get('source'), "timestamp": a.get('timestamp')} for a in data.get('alerts', [])
        ],
        "blocked_ips": [
            {"ip": b.ip, "reason": b.reason, "created_at": b.created_at.isoformat()} for b in __import__('intrusion_app').models.BlockedIP.objects.order_by('-created_at')[:10]
        ]
        ,
        "os_blocking_enabled": getattr(__import__('django.conf').conf.settings, 'IDS_ENABLE_OS_BLOCKING', False)
    })

def ai_check(request):
    data = get_dashboard_data()
    prediction = "ATTACK" if data["active_alerts"] > 0 else "SAFE"

    return JsonResponse({
        "prediction": prediction,
        "alerts": data["active_alerts"],
        "traffic": data["traffic_gb"]
    })


@login_required
@require_POST
def block_ip(request):
    """Create a BlockedIP entry for the provided `ip` POST param."""
    ip = request.POST.get('ip')
    reason = request.POST.get('reason', 'manual')
    if not ip:
        return JsonResponse({'ok': False, 'error': 'missing ip'}, status=400)

    from .models import BlockedIP
    obj, created = BlockedIP.objects.get_or_create(ip=ip, defaults={'reason': reason})

    # Optional OS-level block: only allow for superusers to prevent abuse
    if getattr(settings, 'IDS_ENABLE_OS_BLOCKING', False):
        if not request.user.is_superuser:
            return JsonResponse({'ok': False, 'error': 'admin required for OS blocking'}, status=403)
        try:
            system = platform.system().lower()
            if system == 'windows':
                rule_name = f"InfoIDS Block {ip}"
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=%s' % rule_name, 'dir=in', 'action=block', f'remoteip={ip}'
                ]
                subprocess.run(cmd, check=False)
            else:
                cmd = ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP']
                subprocess.run(cmd, check=False)
        except Exception as e:
            return JsonResponse({'ok': False, 'error': str(e)}, status=500)

    return JsonResponse({'ok': True, 'created': created, 'ip': obj.ip})


@login_required
@require_POST
def unblock_ip(request):
    """Remove BlockedIP entry for provided `ip` POST param."""
    ip = request.POST.get('ip')
    if not ip:
        return JsonResponse({'ok': False, 'error': 'missing ip'}, status=400)

    from .models import BlockedIP
    deleted, _ = BlockedIP.objects.filter(ip=ip).delete()

    if getattr(settings, 'IDS_ENABLE_OS_BLOCKING', False):
        if not request.user.is_superuser:
            return JsonResponse({'ok': False, 'error': 'admin required for OS blocking'}, status=403)
        try:
            system = platform.system().lower()
            if system == 'windows':
                rule_name = f"InfoIDS Block {ip}"
                cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=%s' % rule_name]
                subprocess.run(cmd, check=False)
            else:
                cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
                subprocess.run(cmd, check=False)
        except Exception as e:
            return JsonResponse({'ok': False, 'error': str(e)}, status=500)

    return JsonResponse({'ok': True, 'deleted': deleted})




