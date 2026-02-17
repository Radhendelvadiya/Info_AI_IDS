from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta
from functools import wraps

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


# ================================
# Permission Checker Decorator
# ================================
def admin_or_analyst_only(view_func):
    """Decorator to restrict access to admins and analysts only"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        try:
            from accounts.models import UserProfile
            user_profile = UserProfile.objects.get(user=request.user)
            if user_profile.role not in ["ADMIN", "ANALYST"]:
                return JsonResponse({
                    'ok': False, 
                    'error': 'Permission denied. Only admins and analysts can perform this action.'
                }, status=403)
        except UserProfile.DoesNotExist:
            return JsonResponse({
                'ok': False, 
                'error': 'User profile not found'
            }, status=403)
        except Exception as e:
            return JsonResponse({
                'ok': False, 
                'error': str(e)
            }, status=500)
        return view_func(request, *args, **kwargs)
    return wrapper


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
    try:
        from accounts.models import UserProfile
        user_profile = UserProfile.objects.get(user=request.user)
        user_role = user_profile.role
    except:
        user_role = "VIEWER"
    
    context = {
        'user_role': user_role,
        'can_modify_ips': user_role in ["ADMIN", "ANALYST"]
    }
    return render(request, 'dashboard.html', context)


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
        ],
        # Attack detections from AI/ML models
        "attack_detections": [
            {
                "attack_type": a.attack_type,
                "source_ip": a.source_ip,
                "severity": a.severity,
                "confidence_score": a.confidence_score,
                "ai_model": a.ai_model_used,
                "detected_at": a.detected_at.isoformat()
            }
            for a in __import__('intrusion_app').models.AttackDetection.objects.filter(is_active=True).order_by('-detected_at')[:20]
        ],
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
@admin_or_analyst_only
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
@admin_or_analyst_only
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


@login_required
@require_POST
@admin_or_analyst_only
def log_attack_detection(request):
    """Log AI/ML detected attack with confidence score"""
    try:
        import json
        data = json.loads(request.body)
        
        from .models import AttackDetection
        
        attack = AttackDetection.objects.create(
            attack_type=data.get('attack_type', 'Unknown'),
            source_ip=data.get('source_ip'),
            destination_ip=data.get('destination_ip'),
            port=data.get('port'),
            severity=data.get('severity', 'MEDIUM'),
            confidence_score=float(data.get('confidence_score', 0.0)),
            description=data.get('description', ''),
            ai_model_used=data.get('ai_model_used', 'Unknown')
        )
        
        return JsonResponse({
            'ok': True,
            'attack_id': attack.id,
            'message': f'Attack detected: {attack.attack_type}'
        })
    except Exception as e:
        return JsonResponse({
            'ok': False,
            'error': str(e)
        }, status=400)


@login_required
def get_attack_statistics(request):
    """Get attack detection statistics - accessible to all logged-in users"""
    from .models import AttackDetection
    from django.db.models import Count, Q
    from django.utils import timezone
    from datetime import timedelta
    
    # Get attacks from last 24 hours
    since = timezone.now() - timedelta(days=1)
    
    recent_attacks = AttackDetection.objects.filter(
        detected_at__gte=since,
        is_active=True
    )
    
    # Count by type
    attack_counts = recent_attacks.values('attack_type').annotate(count=Count('id')).order_by('-count')
    
    # Count by severity
    severity_counts = recent_attacks.values('severity').annotate(count=Count('id')).order_by('-count')
    
    # Top source IPs
    top_ips = recent_attacks.values('source_ip').annotate(count=Count('id')).order_by('-count')[:10]
    
    # Average confidence score
    avg_confidence = recent_attacks.aggregate(models.Avg('confidence_score'))['confidence_score__avg'] or 0.0
    
    return JsonResponse({
        'total_attacks_24h': recent_attacks.count(),
        'attack_types': list(attack_counts),
        'by_severity': list(severity_counts),
        'top_source_ips': list(top_ips),
        'average_confidence': round(avg_confidence, 2),
        'recent_attacks': [
            {
                'id': a.id,
                'attack_type': a.attack_type,
                'source_ip': a.source_ip,
                'severity': a.severity,
                'confidence_score': a.confidence_score,
                'ai_model': a.ai_model_used,
                'detected_at': a.detected_at.isoformat()
            }
            for a in recent_attacks.order_by('-detected_at')[:10]
        ]
    })


@login_required
def settings(request):
    """Settings page with role-based access"""
    try:
        from accounts.models import UserProfile
        user_profile = UserProfile.objects.get(user=request.user)
        user_role = user_profile.role
    except:
        user_role = "VIEWER"
    
    # Only ADMIN can access full settings
    if user_role not in ["ADMIN", "ANALYST"]:
        return render(request, 'settings_restricted.html', {'user_role': user_role})
    
    from .models import ModelMetric
    latest_metric = ModelMetric.objects.order_by('-trained_at').first()
    
    context = {
        'user_role': user_role,
        'can_train_models': user_role == "ADMIN",
        'latest_model_accuracy': latest_metric.accuracy * 100 if latest_metric else 0,
        'latest_model_date': latest_metric.trained_at if latest_metric else None,
    }
    
    return render(request, 'settings.html', context)


@login_required
@require_POST
@admin_or_analyst_only
def train_ml_model(request):
    """Train ML model on AI detection data - Admin only"""
    try:
        from accounts.models import UserProfile
        user_profile = UserProfile.objects.get(user=request.user)
        if user_profile.role != "ADMIN":
            return JsonResponse({
                'ok': False, 
                'error': 'Only admins can train models'
            }, status=403)
    except:
        pass
    
    try:
        import json
        data = json.loads(request.body)
        
        from .models import AttackDetection, ModelMetric
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder
        import numpy as np
        
        # Get training data
        attacks = AttackDetection.objects.filter(is_active=True)[:200]
        
        if attacks.count() < 10:
            return JsonResponse({
                'ok': False,
                'error': 'Not enough data for training (minimum 10 samples)'
            }, status=400)
        
        # Prepare training data
        X = []
        y = []
        
        severity_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        attack_type_encoder = LabelEncoder()
        
        attack_types = [a.attack_type for a in attacks]
        attack_type_encoder.fit(attack_types)
        
        for attack in attacks:
            # Features: confidence, severity, port (if exists)
            features = [
                attack.confidence_score,
                severity_map.get(attack.severity, 1),
                attack.port if attack.port else 0,
            ]
            X.append(features)
            y.append(attack_type_encoder.transform([attack.attack_type])[0])
        
        X = np.array(X)
        y = np.array(y)
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        
        # Calculate accuracy
        accuracy = model.score(X, y)
        
        # Save metrics
        metric = ModelMetric.objects.create(accuracy=accuracy)
        
        return JsonResponse({
            'ok': True,
            'message': 'Model trained successfully',
            'accuracy': round(accuracy * 100, 2),
            'samples_used': len(X),
            'model_timestamp': metric.trained_at.isoformat()
        })
    
    except Exception as e:
        return JsonResponse({
            'ok': False,
            'error': str(e)
        }, status=500)


@login_required
def get_model_status(request):
    """Get current ML model status"""
    from .models import ModelMetric
    
    latest_metric = ModelMetric.objects.order_by('-trained_at').first()
    
    return JsonResponse({
        'has_model': latest_metric is not None,
        'accuracy': round(latest_metric.accuracy * 100, 2) if latest_metric else 0,
        'trained_at': latest_metric.trained_at.isoformat() if latest_metric else None,
        'model_age_hours': (timezone.now() - latest_metric.trained_at).total_seconds() / 3600 if latest_metric else None
    })




