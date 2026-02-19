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


# ================================
# USER MANAGEMENT VIEWS
# ================================

@login_required
@admin_or_analyst_only
def user_management(request):
    """Display user management page"""
    from accounts.models import UserProfile
    
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        context = {
            'user': request.user,
            'user_role': user_profile.role
        }
        return render(request, 'user_management.html', context)
    except UserProfile.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'User profile not found'}, status=403)


@login_required
@admin_or_analyst_only
def get_users(request):
    """Get list of all users with their roles and auth method"""
    from accounts.models import UserProfile
    from django.contrib.auth.models import User
    
    try:
        users = User.objects.all().select_related('userprofile')
        users_data = []
        
        for user in users:
            try:
                role = user.userprofile.role
                auth_method = user.userprofile.auth_method
            except UserProfile.DoesNotExist:
                role = "VIEWER"
                auth_method = "email"
            
            users_data.append({
                'id': user.id,
                'email': user.email,
                'role': role,
                'auth_method': auth_method
            })
        
        return JsonResponse({
            'ok': True,
            'users': users_data
        })
    except Exception as e:
        return JsonResponse({
            'ok': False,
            'error': str(e)
        }, status=500)


@login_required
@admin_or_analyst_only
@require_POST
def add_user(request):
    """Create a new user with specified role"""
    from accounts.models import UserProfile
    from django.contrib.auth.models import User
    
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        email = request.POST.get('email', '').strip().lower()
        role = request.POST.get('role', 'VIEWER').upper()
        
        # Validate input
        if not email:
            return JsonResponse({
                'ok': False,
                'error': 'Email is required'
            }, status=400)
        
        # Basic email format validation
        if '@' not in email or '.' not in email:
            return JsonResponse({
                'ok': False,
                'error': 'Invalid email format'
            }, status=400)
        
        # Analyst can't create Admin users
        if user_profile.role == 'ANALYST' and role == 'ADMIN':
            return JsonResponse({
                'ok': False,
                'error': 'You can only assign Analyst and Viewer roles'
            }, status=403)
        
        # Validate role
        if role not in ['ADMIN', 'ANALYST', 'VIEWER']:
            return JsonResponse({
                'ok': False,
                'error': 'Invalid role. Must be ADMIN, ANALYST, or VIEWER'
            }, status=400)
        
        # Check if user already exists (case-insensitive)
        if User.objects.filter(email__iexact=email).exists():
            return JsonResponse({
                'ok': False,
                'error': 'An account with this email already exists. Please use a different email.'
            }, status=400)
        
        # Create user (username = sanitized email)
        username_base = email.split('@')[0]
        username = username_base
        counter = 1
        
        # Ensure unique username by appending counter if needed
        while User.objects.filter(username__iexact=username).exists():
            username = f"{username_base}_{counter}"
            counter += 1
        
        # Create user with a secure random password. Some custom managers may not
        # implement `make_random_password`, so use it if available or fall back
        # to the `secrets` module.
        import secrets
        make_pw = getattr(User.objects, 'make_random_password', None)
        if callable(make_pw):
            random_password = make_pw()
        else:
            random_password = secrets.token_urlsafe(12)

        # Create user
        new_user = User.objects.create_user(
            username=username,
            email=email,
            password=random_password
        )
        
        # Create or update user profile with role
        user_profile_obj, created = UserProfile.objects.get_or_create(
            user=new_user,
            defaults={'role': role}
        )
        if not created:
            user_profile_obj.role = role
            user_profile_obj.save()
        
        return JsonResponse({
            'ok': True,
            'message': f'User {email} created with role {role}',
            'user_id': new_user.id
        })
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


@login_required
@admin_or_analyst_only
@require_POST
def manage_user(request):
    """Update user role"""
    from accounts.models import UserProfile
    from django.contrib.auth.models import User
    
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        user_id = request.POST.get('user_id')
        new_role = request.POST.get('role', '').upper()
        
        if not user_id or not new_role:
            return JsonResponse({
                'ok': False,
                'error': 'Missing user_id or role'
            }, status=400)
        
        # Validate role
        if new_role not in ['ADMIN', 'ANALYST', 'VIEWER']:
            return JsonResponse({
                'ok': False,
                'error': 'Invalid role'
            }, status=400)
        
        # Get target user
        target_user = User.objects.get(id=user_id)
        target_profile = UserProfile.objects.get(user=target_user)
        
        # Analyst can't assign Admin role
        if user_profile.role == 'ANALYST' and new_role == 'ADMIN':
            return JsonResponse({
                'ok': False,
                'error': 'You can only assign Analyst and Viewer roles'
            }, status=403)
        
        # Analyst can't change another Analyst's role
        if user_profile.role == 'ANALYST' and target_profile.role == 'ANALYST':
            return JsonResponse({
                'ok': False,
                'error': 'You cannot change roles of other Analysts'
            }, status=403)
        
        # Update role
        target_profile.role = new_role
        target_profile.save()

        # Optionally update password if provided
        new_password = request.POST.get('password', '')
        if new_password:
            target_user.set_password(new_password)
            target_user.save()
        
        return JsonResponse({
            'ok': True,
            'message': f'User role updated to {new_role}'
        })
    except User.DoesNotExist:
        return JsonResponse({
            'ok': False,
            'error': 'User not found'
        }, status=404)
    except UserProfile.DoesNotExist:
        return JsonResponse({
            'ok': False,
            'error': 'User profile not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'ok': False,
            'error': str(e)
        }, status=500)


@login_required
@admin_or_analyst_only
@require_POST
def remove_user(request):
    """Delete a user"""
    from accounts.models import UserProfile
    from django.contrib.auth.models import User
    
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        user_id = request.POST.get('user_id')
        
        if not user_id:
            return JsonResponse({
                'ok': False,
                'error': 'user_id is required'
            }, status=400)
        
        # Can't delete yourself
        if int(user_id) == request.user.id:
            return JsonResponse({
                'ok': False,
                'error': 'You cannot delete your own account'
            }, status=400)
        
        # Get target user
        target_user = User.objects.get(id=user_id)
        target_profile = UserProfile.objects.get(user=target_user)
        
        # Analyst can only delete Viewer users
        if user_profile.role == 'ANALYST':
            if target_profile.role != 'VIEWER':
                return JsonResponse({
                    'ok': False,
                    'error': 'You can only delete Viewer users'
                }, status=403)
        
        # Delete user
        target_user.delete()
        
        return JsonResponse({
            'ok': True,
            'message': 'User deleted successfully'
        })
    except User.DoesNotExist:
        return JsonResponse({
            'ok': False,
            'error': 'User not found'
        }, status=404)
    except UserProfile.DoesNotExist:
        return JsonResponse({
            'ok': False,
            'error': 'User profile not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'ok': False,
            'error': str(e)
        }, status=500)




