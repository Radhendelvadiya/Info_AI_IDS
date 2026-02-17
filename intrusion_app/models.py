from django.db import models

# Create your models here.
from django.db import models

class Alert(models.Model):
    attack_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.attack_type


class TrafficLog(models.Model):
    bytes_count = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)


class ModelMetric(models.Model):
    accuracy = models.FloatField()
    trained_at = models.DateTimeField(auto_now_add=True)


class BlockedIP(models.Model):
    ip = models.CharField(max_length=64)
    reason = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class AttackDetection(models.Model):
    """Track AI/ML detected attacks with confidence scores"""
    ATTACK_TYPE_CHOICES = [
        ("Port Scan", "Port Scan"),
        ("Brute Force", "Brute Force Attack"),
        ("DDoS", "DDoS Attack"),
        ("Malware", "Malware Detection"),
        ("Anomaly", "AI Anomaly"),
        ("Suspicious Port", "Suspicious Port Access"),
        ("SQL Injection", "SQL Injection"),
        ("XSS", "Cross-Site Scripting"),
        ("Unknown", "Unknown Attack"),
    ]
    
    SEVERITY_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]
    
    attack_type = models.CharField(max_length=50, choices=ATTACK_TYPE_CHOICES)
    source_ip = models.CharField(max_length=64, null=True, blank=True)
    destination_ip = models.CharField(max_length=64, null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="MEDIUM")
    confidence_score = models.FloatField(default=0.0)  # 0.0 to 1.0 (ML confidence)
    description = models.TextField(blank=True)
    ai_model_used = models.CharField(max_length=100, blank=True)  # Which ML model detected it
    detected_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.attack_type} from {self.source_ip} - {self.severity}"

