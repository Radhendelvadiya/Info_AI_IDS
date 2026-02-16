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

