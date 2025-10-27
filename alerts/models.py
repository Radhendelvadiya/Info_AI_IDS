from django.db import models

SEVERITY_CHOICES = [
    ('Low', 'Low'),
    ('Medium', 'Medium'),
    ('High', 'High'),
    ('Critical', 'Critical'),
]

ATTACK_CHOICES = [
    ('DoS', 'DoS'),
    ('Probe', 'Probe'),
    ('R2L', 'R2L'),
    ('U2R', 'U2R'),
    ('Normal', 'Normal'),
]

class Alert(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    attack_type = models.CharField(max_length=20, choices=ATTACK_CHOICES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)

    def __str__(self):
        return f"{self.source_ip} - {self.attack_type} ({self.severity})"
