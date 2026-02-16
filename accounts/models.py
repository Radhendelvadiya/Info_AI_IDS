from django.db import models
from django.conf import settings

class UserProfile(models.Model):
    ROLE_CHOICES = [
        ("ADMIN", "Admin"),
        ("ANALYST", "SOC Analyst"),
        ("VIEWER", "Viewer"),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default="VIEWER"
    )

    def __str__(self):
        return f"{self.user} - {self.role}"
