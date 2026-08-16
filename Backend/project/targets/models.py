from django.db import models

class Target(models.Model):
    TARGET_TYPE_CHOICES = [
        ('DOMAIN', 'DOMAIN'),
        ('IP', 'IP'),
        ('CIDR', 'CIDR'),
        ('URL', 'URL'),
        ('API', 'API'),
        ('REPOSITORY', 'REPOSITORY'),
    ]

    ENVIRONMENT_CHOICES = [
        ('LIVE', 'LIVE'),
        ('STAGING', 'STAGING'),
        ('DEVELOPMENT', 'DEVELOPMENT'),
        ('LOCAL', 'LOCAL'),
    ]

    STATUS_CHOICES = [
        ('ACTIVE', 'ACTIVE'),
        ('INACTIVE', 'INACTIVE'),
    ]

    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='targets')
    name = models.CharField(max_length=255)
    target_type = models.CharField(max_length=20, choices=TARGET_TYPE_CHOICES)
    value = models.CharField(max_length=255)
    environment = models.CharField(max_length=20, choices=ENVIRONMENT_CHOICES)
    scope = models.BooleanField(default=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    notes = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.target_type})"
