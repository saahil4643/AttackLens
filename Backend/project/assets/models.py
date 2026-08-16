from django.db import models

class Asset(models.Model):
    ASSET_TYPE_CHOICES = [
        ('DOMAIN', 'DOMAIN'),
        ('IP', 'IP'),
        ('SUBDOMAIN', 'SUBDOMAIN'),
        ('HOST', 'HOST'),
        ('URL', 'URL'),
        ('API', 'API'),
        ('PORT', 'PORT'),
        ('SERVICE', 'SERVICE'),
    ]

    STATUS_CHOICES = [
        ('SAFE', 'SAFE'),
        ('WARNING', 'WARNING'),
        ('COMPROMISED', 'COMPROMISED'),
    ]

    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='assets')
    target = models.ForeignKey('targets.Target', on_delete=models.SET_NULL, null=True, blank=True, related_name='assets')
    asset_type = models.CharField(max_length=20, choices=ASSET_TYPE_CHOICES)
    value = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='SAFE')
    metadata = models.JSONField(default=dict, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.value} ({self.asset_type})"
