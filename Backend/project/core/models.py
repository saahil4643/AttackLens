from django.db import models

class TestingModule(models.Model):
    key = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    category = models.CharField(max_length=50)  # RECON, NETWORK, WEB, API, CODE, SUPPLY_CHAIN, EXPOSURE
    version = models.CharField(max_length=20, default='1.0.0')
    enabled = models.BooleanField(default=True)
    requires_live_url = models.BooleanField(default=False)
    requires_source_code = models.BooleanField(default=False)
    requires_authentication = models.BooleanField(default=False)
    supports_live_testing = models.BooleanField(default=True)
    supports_local_testing = models.BooleanField(default=True)
    configuration_schema = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} [{self.category}]"
