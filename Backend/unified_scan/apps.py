from django.apps import AppConfig


class UnifiedScanConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'unified_scan'
    verbose_name = 'AttackLens Unified Scan Orchestrator'
