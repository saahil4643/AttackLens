from django.db import models

class Scan(models.Model):
    SCAN_TYPE_CHOICES = [
        ('RECON', 'RECON'),
        ('NETWORK', 'NETWORK'),
        ('WEB', 'WEB'),
        ('API', 'API'),
        ('CODE', 'CODE'),
        ('FULL', 'FULL'),
    ]

    STATUS_CHOICES = [
        ('QUEUED', 'QUEUED'),
        ('RUNNING', 'RUNNING'),
        ('COMPLETED', 'COMPLETED'),
        ('FAILED', 'FAILED'),
        ('CANCELLED', 'CANCELLED'),
    ]

    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='scans')
    name = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='QUEUED')
    progress = models.IntegerField(default=0)
    configuration = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.scan_type} ({self.status})"


class ScanJob(models.Model):
    STATUS_CHOICES = [
        ('QUEUED', 'QUEUED'),
        ('RUNNING', 'RUNNING'),
        ('COMPLETED', 'COMPLETED'),
        ('FAILED', 'FAILED'),
        ('CANCELLED', 'CANCELLED'),
        ('SKIPPED', 'SKIPPED'),
    ]

    assessment = models.ForeignKey('projects.Assessment', on_delete=models.CASCADE, related_name='jobs')
    testing_module = models.ForeignKey('core.TestingModule', on_delete=models.CASCADE, related_name='jobs')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='QUEUED')
    progress = models.IntegerField(default=0)  # Min 0, Max 100 enforced via validator or view validation
    priority = models.IntegerField(default=10)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True, default='')
    result = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Job {self.id} - {self.testing_module.name} ({self.status})"

    def save(self, *args, **kwargs):
        if self.progress is not None:
            self.progress = max(0, min(100, int(self.progress)))
            
        if self.pk:
            # Fetch the current state from the database
            original = ScanJob.objects.get(pk=self.pk)
            if original.status != self.status:
                from scans.services.execution_service import ExecutionService
                ExecutionService.validate_transition(original.status, self.status)
                
        super().save(*args, **kwargs)



class ModuleExecution(models.Model):
    ENV_CHOICES = [
        ('LIVE', 'LIVE'),
        ('LOCAL', 'LOCAL'),
        ('SANDBOX', 'SANDBOX'),
    ]

    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='executions')
    module_key = models.CharField(max_length=100)
    execution_environment = models.CharField(max_length=20, choices=ENV_CHOICES)
    status = models.CharField(max_length=50)
    result = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Execution {self.id} - {self.module_key} ({self.execution_environment})"


class ExecutionLog(models.Model):
    LEVEL_CHOICES = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARNING', 'WARNING'),
        ('ERROR', 'ERROR'),
    ]

    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='logs')
    level = models.CharField(max_length=20, choices=LEVEL_CHOICES, default='INFO')
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.level}: {self.message[:50]}"
