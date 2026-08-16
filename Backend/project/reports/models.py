from django.db import models

class Report(models.Model):
    REPORT_TYPE_CHOICES = [
        ('EXECUTIVE', 'EXECUTIVE'),
        ('TECHNICAL', 'TECHNICAL'),
        ('NETWORK', 'NETWORK'),
        ('WEB', 'WEB'),
        ('API', 'API'),
        ('CODE', 'CODE'),
    ]

    STATUS_CHOICES = [
        ('READY', 'READY'),
        ('GENERATING', 'GENERATING'),
        ('FAILED', 'FAILED'),
    ]

    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='reports')
    name = models.CharField(max_length=255)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='READY')
    file = models.FileField(upload_to='reports/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.report_type} ({self.status})"
