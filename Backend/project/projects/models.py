from django.db import models

class Project(models.Model):
    STATUS_CHOICES = [
        ('ACTIVE', 'ACTIVE'),
        ('ARCHIVED', 'ARCHIVED'),
        ('COMPLETED', 'COMPLETED'),
    ]

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Added fields for source ZIP / live URL intake
    live_url = models.URLField(max_length=500, blank=True, default='')
    source_archive = models.FileField(upload_to='source_archives/', blank=True, null=True)
    source_archive_name = models.CharField(max_length=255, blank=True, default='')
    source_archive_size = models.BigIntegerField(null=True, blank=True)
    source_uploaded_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name


class Assessment(models.Model):
    STATUS_CHOICES = [
        ('DRAFT', 'DRAFT'),
        ('READY', 'READY'),
        ('QUEUED', 'QUEUED'),
        ('RUNNING', 'RUNNING'),
        ('COMPLETED', 'COMPLETED'),
        ('FAILED', 'FAILED'),
        ('CANCELLED', 'CANCELLED'),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='assessments')
    name = models.CharField(max_length=255)
    live_url = models.URLField(max_length=500, blank=True, default='')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='DRAFT')
    selected_modules = models.JSONField(default=list, blank=True)  # List of TestingModule keys (strings)
    configuration = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} - {self.project.name} ({self.status})"


class AssessmentScope(models.Model):
    TARGET_TYPE_CHOICES = [
        ('LIVE_URL', 'LIVE_URL'),
        ('DOMAIN', 'DOMAIN'),
        ('IP', 'IP'),
        ('CIDR', 'CIDR'),
        ('API', 'API'),
        ('SOURCE_CODE', 'SOURCE_CODE'),
    ]

    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='scopes')
    target_type = models.CharField(max_length=20, choices=TARGET_TYPE_CHOICES)
    target = models.CharField(max_length=500)
    included = models.BooleanField(default=True)
    notes = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        action = "Include" if self.included else "Exclude"
        return f"{action} - {self.target_type}: {self.target}"
