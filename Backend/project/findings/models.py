from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from decimal import Decimal

class Finding(models.Model):
    CATEGORY_CHOICES = [
        ('NETWORK', 'NETWORK'),
        ('WEB', 'WEB'),
        ('API', 'API'),
        ('AUTHENTICATION', 'AUTHENTICATION'),
        ('AUTHORIZATION', 'AUTHORIZATION'),
        ('CONFIGURATION', 'CONFIGURATION'),
        ('CRYPTOGRAPHY', 'CRYPTOGRAPHY'),
        ('INJECTION', 'INJECTION'),
        ('DISCLOSURE', 'DISCLOSURE'),
        ('SECRETS', 'SECRETS'),
        ('DEPENDENCY', 'DEPENDENCY'),
        ('SOURCE_CODE', 'SOURCE_CODE'),
        ('TLS', 'TLS'),
        ('OSINT', 'OSINT'),
        ('OTHER', 'OTHER'),
    ]

    SEVERITY_CHOICES = [
        ('CRITICAL', 'CRITICAL'),
        ('HIGH', 'HIGH'),
        ('MEDIUM', 'MEDIUM'),
        ('LOW', 'LOW'),
        ('INFO', 'INFO'),
    ]

    CONFIDENCE_CHOICES = [
        ('CONFIRMED', 'CONFIRMED'),
        ('HIGH', 'HIGH'),
        ('MEDIUM', 'MEDIUM'),
        ('LOW', 'LOW'),
    ]

    STATUS_CHOICES = [
        ('OPEN', 'OPEN'),
        ('CONFIRMED', 'CONFIRMED'),
        ('FALSE_POSITIVE', 'FALSE_POSITIVE'),
        ('ACCEPTED_RISK', 'ACCEPTED_RISK'),
        ('RESOLVED', 'RESOLVED'),
    ]

    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='findings')
    assessment = models.ForeignKey('projects.Assessment', on_delete=models.SET_NULL, null=True, blank=True, related_name='findings')
    scan_job = models.ForeignKey('scans.ScanJob', on_delete=models.SET_NULL, null=True, blank=True, related_name='findings')
    testing_module = models.ForeignKey('core.TestingModule', on_delete=models.SET_NULL, null=True, blank=True, related_name='findings')
    asset = models.ForeignKey('assets.Asset', on_delete=models.SET_NULL, null=True, blank=True, related_name='findings')
    
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='OTHER')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='INFO')
    confidence = models.CharField(max_length=20, choices=CONFIDENCE_CHOICES, default='MEDIUM')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    cvss_score = models.DecimalField(
        max_digits=3, 
        decimal_places=1, 
        default=0.0, 
        validators=[MinValueValidator(Decimal('0.0')), MaxValueValidator(Decimal('10.0'))]
    )
    cwe = models.CharField(max_length=50, blank=True, default='')
    remediation = models.TextField(blank=True, default='')
    references = models.JSONField(default=list, blank=True)
    fingerprint = models.CharField(max_length=64, unique=True, null=True, blank=True, db_index=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} ({self.severity})"


class FindingOccurrence(models.Model):
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name='occurrences')
    scan_job = models.ForeignKey('scans.ScanJob', on_delete=models.CASCADE, related_name='finding_occurrences')
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"Occurrence of Finding {self.finding.id} in Job {self.scan_job.id}"


class FindingEvidence(models.Model):
    EVIDENCE_TYPE_CHOICES = [
        ('HTTP_REQUEST', 'HTTP_REQUEST'),
        ('HTTP_RESPONSE', 'HTTP_RESPONSE'),
        ('NETWORK', 'NETWORK'),
        ('SOURCE_CODE', 'SOURCE_CODE'),
        ('CONFIGURATION', 'CONFIGURATION'),
        ('COMMAND_OUTPUT', 'COMMAND_OUTPUT'),
        ('SCREENSHOT', 'SCREENSHOT'),
        ('TEXT', 'TEXT'),
        ('OTHER', 'OTHER'),
    ]

    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name='evidence_records')
    evidence_type = models.CharField(max_length=30, choices=EVIDENCE_TYPE_CHOICES, default='OTHER')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')
    request = models.JSONField(default=dict, blank=True)
    response = models.JSONField(default=dict, blank=True)
    location = models.TextField(blank=True, default='')
    payload = models.TextField(blank=True, default='')
    code_snippet = models.TextField(blank=True, default='')
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Evidence {self.id} ({self.evidence_type}) for Finding {self.finding.id}"
