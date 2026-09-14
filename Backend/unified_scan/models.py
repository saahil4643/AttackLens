import uuid
from django.db import models
from django.utils import timezone


class UnifiedScanRecord(models.Model):
    """
    Persistent model representing a Unified Security Scan across multiple security engines.
    """
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("RUNNING", "Running"),
        ("COMPLETED", "Completed"),
        ("FAILED", "Failed"),
        ("ABORTED", "Aborted"),
    ]

    PROFILE_CHOICES = [
        ("quick", "Quick Recon"),
        ("standard", "Standard Balanced"),
        ("deep", "Deep Pentest"),
    ]

    INTENSITY_CHOICES = [
        ("low", "Low"),
        ("normal", "Normal"),
        ("aggressive", "Aggressive"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target = models.CharField(max_length=512, help_text="Target URL, hostname, or IP address")
    cleaned_target = models.CharField(max_length=256, blank=True, default="")
    resolved_ip = models.CharField(max_length=128, blank=True, default="")

    codebase_source_type = models.CharField(max_length=32, default="path", help_text="'path' or 'zip'")
    codebase_path = models.CharField(max_length=1024, blank=True, default="")
    codebase_zip_name = models.CharField(max_length=256, blank=True, default="")

    scan_profile = models.CharField(max_length=32, choices=PROFILE_CHOICES, default="standard")
    intensity = models.CharField(max_length=32, choices=INTENSITY_CHOICES, default="normal")
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="PENDING", db_index=True)
    
    progress_percent = models.IntegerField(default=0)
    current_module_id = models.CharField(max_length=64, blank=True, default="")
    
    overall_score = models.IntegerField(default=100)
    score_grade = models.CharField(max_length=8, default="A")
    risk_rating = models.CharField(max_length=64, default="Low Risk")

    active_modules = models.JSONField(default=list, help_text="List of active module IDs requested")
    findings_summary = models.JSONField(
        default=dict,
        help_text="Count of critical, high, medium, low, info findings"
    )
    module_statuses = models.JSONField(
        default=dict,
        help_text="Per-module execution state (pending, running, completed, failed, duration, steps)"
    )
    module_results = models.JSONField(
        default=dict,
        help_text="Full results dictionary returned by each module"
    )
    findings = models.JSONField(
        default=list,
        help_text="Aggregated and standardized list of security findings"
    )
    logs = models.JSONField(
        default=list,
        help_text="Ordered log entries emitted during orchestration"
    )
    error_message = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Unified Scan Record"
        verbose_name_plural = "Unified Scan Records"

    def __str__(self):
        return f"Unified Scan [{self.id}] - {self.target} ({self.status})"

    def to_dict(self, include_raw_results: bool = True):
        data = {
            "id": str(self.id),
            "target": self.target,
            "cleaned_target": self.cleaned_target,
            "resolved_ip": self.resolved_ip,
            "codebase_source_type": self.codebase_source_type,
            "codebase_path": self.codebase_path,
            "codebase_zip_name": self.codebase_zip_name,
            "scan_profile": self.scan_profile,
            "intensity": self.intensity,
            "status": self.status,
            "progress_percent": self.progress_percent,
            "current_module_id": self.current_module_id,
            "overall_score": self.overall_score,
            "score_grade": self.score_grade,
            "risk_rating": self.risk_rating,
            "active_modules": self.active_modules,
            "findings_summary": self.findings_summary or {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0
            },
            "module_statuses": self.module_statuses,
            "findings": self.findings,
            "logs": self.logs,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
        if include_raw_results:
            data["module_results"] = self.module_results
        return data


class Finding(models.Model):
    """
    Unified Security Finding Model.
    Standardized entity consolidating findings from all 9 AttackLens security engines.
    """
    SEVERITY_CHOICES = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Informational"),
    ]

    CONFIDENCE_CHOICES = [
        ("certain", "Certain"),
        ("firm", "Firm"),
        ("tentative", "Tentative"),
    ]

    STATUS_CHOICES = [
        ("open", "Open"),
        ("confirmed", "Confirmed"),
        ("remediated", "Remediated"),
        ("accepted", "Accepted Risk"),
        ("false_positive", "False Positive"),
    ]

    MODULE_CHOICES = [
        ("ports", "Port & Network Discovery"),
        ("http", "HTTP Detection & Header Audit"),
        ("endpoints", "Endpoint & Route Discovery"),
        ("attack-surface", "Web Application & Form Analysis"),
        ("fingerprint", "Technology Fingerprinting"),
        ("tls", "TLS / SSL Security Analysis"),
        ("security-config", "Security Configuration Audit"),
        ("api-analysis", "API Security & Deep Analysis"),
        ("codebase-analysis", "Codebase Security (SAST & Secrets)"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(
        UnifiedScanRecord,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_findings"
    )

    title = models.CharField(max_length=256, db_index=True)
    description = models.TextField()
    severity = models.CharField(max_length=32, choices=SEVERITY_CHOICES, default="medium", db_index=True)
    confidence = models.CharField(max_length=32, choices=CONFIDENCE_CHOICES, default="firm")
    cvss_score = models.FloatField(default=0.0)
    cwe = models.CharField(max_length=64, blank=True, default="", db_index=True)

    source_module = models.CharField(max_length=64, choices=MODULE_CHOICES, db_index=True)
    source_module_name = models.CharField(max_length=128, blank=True, default="")

    target = models.CharField(max_length=512, db_index=True, help_text="Target host, URL, IP or repo")
    location = models.CharField(max_length=512, blank=True, default="", help_text="Specific asset/endpoint/file/port")

    evidence = models.JSONField(default=dict, help_text="Structured proof, banners, or code context")
    request_data = models.TextField(blank=True, default="")
    response_data = models.TextField(blank=True, default="")

    remediation = models.TextField(blank=True, default="")
    references = models.JSONField(default=list, help_text="List of reference URLs (CVE, OWASP, CWE)")

    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default="open", db_index=True)
    status_note = models.TextField(blank=True, default="")

    # Deduplication fingerprint hash (SHA-256 of module + target + location + cwe + title)
    fingerprint_hash = models.CharField(max_length=64, unique=True, db_index=True)
    occurrence_count = models.IntegerField(default=1)

    first_seen = models.DateTimeField(default=timezone.now, db_index=True)
    last_seen = models.DateTimeField(default=timezone.now, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-last_seen", "-cvss_score"]
        verbose_name = "Security Finding"
        verbose_name_plural = "Security Findings"

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title} ({self.source_module}) on {self.target}"

    def to_dict(self):
        return {
            "id": str(self.id),
            "scanId": str(self.scan.id) if self.scan else None,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "cvss": self.cvss_score,
            "cvss_score": self.cvss_score,
            "cwe": self.cwe,
            "source_module": self.source_module,
            "moduleId": self.source_module,
            "source_module_name": self.source_module_name,
            "moduleName": self.source_module_name,
            "target": self.target,
            "location": self.location,
            "affectedAsset": self.location or self.target,
            "evidence": self.evidence,
            "request": self.request_data,
            "response": self.response_data,
            "remediation": self.remediation,
            "references": self.references or [],
            "status": self.status,
            "status_note": self.status_note,
            "fingerprint_hash": self.fingerprint_hash,
            "occurrence_count": self.occurrence_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "detectedTime": self.first_seen.isoformat() if self.first_seen else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class SecurityReport(models.Model):
    """
    Persistent model representing a generated Professional Security Report.
    """
    REPORT_TYPE_CHOICES = [
        ("executive", "Executive Summary"),
        ("technical", "Technical Pentest Audit"),
        ("attack_surface", "Attack Surface & Perimeter"),
        ("full_audit", "Full Security Assessment"),
    ]

    FORMAT_CHOICES = [
        ("pdf", "PDF Document"),
        ("html", "HTML Interactive"),
        ("json", "JSON Export"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=256, db_index=True)
    report_type = models.CharField(max_length=32, choices=REPORT_TYPE_CHOICES, default="executive", db_index=True)
    format = models.CharField(max_length=16, choices=FORMAT_CHOICES, default="pdf")
    
    target = models.CharField(max_length=512, default="Global Organization", db_index=True)
    scan = models.ForeignKey(
        UnifiedScanRecord,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports"
    )
    
    status = models.CharField(max_length=32, default="completed", db_index=True)
    overall_risk_score = models.FloatField(default=0.0)
    risk_level = models.CharField(max_length=32, default="Informational")
    grade = models.CharField(max_length=8, default="A")
    total_findings = models.IntegerField(default=0)
    
    severity_breakdown = models.JSONField(default=dict)
    summary_data = models.JSONField(default=dict)
    html_content = models.TextField(blank=True, default="")
    
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Security Report"
        verbose_name_plural = "Security Reports"

    def __str__(self):
        return f"[{self.report_type.upper()}] {self.title} ({self.target})"

    def to_dict(self, include_html: bool = False):
        data = {
            "id": str(self.id),
            "title": self.title,
            "report_type": self.report_type,
            "type": self.report_type,
            "format": self.format,
            "target": self.target,
            "scan_id": str(self.scan.id) if self.scan else None,
            "status": self.status,
            "overall_risk_score": self.overall_risk_score,
            "risk_score": self.overall_risk_score,
            "risk_level": self.risk_level,
            "grade": self.grade,
            "total_findings": self.total_findings,
            "severity_breakdown": self.severity_breakdown,
            "summary_data": self.summary_data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "generatedAt": self.created_at.isoformat() if self.created_at else None,
            "size": f"{max(12, len(self.html_content) // 1024)} KB" if self.html_content else "24 KB",
        }
        if include_html:
            data["html_content"] = self.html_content
        return data

