from rest_framework.exceptions import ValidationError
from django.utils import timezone
from findings.models import Finding, FindingOccurrence, FindingEvidence
from assets.models import Asset
from findings.services.fingerprint import generate_finding_fingerprint
from findings.services.redaction import redact_evidence

class FindingNormalizer:
    VALID_SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
    VALID_CONFIDENCES = {'CONFIRMED', 'HIGH', 'MEDIUM', 'LOW'}
    VALID_CATEGORIES = {
        'NETWORK', 'WEB', 'API', 'AUTHENTICATION', 'AUTHORIZATION', 
        'CONFIGURATION', 'CRYPTOGRAPHY', 'INJECTION', 'DISCLOSURE', 
        'SECRETS', 'DEPENDENCY', 'SOURCE_CODE', 'TLS', 'OSINT', 'OTHER'
    }

    @classmethod
    def normalize_finding(cls, scan_job, raw_data):
        """
        Validates, normalizes, and saves raw scanner output to Findings, Occurrences, and Evidences.
        """
        # 1. Validation of required inputs
        title = raw_data.get('title')
        category = raw_data.get('category')
        severity = raw_data.get('severity')
        confidence = raw_data.get('confidence')
        
        if not title:
            raise ValidationError("Finding title is required.")
        if not category:
            raise ValidationError("Finding category is required.")
        if not severity:
            raise ValidationError("Finding severity is required.")
        if not confidence:
            raise ValidationError("Finding confidence is required.")

        # Normalize choices values
        category = category.upper()
        severity = severity.upper()
        confidence = confidence.upper()

        if category not in cls.VALID_CATEGORIES:
            raise ValidationError(f"Invalid category '{category}'. Must be one of {cls.VALID_CATEGORIES}.")
        if severity not in cls.VALID_SEVERITIES:
            raise ValidationError(f"Invalid severity '{severity}'. Must be one of {cls.VALID_SEVERITIES}.")
        if confidence not in cls.VALID_CONFIDENCES:
            raise ValidationError(f"Invalid confidence '{confidence}'. Must be one of {cls.VALID_CONFIDENCES}.")

        # Normalize CVSS score
        cvss = raw_data.get('cvss_score', 0.0)
        try:
            cvss_score = float(cvss)
        except (ValueError, TypeError):
            raise ValidationError("CVSS score must be a numeric value.")
            
        if not (0.0 <= cvss_score <= 10.0):
            raise ValidationError("CVSS score must be between 0.0 and 10.0.")

        # Normalize CWE
        cwe = raw_data.get('cwe', '').strip()
        if cwe:
            cwe_upper = cwe.upper()
            if not cwe_upper.startswith('CWE-'):
                cwe = f"CWE-{cwe_upper}"
            else:
                cwe = cwe_upper

        # Resolve Asset Relationship if asset_id is provided
        asset = None
        asset_id = raw_data.get('asset_id')
        if asset_id:
            try:
                asset = Asset.objects.get(id=asset_id)
            except Asset.DoesNotExist:
                pass

        location = raw_data.get('location', '').strip()
        description = raw_data.get('description', '').strip()
        remediation = raw_data.get('remediation', '').strip()
        references = raw_data.get('references', [])
        metadata = raw_data.get('metadata', {})

        # 2. Hashing Fingerprint
        project = scan_job.assessment.project
        testing_module = scan_job.testing_module
        
        fingerprint = generate_finding_fingerprint(
            project_id=project.id,
            asset_id=asset.id if asset else None,
            testing_module_key=testing_module.key,
            category=category,
            title=title,
            location=location
        )

        # 3. Deduplication Logic: Get or Create Finding
        finding = Finding.objects.filter(fingerprint=fingerprint).first()
        if finding:
            # Re-update mutable properties
            finding.description = description
            finding.severity = severity
            finding.confidence = confidence
            finding.cvss_score = cvss_score
            finding.cwe = cwe
            finding.remediation = remediation
            finding.references = references
            finding.metadata = metadata
            finding.updated_at = timezone.now()
            # If finding was previously resolved, re-open it
            if finding.status == 'RESOLVED':
                finding.status = 'OPEN'
            finding.save()
        else:
            finding = Finding.objects.create(
                project=project,
                assessment=scan_job.assessment,
                scan_job=scan_job,
                testing_module=testing_module,
                asset=asset,
                title=title,
                description=description,
                category=category,
                severity=severity,
                confidence=confidence,
                status='OPEN',
                cvss_score=cvss_score,
                cwe=cwe,
                remediation=remediation,
                references=references,
                fingerprint=fingerprint,
                metadata=metadata
            )

        # 4. Create Occurrence tracking
        FindingOccurrence.objects.create(
            finding=finding,
            scan_job=scan_job,
            metadata=metadata
        )

        # 5. Create Redacted Evidence records
        raw_evidence = raw_data.get('evidence', [])
        if not isinstance(raw_evidence, list):
            raw_evidence = []
            
        for ev in raw_evidence:
            evidence_type = ev.get('evidence_type', 'OTHER').upper()
            ev_title = ev.get('title', 'Scanner Evidence')
            ev_desc = ev.get('description', '')
            
            # Redact fields recursively before storing
            ev_req = redact_evidence(ev.get('request', {}))
            ev_resp = redact_evidence(ev.get('response', {}))
            ev_payload = redact_evidence(ev.get('payload', ''))
            ev_code = redact_evidence(ev.get('code_snippet', ''))
            ev_loc = ev.get('location', '')
            ev_meta = redact_evidence(ev.get('metadata', {}))

            FindingEvidence.objects.create(
                finding=finding,
                evidence_type=evidence_type,
                title=ev_title,
                description=ev_desc,
                request=ev_req if isinstance(ev_req, dict) else {"raw": ev_req},
                response=ev_resp if isinstance(ev_resp, dict) else {"raw": ev_resp},
                location=ev_loc,
                payload=ev_payload,
                code_snippet=ev_code,
                metadata=ev_meta if isinstance(ev_meta, dict) else {"raw": ev_meta}
            )

        return finding
