from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.exceptions import ValidationError
from core.models import TestingModule
from projects.models import Project, Assessment, AssessmentScope
from scans.models import ScanJob, ModuleExecution
from findings.models import Finding, FindingOccurrence, FindingEvidence
from findings.services.redaction import redact_text, redact_evidence
from findings.services.fingerprint import generate_finding_fingerprint
from findings.services.normalizer import FindingNormalizer

class FindingsNormalizationTests(APITestCase):

    def setUp(self):
        # Create core data
        self.web_module, _ = TestingModule.objects.get_or_create(
            key='web_security_headers_test',
            defaults={
                'name': 'Web Security Headers',
                'category': 'WEB',
                'enabled': True,
                'requires_live_url': True,
                'requires_source_code': False
            }
        )
        self.web_module.name = 'Web Security Headers'
        self.web_module.category = 'WEB'
        self.web_module.enabled = True
        self.web_module.requires_live_url = True
        self.web_module.requires_source_code = False
        self.web_module.save()
        self.project = Project.objects.create(
            name="Norm Project",
            live_url="http://example.com"
        )
        self.assessment = Assessment.objects.create(
            project=self.project,
            name="Assessment Norm",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test']
        )
        self.scope = AssessmentScope.objects.create(
            assessment=self.assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        self.job = ScanJob.objects.create(
            assessment=self.assessment,
            testing_module=self.web_module,
            status='QUEUED'
        )

    def test_redaction_utility(self):
        # 1. Bearer Token
        raw_bearer = "Authorization: Bearer mySecretToken123"
        self.assertIn("[REDACTED]", redact_text(raw_bearer))
        self.assertNotIn("mySecretToken123", redact_text(raw_bearer))

        # 2. Key-value credentials
        raw_pass = "DB_PASSWORD = 'superSecretPassword';"
        self.assertIn("[REDACTED]", redact_text(raw_pass))
        self.assertNotIn("superSecretPassword", redact_text(raw_pass))

        # 3. API Key
        raw_key = "api_key: 'my-private-api-key-999'"
        self.assertIn("[REDACTED]", redact_text(raw_key))
        self.assertNotIn("my-private-api-key-999", redact_text(raw_key))

        # 4. Private PEM key
        raw_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3\n-----END PRIVATE KEY-----"
        self.assertIn("[REDACTED PRIVATE KEY]", redact_text(raw_pem))
        self.assertNotIn("MIIEvgIBADANBgkqhkiG9w", redact_text(raw_pem))

        # 5. Dict structure redaction
        evidence_dict = {
            "headers": {
                "Authorization": "Bearer superSecretJwtSecret",
                "Cookie": "session_id=abc123xyz"
            },
            "body": {
                "password": "userPlainPassword",
                "normal_field": "public_data"
            }
        }
        redacted = redact_evidence(evidence_dict)
        self.assertEqual(redacted["headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(redacted["headers"]["Cookie"], "[REDACTED]")
        self.assertEqual(redacted["body"]["password"], "[REDACTED]")
        self.assertEqual(redacted["body"]["normal_field"], "public_data")

    def test_fingerprint_determinism(self):
        fp1 = generate_finding_fingerprint(1, 2, "sast", "CODE", "SQL Injection", "views.py:12")
        fp2 = generate_finding_fingerprint(1, 2, "sast", "CODE", "SQL Injection", "views.py:12")
        fp3 = generate_finding_fingerprint(1, 2, "sast", "CODE", "XSS Vulnerability", "views.py:12")
        
        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)

    def test_cwe_normalization(self):
        raw1 = {"title": "XSS", "category": "WEB", "severity": "HIGH", "confidence": "HIGH", "cwe": "79"}
        raw2 = {"title": "XSS", "category": "WEB", "severity": "HIGH", "confidence": "HIGH", "cwe": "cwe-79"}
        
        f1 = FindingNormalizer.normalize_finding(self.job, raw1)
        f2 = FindingNormalizer.normalize_finding(self.job, raw2)
        
        self.assertEqual(f1.cwe, "CWE-79")
        self.assertEqual(f2.cwe, "CWE-79")

    def test_normalizer_validations(self):
        # 1. Invalid Category
        raw_bad_cat = {"title": "XSS", "category": "BAD_CAT", "severity": "HIGH", "confidence": "HIGH"}
        with self.assertRaises(ValidationError):
            FindingNormalizer.normalize_finding(self.job, raw_bad_cat)

        # 2. Invalid Severity
        raw_bad_sev = {"title": "XSS", "category": "WEB", "severity": "EXTREME", "confidence": "HIGH"}
        with self.assertRaises(ValidationError):
            FindingNormalizer.normalize_finding(self.job, raw_bad_sev)

        # 3. Invalid Confidence
        raw_bad_conf = {"title": "XSS", "category": "WEB", "severity": "HIGH", "confidence": "UNKNOWN"}
        with self.assertRaises(ValidationError):
            FindingNormalizer.normalize_finding(self.job, raw_bad_conf)

        # 4. CVSS Out of bounds
        raw_bad_cvss = {"title": "XSS", "category": "WEB", "severity": "HIGH", "confidence": "HIGH", "cvss_score": 11.5}
        with self.assertRaises(ValidationError):
            FindingNormalizer.normalize_finding(self.job, raw_bad_cvss)

    def test_deduplication_and_occurrences(self):
        raw_finding = {
            "title": "SQL Injection",
            "category": "INJECTION",
            "severity": "CRITICAL",
            "confidence": "CONFIRMED",
            "cvss_score": 9.8,
            "cwe": "CWE-89",
            "location": "login.py:15",
            "description": "SQL injection in login parameter",
            "evidence": [
                {
                    "evidence_type": "HTTP_REQUEST",
                    "title": "Malicious Request",
                    "request": "POST /login password=secretAdmin"
                }
            ]
        }

        # 1st Discover: Creates Finding and 1 Occurrence
        f1 = FindingNormalizer.normalize_finding(self.job, raw_finding)
        self.assertEqual(Finding.objects.count(), 1)
        self.assertEqual(FindingOccurrence.objects.count(), 1)
        self.assertEqual(FindingEvidence.objects.count(), 1)
        
        # Verify evidence redaction inside DB
        ev = FindingEvidence.objects.first()
        self.assertIn("[REDACTED]", ev.request["raw"])

        # 2nd Discover (in another job of the same module): Keeps 1 Finding, creates 2nd Occurrence
        job2 = ScanJob.objects.create(assessment=self.assessment, testing_module=self.web_module, status='QUEUED')
        f2 = FindingNormalizer.normalize_finding(job2, raw_finding)
        
        self.assertEqual(Finding.objects.count(), 1)
        self.assertEqual(FindingOccurrence.objects.count(), 2)
        self.assertEqual(f1.id, f2.id)

    def test_finding_api_filters_and_search(self):
        # Populate findings
        raw1 = {"title": "XSS Vulnerability", "category": "WEB", "severity": "HIGH", "confidence": "HIGH", "location": "1"}
        raw2 = {"title": "Port Open", "category": "NETWORK", "severity": "LOW", "confidence": "LOW", "location": "2"}
        FindingNormalizer.normalize_finding(self.job, raw1)
        FindingNormalizer.normalize_finding(self.job, raw2)

        # 1. Search filter
        url = reverse('finding-list')
        response = self.client.get(f"{url}?search=Port")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['title'], "Port Open")

        # 2. Category filter
        response = self.client.get(f"{url}?category=WEB")
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['title'], "XSS Vulnerability")

    def test_finding_status_transitions(self):
        raw = {"title": "SQL Injection", "category": "INJECTION", "severity": "CRITICAL", "confidence": "CONFIRMED"}
        finding = FindingNormalizer.normalize_finding(self.job, raw)
        
        # Patch transitions
        url = reverse('finding-detail', args=[finding.id])
        
        # 1. Valid: OPEN -> CONFIRMED
        response = self.client.patch(url, {"status": "CONFIRMED"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 2. Invalid: CONFIRMED -> OPEN
        response = self.client.patch(url, {"status": "OPEN"}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_assessment_overview_and_scanjob_finding_counts(self):
        raw1 = {"title": "SQLi", "category": "INJECTION", "severity": "CRITICAL", "confidence": "CONFIRMED", "location": "1"}
        raw2 = {"title": "CSRF", "category": "WEB", "severity": "MEDIUM", "confidence": "HIGH", "location": "2"}
        
        FindingNormalizer.normalize_finding(self.job, raw1)
        FindingNormalizer.normalize_finding(self.job, raw2)
        
        # 1. Check assessment overview API
        url = reverse('assessment-overview', args=[self.assessment.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['finding_count'], 2)
        self.assertEqual(response.data['critical_findings'], 1)
        self.assertEqual(response.data['medium_findings'], 1)

    def test_placeholder_scanner_zero_findings(self):
        # Launch placeholder assessment start, execute, and verify count remains 0
        self.client.post(reverse('assessment-start', args=[self.assessment.id]), format='json')
        job = self.assessment.jobs.first()
        
        # Synchronously execute job
        self.client.post(reverse('scanjob-execute', args=[job.id]), format='json')
        job.refresh_from_db()
        self.assertEqual(job.status, 'COMPLETED')
        self.assertEqual(job.result.get('findings_count'), 0)
        
        # Verify no findings created
        self.assertEqual(Finding.objects.count(), 0)

    def test_evidence_apis(self):
        raw = {
            "title": "SQLi", "category": "INJECTION", "severity": "CRITICAL", "confidence": "CONFIRMED",
            "evidence": [
                {
                    "evidence_type": "HTTP_REQUEST",
                    "title": "Payload Sent",
                    "request": {"cookie": "my-secret-cookie"}
                }
            ]
        }
        finding = FindingNormalizer.normalize_finding(self.job, raw)
        evidence = finding.evidence_records.first()
        
        # GET /api/findings/{id}/evidence/
        url = reverse('finding-evidence', args=[finding.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['request']['cookie'], "[REDACTED]")

        # GET /api/evidence/{evidence_id}/
        url_ev = reverse('findingevidence-detail', args=[evidence.id])
        response_ev = self.client.get(url_ev)
        self.assertEqual(response_ev.status_code, status.HTTP_200_OK)
        self.assertEqual(response_ev.data['request']['cookie'], "[REDACTED]")
