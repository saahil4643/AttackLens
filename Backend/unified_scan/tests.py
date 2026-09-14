from django.test import TestCase, Client
import json
import uuid
from .models import UnifiedScanRecord, Finding
from .services.orchestrator import UnifiedScanOrchestrator
from .services.findings_engine import FindingsEngine


class UnifiedScanTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.record = UnifiedScanRecord.objects.create(
            target="http://127.0.0.1:8000",
            scan_profile="quick",
            intensity="normal",
            status="PENDING",
            active_modules=["ports", "http"],
            findings_summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
            module_statuses={"ports": {"status": "pending"}, "http": {"status": "pending"}}
        )

    def test_start_unified_scan_missing_target(self):
        resp = self.client.post(
            "/api/unified-scan/start/",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertFalse(data["success"])

    def test_start_unified_scan_success(self):
        resp = self.client.post(
            "/api/unified-scan/start/",
            data=json.dumps({
                "target": "127.0.0.1",
                "modules": ["ports", "http"],
                "scan_profile": "quick"
            }),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertIn("scan_id", data)

    def test_get_scan_status(self):
        resp = self.client.get(f"/api/unified-scan/{self.record.id}/status/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["scan_id"], str(self.record.id))
        self.assertEqual(data["status"], "PENDING")

    def test_get_scan_results(self):
        resp = self.client.get(f"/api/unified-scan/{self.record.id}/results/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertIn("scan", data)

    def test_abort_unified_scan(self):
        resp = self.client.post(f"/api/unified-scan/{self.record.id}/abort/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.record.refresh_from_db()
        self.assertEqual(self.record.status, "ABORTED")

    def test_list_scans(self):
        resp = self.client.get("/api/unified-scan/list/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["count"], 1)

    def test_orchestrator_posture_calculation(self):
        orchestrator = UnifiedScanOrchestrator(
            scan_record_id=str(self.record.id),
            target="http://127.0.0.1:8000",
            active_module_ids=["ports"]
        )
        orchestrator.findings = [
            {"severity": "high", "title": "High Vulnerability", "cvss": 7.5},
            {"severity": "medium", "title": "Medium Issue", "cvss": 5.0}
        ]
        score, grade, risk_text, counts = orchestrator.calculate_security_posture()
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["total"], 2)
        self.assertLess(score, 100)


class UnifiedFindingsEngineTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.scan_record = UnifiedScanRecord.objects.create(
            target="https://example.com",
            scan_profile="standard",
            status="COMPLETED"
        )

    def test_findings_engine_ingest_and_deduplication(self):
        raw_finding = {
            "title": "Missing Content-Security-Policy",
            "description": "CSP header is not set.",
            "severity": "medium",
            "confidence": "firm",
            "cvss": 5.4,
            "cwe": "CWE-693",
            "affectedAsset": "https://example.com",
            "evidence": {"header_missing": "Content-Security-Policy"},
            "remediation": "Add CSP header to server response.",
            "references": ["https://owasp.org/www-project-secure-headers/"]
        }

        # Ingest first time
        finding1, created1 = FindingsEngine.ingest_finding(
            raw_finding=raw_finding,
            source_module="http",
            target="https://example.com",
            scan_record=self.scan_record
        )
        self.assertTrue(created1)
        self.assertEqual(finding1.occurrence_count, 1)
        self.assertEqual(finding1.status, "open")
        self.assertEqual(finding1.cvss_score, 5.4)

        # Ingest second time with same fingerprint - must deduplicate
        finding2, created2 = FindingsEngine.ingest_finding(
            raw_finding=raw_finding,
            source_module="http",
            target="https://example.com",
            scan_record=self.scan_record
        )
        self.assertFalse(created2)
        self.assertEqual(finding2.id, finding1.id)
        self.assertEqual(finding2.occurrence_count, 2)

        # Total findings in DB should be exactly 1
        self.assertEqual(Finding.objects.count(), 1)

    def test_findings_filtering_and_search(self):
        # Create distinct findings
        f1 = {
            "title": "Exposed MySQL Port (3306/TCP)",
            "description": "Database port open to world.",
            "severity": "high",
            "cwe": "CWE-284",
            "affectedAsset": "3306/TCP",
            "cvss": 7.5
        }
        f2 = {
            "title": "Cleartext HTTP Protocol",
            "description": "Server accepts unencrypted HTTP traffic.",
            "severity": "medium",
            "cwe": "CWE-319",
            "affectedAsset": "http://example.com",
            "cvss": 5.0
        }
        f3 = {
            "title": "Hardcoded AWS Secret Key",
            "description": "API secret found in config.py.",
            "severity": "critical",
            "cwe": "CWE-798",
            "affectedAsset": "config.py:14",
            "cvss": 9.8
        }

        FindingsEngine.ingest_finding(f1, "ports", "example.com")
        FindingsEngine.ingest_finding(f2, "http", "example.com")
        FindingsEngine.ingest_finding(f3, "codebase-analysis", "example.com")

        # Test filter by severity
        crit_qs = FindingsEngine.get_findings_queryset({"severity": "critical"})
        self.assertEqual(crit_qs.count(), 1)
        self.assertEqual(crit_qs.first().severity, "critical")

        # Test filter by module
        code_qs = FindingsEngine.get_findings_queryset({"module": "codebase-analysis"})
        self.assertEqual(code_qs.count(), 1)

        # Test search query
        search_qs = FindingsEngine.get_findings_queryset({"search": "AWS"})
        self.assertEqual(search_qs.count(), 1)
        self.assertIn("AWS", search_qs.first().title)

    def test_api_list_findings(self):
        raw = {
            "title": "Weak TLS 1.0 Cipher Supported",
            "description": "Server supports deprecated TLS 1.0.",
            "severity": "high",
            "cwe": "CWE-326",
            "affectedAsset": "example.com:443",
            "cvss": 7.5
        }
        FindingsEngine.ingest_finding(raw, "tls", "example.com", self.scan_record)

        resp = self.client.get("/api/findings/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["total"], 1)
        self.assertIn("stats", data)
        self.assertEqual(data["stats"]["by_severity"]["high"], 1)

    def test_api_get_finding_detail(self):
        raw = {
            "title": "Sensitive API Endpoint Exposed",
            "description": "/api/v1/admin/users accessible without token.",
            "severity": "critical",
            "cwe": "CWE-306",
            "affectedAsset": "/api/v1/admin/users",
            "cvss": 9.1
        }
        finding, _ = FindingsEngine.ingest_finding(raw, "api-analysis", "api.example.com")

        resp = self.client.get(f"/api/findings/{finding.id}/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["finding"]["title"], "Sensitive API Endpoint Exposed")
        self.assertEqual(data["finding"]["severity"], "critical")

    def test_api_update_finding_status(self):
        raw = {
            "title": "Missing Strict-Transport-Security",
            "description": "HSTS header missing.",
            "severity": "low",
            "cvss": 3.0
        }
        finding, _ = FindingsEngine.ingest_finding(raw, "http", "example.com")

        resp = self.client.patch(
            f"/api/findings/{finding.id}/status/",
            data=json.dumps({
                "status": "remediated",
                "status_note": "Configured max-age=31536000 on NGINX."
            }),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["finding"]["status"], "remediated")
        self.assertEqual(data["finding"]["status_note"], "Configured max-age=31536000 on NGINX.")

        finding.refresh_from_db()
        self.assertEqual(finding.status, "remediated")

    def test_api_bulk_update_status(self):
        f1, _ = FindingsEngine.ingest_finding({"title": "Finding 1", "severity": "low"}, "http", "example.com")
        f2, _ = FindingsEngine.ingest_finding({"title": "Finding 2", "severity": "info"}, "ports", "example.com")

        resp = self.client.post(
            "/api/findings/bulk-status/",
            data=json.dumps({
                "finding_ids": [str(f1.id), str(f2.id)],
                "status": "accepted",
                "status_note": "Accepted risk during Q3 triage."
            }),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["updated_count"], 2)

        f1.refresh_from_db()
        f2.refresh_from_db()
        self.assertEqual(f1.status, "accepted")
        self.assertEqual(f2.status, "accepted")

    def test_api_findings_stats(self):
        FindingsEngine.ingest_finding({"title": "Critical 1", "severity": "critical"}, "ports", "target1.com")
        FindingsEngine.ingest_finding({"title": "High 1", "severity": "high"}, "http", "target2.com")

        resp = self.client.get("/api/findings/stats/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        stats = data["stats"]
        self.assertEqual(stats["by_severity"]["critical"], 1)
        self.assertEqual(stats["by_severity"]["high"], 1)
        self.assertEqual(stats["total_findings"], 2)


class RiskScoringEngineTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.scan_record = UnifiedScanRecord.objects.create(
            target="https://target.corp",
            scan_profile="deep",
            status="COMPLETED"
        )

    def test_risk_calculation_weights_and_status(self):
        from .services.risk_engine import RiskScoringEngine

        # Critical open finding on sensitive port
        f_crit = {
            "title": "Exposed Redis Key-Value Store (6379/TCP)",
            "severity": "critical",
            "cvss": 9.8,
            "confidence": "certain",
            "status": "open",
            "location": "6379/TCP",
            "target": "target.corp"
        }
        f_obj1, _ = FindingsEngine.ingest_finding(f_crit, "ports", "target.corp", self.scan_record)

        risk_profile1 = RiskScoringEngine.calculate_target_risk("target.corp")
        self.assertGreater(risk_profile1["overall_risk_score"], 40.0)
        self.assertIn(risk_profile1["risk_level"], ["High", "Critical"])
        self.assertIn("6379/TCP", [r["location"] for r in risk_profile1["top_risks"]])

        # Mark finding as remediated -> risk should drop to 0
        f_obj1.status = "remediated"
        f_obj1.save()

        risk_profile2 = RiskScoringEngine.calculate_target_risk("target.corp")
        self.assertEqual(risk_profile2["overall_risk_score"], 0.0)
        self.assertEqual(risk_profile2["risk_level"], "Informational")
        self.assertEqual(risk_profile2["grade"], "A")
        self.assertEqual(risk_profile2["remediated_count"], 1)

    def test_risk_api_endpoints(self):
        # Ingest test findings
        FindingsEngine.ingest_finding({
            "title": "SQL Injection in User Query",
            "severity": "critical",
            "cvss": 9.5,
            "status": "confirmed",
            "location": "/api/v1/users?id="
        }, "api-analysis", "api.target.corp", self.scan_record)

        FindingsEngine.ingest_finding({
            "title": "Weak SSL Certificate",
            "severity": "medium",
            "cvss": 5.0,
            "status": "open",
            "location": "api.target.corp:443"
        }, "tls", "api.target.corp", self.scan_record)

        # 1. Global summary
        resp1 = self.client.get("/api/risk/summary/")
        self.assertEqual(resp1.status_code, 200)
        data1 = resp1.json()
        self.assertTrue(data1["success"])
        self.assertIn("overall_risk_score", data1["risk"])
        self.assertIn("module_risk_breakdown", data1["risk"])

        # 2. Target specific risk
        resp2 = self.client.get("/api/risk/target/?target=api.target.corp")
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertTrue(data2["success"])
        self.assertEqual(data2["risk"]["target"], "api.target.corp")
        self.assertGreater(data2["risk"]["overall_risk_score"], 0)

        # 3. Scan specific risk
        resp3 = self.client.get(f"/api/risk/scan/{self.scan_record.id}/")
        self.assertEqual(resp3.status_code, 200)
        data3 = resp3.json()
        self.assertTrue(data3["success"])
        self.assertEqual(data3["risk"]["scan_id"], str(self.scan_record.id))

        # 4. Trends endpoint
        resp4 = self.client.get("/api/risk/trends/")
        self.assertEqual(resp4.status_code, 200)
        data4 = resp4.json()
        self.assertTrue(data4["success"])
        self.assertIn("trends", data4)

        # 5. Recalculate endpoint
        resp5 = self.client.post("/api/risk/recalculate/")
        self.assertEqual(resp5.status_code, 200)
        data5 = resp5.json()
        self.assertTrue(data5["success"])


class AttackSurfaceCorrelationEngineTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.scan_record = UnifiedScanRecord.objects.create(
            target="https://app.correlate.corp",
            scan_profile="standard",
            status="COMPLETED",
            resolved_ip="192.168.1.50",
            cleaned_target="app.correlate.corp",
            module_results={
                "ports": {
                    "open_ports": [80, 443, 3306],
                    "open_port_details": [
                        {"port": 80, "service": "HTTP (nginx)", "status": "open"},
                        {"port": 443, "service": "HTTPS", "status": "open"},
                        {"port": 3306, "service": "MySQL Database", "status": "open"}
                    ]
                },
                "fingerprint": {
                    "technologies": [
                        {"name": "Django", "category": "Web Framework", "version": "5.1"},
                        {"name": "Nginx", "category": "Web Server", "version": "1.24"}
                    ]
                },
                "endpoints": {
                    "endpoints": ["/", "/login", "/api/v1/auth", "/admin"]
                },
                "api-analysis": {
                    "api_endpoints": [
                        {"path": "/api/v1/auth", "method": "POST", "auth_required": False}
                    ]
                },
                "tls": {
                    "success": True,
                    "tls_version": "TLS 1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384"
                }
            }
        )

        # Ingest correlated findings
        FindingsEngine.ingest_finding({
            "title": "Exposed MySQL Database Port (3306/TCP)",
            "severity": "high",
            "cvss": 7.5,
            "location": "3306/TCP",
            "target": "app.correlate.corp"
        }, "ports", "app.correlate.corp", self.scan_record)

        FindingsEngine.ingest_finding({
            "title": "API Authentication Missing on Auth Endpoint",
            "severity": "critical",
            "cvss": 9.2,
            "location": "/api/v1/auth",
            "target": "app.correlate.corp"
        }, "api-analysis", "app.correlate.corp", self.scan_record)

    def test_correlation_graph_generation(self):
        from .services.correlation_engine import AttackSurfaceCorrelationEngine

        result = AttackSurfaceCorrelationEngine.correlate_scan(str(self.scan_record.id))
        self.assertTrue(result["success"])
        self.assertIn("graph", result)
        self.assertIn("inventory", result)
        self.assertIn("summary", result)

        nodes = result["graph"]["nodes"]
        edges = result["graph"]["edges"]

        node_types = {n["type"] for n in nodes}
        self.assertIn("target", node_types)
        self.assertIn("domain", node_types)
        self.assertIn("port", node_types)
        self.assertIn("service", node_types)
        self.assertIn("technology", node_types)
        self.assertIn("endpoint", node_types)
        self.assertIn("finding", node_types)

        # Verify summary counts
        summary = result["summary"]
        self.assertGreaterEqual(summary["port_count"], 3)
        self.assertGreaterEqual(summary["finding_count"], 2)
        self.assertGreater(summary["overall_risk_score"], 0)

    def test_correlation_apis(self):
        # 1. Full correlation endpoint
        resp1 = self.client.get(f"/api/attack-surface/correlation/?scan_id={self.scan_record.id}")
        self.assertEqual(resp1.status_code, 200)
        data1 = resp1.json()
        self.assertTrue(data1["success"])
        self.assertIn("graph", data1)
        self.assertIn("tree", data1)

        # 2. Inventory endpoint
        resp2 = self.client.get(f"/api/attack-surface/inventory/?target=app.correlate.corp")
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertTrue(data2["success"])
        self.assertIn("inventory", data2)
        self.assertIn("ports", data2["inventory"])

        # 3. Post correlate endpoint
        resp3 = self.client.post(
            "/api/attack-surface/correlate/",
            data=json.dumps({"target": "app.correlate.corp"}),
            content_type="application/json"
        )
        self.assertEqual(resp3.status_code, 200)
        data3 = resp3.json()
        self.assertTrue(data3["success"])


class SecurityCommandCenterDashboardTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.scan_record = UnifiedScanRecord.objects.create(
            target="soc.enterprise.corp",
            scan_profile="standard",
            intensity="normal",
            active_modules=["ports", "api-analysis", "tls", "fingerprint"],
            module_statuses={
                "ports": {"status": "completed"},
                "api-analysis": {"status": "completed"},
                "tls": {"status": "completed"},
                "fingerprint": {"status": "completed"}
            },
            status="COMPLETED",
            progress_percent=100
        )

        # Ingest findings
        FindingsEngine.ingest_finding({
            "title": "Remote Code Execution via Spring4Shell",
            "severity": "critical",
            "cvss": 9.8,
            "location": "8080/TCP",
            "target": "soc.enterprise.corp"
        }, "fingerprint", "soc.enterprise.corp", self.scan_record)

        FindingsEngine.ingest_finding({
            "title": "SQL Injection in User Profile Parameter",
            "severity": "high",
            "cvss": 8.4,
            "location": "/api/v1/users",
            "target": "soc.enterprise.corp"
        }, "api-analysis", "soc.enterprise.corp", self.scan_record)

    def test_dashboard_summary_endpoint(self):
        resp = self.client.get("/api/dashboard/summary/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["status"], "success")
        self.assertIn("risk", data)
        self.assertIn("attack_surface", data)
        self.assertIn("recent_scans", data)
        self.assertIn("top_vulnerabilities", data)
        self.assertIn("high_risk_assets", data)
        self.assertIn("module_risk_breakdown", data)
        self.assertIn("risk_trends", data)
        self.assertIn("targets_overview", data)

        # Verify risk values
        self.assertGreater(data["risk"]["overall_risk_score"], 0)
        self.assertGreaterEqual(data["risk"]["severity_breakdown"]["critical"], 1)
        self.assertGreaterEqual(data["risk"]["severity_breakdown"]["high"], 1)

        # Verify recent scans list
        self.assertGreaterEqual(len(data["recent_scans"]), 1)
        self.assertEqual(data["recent_scans"][0]["target"], "soc.enterprise.corp")

        # Verify top vulnerabilities
        self.assertGreaterEqual(len(data["top_vulnerabilities"]), 2)
        self.assertEqual(data["top_vulnerabilities"][0]["severity"], "critical")

        # Verify high risk assets
        self.assertGreaterEqual(len(data["high_risk_assets"]), 1)

    def test_dashboard_summary_target_filtered(self):
        resp = self.client.get("/api/dashboard/summary/?target=soc.enterprise.corp")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["status"], "success")
        self.assertEqual(data["selected_target"], "soc.enterprise.corp")
        self.assertGreater(data["risk"]["overall_risk_score"], 0)


class ProfessionalSecurityReportingTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.scan_record = UnifiedScanRecord.objects.create(
            target="audit.corp.internal",
            scan_profile="deep",
            intensity="normal",
            active_modules=["ports", "api-analysis", "tls"],
            status="COMPLETED",
            progress_percent=100
        )

        FindingsEngine.ingest_finding({
            "title": "Unauthenticated Administrative API Access",
            "severity": "critical",
            "cvss": 9.6,
            "location": "/api/admin/system",
            "target": "audit.corp.internal",
            "remediation": "Implement OAuth2 Bearer token authentication."
        }, "api-analysis", "audit.corp.internal", self.scan_record)

    def test_report_generation_service(self):
        from .services.report_generator import SecurityReportGenerator

        report = SecurityReportGenerator.generate_report(
            target="audit.corp.internal",
            report_type="executive",
            format_type="pdf",
            title="Q3 Executive Pentest Deliverable"
        )
        self.assertIsNotNone(report.id)
        self.assertEqual(report.title, "Q3 Executive Pentest Deliverable")
        self.assertEqual(report.report_type, "executive")
        self.assertGreater(report.overall_risk_score, 0)
        self.assertIn("<!DOCTYPE html>", report.html_content)
        self.assertIn("Unauthenticated Administrative API Access", report.html_content)

    def test_report_api_endpoints(self):
        # 1. Generate Report via API
        resp1 = self.client.post(
            "/api/reports/generate/",
            data=json.dumps({
                "target": "audit.corp.internal",
                "report_type": "technical",
                "format": "pdf",
                "title": "API Technical Audit"
            }),
            content_type="application/json"
        )
        self.assertEqual(resp1.status_code, 201)
        data1 = resp1.json()
        report_id = data1["id"]
        self.assertEqual(data1["title"], "API Technical Audit")
        self.assertEqual(data1["report_type"], "technical")

        # 2. List Reports
        resp2 = self.client.get("/api/reports/")
        self.assertEqual(resp2.status_code, 200)
        reports_list = resp2.json()
        self.assertGreaterEqual(len(reports_list), 1)

        # 3. Retrieve HTML view
        resp3 = self.client.get(f"/api/reports/{report_id}/html/")
        self.assertEqual(resp3.status_code, 200)
        self.assertEqual(resp3["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(b"API Technical Audit", resp3.content)

        # 4. Download endpoint
        resp4 = self.client.get(f"/api/reports/{report_id}/download/")
        self.assertEqual(resp4.status_code, 200)
        self.assertIn("attachment; filename=", resp4["Content-Disposition"])

        # 5. Delete Report
        resp5 = self.client.delete(f"/api/reports/{report_id}/")
        self.assertEqual(resp5.status_code, 200)


class EndToEndPipelineAndHardeningTestCase(TestCase):
    """
    Complete end-to-end integration and system hardening test suite.
    Validates the entire pipeline:
      Target -> Unified Scan -> Modules -> Unified Findings -> Risk Engine -> Attack Surface -> Dashboard -> Reports
    """

    def setUp(self):
        self.client = Client()
        self.test_target = "e2e-test.attacklens.security"

    def test_complete_security_assessment_lifecycle(self):
        # ── Step 1: Start Unified Scan via API ───────────────────────────────
        start_resp = self.client.post(
            "/api/unified-scan/start/",
            data=json.dumps({
                "target": self.test_target,
                "modules": ["port-scan", "http-detection", "endpoint-discovery", "api-analysis", "tls-analysis"],
                "scan_profile": "standard",
                "intensity": "normal"
            }),
            content_type="application/json"
        )
        self.assertEqual(start_resp.status_code, 201)
        start_data = start_resp.json()
        self.assertTrue(start_data["success"])
        scan_id = start_data["scan_id"]
        self.assertIsNotNone(scan_id)

        # ── Step 2: Retrieve Scan Record and Progress ────────────────────────
        status_resp = self.client.get(f"/api/unified-scan/{scan_id}/status/")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.json()
        self.assertEqual(status_data["target"], self.test_target)

        # ── Step 3: Populate Real Scanner Findings & Process ─────────────────
        scan_record = UnifiedScanRecord.objects.get(id=scan_id)
        
        # Ingest Port Scanner Finding via FindingsEngine
        f1_list = FindingsEngine.ingest_findings(
            source_module="ports",
            target=self.test_target,
            raw_findings=[
                {
                    "title": "Exposed Remote Management Port 22 (SSH)",
                    "description": "Open SSH service detected on default port 22.",
                    "severity": "medium",
                    "cvss_score": 5.3,
                    "location": "22/tcp",
                    "evidence": {"banner": "OpenSSH 8.9p1"},
                    "remediation": "Restrict SSH access to authorized bastion jump hosts.",
                }
            ],
            scan_record=scan_record
        )
        f1 = f1_list[0]

        # Ingest API Scanner Finding via FindingsEngine
        f2_list = FindingsEngine.ingest_findings(
            source_module="api-analysis",
            target=self.test_target,
            raw_findings=[
                {
                    "title": "Broken Object Level Authorization (BOLA)",
                    "description": "Unauthenticated access to user profile endpoint.",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cwe": "CWE-284",
                    "location": "/api/v1/users/1042",
                    "evidence": {"response": "200 OK sensitive PII"},
                    "remediation": "Implement robust JWT claims validation on all API routes.",
                }
            ],
            scan_record=scan_record
        )
        f2 = f2_list[0]

        # Ingest TLS Scanner Finding via FindingsEngine
        f3_list = FindingsEngine.ingest_findings(
            source_module="tls",
            target=self.test_target,
            raw_findings=[
                {
                    "title": "Deprecated TLS 1.0 / 1.1 Protocols Enabled",
                    "description": "Weak legacy cipher suites permitted by server.",
                    "severity": "low",
                    "cvss_score": 3.7,
                    "cwe": "CWE-326",
                    "location": "https://e2e-test.attacklens.security:443",
                    "evidence": {"cipher": "RSA-3DES-EDE-CBC-SHA"},
                    "remediation": "Enforce TLS 1.2 minimum and disable legacy CBC ciphers.",
                }
            ],
            scan_record=scan_record
        )
        f3 = f3_list[0]

        # ── Step 4: Validate Finding List & Deduplication ─────────────────────
        findings_resp = self.client.get(f"/api/findings/?target={self.test_target}")
        self.assertEqual(findings_resp.status_code, 200)
        findings_data = findings_resp.json()
        self.assertEqual(findings_data["total"], 3)
        self.assertEqual(findings_data["stats"]["by_severity"]["critical"], 1)
        self.assertEqual(findings_data["stats"]["by_severity"]["medium"], 1)
        self.assertEqual(findings_data["stats"]["by_severity"]["low"], 1)

        # Ingest a duplicate finding and verify engine deduplication
        dup_findings = [
            {
                "title": "Exposed Remote Management Port 22 (SSH)",
                "severity": "medium",
                "cvss_score": 5.3,
                "location": "22/tcp",
                "description": "Open SSH service detected on default port 22.",
                "evidence": {"banner": "OpenSSH 8.9p1"}
            }
        ]
        ingested = FindingsEngine.ingest_findings(
            source_module="ports",
            target=self.test_target,
            raw_findings=dup_findings,
            scan_record=scan_record
        )
        # Should deduplicate without increasing count
        all_findings = Finding.objects.filter(target=self.test_target)
        self.assertEqual(all_findings.count(), 3)

        # ── Step 5: Test Finding Status Lifecycle & Risk Recalculation ────────
        # Initial Risk Score
        risk_resp1 = self.client.get(f"/api/risk/target/?target={self.test_target}")
        self.assertEqual(risk_resp1.status_code, 200)
        initial_score = risk_resp1.json()["risk"]["overall_risk_score"]
        self.assertGreater(initial_score, 0)

        # Mark Critical BOLA Finding as REMEDIATED
        update_resp = self.client.post(
            f"/api/findings/{f2.id}/status/",
            data=json.dumps({
                "status": "remediated",
                "status_note": "Applied token authorization check."
            }),
            content_type="application/json"
        )
        self.assertEqual(update_resp.status_code, 200)
        self.assertEqual(update_resp.json()["finding"]["status"], "remediated")

        # Verify that risk score automatically reduced
        risk_resp2 = self.client.get(f"/api/risk/target/?target={self.test_target}")
        self.assertEqual(risk_resp2.status_code, 200)
        updated_score = risk_resp2.json()["risk"]["overall_risk_score"]
        self.assertLess(updated_score, initial_score)

        # ── Step 6: Attack Surface Correlation Engine ────────────────────────
        as_resp = self.client.get(f"/api/attack-surface/summary/?target={self.test_target}")
        self.assertEqual(as_resp.status_code, 200)
        as_data = as_resp.json()
        self.assertIn("summary", as_data)
        self.assertIn("graph", as_data)
        self.assertIn("tree", as_data)
        self.assertGreater(len(as_data["graph"]["nodes"]), 0)

        # ── Step 7: Command Center Dashboard API ─────────────────────────────
        dash_resp = self.client.get(f"/api/dashboard/summary/?target={self.test_target}")
        self.assertEqual(dash_resp.status_code, 200)
        dash_data = dash_resp.json()
        self.assertEqual(dash_data["status"], "success")
        self.assertEqual(dash_data["selected_target"], self.test_target)
        self.assertIn("risk", dash_data)
        self.assertIn("attack_surface", dash_data)
        self.assertIn("module_risk_breakdown", dash_data)

        # ── Step 8: Professional Security Report Generation ──────────────────
        report_types = ["executive", "technical", "attack_surface", "full_audit"]
        for r_type in report_types:
            gen_resp = self.client.post(
                "/api/reports/generate/",
                data=json.dumps({
                    "target": self.test_target,
                    "scan_id": str(scan_id),
                    "report_type": r_type,
                    "format": "pdf",
                    "title": f"E2E {r_type.title()} Report"
                }),
                content_type="application/json"
            )
            self.assertEqual(gen_resp.status_code, 201)
            report_info = gen_resp.json()
            r_id = report_info["id"]

            # Test HTML Preview Endpoint
            preview_resp = self.client.get(f"/api/reports/{r_id}/html/")
            self.assertEqual(preview_resp.status_code, 200)
            self.assertEqual(preview_resp["Content-Type"], "text/html; charset=utf-8")
            self.assertIn(b"<!DOCTYPE html>", preview_resp.content)

            # Test Download Endpoint
            download_resp = self.client.get(f"/api/reports/{r_id}/download/")
            self.assertEqual(download_resp.status_code, 200)
            self.assertIn("attachment;", download_resp["Content-Disposition"])

    def test_invalid_inputs_and_edge_cases(self):
        # 1. Invalid scan start: empty target
        r1 = self.client.post("/api/unified-scan/start/", data=json.dumps({}), content_type="application/json")
        self.assertEqual(r1.status_code, 400)

        # 2. Non-existent scan status
        r2 = self.client.get(f"/api/unified-scan/{uuid.uuid4()}/status/")
        self.assertEqual(r2.status_code, 404)

        # 3. Non-existent finding status update
        r3 = self.client.post(
            f"/api/findings/{uuid.uuid4()}/status/",
            data=json.dumps({"status": "remediated"}),
            content_type="application/json"
        )
        self.assertEqual(r3.status_code, 404)

        # 4. Invalid finding status value
        dummy_finding = Finding.objects.create(
            target="invalid-status.test",
            source_module="ports",
            title="Test Finding",
            description="Test Description",
            severity="low",
            status="open",
            fingerprint_hash=FindingsEngine.compute_fingerprint("ports", "invalid-status.test", "", "", "Test Finding")
        )
        r4 = self.client.post(
            f"/api/findings/{dummy_finding.id}/status/",
            data=json.dumps({"status": "invalid_status_xyz"}),
            content_type="application/json"
        )
        self.assertEqual(r4.status_code, 400)

        # 5. Non-existent report detail
        r5 = self.client.get(f"/api/reports/{uuid.uuid4()}/")
        self.assertEqual(r5.status_code, 404)





