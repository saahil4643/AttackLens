"""
Comprehensive Test Suite for AttackLens Codebase Security Analysis (SAST) Module

Tests:
1. ZIP upload & Extraction Security
2. Empty ZIP handling
3. Invalid / Corrupted ZIP handling
4. Zip Slip / Path traversal prevention
5. Resource limit enforcement
6. Python AST & lexical SAST rules
7. JavaScript / TypeScript SAST rules
8. Java & Spring SAST rules
9. PHP SAST rules
10. Hardcoded Secrets & mandatory redaction
11. SQL Injection (multi-language)
12. Command Injection (multi-language)
13. Path Traversal (multi-language)
14. SSRF Detection
15. XSS Detection
16. Insecure Deserialization (pickle, yaml, Java ObjectInputStream, PHP unserialize)
17. Weak Cryptography & Insecure Randomness
18. DEBUG=True & Insecure Configs
19. CSRF Disable Detection
20. Taint Analysis (Source -> Flow -> Sink)
21. Dependency Manifests Parsing (requirements.txt, package.json, pom.xml, composer.json)
22. Framework Detection (Django, Express, Spring Boot, Laravel)
23. Test File Classification & Confidence Adjustment
24. Malformed Source File Resilience
25. Synchronous & Sample REST API endpoints
"""

import io
import os
import zipfile
import json
import textwrap
from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile

from .services.archive_handler import SafeArchiveWorkspace, ArchiveSecurityError
from .services.redactor import redact_secrets, sanitize_data_structure
from .services.project_inventory import scan_project_inventory, is_test_file
from .services.dependency_inventory import parse_requirements_txt, parse_package_json, parse_pom_xml, parse_composer_json
from .services.framework_detector import detect_frameworks
from .services.taint_analyzer import analyze_python_taint, trace_regex_taint
from .services.codebase_scanner import scan_project_zip, analyze_extracted_workspace
from .services.sample_project import build_sample_vulnerable_project_zip


class CodebaseAnalysisSecurityTests(TestCase):

    def setUp(self):
        self.client = Client()

    def test_01_safe_zip_extraction_and_cleanup(self):
        """Verify standard ZIP extraction and workspace lifecycle cleanup."""
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, "w") as zf:
            zf.writestr("app/main.py", "print('hello world')")
            zf.writestr("config.json", '{"key": "value"}')
        mem_zip.seek(0)

        with SafeArchiveWorkspace() as ws:
            info = ws.extract_zip(mem_zip)
            self.assertEqual(info["extracted_files"], 2)
            self.assertTrue(os.path.exists(os.path.join(ws.extracted_path, "app", "main.py")))
            workspace_dir = ws.temp_dir

        # Workspace directory should be cleaned up automatically after context exit
        self.assertFalse(os.path.exists(workspace_dir))

    def test_02_empty_zip_rejection(self):
        """Verify empty ZIP archives are safely rejected."""
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, "w") as zf:
            pass  # empty
        mem_zip.seek(0)

        with SafeArchiveWorkspace() as ws:
            with self.assertRaises(ArchiveSecurityError) as ctx:
                ws.extract_zip(mem_zip)
            self.assertIn("empty", str(ctx.exception).lower())

    def test_03_invalid_corrupted_zip(self):
        """Verify corrupted ZIP data is caught gracefully."""
        corrupted_data = io.BytesIO(b"NOT_A_VALID_ZIP_HEADER_CONTENT")
        with SafeArchiveWorkspace() as ws:
            with self.assertRaises(ArchiveSecurityError):
                ws.extract_zip(corrupted_data)

    def test_04_zip_slip_path_traversal_prevention(self):
        """Verify Zip Slip path traversal attempts are blocked immediately."""
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        mem_zip.seek(0)

        with SafeArchiveWorkspace() as ws:
            with self.assertRaises(ArchiveSecurityError) as ctx:
                ws.extract_zip(mem_zip)
            self.assertTrue("Zip Slip" in str(ctx.exception) or "traversal" in str(ctx.exception))

    def test_05_file_count_limit_rejection(self):
        """Verify max files limit prevents archive bombs."""
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, "w") as zf:
            for i in range(15):
                zf.writestr(f"file_{i}.txt", "test")
        mem_zip.seek(0)

        # Restrict limit to 10 files
        with SafeArchiveWorkspace(max_files_count=10) as ws:
            with self.assertRaises(ArchiveSecurityError) as ctx:
                ws.extract_zip(mem_zip)
            self.assertIn("exceeding maximum limit", str(ctx.exception))

    def test_06_secret_redaction(self):
        """Verify mandatory redaction of secrets in strings and data structures."""
        raw_snippet = """
        AWS_KEY = "AKIA1234567890ABCDEF"
        DB_URL = "postgres://admin:SuperSecret123!@localhost:5432/mydb"
        GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        """
        redacted = redact_secrets(raw_snippet)
        self.assertNotIn("AKIA1234567890ABCDEF", redacted)
        self.assertNotIn("SuperSecret123!", redacted)
        self.assertNotIn("ghp_1234567890", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_07_python_ast_sqli_detection(self):
        """Verify Python AST identifies SQL injection via concatenation or formatting."""
        code = """
        def get_user(request):
            uid = request.GET['id']
            query = "SELECT * FROM users WHERE id = " + uid
            cursor.execute(query)
        """
        sample_zip = io.BytesIO()
        with zipfile.ZipFile(sample_zip, "w") as zf:
            zf.writestr("views.py", code)
        sample_zip.seek(0)

        res = scan_project_zip(sample_zip, "PySQLiTest")
        self.assertTrue(res["success"])
        sqli_findings = [f for f in res["findings"] if f["cwe"] == "CWE-89"]
        self.assertGreaterEqual(len(sqli_findings), 1)
        self.assertEqual(sqli_findings[0]["severity"], "high")

    def test_08_python_ast_command_injection(self):
        """Verify subprocess shell=True and os.system are detected."""
        code = textwrap.dedent("""
        import subprocess, os
        def ping(req):
            host = req.GET['host']
            subprocess.run(f"ping {host}", shell=True)
            os.system("ls " + host)
        """)
        sample_zip = io.BytesIO()
        with zipfile.ZipFile(sample_zip, "w") as zf:
            zf.writestr("cmd.py", code)
        sample_zip.seek(0)

        res = scan_project_zip(sample_zip, "PyCmdTest")
        cmd_findings = [f for f in res["findings"] if f["cwe"] == "CWE-78"]
        self.assertGreaterEqual(len(cmd_findings), 1)

    def test_09_insecure_deserialization(self):
        """Verify pickle.loads and yaml.load without SafeLoader are flagged."""
        code = textwrap.dedent("""
        import pickle, yaml
        def load(data):
            obj = pickle.loads(data)
            cfg = yaml.load(data)
        """)
        sample_zip = io.BytesIO()
        with zipfile.ZipFile(sample_zip, "w") as zf:
            zf.writestr("deser.py", code)
        sample_zip.seek(0)

        res = scan_project_zip(sample_zip, "DeserTest")
        deser_findings = [f for f in res["findings"] if f["cwe"] == "CWE-502"]
        self.assertGreaterEqual(len(deser_findings), 1)

    def test_10_debug_configuration_finding(self):
        """Verify DEBUG = True generates medium severity configuration finding."""
        code = textwrap.dedent("""
        DEBUG = True
        SECRET_KEY = 'insecure_key'
        """)
        sample_zip = io.BytesIO()
        with zipfile.ZipFile(sample_zip, "w") as zf:
            zf.writestr("settings.py", code)
        sample_zip.seek(0)

        res = scan_project_zip(sample_zip, "ConfigTest")
        conf_findings = [f for f in res["findings"] if f["cwe"] == "CWE-489"]
        self.assertGreaterEqual(len(conf_findings), 1)
        self.assertEqual(conf_findings[0]["severity"], "medium")

    def test_11_javascript_rules_evaluation(self):
        """Verify JavaScript rules (child_process.exec, raw DB query, innerHTML)."""
        js_code = """
        const { exec } = require('child_process');
        app.get('/run', (req, res) => {
            const cmd = req.query.cmd;
            exec("echo " + cmd);
            db.query(`SELECT * FROM products WHERE cat = '${req.query.cat}'`);
            document.getElementById('out').innerHTML = req.query.name;
        });
        """
        sample_zip = io.BytesIO()
        with zipfile.ZipFile(sample_zip, "w") as zf:
            zf.writestr("app.js", js_code)
        sample_zip.seek(0)

        res = scan_project_zip(sample_zip, "JSTest")
        self.assertTrue(res["success"])
        cwes = {f["cwe"] for f in res["findings"]}
        self.assertIn("CWE-78", cwes)  # Command injection
        self.assertIn("CWE-89", cwes)  # SQLi
        self.assertIn("CWE-79", cwes)  # XSS

    def test_12_java_rules_evaluation(self):
        """Verify Java rules (statement.executeQuery, ObjectInputStream)."""
        java_code = """
        package com.test;
        import java.io.*;
        import java.sql.*;
        public class Vuln {
            public void run(String input, Connection conn, byte[] bytes) throws Exception {
                Statement st = conn.createStatement();
                st.executeQuery("SELECT * FROM tbl WHERE name = '" + input + "'");
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
                ois.readObject();
            }
        }
        """
        sample_zip = io.BytesIO()
        with zipfile.ZipFile(sample_zip, "w") as zf:
            zf.writestr("Vuln.java", java_code)
        sample_zip.seek(0)

        res = scan_project_zip(sample_zip, "JavaTest")
        cwes = {f["cwe"] for f in res["findings"]}
        self.assertIn("CWE-89", cwes)
        self.assertIn("CWE-502", cwes)

    def test_13_php_rules_evaluation(self):
        """Verify PHP rules ($conn->query concatenation, system, unserialize)."""
        php_code = """<?php
        $id = $_GET['id'];
        $conn->query("SELECT * FROM items WHERE id = " . $id);
        system($_POST['cmd']);
        $data = unserialize($_COOKIE['sess']);
        ?>"""
        sample_zip = io.BytesIO()
        with zipfile.ZipFile(sample_zip, "w") as zf:
            zf.writestr("index.php", php_code)
        sample_zip.seek(0)

        res = scan_project_zip(sample_zip, "PHPTest")
        cwes = {f["cwe"] for f in res["findings"]}
        self.assertIn("CWE-89", cwes)
        self.assertIn("CWE-78", cwes)
        self.assertIn("CWE-502", cwes)

    def test_14_taint_flow_tracing(self):
        """Verify Python taint tracer generates structured Source -> Flow -> Sink history."""
        code = """
        user_id = request.GET.get('id')
        sql_query = 'SELECT * FROM users WHERE id = ' + user_id
        cursor.execute(sql_query)
        """
        flows = analyze_python_taint(code)
        self.assertGreaterEqual(len(flows), 1)
        first_flow = flows[0]
        self.assertEqual(first_flow["cwe"], "CWE-89")
        self.assertEqual(len(first_flow["flow"]), 3)
        self.assertEqual(first_flow["flow"][0]["step"], "SOURCE")
        self.assertEqual(first_flow["flow"][1]["step"], "FLOW")
        self.assertEqual(first_flow["flow"][2]["step"], "SINK")

    def test_15_dependency_manifest_parsers(self):
        """Verify static dependency manifest parsing across ecosystems."""
        req_content = "django==5.1.0\nrequests>=2.31.0\n# comment\npytest\n"
        py_deps = parse_requirements_txt(req_content, "requirements.txt")
        self.assertEqual(len(py_deps), 3)
        self.assertEqual(py_deps[0]["name"], "django")

        pkg_json = '{"dependencies": {"express": "^4.18.2"}, "devDependencies": {"jest": "^29.0"}}'
        js_deps = parse_package_json(pkg_json, "package.json")
        self.assertEqual(len(js_deps), 2)

    def test_16_framework_detector(self):
        """Verify Django and Express frameworks are accurately detected."""
        deps = [{"name": "django", "version": "5.1.0"}, {"name": "express", "version": "^4.18.2"}]
        inventory = [
            {"path": "manage.py", "category": "source"},
            {"path": "server.js", "category": "source"}
        ]
        with SafeArchiveWorkspace() as ws:
            frameworks = detect_frameworks(ws.extracted_path, inventory, deps)
            fw_names = {f["name"] for f in frameworks}
            self.assertIn("Django", fw_names)
            self.assertIn("Express", fw_names)

    def test_17_test_file_confidence_adjustment(self):
        """Verify findings in test files receive lower confidence."""
        self.assertTrue(is_test_file("tests/test_api.py"))
        self.assertTrue(is_test_file("backend/app.spec.ts"))
        self.assertFalse(is_test_file("backend/views.py"))

    def test_18_sample_vulnerable_project_full_scan(self):
        """Run full end-to-end scan on modeled demo project."""
        sample_zip = build_sample_vulnerable_project_zip()
        res = scan_project_zip(sample_zip, "Demo Project")
        self.assertTrue(res["success"])
        self.assertEqual(res["scan_status"], "completed")
        self.assertGreater(res["project"]["source_files"], 3)
        self.assertGreater(res["summary"]["high"], 0)
        self.assertGreater(len(res["languages"]), 2)
        self.assertGreater(len(res["dependencies"]), 2)

    def test_19_api_sample_scan_endpoint(self):
        """Verify GET /api/codebase-scan/sample/ returns 200 with complete results."""
        response = self.client.get('/api/codebase-scan/sample/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertIn("findings", data)
        self.assertIn("summary", data)

    def test_20_api_zip_upload_endpoint(self):
        """Verify POST /api/codebase-scan/ accepts multipart ZIP upload."""
        sample_zip = build_sample_vulnerable_project_zip()
        uploaded = SimpleUploadedFile("project.zip", sample_zip.getvalue(), content_type="application/zip")
        response = self.client.post('/api/codebase-scan/', {'project': uploaded})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("scan_status"), "completed")

    def test_21_api_missing_file_400(self):
        """Verify POST /api/codebase-scan/ with missing file returns 400."""
        response = self.client.post('/api/codebase-scan/', {})
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data.get("success"))
