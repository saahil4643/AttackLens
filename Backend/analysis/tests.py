from django.test import TestCase, Client
from analysis.engine.headers import analyze_security_headers, parse_csp_directives, parse_hsts_attributes
from analysis.engine.cookies import analyze_cookies, parse_raw_cookie_header
from analysis.engine.cors import analyze_cors_configuration
from analysis.engine.scoring import calculate_security_score
from analysis.engine.info_disclosure import analyze_information_disclosure
from analysis.engine.methods import check_safe_http_methods


class SecurityConfigurationTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_csp_parsing_and_analysis(self):
        # 1. Strong CSP
        strong_csp = "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        directives = parse_csp_directives(strong_csp)
        self.assertIn("default-src", directives)
        self.assertEqual(directives["object-src"], ["'none'"])

        headers = {"Content-Security-Policy": strong_csp}
        res, findings = analyze_security_headers(headers, is_https=True)
        self.assertTrue(res["Content-Security-Policy"]["present"])
        self.assertEqual(res["Content-Security-Policy"]["status"], "pass")
        self.assertEqual(len([f for f in findings if f.category == "security_headers" and "Content-Security-Policy" in f.title]), 0)

        # 2. Weak CSP (unsafe-inline, missing object-src)
        weak_csp = "script-src 'self' 'unsafe-inline' 'unsafe-eval' *"
        res_weak, findings_weak = analyze_security_headers({"Content-Security-Policy": weak_csp}, is_https=True)
        self.assertEqual(res_weak["Content-Security-Policy"]["status"], "warning")
        self.assertTrue(any("Weak Content-Security-Policy" in f.title for f in findings_weak))

        # 3. Missing CSP
        res_missing, findings_missing = analyze_security_headers({}, is_https=True)
        self.assertFalse(res_missing["Content-Security-Policy"]["present"])
        self.assertEqual(res_missing["Content-Security-Policy"]["status"], "fail")
        self.assertTrue(any("Missing Content-Security-Policy" in f.title for f in findings_missing))

    def test_hsts_analysis(self):
        # Valid HSTS
        hsts_val = "max-age=31536000; includeSubDomains; preload"
        parsed = parse_hsts_attributes(hsts_val)
        self.assertEqual(parsed["max_age"], 31536000)
        self.assertTrue(parsed["include_subdomains"])
        self.assertTrue(parsed["preload"])

        headers = {"Strict-Transport-Security": hsts_val}
        res, findings = analyze_security_headers(headers, is_https=True)
        self.assertTrue(res["Strict-Transport-Security"]["present"])
        self.assertEqual(res["Strict-Transport-Security"]["status"], "pass")

        # Missing HSTS over HTTPS
        res_none, findings_none = analyze_security_headers({}, is_https=True)
        self.assertTrue(any("Missing Strict-Transport-Security" in f.title for f in findings_none))

    def test_xfo_and_csp_frame_ancestors(self):
        # When XFO is missing but CSP frame-ancestors is present
        headers = {"Content-Security-Policy": "frame-ancestors 'self'"}
        res, findings = analyze_security_headers(headers, is_https=True)
        self.assertEqual(res["X-Frame-Options"]["status"], "pass")
        self.assertFalse(any("Clickjacking" in f.title for f in findings))

    def test_cookie_security_and_no_value_exposure(self):
        raw_cookie = "sessionid=secret_token_12345; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com"
        meta = parse_raw_cookie_header(raw_cookie)
        self.assertEqual(meta["name"], "sessionid")
        self.assertTrue(meta["secure"])
        self.assertTrue(meta["httponly"])
        self.assertEqual(meta["samesite"], "Lax")
        self.assertTrue(meta["is_session_indicator"])
        # Ensure secret value is NEVER stored in meta
        self.assertNotIn("secret_token_12345", str(meta))

        # Insecure session cookie (missing Secure & HttpOnly)
        insecure_cookie = "sessionid=secret_value; Path=/"
        cookies_meta, findings = analyze_cookies([insecure_cookie], is_https=True)
        self.assertFalse(cookies_meta[0]["secure"])
        self.assertFalse(cookies_meta[0]["httponly"])
        self.assertTrue(any("Missing 'Secure'" in f.title for f in findings))
        self.assertTrue(any("Missing 'HttpOnly'" in f.title for f in findings))
        # Ensure secret value is NOT leaked in findings evidence
        self.assertNotIn("secret_value", str([f.to_dict() for f in findings]))

    def test_cors_analysis(self):
        # 1. Dangerous CORS (wildcard + credentials)
        bad_cors = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
        res, findings = analyze_cors_configuration(bad_cors)
        self.assertEqual(res["risk_level"], "high")
        self.assertTrue(any("Wildcard Origin With Credentials" in f.title for f in findings))

        # 2. Public Wildcard API without credentials
        pub_cors = {"Access-Control-Allow-Origin": "*"}
        res_pub, findings_pub = analyze_cors_configuration(pub_cors)
        self.assertEqual(res_pub["risk_level"], "info")

    def test_info_disclosure_headers(self):
        headers = {
            "Server": "nginx/1.24.0",
            "X-Powered-By": "Express",
            "X-AspNet-Version": "4.0.30319"
        }
        disclosed, findings = analyze_information_disclosure(headers)
        self.assertIn("Server", disclosed)
        self.assertIn("X-Powered-By", disclosed)
        self.assertTrue(any(f.category == "information_disclosure" for f in findings))

    def test_security_score_calculation(self):
        findings = [
            {"severity": "medium", "title": "Missing CSP"},
            {"severity": "low", "title": "Server Banner"}
        ]
        score_data = calculate_security_score({}, {}, [], {}, findings)
        self.assertEqual(score_data["score_name"], "Web Security Configuration Score")
        self.assertLess(score_data["score"], 100)
        self.assertIn(score_data["grade"], ["A+", "A", "B", "C", "D", "F"])

    def test_security_configuration_api_endpoint(self):
        # Missing target parameter
        resp = self.client.get("/api/security-configuration/")
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertFalse(data["success"])

        # Invalid target domain resolution
        resp_invalid = self.client.get("/api/security-configuration/?target=invalid-non-existent-domain-999.test")
        self.assertEqual(resp_invalid.status_code, 400)
        data_invalid = resp_invalid.json()
        self.assertEqual(data_invalid["scan_status"], "failed")
