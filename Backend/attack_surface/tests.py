"""
Unit tests for Web Application Attack-Surface Analysis module.
"""
from django.test import TestCase, Client
from django.urls import reverse

from .services.endpoint_classifier import classify_endpoint, classify_form
from .services.authentication_surface import build_authentication_surface, build_session_surface
from .services.functionality_classifier import build_functionality_map
from .services.test_candidate_planner import generate_test_candidates
from .services.models import (
    EndpointSurfaceRecord,
    FormSurfaceRecord,
    ApiSurfaceRecord,
    AdminSurfaceRecord,
    FileUploadSurfaceRecord,
    DocSurfaceRecord,
    OperationalSurfaceRecord,
)


class EndpointClassifierTest(TestCase):
    def test_endpoint_classification(self):
        cat, conf = classify_endpoint("https://example.com/api/v1/users", content_type="application/json")
        self.assertEqual(cat, "api")
        self.assertGreaterEqual(conf, 0.90)

        cat, _ = classify_endpoint("/login")
        self.assertEqual(cat, "authentication")

        cat, _ = classify_endpoint("/admin/dashboard")
        self.assertEqual(cat, "administrative")

        cat, _ = classify_endpoint("/assets/app.min.js")
        self.assertEqual(cat, "static")

        cat, _ = classify_endpoint("/upload/document")
        self.assertEqual(cat, "upload")

        cat, _ = classify_endpoint("/swagger.json")
        self.assertEqual(cat, "documentation")

        cat, _ = classify_endpoint("/healthz")
        self.assertEqual(cat, "health")

    def test_form_classification(self):
        # Login form
        cat, conf = classify_form("/login", "POST", ["username", "password"], ["text", "password"])
        self.assertEqual(cat, "login")
        self.assertGreaterEqual(conf, 0.90)

        # File upload form
        cat, _ = classify_form("/upload", "POST", ["file", "submit"], ["file", "submit"])
        self.assertEqual(cat, "upload")

        # Search form
        cat, _ = classify_form("/search", "GET", ["q"], ["text"])
        self.assertEqual(cat, "search")

        # Registration form
        cat, _ = classify_form("/register", "POST", ["email", "password", "password_confirm", "full_name"], ["email", "password", "password", "text"])
        self.assertEqual(cat, "registration")


class AuthenticationSurfaceTest(TestCase):
    def test_auth_and_session_surface(self):
        endpoints = [{"path": "/login", "method": "POST", "source": "crawler"}]
        forms = [{
            "action": "/auth/signin",
            "method": "POST",
            "classification": "login",
            "input_names": ["user", "password"]
        }]
        apis = [{
            "endpoint": "https://example.com/api/token",
            "path": "/api/token",
            "method": "POST",
            "authentication": {"required": True, "type": "bearer"}
        }]

        auth_records = build_authentication_surface(endpoints, forms, apis)
        self.assertGreaterEqual(len(auth_records), 2)
        types = [a.type for a in auth_records]
        self.assertIn("login", types)

        # Session surface - verify no values exposed
        cookies = [
            {"name": "sessionid", "secure": True, "httponly": True, "samesite": "Lax"},
            {"name": "theme", "secure": False, "httponly": False, "samesite": "None"}
        ]
        session_records = build_session_surface(cookies)
        self.assertEqual(len(session_records), 2)
        sess_cookie = next(s for s in session_records if s.cookie_name == "sessionid")
        self.assertTrue(sess_cookie.is_secure)
        self.assertTrue(sess_cookie.is_httponly)
        self.assertTrue(sess_cookie.likely_session_indicator)


class FunctionalityClassifierTest(TestCase):
    def test_functionality_map(self):
        func_map = build_functionality_map(
            endpoints=[{"path": "/login", "method": "GET"}],
            forms=[{"action": "/search", "classification": "search", "input_names": ["q"]}],
            api_endpoints=[{"endpoint": "/api/v1/users", "path": "/api/v1/users"}],
            admin_surfaces=[{"endpoint": "/admin"}],
            upload_surfaces=[{"endpoint": "/upload"}],
            doc_surfaces=[{"documentation_url": "/openapi.json", "spec_format": "openapi"}],
            operational_endpoints=[{"endpoint": "/health"}]
        )
        cat_names = [f.category for f in func_map]
        self.assertIn("authentication", cat_names)
        self.assertIn("search", cat_names)
        self.assertIn("administration", cat_names)
        self.assertIn("file_upload", cat_names)
        self.assertIn("documentation", cat_names)
        self.assertIn("health", cat_names)


class TestCandidatePlannerTest(TestCase):
    def test_candidate_generation(self):
        candidates = generate_test_candidates(
            auth_surfaces=[{"endpoint": "/login", "method": "POST", "type": "login"}],
            upload_surfaces=[{"endpoint": "/upload", "method": "POST"}],
            admin_surfaces=[{"endpoint": "/admin"}],
            api_endpoints=[{"path": "/api/items", "authentication": {"required": True, "type": "bearer"}}],
            parameters=[{"name": "id", "location": "query", "endpoints": ["/api/items"]}],
            session_surfaces=[{"cookie_name": "sessionid", "is_secure": False, "is_httponly": False}],
            websockets=[{"url": "wss://example.com/socket"}],
            doc_surfaces=[{"documentation_url": "/swagger.json", "spec_format": "swagger"}],
            debug_surfaces=[{"endpoint": "/", "type": "server_disclosure"}]
        )
        self.assertGreaterEqual(len(candidates), 5)
        priorities = [c.priority for c in candidates]
        self.assertIn("high", priorities)
        self.assertIn("medium", priorities)


class AttackSurfaceViewTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_missing_target_parameter(self):
        response = self.client.get('/web-application-analysis/')
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data.get("success", True))

    def test_invalid_target_hostname(self):
        response = self.client.get('/web-application-analysis/?target=invalid-nonexistent-domain-99999.xyz')
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertFalse(data.get("success", True))
        self.assertIn("error", data)
