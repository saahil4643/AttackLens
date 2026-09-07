import json
from django.test import TestCase, Client
from api_analysis.services.parameter_analyzer import extract_parameters_from_url, infer_primitive_type
from api_analysis.services.openapi_parser import parse_openapi_spec
from api_analysis.services.auth_detector import analyze_auth_from_response
from api_analysis.services.api_scanner import extract_api_version, inspect_json_structure


class ApiAnalysisTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_parameter_extraction_and_typing(self):
        # 1. Bracket path parameter
        params1 = extract_parameters_from_url("https://example.com/api/v1/users/{userId}")
        self.assertEqual(len(params1), 1)
        self.assertEqual(params1[0].name, "userId")
        self.assertEqual(params1[0].location, "path")
        self.assertTrue(params1[0].required)

        # 2. Colon path parameter + query parameters
        params2 = extract_parameters_from_url("https://example.com/api/orders/:orderId?page=2&limit=50&active=true&search=laptop")
        p_names = {p.name: p for p in params2}
        self.assertIn("orderId", p_names)
        self.assertEqual(p_names["orderId"].location, "path")

        self.assertIn("page", p_names)
        self.assertEqual(p_names["page"].location, "query")
        self.assertEqual(p_names["page"].type, "integer")

        self.assertIn("active", p_names)
        self.assertEqual(p_names["active"].type, "boolean")

        self.assertIn("search", p_names)
        self.assertEqual(p_names["search"].type, "string")

        # 3. Dynamic numeric segment
        params3 = extract_parameters_from_url("https://example.com/api/products/4982")
        self.assertTrue(any(p.location == "path" and p.type == "integer" for p in params3))

    def test_sensitive_parameter_redaction(self):
        params = extract_parameters_from_url("https://example.com/api/auth/callback?access_token=super_secret_token_value_12345&state=xyz")
        token_param = next(p for p in params if p.name == "access_token")
        self.assertEqual(token_param.example, "[REDACTED]")

    def test_openapi_v3_parsing(self):
        oas3_spec = {
            "openapi": "3.0.1",
            "info": {
                "title": "Sample Store API",
                "version": "v1.2.0"
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            },
            "security": [{"bearerAuth": []}],
            "paths": {
                "/api/v1/inventory": {
                    "get": {
                        "summary": "List inventory items",
                        "parameters": [
                            {
                                "name": "category",
                                "in": "query",
                                "required": False,
                                "schema": {"type": "string"}
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "application/json": {
                                        "schema": {"type": "array"}
                                    }
                                }
                            }
                        }
                    },
                    "post": {
                        "summary": "Create item",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Created"}
                        }
                    }
                }
            }
        }

        doc_info, endpoints, findings = parse_openapi_spec(oas3_spec, "https://example.com/openapi.json", "https://example.com")
        self.assertEqual(doc_info.title, "Sample Store API")
        self.assertEqual(doc_info.version, "v1.2.0")
        self.assertEqual(len(endpoints), 2)

        get_ep = next(e for e in endpoints if e.method == "GET")
        self.assertEqual(get_ep.path, "/api/v1/inventory")
        self.assertTrue(get_ep.authentication.required)
        self.assertEqual(get_ep.response.status_code, 200)
        self.assertEqual(get_ep.response.structure, "array")
        self.assertEqual(len(get_ep.parameters), 1)

        post_ep = next(e for e in endpoints if e.method == "POST")
        self.assertTrue(any(p.location == "body" for p in post_ep.parameters))
        self.assertEqual(post_ep.response.status_code, 201)

    def test_swagger_v2_parsing(self):
        swagger_spec = {
            "swagger": "2.0",
            "info": {"title": "Legacy API", "version": "v1"},
            "basePath": "/api",
            "paths": {
                "/users/{id}": {
                    "get": {
                        "summary": "Get User",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "type": "integer"}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }
        doc_info, endpoints, findings = parse_openapi_spec(swagger_spec, "https://example.com/swagger.json", "https://example.com")
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].path, "/api/users/{id}")
        self.assertEqual(endpoints[0].parameters[0].name, "id")
        self.assertEqual(endpoints[0].parameters[0].type, "integer")

    def test_auth_detection_from_response(self):
        # 401 with Bearer WWW-Authenticate
        auth_info, _ = analyze_auth_from_response(
            status_code=401,
            headers={"WWW-Authenticate": "Bearer realm='api', error='invalid_token'"},
            endpoint_url="https://example.com/api/secure"
        )
        self.assertTrue(auth_info.required)
        self.assertEqual(auth_info.type, "bearer")

        # 401 with Basic WWW-Authenticate
        auth_info2, _ = analyze_auth_from_response(
            status_code=401,
            headers={"WWW-Authenticate": "Basic realm='Restricted'"},
            endpoint_url="https://example.com/api/admin"
        )
        self.assertTrue(auth_info2.required)
        self.assertEqual(auth_info2.type, "basic")

    def test_api_version_extraction(self):
        self.assertEqual(extract_api_version("/api/v1/users"), "v1")
        self.assertEqual(extract_api_version("/rest/v2/orders/123"), "v2")
        self.assertEqual(extract_api_version("/v3/graphql"), "v3")
        self.assertIsNone(extract_api_version("/api/users"))

    def test_json_structure_inspection(self):
        self.assertEqual(inspect_json_structure('{"id": 1, "name": "test"}'), "object")
        self.assertEqual(inspect_json_structure('[{"id": 1}, {"id": 2}]'), "array")
        self.assertEqual(inspect_json_structure('"hello world"'), "primitive")
        self.assertEqual(inspect_json_structure('true'), "primitive")
        self.assertEqual(inspect_json_structure('<html>not json</html>'), "unknown")

    def test_api_analysis_endpoint_validation(self):
        # Missing target parameter
        resp = self.client.get("/api/api-analysis/")
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertFalse(data["success"])

        # Invalid non-existent target
        resp_inv = self.client.get("/api/api-analysis/?target=invalid-domain-999999.test")
        self.assertEqual(resp_inv.status_code, 400)
        data_inv = resp_inv.json()
        self.assertEqual(data_inv["scan_status"], "failed")
