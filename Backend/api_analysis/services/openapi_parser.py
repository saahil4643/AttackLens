"""
OpenAPI & Swagger Specification Discovery & Parsing Service
"""
import json
import urllib.parse
from typing import Dict, Any, List, Tuple, Optional
import requests
import yaml
from .models import ApiEndpoint, ApiParameter, ApiAuthIndicator, ApiResponseInfo, ApiDocumentation, ApiFinding

COMMON_DOC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api-docs/openapi.json",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/v1/openapi.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
]


def extract_schema_type(schema_dict: Optional[Dict[str, Any]]) -> str:
    """Recursively resolves schema type string."""
    if not schema_dict or not isinstance(schema_dict, dict):
        return "unknown"
    if "type" in schema_dict:
        t = schema_dict["type"]
        if isinstance(t, list):
            return "/".join(str(x) for x in t)
        return str(t)
    if "$ref" in schema_dict:
        return schema_dict["$ref"].split("/")[-1]
    if "properties" in schema_dict:
        return "object"
    if "items" in schema_dict:
        return f"array[{extract_schema_type(schema_dict.get('items'))}]"
    return "unknown"


def parse_openapi_spec(
    spec_data: Dict[str, Any],
    doc_url: str,
    base_target: str
) -> Tuple[ApiDocumentation, List[ApiEndpoint], List[ApiFinding]]:
    """
    Parses OpenAPI 3.x / Swagger 2.0 object into structured ApiDocumentation and ApiEndpoint models.
    """
    endpoints: List[ApiEndpoint] = []
    findings: List[ApiFinding] = []

    parsed_target = urllib.parse.urlparse(base_target)
    default_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
    hostname = parsed_target.hostname or ""

    is_oas3 = "openapi" in spec_data
    is_swagger2 = "swagger" in spec_data

    info = spec_data.get("info", {})
    title = info.get("title", "API Specification")
    api_version = info.get("version", "v1")

    # 1. Parse Security Schemes
    security_schemes: Dict[str, Dict[str, Any]] = {}
    auth_names = []

    if is_oas3:
        components = spec_data.get("components", {})
        security_schemes = components.get("securitySchemes", {})
    elif is_swagger2:
        security_schemes = spec_data.get("securityDefinitions", {})

    for s_name, s_def in security_schemes.items():
        s_type = s_def.get("type", "unknown")
        auth_names.append(f"{s_name} ({s_type})")

    doc_info = ApiDocumentation(
        url=doc_url,
        doc_format="openapi_3" if is_oas3 else ("swagger_2" if is_swagger2 else "api_docs"),
        title=title,
        version=api_version,
        endpoint_count=0,
        auth_schemes=auth_names
    )

    # 2. Parse Base Path / Servers
    base_prefix = ""
    if is_oas3:
        servers = spec_data.get("servers", [])
        if servers and isinstance(servers, list):
            first_srv = servers[0].get("url", "")
            if first_srv.startswith("/"):
                base_prefix = first_srv.rstrip("/")
            elif "://" in first_srv:
                base_prefix = urllib.parse.urlparse(first_srv).path.rstrip("/")
    elif is_swagger2:
        base_prefix = spec_data.get("basePath", "").rstrip("/")

    # 3. Parse Paths & Operations
    paths = spec_data.get("paths", {})
    if isinstance(paths, dict):
        for path_key, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            full_path = f"{base_prefix}{path_key}"
            full_url = urllib.parse.urljoin(default_origin, full_path)

            # Common path-level parameters
            path_level_params = path_item.get("parameters", [])

            for method in ["get", "post", "put", "patch", "delete", "options", "head"]:
                if method not in path_item or not isinstance(path_item[method], dict):
                    continue

                op = path_item[method]
                op_summary = op.get("summary") or op.get("operationId")
                op_description = op.get("description")

                # Extract Parameters
                extracted_params: List[ApiParameter] = []
                all_raw_params = list(path_level_params) + list(op.get("parameters", []))

                for p in all_raw_params:
                    if not isinstance(p, dict):
                        continue
                    p_name = p.get("name", "")
                    p_in = p.get("in", "query")
                    p_req = p.get("required", False)
                    p_desc = p.get("description", "")
                    p_schema = p.get("schema") or p
                    p_type = extract_schema_type(p_schema)

                    extracted_params.append(ApiParameter(
                        name=p_name,
                        location=p_in,
                        param_type=p_type,
                        required=p_req,
                        description=p_desc,
                        example=p.get("example")
                    ))

                # Extract Request Body (OAS 3)
                req_body = op.get("requestBody")
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    for c_type, c_obj in content.items():
                        b_schema = c_obj.get("schema", {})
                        extracted_params.append(ApiParameter(
                            name="requestBody",
                            location="body",
                            param_type=extract_schema_type(b_schema),
                            required=req_body.get("required", False),
                            description=f"Payload Content-Type: {c_type}"
                        ))

                # Extract Authentication indicator
                op_security = op.get("security", spec_data.get("security", []))
                auth_req = bool(op_security and len(op_security) > 0)
                auth_type_str = "none"
                auth_evidence = []

                if auth_req:
                    auth_evidence.append("Declared in OpenAPI security requirements")
                    for sec_obj in op_security:
                        for s_key in sec_obj.keys():
                            scheme_info = security_schemes.get(s_key, {})
                            s_type = scheme_info.get("type", "unknown").lower()
                            if s_type in ("http", "oauth2", "apikey", "bearer"):
                                auth_type_str = scheme_info.get("scheme", s_type).lower()
                            else:
                                auth_type_str = s_type
                            auth_evidence.append(f"Scheme: {s_key} ({s_type})")

                # Extract Response details
                responses = op.get("responses", {})
                expected_status = 200
                res_content_type = "application/json"
                res_structure = "object"

                for status_code_key, res_obj in responses.items():
                    if str(status_code_key).isdigit():
                        expected_status = int(status_code_key)
                    if isinstance(res_obj, dict):
                        res_content = res_obj.get("content", {})
                        if res_content:
                            res_content_type = list(res_content.keys())[0]
                            res_schema = res_content[res_content_type].get("schema", {})
                            res_structure = extract_schema_type(res_schema)
                    break

                endpoint_obj = ApiEndpoint(
                    endpoint=full_url,
                    path=full_path,
                    hostname=hostname,
                    method=method.upper(),
                    api_type="REST",
                    version=api_version,
                    source="openapi",
                    summary=op_summary,
                    description=op_description,
                    parameters=extracted_params,
                    authentication=ApiAuthIndicator(
                        required=auth_req,
                        auth_type=auth_type_str,
                        evidence=auth_evidence
                    ),
                    response=ApiResponseInfo(
                        status_code=expected_status,
                        content_type=res_content_type,
                        structure=res_structure
                    ),
                    confidence=0.99
                )
                endpoints.append(endpoint_obj)

    doc_info.endpoint_count = len(endpoints)

    # Observation finding
    findings.append(ApiFinding(
        id="API-DOC-001",
        title="Public OpenAPI / Swagger Specification Discovered",
        category="api_documentation",
        severity="info",
        confidence=0.99,
        description=f"Public API documentation was discovered at '{doc_url}'. It exposes {len(endpoints)} endpoint operation definitions and {len(auth_names)} authentication schemes.",
        evidence={
            "documentation_url": doc_url,
            "format": doc_info.format,
            "api_title": title,
            "api_version": api_version,
            "endpoint_count": len(endpoints),
            "auth_schemes": auth_names
        },
        recommendation="Ensure internal-only API endpoints and sensitive parameters are not unintentionally exposed in public documentation."
    ))

    return doc_info, endpoints, findings


def probe_and_parse_openapi(
    base_target: str,
    known_urls: Optional[List[str]] = None,
    timeout: float = 4.0
) -> Tuple[List[ApiDocumentation], List[ApiEndpoint], List[ApiFinding]]:
    """
    Probes common OpenAPI/Swagger paths and extracts documentation and endpoints.
    """
    discovered_docs: List[ApiDocumentation] = []
    discovered_endpoints: List[ApiEndpoint] = []
    findings: List[ApiFinding] = []

    parsed_target = urllib.parse.urlparse(base_target)
    base_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

    urls_to_check = set()
    for path in COMMON_DOC_PATHS:
        urls_to_check.add(urllib.parse.urljoin(base_origin, path))

    if known_urls:
        for u in known_urls:
            u_lower = u.lower()
            if any(k in u_lower for k in ("openapi", "swagger", "api-doc")):
                urls_to_check.add(u)

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackLens/1.0",
        "Accept": "application/json,application/yaml,text/yaml,application/x-yaml,text/html,*/*"
    })

    for check_url in list(urls_to_check):
        try:
            resp = session.get(check_url, timeout=timeout, allow_redirects=True, verify=False)
            if resp.status_code != 200:
                continue

            content_type = resp.headers.get("Content-Type", "").lower()
            text = resp.text.strip()
            if not text:
                continue

            parsed_spec = None
            if "json" in content_type or text.startswith("{"):
                try:
                    parsed_spec = json.loads(text)
                except Exception:
                    pass
            
            if parsed_spec is None:
                try:
                    parsed_spec = yaml.safe_load(text)
                except Exception:
                    pass

            if isinstance(parsed_spec, dict) and ("openapi" in parsed_spec or "swagger" in parsed_spec):
                doc_meta, eps, doc_findings = parse_openapi_spec(
                    spec_data=parsed_spec,
                    doc_url=resp.url,
                    base_target=base_target
                )
                discovered_docs.append(doc_meta)
                discovered_endpoints.extend(eps)
                findings.extend(doc_findings)
                # Found valid spec, limit redundant checks
                if len(discovered_docs) >= 2:
                    break
        except Exception:
            continue

    return discovered_docs, discovered_endpoints, findings
