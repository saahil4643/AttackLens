"""
Overall Web Application Attack-Surface Analyzer & Correlator Engine.
"""
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Callable, Set

from scan.views import (
    clean_and_extract_target,
    parse_request_params,
    crawl_target_endpoints,
    perform_http_detection,
    scan_single_port,
    COMMON_PORTS,
)
from technology_fingerprinting.views import analyze_target_technologies
from analysis.engine.analyzer import analyze_security_configuration
from tls_analysis.services.tls_scanner import scan_tls_security
from api_analysis.services.api_scanner import scan_api_inventory

from .models import (
    AssetRecord,
    WebServiceRecord,
    EndpointSurfaceRecord,
    ApiSurfaceRecord,
    AuthSurfaceRecord,
    SessionSurfaceRecord,
    FormSurfaceRecord,
    FileUploadSurfaceRecord,
    AdminSurfaceRecord,
    DocSurfaceRecord,
    DebugErrorSurfaceRecord,
    OperationalSurfaceRecord,
    WebSocketSurfaceRecord,
    ExternalDependencyRecord,
    ParameterSurfaceRecord,
    FunctionalityCategoryRecord,
    TestCandidateRecord,
    AttackSurfaceSummary,
)
from .endpoint_classifier import classify_endpoint, classify_form
from .authentication_surface import build_authentication_surface, build_session_surface
from .functionality_classifier import build_functionality_map
from .test_candidate_planner import generate_test_candidates


# Common external service domain heuristics
EXTERNAL_DOMAIN_CATEGORIES = {
    "cdn": ["cdn", "cloudflare", "akamai", "fastly", "cloudfront", "jsdelivr", "unpkg", "cdnjs", "static"],
    "analytics": ["google-analytics", "googletagmanager", "segment", "hotjar", "mixpanel", "sentry", "datadog", "newrelic"],
    "payment": ["stripe", "paypal", "braintree", "square", "adyen", "razorpay"],
    "identity": ["auth0", "okta", "cognito", "firebase", "accounts.google", "login.microsoftonline"],
    "storage": ["s3.amazonaws", "storage.googleapis", "blob.core.windows", "cloudinary"],
    "font": ["fonts.googleapis", "fonts.gstatic", "typekit", "use.typekit"],
}


def classify_external_domain(host: str) -> str:
    """Categorizes an external host into cdn, analytics, payment, identity, storage, font, or api."""
    host_lower = host.lower()
    for category, keywords in EXTERNAL_DOMAIN_CATEGORIES.items():
        if any(kw in host_lower for kw in keywords):
            return category
    if "api." in host_lower:
        return "api"
    return "unknown"


def analyze_web_application_attack_surface(
    raw_target: str,
    max_crawl_pages: int = 15,
    event_callback: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None
) -> Dict[str, Any]:
    """
    Executes a comprehensive, non-destructive attack-surface mapping and correlation
    across all reconnaissance layers of Attack Lens.
    """
    start_time = time.time()

    def notify(event_type: str, message: str, data: Optional[Dict[str, Any]] = None):
        if event_callback:
            event_callback(event_type, message, data)

    # 1. Target Normalization & Host Validation
    cleaned_target = clean_and_extract_target(raw_target)
    if not cleaned_target:
        return {
            "success": False,
            "target": raw_target,
            "error": f"Invalid target '{raw_target}'. Could not extract valid hostname or IP address."
        }

    notify("target_init", f"Resolving target DNS and verifying scope for '{cleaned_target}'...")

    # DNS Resolution
    ip = None
    try:
        addr_info = socket.getaddrinfo(cleaned_target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ip = addr_info[0][4][0]
    except socket.gaierror:
        return {
            "success": False,
            "target": raw_target,
            "cleaned_target": cleaned_target,
            "error": f"DNS resolution failed for '{cleaned_target}'. Host does not exist or is offline."
        }
    except Exception as e:
        return {
            "success": False,
            "target": raw_target,
            "cleaned_target": cleaned_target,
            "error": f"Host resolution error: {str(e)}"
        }

    # Determine base scheme & target info for crawler
    has_scheme = "://" in raw_target
    scheme = "https"
    if has_scheme:
        scheme = urllib.parse.urlparse(raw_target).scheme or "https"

    target_info = {
        "raw_target": raw_target,
        "hostname": cleaned_target,
        "scheme": scheme,
        "explicit_port": None,
        "has_explicit_scheme": has_scheme,
        "path": "/"
    }

    # 2. Port & Web Service Discovery (Quick Scan)
    notify("port_scan", f"Scanning core web ports on {cleaned_target} ({ip})...")
    quick_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000]
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_single_port, ip, p, 0.5, 0.01): p for p in quick_ports}
        for future in as_completed(futures):
            p = future.result()
            if p is not None:
                open_ports.append(p)
    open_ports.sort()

    # 3. HTTP / HTTPS Inspection
    notify("http_detection", f"Inspecting HTTP/HTTPS service and response headers...")
    http_data = {}
    try:
        http_data = perform_http_detection(target_info)
    except Exception as e:
        http_data = {"error": str(e), "headers": {}}

    final_url = http_data.get("final_url") or f"{scheme}://{cleaned_target}/"
    page_title = http_data.get("page_title")
    server_header = http_data.get("server") or http_data.get("headers", {}).get("server")
    status_code = http_data.get("status_code", 200)

    # 4. Technology Fingerprinting
    notify("technology_fingerprint", "Fingerprinting application technologies, CMS, and frameworks...")
    tech_data = {}
    technologies_list = []
    try:
        tech_data = analyze_target_technologies(raw_target)
        technologies_list = [t.get("name") for t in tech_data.get("technologies", []) if t.get("name")]
    except Exception as e:
        tech_data = {"error": str(e), "technologies": []}

    # 5. Endpoint & Surface Crawl
    notify("endpoint_discovery", f"Discovering web surface, routes, and forms (max {max_crawl_pages} pages)...")
    crawl_data = {}
    try:
        crawl_data = crawl_target_endpoints(target_info, max_pages=max_crawl_pages)
    except Exception as e:
        crawl_data = {
            "endpoints": [final_url],
            "in_scope_endpoints": [final_url],
            "out_of_scope_endpoints": [],
            "forms": [],
            "javascript_files": [],
            "api_paths": [],
            "scope_summary": {"external_domains": []}
        }

    # 6. Security Configuration Analysis
    notify("security_config", "Analyzing security headers, cookie flags, and CORS configuration...")
    sec_config_data = {}
    try:
        sec_config_data = analyze_security_configuration(cleaned_target, port=http_data.get("port"))
    except Exception as e:
        sec_config_data = {"error": str(e), "findings": [], "cookies": []}

    # 7. TLS / SSL Analysis
    notify("tls_analysis", "Analyzing TLS/SSL certificate, cipher suites, and protocols...")
    tls_data = {}
    try:
        tls_data = scan_tls_security(cleaned_target, port=443)
    except Exception as e:
        tls_data = {"error": str(e), "protocols": {}, "certificate": {}}

    # 8. API Deep Analysis & Inventory
    notify("api_analysis", "Cataloging REST/GraphQL APIs, parameters, and OpenAPI specifications...")
    api_data = {}
    try:
        api_data = scan_api_inventory(raw_target, max_crawl_pages=max_crawl_pages)
    except Exception as e:
        api_data = {"endpoints": [], "api_documentation": [], "observations": [], "findings": []}

    # 9. Synthesize & Correlate Attack Surface Components
    notify("attack_surface_correlation", "Correlating and structuring overall attack surface inventory...")

    # A. Asset Inventory
    assets: List[AssetRecord] = []
    seen_assets: Set[str] = set()

    # In-scope Target Host asset
    main_asset_sig = f"{cleaned_target}:{ip}"
    assets.append(AssetRecord(
        host=cleaned_target,
        ip=ip,
        port=http_data.get("port") or (443 if 443 in open_ports else (80 if 80 in open_ports else None)),
        protocol=http_data.get("protocol", "HTTPS"),
        service="web",
        scope="in_scope",
        source="dns_resolver"
    ))
    seen_assets.add(main_asset_sig)

    # Open Ports assets
    for p in open_ports:
        port_sig = f"{cleaned_target}:{p}"
        if port_sig not in seen_assets:
            seen_assets.add(port_sig)
            assets.append(AssetRecord(
                host=cleaned_target,
                ip=ip,
                port=p,
                protocol="HTTPS" if p in (443, 8443) else "HTTP",
                service=COMMON_PORTS.get(p, "web"),
                scope="in_scope",
                source="port_scanner"
            ))

    # External Domains assets
    discovered_external_domains = crawl_data.get("scope_summary", {}).get("external_domains", [])
    for ext_d in discovered_external_domains:
        if ext_d and ext_d not in seen_assets and ext_d != cleaned_target:
            seen_assets.add(ext_d)
            assets.append(AssetRecord(
                host=ext_d,
                ip=None,
                port=None,
                protocol="HTTPS",
                service="external_service",
                scope="external_dependency",
                source="crawler_references"
            ))

    # B. Web Service Inventory
    web_services: List[WebServiceRecord] = []
    web_services.append(WebServiceRecord(
        host=cleaned_target,
        port=http_data.get("port") or 443,
        protocol=http_data.get("protocol", "HTTPS"),
        status_code=status_code,
        server=server_header,
        final_url=final_url,
        page_title=page_title,
        technologies=technologies_list[:8]
    ))

    # C. Endpoint Surface Inventory
    all_raw_endpoints = crawl_data.get("in_scope_endpoints", []) or [final_url]
    endpoints_inventory: List[EndpointSurfaceRecord] = []
    seen_endpoints: Set[str] = set()

    for ep_url in all_raw_endpoints:
        parsed = urllib.parse.urlparse(ep_url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        if path in seen_endpoints:
            continue
        seen_endpoints.add(path)

        cat, conf = classify_endpoint(ep_url, source="crawler")
        endpoints_inventory.append(EndpointSurfaceRecord(
            path=path,
            url=ep_url,
            method="GET",
            source="crawler",
            status_code=200 if ep_url == final_url else None,
            category=cat,
            confidence=conf
        ))

    # D. API Surface Inventory
    api_endpoints_raw = api_data.get("endpoints", [])
    apis_inventory: List[ApiSurfaceRecord] = []
    for a in api_endpoints_raw:
        apis_inventory.append(ApiSurfaceRecord(
            endpoint=a.get("endpoint", ""),
            path=a.get("path", ""),
            method=a.get("method", "GET"),
            type=a.get("type", "REST"),
            version=a.get("version"),
            parameters=a.get("parameters", []),
            authentication=a.get("authentication"),
            status_code=a.get("response", {}).get("status_code"),
            content_type=a.get("response", {}).get("content_type"),
            documentation_source=a.get("source"),
            rate_limit=a.get("rate_limit"),
            confidence=a.get("confidence", 0.95)
        ))

    # E. Forms Inventory
    raw_forms = crawl_data.get("forms", [])
    forms_inventory: List[FormSurfaceRecord] = []
    seen_forms: Set[str] = set()

    for f in raw_forms:
        action = f.get("action") or final_url
        method = f.get("method", "GET").upper()
        params = f.get("parameters", [])
        input_names = [p.get("name") for p in params if p.get("name")]
        input_types = [p.get("type") for p in params if p.get("type")]

        form_sig = f"{method}:{action}:{','.join(sorted(input_names))}"
        if form_sig in seen_forms:
            continue
        seen_forms.add(form_sig)

        cls, conf = classify_form(action, method, input_names, input_types)
        forms_inventory.append(FormSurfaceRecord(
            action=action,
            method=method,
            input_names=input_names,
            input_types=input_types,
            fields_count=len(input_names),
            classification=cls,
            confidence=conf
        ))

    # F. File Upload Surface
    file_uploads: List[FileUploadSurfaceRecord] = []
    seen_uploads: Set[str] = set()

    for f in forms_inventory:
        if f.classification == "upload" or "file" in [t.lower() for t in f.input_types]:
            if f.action not in seen_uploads:
                seen_uploads.add(f.action)
                file_uploads.append(FileUploadSurfaceRecord(
                    endpoint=f.action,
                    method=f.method,
                    type="form_input",
                    source="html_form",
                    confidence=0.98,
                    evidence=f"HTML form containing file input elements ({', '.join(f.input_names)})"
                ))

    # G. Administrative Surface
    admin_surfaces: List[AdminSurfaceRecord] = []
    seen_admins: Set[str] = set()

    for ep in endpoints_inventory:
        if ep.category == "administrative":
            if ep.path not in seen_admins:
                seen_admins.add(ep.path)
                admin_surfaces.append(AdminSurfaceRecord(
                    endpoint=ep.path,
                    classification="administrative",
                    confidence=ep.confidence,
                    evidence="Administrative URL path route detected during discovery crawl"
                ))

    # H. Documentation Surface
    doc_surfaces: List[DocSurfaceRecord] = []
    for d in api_data.get("api_documentation", []):
        doc_surfaces.append(DocSurfaceRecord(
            documentation_url=d.get("url", ""),
            spec_format=d.get("format", "openapi"),
            api_version=d.get("version"),
            endpoint_count=d.get("endpoint_count", 0),
            source="openapi_discovery"
        ))

    # I. Operational / Health Endpoints
    operational_endpoints: List[OperationalSurfaceRecord] = []
    seen_ops: Set[str] = set()

    for ep in endpoints_inventory:
        if ep.category == "health":
            if ep.path not in seen_ops:
                seen_ops.add(ep.path)
                operational_endpoints.append(OperationalSurfaceRecord(
                    endpoint=ep.path,
                    type="health",
                    method=ep.method,
                    confidence=ep.confidence
                ))

    # J. Authentication & Session Surfaces
    raw_endpoints_dict = [ep.to_dict() for ep in endpoints_inventory]
    raw_forms_dict = [f.to_dict() for f in forms_inventory]
    raw_apis_dict = [a.to_dict() for a in apis_inventory]
    auth_surfaces: List[AuthSurfaceRecord] = build_authentication_surface(
        raw_endpoints_dict,
        raw_forms_dict,
        raw_apis_dict
    )

    # Session Surface from cookies
    cookie_records = sec_config_data.get("cookies", []) or []
    session_surfaces: List[SessionSurfaceRecord] = build_session_surface(cookie_records)

    # K. WebSocket Surface
    websockets: List[WebSocketSurfaceRecord] = []
    seen_ws: Set[str] = set()
    # Check crawler js files and endpoint texts for ws:// and wss://
    ws_regex = re.compile(r"wss?://[^\s\"'<>]+", re.IGNORECASE)
    for js_file in crawl_data.get("in_scope_javascript_files", []):
        if ws_regex.search(js_file):
            for match in ws_regex.findall(js_file):
                if match not in seen_ws:
                    seen_ws.add(match)
                    protocol = "wss" if match.startswith("wss://") else "ws"
                    websockets.append(WebSocketSurfaceRecord(
                        url=match,
                        protocol=protocol,
                        source="javascript",
                        confidence=0.92
                    ))

    # L. External Dependencies & 3rd Party Integrations
    external_dependencies: List[ExternalDependencyRecord] = []
    seen_ext: Set[str] = set()
    for ext_host in discovered_external_domains:
        if ext_host and ext_host not in seen_ext and ext_host != cleaned_target:
            seen_ext.add(ext_host)
            category = classify_external_domain(ext_host)
            external_dependencies.append(ExternalDependencyRecord(
                host=ext_host,
                category=category,
                source="html_references",
                referenced_urls=[]
            ))

    # M. Parameter Inventory
    parameters_map: Dict[str, ParameterSurfaceRecord] = {}
    # From APIs
    for a in apis_inventory:
        for p in a.parameters:
            p_name = p.get("name")
            p_loc = p.get("location", "query")
            p_type = p.get("type", "string")
            if p_name:
                key = f"{p_name}:{p_loc}"
                if key not in parameters_map:
                    parameters_map[key] = ParameterSurfaceRecord(
                        name=p_name,
                        location=p_loc,
                        endpoints=[a.path],
                        parameter_type=p_type,
                        source="api_analysis"
                    )
                else:
                    if a.path not in parameters_map[key].endpoints:
                        parameters_map[key].endpoints.append(a.path)

    # From Forms
    for f in forms_inventory:
        for p_name in f.input_names:
            if p_name:
                key = f"{p_name}:form"
                if key not in parameters_map:
                    parameters_map[key] = ParameterSurfaceRecord(
                        name=p_name,
                        location="form",
                        endpoints=[f.action],
                        parameter_type="string",
                        source="form"
                    )
                else:
                    if f.action not in parameters_map[key].endpoints:
                        parameters_map[key].endpoints.append(f.action)

    parameters_inventory: List[ParameterSurfaceRecord] = list(parameters_map.values())

    # N. Debug / Information Disclosure Surface
    debug_surfaces: List[DebugErrorSurfaceRecord] = []
    if server_header:
        debug_surfaces.append(DebugErrorSurfaceRecord(
            endpoint=final_url,
            type="server_disclosure",
            severity="low" if re.search(r"/\d+\.\d+", server_header) else "info",
            evidence_redacted=f"Server header exposes software banner: '{server_header}'"
        ))

    # O. Application Functionality Map
    functionality_map: List[FunctionalityCategoryRecord] = build_functionality_map(
        raw_endpoints_dict,
        raw_forms_dict,
        raw_apis_dict,
        [a.to_dict() for a in admin_surfaces],
        [u.to_dict() for u in file_uploads],
        [d.to_dict() for d in doc_surfaces],
        [o.to_dict() for o in operational_endpoints]
    )

    # P. Prospective Security Test Candidates (For Future Test Planner)
    test_candidates: List[TestCandidateRecord] = generate_test_candidates(
        [a.to_dict() for a in auth_surfaces],
        [u.to_dict() for u in file_uploads],
        [adm.to_dict() for adm in admin_surfaces],
        raw_apis_dict,
        [p.to_dict() for p in parameters_inventory],
        [s.to_dict() for s in session_surfaces],
        [w.to_dict() for w in websockets],
        [d.to_dict() for d in doc_surfaces],
        [deb.to_dict() for deb in debug_surfaces]
    )

    # Q. High-Level Surface Observations
    observations: List[Dict[str, Any]] = []

    if doc_surfaces:
        observations.append({
            "type": "api_documentation",
            "title": "Public API Documentation Discovered",
            "description": f"Found {len(doc_surfaces)} public API documentation specifications ({', '.join([d.spec_format.upper() for d in doc_surfaces])}).",
            "severity": "info"
        })

    if auth_surfaces:
        observations.append({
            "type": "authentication_surface",
            "title": "Authentication Interfaces Observed",
            "description": f"Discovered {len(auth_surfaces)} authentication and token entry points across web and API layers.",
            "severity": "info"
        })

    if file_uploads:
        observations.append({
            "type": "file_upload_surface",
            "title": "File Upload Functionality Identified",
            "description": f"Identified {len(file_uploads)} file upload interfaces with multipart capabilities.",
            "severity": "info"
        })

    if admin_surfaces:
        observations.append({
            "type": "administrative_surface",
            "title": "Administrative Surface Exposed",
            "description": f"Identified {len(admin_surfaces)} administrative endpoints and dashboard paths.",
            "severity": "info"
        })

    if not session_surfaces:
        observations.append({
            "type": "session_surface",
            "title": "No Stateless / Session Cookies Observed",
            "description": "No active session cookies were set on initial unauthenticated landing requests.",
            "severity": "info"
        })
    else:
        insecure_cookies = [c for c in session_surfaces if not c.is_secure or not c.is_httponly]
        if insecure_cookies:
            observations.append({
                "type": "session_cookie_flags",
                "title": "Session Cookies Missing Recommended Security Flags",
                "description": f"{len(insecure_cookies)} cookie(s) lack Secure or HttpOnly flags.",
                "severity": "low"
            })

    # Summary
    summary = AttackSurfaceSummary(
        assets=len(assets),
        web_services=len(web_services),
        endpoints=len(endpoints_inventory),
        api_endpoints=len(apis_inventory),
        authentication_surfaces=len(auth_surfaces),
        forms=len(forms_inventory),
        file_uploads=len(file_uploads),
        administrative_surfaces=len(admin_surfaces),
        documentation=len(doc_surfaces),
        websockets=len(websockets),
        operational_endpoints=len(operational_endpoints),
        external_dependencies=len(external_dependencies),
        parameters=len(parameters_inventory),
        test_candidates=len(test_candidates)
    )

    elapsed_time = round(time.time() - start_time, 2)

    final_result = {
        "success": True,
        "target": raw_target,
        "cleaned_target": cleaned_target,
        "scan_status": "completed",
        "elapsed_seconds": elapsed_time,
        "summary": summary.to_dict(),
        "assets": [a.to_dict() for a in assets],
        "web_services": [w.to_dict() for w in web_services],
        "endpoints": [e.to_dict() for e in endpoints_inventory],
        "apis": [a.to_dict() for a in apis_inventory],
        "authentication": [a.to_dict() for a in auth_surfaces],
        "session_cookies": [s.to_dict() for s in session_surfaces],
        "forms": [f.to_dict() for f in forms_inventory],
        "file_uploads": [u.to_dict() for u in file_uploads],
        "administrative_surfaces": [adm.to_dict() for adm in admin_surfaces],
        "documentation": [d.to_dict() for d in doc_surfaces],
        "websockets": [w.to_dict() for w in websockets],
        "operational_endpoints": [o.to_dict() for o in operational_endpoints],
        "external_dependencies": [ext.to_dict() for ext in external_dependencies],
        "parameters": [p.to_dict() for p in parameters_inventory],
        "technologies": technologies_list,
        "functionality_map": [f.to_dict() for f in functionality_map],
        "observations": observations,
        "test_candidates": [c.to_dict() for c in test_candidates],
        "security_configuration": {
            "score": sec_config_data.get("security_score", 0),
            "findings_count": len(sec_config_data.get("findings", [])),
        },
        "tls": {
            "supported_protocols": tls_data.get("supported_protocols", []),
            "certificate_valid": tls_data.get("certificate", {}).get("is_valid", True),
        },
        "errors": []
    }

    notify("complete", f"Attack surface analysis complete in {elapsed_time}s ({summary.endpoints} endpoints, {summary.api_endpoints} APIs mapped).", final_result)

    return final_result
