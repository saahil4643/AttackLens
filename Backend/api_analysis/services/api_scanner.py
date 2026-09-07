"""
API Deep Analysis Master Scanner & Inventory Orchestrator
"""
import json
import re
import time
import urllib.parse
from typing import Dict, Any, List, Optional, Callable, Set
import requests
import urllib3

from scan.views import parse_http_target, crawl_target_endpoints
from .models import (
    ApiEndpoint,
    ApiParameter,
    ApiAuthIndicator,
    ApiResponseInfo,
    ApiRateLimitInfo,
    ApiDocumentation,
    ApiFinding
)
from .openapi_parser import probe_and_parse_openapi
from .graphql_detector import detect_graphql_endpoint
from .parameter_analyzer import extract_parameters_from_url
from .auth_detector import analyze_auth_from_response

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_PATH_PATTERNS = re.compile(
    r'(?:^|/)(?:api|v[0-9]+|rest|graphql|rpc|json|auth|users|products|orders|items|search|admin|webhooks|v1|v2|v3)(?:/|[?#]|$)',
    re.IGNORECASE
)

VERSION_REGEX = re.compile(r'/(v[0-9]+)(?:/|$)', re.IGNORECASE)


def extract_api_version(path: str) -> Optional[str]:
    """Extracts API version identifier like 'v1', 'v2' from path."""
    match = VERSION_REGEX.search(path)
    if match:
        return match.group(1).lower()
    return None


def inspect_json_structure(response_text: str) -> str:
    """Safely determines top-level JSON structure without storing secrets."""
    if not response_text:
        return "unknown"
    t = response_text.strip()
    if t.startswith("{") and t.endswith("}"):
        return "object"
    if t.startswith("[") and t.endswith("]"):
        return "array"
    if (t.startswith('"') and t.endswith('"')) or t in ("true", "false", "null") or t.isdigit():
        return "primitive"
    return "unknown"


def extract_rate_limits(headers: Dict[str, str]) -> ApiRateLimitInfo:
    """Extracts rate-limit header metadata."""
    norm = {k.lower(): v.strip() for k, v in headers.items()}
    limit = norm.get("x-ratelimit-limit") or norm.get("ratelimit-limit")
    remaining = norm.get("x-ratelimit-remaining") or norm.get("ratelimit-remaining")
    reset = norm.get("x-ratelimit-reset") or norm.get("ratelimit-reset")
    retry_after = norm.get("retry-after")

    detected = bool(limit or remaining or reset or retry_after)
    return ApiRateLimitInfo(
        detected=detected,
        limit=limit,
        remaining=remaining,
        reset=reset,
        retry_after=retry_after
    )


def scan_api_inventory(
    raw_target: str,
    max_crawl_pages: int = 15,
    event_callback: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None
) -> Dict[str, Any]:
    """
    Executes deep API discovery, parses OpenAPI/Swagger, detects GraphQL,
    extracts parameters and auth requirements, and builds a comprehensive API Inventory.
    """
    start_time = time.time()
    errors: List[str] = []
    scan_status = "completed"

    target_info, err = parse_http_target(raw_target)
    if err:
        return {
            "success": False,
            "target": raw_target,
            "scan_status": "failed",
            "error": err,
            "errors": [err]
        }

    hostname = target_info["hostname"]
    scheme = target_info.get("scheme") or "https"
    explicit_port = target_info.get("explicit_port")
    port_suffix = f":{explicit_port}" if explicit_port and explicit_port not in (80, 443) else ""
    base_target = f"{scheme}://{hostname}{port_suffix}/"

    # DNS Resolution Validation
    resolved_ip = None
    try:
        import socket
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ip = addr_info[0][4][0]
    except socket.gaierror:
        return {
            "success": False,
            "target": raw_target,
            "hostname": hostname,
            "scan_status": "failed",
            "error": f"Could not resolve domain '{hostname}' (DNS failure)",
            "errors": [f"Could not resolve domain '{hostname}'"]
        }
    except Exception as e:
        return {
            "success": False,
            "target": raw_target,
            "hostname": hostname,
            "scan_status": "failed",
            "error": f"Host resolution error: {str(e)}",
            "errors": [str(e)]
        }

    if event_callback:
        event_callback("init", f"Starting API Deep Analysis & Inventory for {hostname}...", {
            "hostname": hostname,
            "target": base_target,
            "ip": resolved_ip
        })

    all_endpoints: List[ApiEndpoint] = []
    all_docs: List[ApiDocumentation] = []
    all_findings: List[ApiFinding] = []
    seen_endpoint_keys: Set[str] = set()

    def add_endpoint(ep: ApiEndpoint):
        key = f"{ep.method}:{ep.path.lower().rstrip('/')}"
        if key not in seen_endpoint_keys:
            seen_endpoint_keys.add(key)
            all_endpoints.append(ep)

    # 1. OpenAPI / Swagger Discovery & Parsing
    if event_callback:
        event_callback("probing_openapi", "Probing for exposed OpenAPI / Swagger documentation files...", None)

    try:
        discovered_docs, openapi_eps, openapi_findings = probe_and_parse_openapi(
            base_target=base_target,
            timeout=4.0
        )
        all_docs.extend(discovered_docs)
        all_findings.extend(openapi_findings)
        for ep in openapi_eps:
            add_endpoint(ep)
    except Exception as e:
        errors.append(f"OpenAPI discovery error: {str(e)}")

    # 2. GraphQL Endpoint Detection
    if event_callback:
        event_callback("detecting_graphql", "Probing for exposed GraphQL API services...", None)

    try:
        gql_eps, gql_findings = detect_graphql_endpoint(
            base_target=base_target,
            timeout=4.0
        )
        all_findings.extend(gql_findings)
        for ep in gql_eps:
            add_endpoint(ep)
    except Exception as e:
        errors.append(f"GraphQL detection error: {str(e)}")

    # 3. Endpoint Discovery Consumption / Crawling
    if event_callback:
        event_callback("discovering_endpoints", f"Crawling application surface for API paths (up to {max_crawl_pages} pages)...", None)

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackLens/1.0",
        "Accept": "application/json,text/html,*/*"
    })

    candidate_urls: List[str] = []
    try:
        crawl_data = crawl_target_endpoints(
            target_info=target_info,
            max_pages=max_crawl_pages,
            event_callback=lambda step, msg: event_callback("crawler_step", msg, None) if event_callback else None
        )

        in_scope_all = list(crawl_data.get("in_scope_endpoints", [])) + list(crawl_data.get("in_scope_api_paths", []))
        candidate_urls = in_scope_all
    except Exception as e:
        errors.append(f"Surface crawl error: {str(e)}")
        candidate_urls = [base_target]

    # 4. Filter and Deep Analyze Candidate API Endpoints
    if event_callback:
        event_callback("analyzing_api_endpoints", f"Analyzing {len(candidate_urls)} discovered surface paths...", None)

    checked_probes = 0
    max_probes = 25  # Limit polite probe requests

    for candidate_url in candidate_urls:
        if checked_probes >= max_probes:
            break

        parsed_candidate = urllib.parse.urlparse(candidate_url)
        cand_path = parsed_candidate.path or "/"

        # Check if already in inventory or matches API pattern
        is_api_candidate = bool(
            API_PATH_PATTERNS.search(cand_path) or
            parsed_candidate.query or
            "api" in (parsed_candidate.hostname or "").lower()
        )

        if not is_api_candidate:
            continue

        endpoint_key = f"GET:{cand_path.lower().rstrip('/')}"
        if endpoint_key in seen_endpoint_keys:
            continue

        checked_probes += 1
        try:
            time.sleep(0.02)  # Polite delay
            resp = session.get(candidate_url, timeout=4.5, allow_redirects=False, verify=False)
            status_code = resp.status_code
            content_type = resp.headers.get("Content-Type", "").lower()
            response_headers = dict(resp.headers)

            is_json = "json" in content_type or "problem+json" in content_type
            is_xml = "xml" in content_type and ("api" in cand_path or "rest" in cand_path)
            json_structure = inspect_json_structure(resp.text) if is_json else "unknown"

            # Determine API type
            if is_json or is_xml or API_PATH_PATTERNS.search(cand_path):
                api_type = "REST" if not cand_path.endswith((".html", ".htm", ".php")) else "Web Endpoint"
            else:
                api_type = "Web Endpoint"

            # Extract Parameters
            extracted_params = extract_parameters_from_url(candidate_url)

            # Analyze Authentication Indicators
            auth_info, auth_findings = analyze_auth_from_response(
                status_code=status_code,
                headers=response_headers,
                endpoint_url=candidate_url
            )
            all_findings.extend(auth_findings)

            # Rate Limit Observation
            rate_limit_info = extract_rate_limits(response_headers)

            # API Version
            version_val = extract_api_version(cand_path)

            # Confidence calculation
            if is_json:
                confidence = 0.95
            elif status_code in (401, 403, 405):
                confidence = 0.90
            elif extracted_params:
                confidence = 0.85
            else:
                confidence = 0.75

            endpoint_obj = ApiEndpoint(
                endpoint=candidate_url,
                path=cand_path,
                hostname=parsed_candidate.hostname or hostname,
                method="GET",
                api_type=api_type,
                version=version_val,
                source="crawler",
                summary=f"{api_type} Endpoint ({cand_path})",
                description=f"Observed HTTP {status_code} response with Content-Type '{content_type or 'unspecified'}'.",
                parameters=extracted_params,
                authentication=auth_info,
                response=ApiResponseInfo(
                    status_code=status_code,
                    content_type=content_type,
                    structure=json_structure,
                    size_bytes=len(resp.content)
                ),
                rate_limit=rate_limit_info,
                cors={
                    "allow_origin": response_headers.get("Access-Control-Allow-Origin"),
                    "allow_methods": response_headers.get("Access-Control-Allow-Methods")
                },
                confidence=confidence
            )
            add_endpoint(endpoint_obj)

        except Exception:
            continue

    # 5. API Inventory Aggregations & Observations
    if event_callback:
        event_callback("evaluating_observations", "Generating API inventory summary and observations...", None)

    # Detect active versions across endpoints
    versions_found = set(ep.version for ep in all_endpoints if ep.version)
    if len(versions_found) > 1:
        all_findings.append(ApiFinding(
            id="API-VER-001",
            title="Multiple API Versions Concurrently Exposed",
            category="deprecated_version",
            severity="low",
            confidence=0.95,
            description=f"Multiple API version prefixes ({', '.join(sorted(list(versions_found)))}) were discovered in active endpoints. Legacy versions may contain unpatched security issues or deprecated authentication mechanisms.",
            evidence={"versions_observed": sorted(list(versions_found))},
            recommendation="Retire deprecated API versions and establish a deprecation lifecycle with sunset headers."
        ))

    # Rate limiting observation
    has_rate_limit = any(ep.rate_limit.detected for ep in all_endpoints)
    if has_rate_limit:
        all_findings.append(ApiFinding(
            id="API-RTL-001",
            title="API Rate-Limiting Headers Observed",
            category="rate_limiting",
            severity="info",
            confidence=0.95,
            description="The API returns standard rate-limiting headers (X-RateLimit-* / Retry-After) to govern request throughput.",
            evidence={"rate_limiting_active": True},
            recommendation="Maintain rate limit policies on authenticated and public endpoints."
        ))

    # Re-index all findings sequentially
    formatted_findings = []
    for idx, f in enumerate(all_findings, start=1):
        f.id = f"API-{idx:03d}"
        formatted_findings.append(f.to_dict())

    # Calculate summary metrics
    rest_count = sum(1 for ep in all_endpoints if ep.type == "REST")
    gql_count = sum(1 for ep in all_endpoints if ep.type == "GraphQL")
    doc_count = sum(1 for ep in all_endpoints if ep.type == "API Documentation" or ep.source == "openapi")
    auth_count = sum(1 for ep in all_endpoints if ep.authentication.required)

    summary = {
        "total_api_endpoints": len(all_endpoints),
        "rest_endpoints": rest_count,
        "graphql_endpoints": gql_count,
        "api_documentation": len(all_docs),
        "authenticated_endpoints": auth_count,
        "versions": sorted(list(versions_found))
    }

    scan_duration = round(time.time() - start_time, 2)

    final_result = {
        "success": True,
        "target": raw_target,
        "hostname": hostname,
        "scan_status": scan_status if not errors else "partial",
        "scan_duration_seconds": scan_duration,
        "summary": summary,
        "api_documentation": [d.to_dict() for d in all_docs],
        "endpoints": [ep.to_dict() for ep in all_endpoints],
        "findings": formatted_findings,
        "errors": errors
    }

    if event_callback:
        event_callback("complete", f"API inventory compiled with {len(all_endpoints)} endpoints.", final_result)

    return final_result
