"""
Security Configuration Master Analyzer Orchestrator
"""
import socket
import time
import urllib.parse
from typing import Dict, Any, List, Optional, Callable
import requests
import urllib3

from scan.views import parse_http_target
from .findings import Finding
from .headers import analyze_security_headers
from .cookies import analyze_cookies
from .cors import analyze_cors_configuration
from .https_redirects import trace_http_to_https_redirect
from .methods import check_safe_http_methods
from .info_disclosure import analyze_information_disclosure
from .scoring import calculate_security_score

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def analyze_security_configuration(
    raw_target: str,
    event_callback: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None
) -> Dict[str, Any]:
    """
    Executes a comprehensive, non-destructive web security configuration assessment.
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
    explicit_port = target_info.get("explicit_port")
    scheme = target_info.get("scheme")
    path = target_info.get("path") or "/"

    if event_callback:
        event_callback("init", f"Initializing security configuration scan for {hostname}...", {
            "hostname": hostname,
            "path": path,
            "port": explicit_port
        })

    # 1. DNS Resolution
    resolved_ip = None
    try:
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

    # Determine probe URL
    if not scheme:
        # Default to HTTPS, fallback to HTTP if needed
        probe_scheme = "https" if explicit_port != 80 else "http"
    else:
        probe_scheme = scheme

    port_str = f":{explicit_port}" if explicit_port and explicit_port not in (80, 443) else ""
    target_url = f"{probe_scheme}://{hostname}{port_str}{path}"

    if event_callback:
        event_callback("probing_target", f"Sending passive probe to {target_url}...", {
            "target_url": target_url,
            "ip": resolved_ip
        })

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 AttackLens/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    main_headers: Dict[str, str] = {}
    raw_set_cookies: List[str] = []
    final_response_url = target_url
    status_code = None
    is_https = probe_scheme == "https"

    try:
        resp = session.get(target_url, timeout=7.0, allow_redirects=True, verify=False)
        main_headers = dict(resp.headers)
        final_response_url = resp.url
        status_code = resp.status_code
        is_https = final_response_url.startswith("https://")

        # Capture raw Set-Cookie headers
        if "Set-Cookie" in resp.headers:
            raw_set_cookies.append(resp.headers["Set-Cookie"])
        # If multiple Set-Cookie headers exist in raw headers
        for k, v in resp.raw.headers.items() if hasattr(resp, "raw") and hasattr(resp.raw, "headers") else []:
            if k.lower() == "set-cookie" and v not in raw_set_cookies:
                raw_set_cookies.append(v)

    except requests.exceptions.SSLError as ssl_err:
        errors.append(f"TLS/SSL Handshake failure: {str(ssl_err)}")
        # Try HTTP fallback
        if probe_scheme == "https" and not explicit_port:
            try:
                target_url = f"http://{hostname}{path}"
                is_https = False
                resp = session.get(target_url, timeout=7.0, allow_redirects=True, verify=False)
                main_headers = dict(resp.headers)
                final_response_url = resp.url
                status_code = resp.status_code
            except Exception as e:
                errors.append(f"HTTP fallback error: {str(e)}")
                scan_status = "partial"
    except Exception as e:
        errors.append(f"Connection error: {str(e)}")
        # If HTTPS failed, try HTTP
        if probe_scheme == "https" and not explicit_port:
            try:
                target_url = f"http://{hostname}{path}"
                is_https = False
                resp = session.get(target_url, timeout=7.0, allow_redirects=True, verify=False)
                main_headers = dict(resp.headers)
                final_response_url = resp.url
                status_code = resp.status_code
            except Exception as ex2:
                errors.append(f"HTTP fallback error: {str(ex2)}")
                scan_status = "partial"
        else:
            scan_status = "partial"

    # All findings accumulator
    all_findings_raw: List[Finding] = []

    # 2. HTTP Security Headers Analysis
    if event_callback:
        event_callback("analyzing_headers", "Analyzing HTTP Security Headers (CSP, HSTS, XFO, XCTO, Referrer, Permissions, COOP, CORP)...", None)
    sec_headers_data, hdr_findings = analyze_security_headers(main_headers, is_https=is_https)
    all_findings_raw.extend(hdr_findings)

    # 3. Cookie Security Analysis
    if event_callback:
        event_callback("analyzing_cookies", "Parsing cookie security flags (Secure, HttpOnly, SameSite) without exposing values...", None)
    cookies_data, cookie_findings = analyze_cookies(raw_set_cookies, is_https=is_https)
    all_findings_raw.extend(cookie_findings)

    # 4. CORS Analysis
    if event_callback:
        event_callback("analyzing_cors", "Inspecting Cross-Origin Resource Sharing (CORS) rules and origin permissions...", None)
    cors_data, cors_findings = analyze_cors_configuration(main_headers)
    all_findings_raw.extend(cors_findings)

    # 5. HTTPS Enforcement & Redirect Analysis
    if event_callback:
        event_callback("checking_https_redirects", "Testing HTTP-to-HTTPS redirect enforcement and redirect hops...", None)
    https_info, redirects_chain, https_findings = trace_http_to_https_redirect(
        hostname=hostname,
        explicit_port=explicit_port,
        path=path
    )
    all_findings_raw.extend(https_findings)

    # 6. HTTP Methods (Safe OPTIONS probe)
    if event_callback:
        event_callback("inspecting_http_methods", "Sending safe OPTIONS probe to inspect allowed HTTP methods...", None)
    http_methods_list, methods_detail, method_findings = check_safe_http_methods(target_url)
    all_findings_raw.extend(method_findings)

    # 7. Information Disclosure Analysis
    if event_callback:
        event_callback("analyzing_info_disclosure", "Scanning for server banners and technology version leakage...", None)
    info_disclosure_headers, info_findings = analyze_information_disclosure(main_headers)
    all_findings_raw.extend(info_findings)

    # 8. Re-index and standardize all findings
    formatted_findings: List[Dict[str, Any]] = []
    for idx, f in enumerate(all_findings_raw, start=1):
        f.id = f"SEC-{idx:03d}"
        formatted_findings.append(f.to_dict())

    # 9. Calculate Security Score & Summary
    if event_callback:
        event_callback("evaluating_findings", "Calculating Web Security Configuration Score...", None)

    score_result = calculate_security_score(
        security_headers=sec_headers_data,
        https_info=https_info,
        cookies=cookies_data,
        cors_info=cors_data,
        findings=formatted_findings
    )

    summary = {
        "total_findings": len(formatted_findings),
        "high": sum(1 for f in formatted_findings if f["severity"] == "high"),
        "medium": sum(1 for f in formatted_findings if f["severity"] == "medium"),
        "low": sum(1 for f in formatted_findings if f["severity"] == "low"),
        "info": sum(1 for f in formatted_findings if f["severity"] == "info"),
        "score": score_result["score"],
        "score_grade": score_result["grade"],
        "score_label": score_result["label"],
        "score_color": score_result["color"]
    }

    scan_duration = round(time.time() - start_time, 2)

    final_result = {
        "success": True,
        "target": raw_target,
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "final_url": final_response_url,
        "status_code": status_code,
        "scan_status": scan_status if not errors else "partial",
        "scan_duration_seconds": scan_duration,
        "summary": summary,
        "security_score": score_result,
        "security_headers": sec_headers_data,
        "cookies": cookies_data,
        "cors": cors_data,
        "https": https_info,
        "redirects": redirects_chain,
        "http_methods": http_methods_list,
        "methods_detail": methods_detail,
        "information_disclosure": info_disclosure_headers,
        "raw_headers": main_headers,
        "findings": formatted_findings,
        "errors": errors
    }

    if event_callback:
        event_callback("complete", "Security configuration scan completed successfully.", final_result)

    return final_result
