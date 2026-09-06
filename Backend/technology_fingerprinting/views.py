import json
import re
import socket
import ssl
import time
import urllib.parse
from typing import Dict, Any, List, Optional

import requests
import urllib3
from bs4 import BeautifulSoup
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from scan.views import parse_http_target, parse_request_params, add_cors_headers
from .fingerprints import FingerprintEngine

# Suppress unverified HTTPS warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def analyze_target_technologies(
    target_info: Dict[str, Any],
    max_pages: int = 5,
    event_callback: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Executes a multi-source passive technology fingerprinting scan on the target.
    """
    hostname = target_info["hostname"]
    explicit_port = target_info.get("explicit_port")
    scheme = target_info.get("scheme") or ("https" if explicit_port == 443 else "http")
    path = target_info.get("path") or "/"

    resolved_ip: Optional[str] = None
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception:
        resolved_ip = None

    errors: List[str] = []
    scan_status = "completed"

    if explicit_port and explicit_port not in (80, 443):
        start_url = f"{scheme}://{hostname}:{explicit_port}{path}"
    else:
        start_url = f"{scheme}://{hostname}{path}"

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 AttackLens/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })

    main_headers: Dict[str, str] = {}
    main_html: str = ""
    cookies_metadata: List[Dict[str, Any]] = []
    discovered_scripts: List[str] = []
    discovered_stylesheets: List[str] = []
    discovered_endpoints: List[str] = [start_url]

    # Step 1: Probe main landing page
    if event_callback:
        event_callback("probing_target", f"Connecting to {start_url} and analyzing HTTP response headers...")

    try:
        resp = session.get(start_url, timeout=6.0, allow_redirects=True, verify=False)
        final_url = resp.url
        main_headers = dict(resp.headers)
        main_html = resp.text

        # Extract cookie metadata safely (no secret values exposed)
        for c in resp.cookies:
            cookies_metadata.append({
                "name": c.name,
                "secure": c.secure,
                "httponly": c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"),
                "samesite": c.get_nonstandard_attr("SameSite", None) or c.get_nonstandard_attr("samesite", None),
                "domain": c.domain or hostname
            })

    except Exception as e:
        # If HTTPS failed on default port, try HTTP fallback
        if scheme == "https" and not explicit_port:
            fallback_url = f"http://{hostname}/"
            try:
                if event_callback:
                    event_callback("fallback_http", f"HTTPS initial connection failed, probing HTTP fallback at {fallback_url}...")
                resp = session.get(fallback_url, timeout=6.0, allow_redirects=True, verify=False)
                final_url = resp.url
                main_headers = dict(resp.headers)
                main_html = resp.text
                for c in resp.cookies:
                    cookies_metadata.append({
                        "name": c.name,
                        "secure": c.secure,
                        "httponly": c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"),
                        "samesite": c.get_nonstandard_attr("SameSite", None),
                        "domain": c.domain or hostname
                    })
            except Exception as e_fb:
                errors.append(f"HTTP/HTTPS connection error: {str(e_fb)}")
                scan_status = "partial"
        else:
            errors.append(f"Target connection error: {str(e)}")
            scan_status = "partial"

    # Step 2: Extract DOM assets & resources
    if main_html:
        if event_callback:
            event_callback("analyzing_html", "Parsing DOM structure, meta tags, and script references...")

        try:
            soup = BeautifulSoup(main_html, "html.parser")
            base_origin = f"{urllib.parse.urlparse(start_url).scheme}://{urllib.parse.urlparse(start_url).netloc}"

            # Extract script URLs
            for s in soup.find_all("script", src=True):
                src = s["src"].strip()
                if src:
                    full_src = urllib.parse.urljoin(start_url, src)
                    discovered_scripts.append(full_src)

            # Extract stylesheets
            for link in soup.find_all("link", rel=lambda r: r and "stylesheet" in r):
                href = link.get("href")
                if href:
                    full_href = urllib.parse.urljoin(start_url, href)
                    discovered_stylesheets.append(full_href)

            # Extract in-scope links & forms
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    discovered_endpoints.append(urllib.parse.urljoin(start_url, href))

            for form in soup.find_all("form"):
                action = form.get("action")
                if action:
                    discovered_endpoints.append(urllib.parse.urljoin(start_url, action))

        except Exception as e:
            errors.append(f"HTML parsing warning: {str(e)}")

    # Step 3: Deep inspect top discovered JavaScript bundles
    js_contents: Dict[str, str] = {}
    if discovered_scripts:
        if event_callback:
            event_callback("inspecting_scripts", f"Inspecting {min(5, len(discovered_scripts))} JavaScript runtime bundles for framework markers...")

        for s_url in discovered_scripts[:5]:
            try:
                s_resp = session.get(s_url, timeout=3.5, verify=False, stream=True)
                if s_resp.status_code == 200:
                    content_chunk = s_resp.raw.read(300_000, decode_content=True).decode('utf-8', errors='ignore')
                    if content_chunk:
                        js_contents[s_url] = content_chunk
            except Exception:
                pass

    # Step 4: Run Fingerprint Matching Engine
    if event_callback:
        event_callback("matching_fingerprints", "Correlating multi-source signatures and computing confidence scores...")

    engine = FingerprintEngine()
    detected_technologies = engine.analyze(
        target_url=start_url,
        response_headers=main_headers,
        cookies_metadata=cookies_metadata,
        html_content=main_html,
        discovered_scripts=discovered_scripts,
        discovered_stylesheets=discovered_stylesheets,
        discovered_endpoints=discovered_endpoints,
        js_contents=js_contents
    )


    # Step 4: Aggregate Category Summary
    summary = {
        "total_technologies": len(detected_technologies),
        "web_servers": sum(1 for t in detected_technologies if t["category"] == "web_server"),
        "backend_frameworks": sum(1 for t in detected_technologies if t["category"] == "backend"),
        "frontend_frameworks": sum(1 for t in detected_technologies if t["category"] == "frontend"),
        "javascript_libraries": sum(1 for t in detected_technologies if t["category"] == "javascript"),
        "cms": sum(1 for t in detected_technologies if t["category"] == "cms"),
        "cdn": sum(1 for t in detected_technologies if t["category"] == "cdn"),
        "hosting": sum(1 for t in detected_technologies if t["category"] == "hosting"),
        "css_frameworks": sum(1 for t in detected_technologies if t["category"] == "css"),
        "analytics": sum(1 for t in detected_technologies if t["category"] == "analytics"),
        "authentication": sum(1 for t in detected_technologies if t["category"] == "authentication"),
        "api": sum(1 for t in detected_technologies if t["category"] == "api"),
        "database": sum(1 for t in detected_technologies if t["category"] == "database"),
    }

    return {
        "target": start_url,
        "resolved_ip": resolved_ip,
        "hostname": hostname,
        "scan_status": scan_status if not (errors and not detected_technologies) else "partial",
        "technologies": detected_technologies,
        "summary": summary,
        "errors": errors if errors else []
    }


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def technology_fingerprint(request):
    """
    Synchronous Technology Fingerprinting API.
    GET /api/technology-fingerprint/?target=<target>
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    params, err = parse_request_params(request)
    if err:
        return add_cors_headers(JsonResponse({"success": False, "error": err}, status=400))

    raw_target = params.get("target") or params.get("url") or params.get("host")
    target_info, err = parse_http_target(raw_target)
    if err:
        return add_cors_headers(JsonResponse({"success": False, "error": err}, status=400))

    try:
        max_pages = int(params.get("max_pages", 5))
    except (ValueError, TypeError):
        max_pages = 5

    result = analyze_target_technologies(target_info, max_pages=max_pages)
    return add_cors_headers(JsonResponse(result))


def technology_fingerprint_stream_generator(target_info: Dict[str, Any], max_pages: int = 5):
    """Yields real-time Server-Sent Events (SSE) telemetry during technology fingerprinting."""
    hostname = target_info["hostname"]
    raw_target = target_info.get("raw_target") or target_info.get("target", "")

    yield f"data: {json.dumps({'event': 'init', 'target': raw_target, 'hostname': hostname, 'message': f'Initializing technology fingerprinting for {hostname}...'})}\n\n"
    time.sleep(0.04)

    events_buffer = []

    def on_event(event_type: str, msg: str):
        events_buffer.append((event_type, msg))

    result = analyze_target_technologies(target_info, max_pages=max_pages, event_callback=on_event)

    for ev_type, ev_msg in events_buffer:
        yield f"data: {json.dumps({'event': 'step', 'step': ev_type, 'message': ev_msg})}\n\n"
        time.sleep(0.02)

    yield f"data: {json.dumps({'event': 'complete', 'success': True, 'data': result})}\n\n"


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def stream_technology_fingerprint(request):
    """
    Live Streaming Technology Fingerprinting API via Server-Sent Events (SSE).
    GET /stream-technology-fingerprint/?target=<target>
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    params, err = parse_request_params(request)
    if err:
        return add_cors_headers(JsonResponse({"success": False, "error": err}, status=400))

    raw_target = params.get("target") or params.get("url") or params.get("host")
    target_info, err = parse_http_target(raw_target)
    if err:
        return add_cors_headers(JsonResponse({"success": False, "error": err}, status=400))

    try:
        max_pages = int(params.get("max_pages", 5))
    except (ValueError, TypeError):
        max_pages = 5

    response = StreamingHttpResponse(
        technology_fingerprint_stream_generator(target_info, max_pages=max_pages),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)
