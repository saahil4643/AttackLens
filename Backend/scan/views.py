# views.py

import json
import re
import socket
import ssl
import time

import urllib.parse
import urllib3
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

# Suppress SSL verification warnings during security assessment scans
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)





# Most common / frequently used ports and their service names
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBIND",
    135: "MSRPC",
    139: "NETBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "MICROSOFT-DS (SMB)",
    465: "SMTPS",
    587: "SUBMISSION",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    2049: "NFS",
    2082: "CPANEL",
    2083: "CPANEL-SSL",
    3000: "NODE/REACT",
    3306: "MYSQL",
    3389: "RDP",
    5000: "FLASK/DEV",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8000: "HTTP-ALT",
    8080: "HTTP-PROXY/TOMCAT",
    8443: "HTTPS-ALT",
    8888: "HTTP-ALT/JUPYTER",
    9000: "SONARQUBE/PORTAINER",
    9200: "ELASTICSEARCH",
    27017: "MONGODB",
}


def add_cors_headers(response):
    """Helper to attach CORS headers to any response."""
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, Accept"
    return response


def clean_and_extract_target(raw_target: str) -> str:
    """
    Extracts and normalizes hostname or IP address from various user inputs:
    - Full URLs: https://example.com/path?arg=1
    - Domains with ports: example.com:8080
    - Bare domains: sub.example.com
    - IPv4 addresses: 192.168.1.1 or 192.168.1.1:8080
    - IPv6 addresses: [::1], ::1, or [2001:db8::1]:8080
    - Targets with auth: user:pass@example.com
    - Inputs with leading/trailing spaces or quotes
    """
    if not raw_target:
        return ""

    target = raw_target.strip().strip('"\'')

    # If scheme not present, prepend scheme so urllib can parse netloc properly
    if "://" not in target:
        parse_result = urllib.parse.urlparse(f"http://{target}")
    else:
        parse_result = urllib.parse.urlparse(target)

    hostname = parse_result.hostname

    if hostname:
        return hostname.strip("[]")

    # Fallback cleanup using regex
    cleaned = re.sub(r"^[a-zA-Z0-9+-.]+://", "", target)
    cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]

    # Remove user:pass@ if present
    if "@" in cleaned:
        cleaned = cleaned.split("@")[-1]

    # Handle bracketed IPv6
    if cleaned.startswith("[") and "]" in cleaned:
        cleaned = cleaned[1 : cleaned.index("]")]
    elif ":" in cleaned and cleaned.count(":") == 1:
        # host:port -> strip port
        cleaned = cleaned.split(":")[0]

    return cleaned.strip("[]").strip()


def scan_single_port(ip: str, port: int, timeout: float = 0.5, delay: float = 0.015) -> int | None:
    """
    Tests a TCP connection to a single port on the target IP with polite pacing
    to avoid triggering rate limits, SYN flood protection, or socket exhaustion.
    """
    if delay > 0:
        time.sleep(delay)

    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port
    except (socket.timeout, socket.error, OSError):
        pass
    finally:
        if sock:
            sock.close()
    return None


def parse_request_params(request):
    """Helper to parse request parameters from GET query or POST body."""
    params = {}
    if request.method == "GET":
        params = request.GET.dict()
    elif request.method == "POST":
        if request.content_type == "application/json" and request.body:
            try:
                params = json.loads(request.body)
            except json.JSONDecodeError:
                return None, "Invalid JSON in request body"
        else:
            params = request.POST.dict()
    return params, None


def resolve_ports_and_target(params):
    """Helper to validate target, extract hostname, and determine port list & mode."""
    raw_target = params.get("target") or params.get("host") or params.get("url")
    if not raw_target:
        return None, {
            "success": False,
            "error": "target parameter is required",
            "supported_inputs": [
                "Plain domain (e.g. example.com, sub.domain.org)",
                "Full URL (e.g. https://example.com/api/v1?query=1)",
                "Domain or IP with port (e.g. example.com:8080, 192.168.1.1:3000)",
                "IPv4 Address (e.g. 192.168.1.1, 127.0.0.1)",
                "IPv6 Address (e.g. ::1, [2001:db8::1], 2001:db8::1)",
                "URL with credentials (e.g. http://user:pass@example.com)"
            ],
            "modes": {
                "quick": "Scans the most commonly used / critical ports (fast, default)",
                "all": "Scans all available ports from 1 to 65535"
            }
        }

    cleaned_target = clean_and_extract_target(str(raw_target))
    if not cleaned_target:
        return None, {
            "success": False,
            "error": "Could not parse target",
            "target": raw_target
        }

    mode = str(params.get("mode") or params.get("scan_type") or params.get("type") or "quick").lower().strip()
    ports_param = params.get("ports")

    # Rate-limiting friendly pacing & concurrency
    if ports_param:
        mode = "custom"
        ports_to_scan = []
        try:
            for item in str(ports_param).split(","):
                item = item.strip()
                if "-" in item:
                    start_p, end_p = map(int, item.split("-"))
                    ports_to_scan.extend(range(max(1, start_p), min(65535, end_p) + 1))
                elif item:
                    port_num = int(item)
                    if 1 <= port_num <= 65535:
                        ports_to_scan.append(port_num)
        except ValueError:
            return None, {
                "success": False,
                "error": "ports parameter must be comma-separated integers or ranges (e.g. '80,443,8000-8080')"
            }
        default_timeout = 0.5
        max_workers = 25
        delay = 0.015
    elif mode in ("all", "full", "all_ports"):
        mode = "all"
        ports_to_scan = list(range(1, 65536))
        default_timeout = 0.3
        max_workers = 40
        delay = 0.005
    elif mode in ("quick", "fast", "common", "top"):
        mode = "quick"
        ports_to_scan = sorted(COMMON_PORTS.keys())
        default_timeout = 0.5
        max_workers = 15
        delay = 0.015
    else:
        return None, {
            "success": False,
            "error": f"Invalid mode '{mode}'. Supported modes: 'quick' (most used ports) or 'all' (all 1-65535 ports)."
        }

    try:
        timeout = float(params.get("timeout", default_timeout))
        timeout = max(0.1, min(timeout, 5.0))
    except (ValueError, TypeError):
        timeout = default_timeout

    try:
        addr_info = socket.getaddrinfo(cleaned_target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ip = addr_info[0][4][0]
    except socket.gaierror:
        return None, {
            "success": False,
            "target": raw_target,
            "cleaned_target": cleaned_target,
            "error": f"Could not resolve target '{cleaned_target}'. Please check hostname or IP address."
        }
    except Exception as e:
        return None, {
            "success": False,
            "target": raw_target,
            "cleaned_target": cleaned_target,
            "error": f"Resolution failed: {str(e)}"
        }

    return {
        "raw_target": raw_target,
        "cleaned_target": cleaned_target,
        "ip": ip,
        "mode": mode,
        "ports_to_scan": ports_to_scan,
        "timeout": timeout,
        "max_workers": max_workers,
        "delay": delay,
    }, None


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def check_ports(request):
    """
    Standard synchronous Port Scanner API.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    start_time = time.time()
    params, err = parse_request_params(request)
    if err:
        return add_cors_headers(JsonResponse({"success": False, "error": err}, status=400))

    config, err_resp = resolve_ports_and_target(params)
    if err_resp:
        return add_cors_headers(JsonResponse(err_resp, status=400))

    ip = config["ip"]
    ports_to_scan = config["ports_to_scan"]
    timeout = config["timeout"]
    max_workers = config["max_workers"]
    delay = config["delay"]

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_single_port, ip, port, timeout, delay): port
            for port in ports_to_scan
        }
        for future in as_completed(futures):
            open_port = future.result()
            if open_port is not None:
                open_ports.append(open_port)

    open_ports.sort()
    scan_duration = round(time.time() - start_time, 2)

    open_port_details = [
        {
            "port": port,
            "service": COMMON_PORTS.get(port, "UNKNOWN"),
            "status": "open"
        }
        for port in open_ports
    ]

    response = JsonResponse({
        "success": True,
        "target": config["raw_target"],
        "cleaned_target": config["cleaned_target"],
        "ip": ip,
        "scan_mode": config["mode"],
        "total_ports_scanned": len(ports_to_scan),
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
        "open_port_details": open_port_details,
        "scan_duration_seconds": scan_duration
    })
    return add_cors_headers(response)


def event_stream_generator(config, start_time):
    """Yields SSE events during the port scan."""
    raw_target = config["raw_target"]
    cleaned_target = config["cleaned_target"]
    ip = config["ip"]
    mode = config["mode"]
    ports_to_scan = config["ports_to_scan"]
    timeout = config["timeout"]
    max_workers = config["max_workers"]
    delay = config["delay"]
    total = len(ports_to_scan)

    # 1. Emit Initializer event
    init_data = {
        "event": "init",
        "target": raw_target,
        "cleaned_target": cleaned_target,
        "ip": ip,
        "scan_mode": mode,
        "total": total,
        "timestamp": time.time(),
    }
    yield f"data: {json.dumps(init_data)}\n\n"

    open_ports = []
    scanned_count = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_single_port, ip, port, timeout, delay): port
            for port in ports_to_scan
        }

        for future in as_completed(futures):
            scanned_count += 1
            port_num = futures[future]
            open_port = future.result()

            if open_port is not None:
                open_ports.append(open_port)
                port_event = {
                    "event": "port_discovered",
                    "port": open_port,
                    "service": COMMON_PORTS.get(open_port, "UNKNOWN"),
                    "status": "open",
                    "scanned": scanned_count,
                    "total": total,
                    "percent": round((scanned_count / total) * 100, 1),
                    "open_count": len(open_ports)
                }
                yield f"data: {json.dumps(port_event)}\n\n"
            elif scanned_count % 30 == 0 or scanned_count == total:
                progress_event = {
                    "event": "progress",
                    "current_port": port_num,
                    "scanned": scanned_count,
                    "total": total,
                    "percent": round((scanned_count / total) * 100, 1),
                    "open_count": len(open_ports)
                }
                yield f"data: {json.dumps(progress_event)}\n\n"

    open_ports.sort()
    scan_duration = round(time.time() - start_time, 2)

    # Final Complete event
    complete_event = {
        "event": "complete",
        "success": True,
        "target": raw_target,
        "cleaned_target": cleaned_target,
        "ip": ip,
        "scan_mode": mode,
        "total_ports_scanned": total,
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
        "open_port_details": [
            {
                "port": p,
                "service": COMMON_PORTS.get(p, "UNKNOWN"),
                "status": "open"
            }
            for p in open_ports
        ],
        "scan_duration_seconds": scan_duration
    }
    yield f"data: {json.dumps(complete_event)}\n\n"


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def stream_ports(request):
    """
    Live Streaming Port Scanner API via Server-Sent Events (SSE).
    Provides real-time discovery events and progress streams to the frontend.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    start_time = time.time()
    params, err = parse_request_params(request)
    if err:
        return add_cors_headers(JsonResponse({"success": False, "error": err}, status=400))

    config, err_resp = resolve_ports_and_target(params)
    if err_resp:
        return add_cors_headers(JsonResponse(err_resp, status=400))

    response = StreamingHttpResponse(
        event_stream_generator(config, start_time),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP / HTTPS Detection & Deep Probe Engine
# ─────────────────────────────────────────────────────────────────────────────

def parse_http_target(raw_target: str):
    """Parses and formats target URL for HTTP inspection."""
    if not raw_target:
        return None, "Target parameter is required"

    target = raw_target.strip().strip('"\'')
    has_explicit_scheme = target.startswith(("http://", "https://"))

    if not has_explicit_scheme:
        # Temporary parse as http to extract host and port accurately
        parsed = urllib.parse.urlparse("http://" + target)
        hostname = parsed.hostname or target.split('/')[0].split(':')[0]
        explicit_port = parsed.port
        path = parsed.path or "/"
        scheme = None
    else:
        parsed = urllib.parse.urlparse(target)
        hostname = parsed.hostname
        explicit_port = parsed.port
        path = parsed.path or "/"
        scheme = parsed.scheme

    if not hostname:
        return None, "Invalid target hostname"

    return {
        "raw_target": target,
        "has_explicit_scheme": has_explicit_scheme,
        "scheme": scheme,
        "hostname": hostname,
        "explicit_port": explicit_port,
        "path": path,
    }, None


def perform_http_detection(target_info):
    """Runs synchronous deep HTTP/HTTPS inspection."""
    hostname = target_info["hostname"]
    explicit_port = target_info.get("explicit_port")
    scheme = target_info.get("scheme")
    path = target_info.get("path", "/")
    start_time = time.time()

    result = {
        "success": True,
        "target": target_info["raw_target"],
        "hostname": hostname,
        "port": explicit_port or 443,
        "ip": None,
        "service": "HTTP/HTTPS",
        "protocol": (scheme or "HTTPS").upper(),
        "reachable": False,
        "status_code": None,
        "status_text": None,
        "final_url": None,
        "page_title": None,
        "server": None,
        "content_type": None,
        "content_length": None,
        "response_time_ms": None,
        "headers": {},
        "security_headers": {},
        "redirects": [],
        "tls": None,
        "error": None,
    }

    # 1. DNS Resolution
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        result["ip"] = addr_info[0][4][0]
    except socket.gaierror:
        result["success"] = False
        result["error"] = f"Could not resolve hostname '{hostname}'"
        return result

    # 2. Port & Protocol Auto-Detection (if no explicit scheme/port given)
    family = socket.AF_INET6 if ":" in result["ip"] else socket.AF_INET
    active_port = explicit_port
    active_scheme = scheme

    if not target_info["has_explicit_scheme"] and not explicit_port:
        # Check HTTPS (443) first
        is_443_open = False
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                if sock.connect_ex((result["ip"], 443)) == 0:
                    is_443_open = True
        except Exception:
            pass

        if is_443_open:
            active_port = 443
            active_scheme = "https"
        else:
            # Check HTTP (80)
            is_80_open = False
            try:
                with socket.socket(family, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2.0)
                    if sock.connect_ex((result["ip"], 80)) == 0:
                        is_80_open = True
            except Exception:
                pass

            if is_80_open:
                active_port = 80
                active_scheme = "http"
            else:
                active_port = 443
                active_scheme = "https"
    elif not active_port:
        active_port = 443 if active_scheme == "https" else 80
    elif not active_scheme:
        active_scheme = "https" if active_port == 443 or active_port == 8443 else "http"

    result["port"] = active_port
    result["protocol"] = active_scheme.upper()

    # Verify TCP socket
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(3.0)
            if sock.connect_ex((result["ip"], active_port)) == 0:
                result["reachable"] = True
            else:
                result["success"] = False
                result["error"] = f"TCP connection to {hostname}:{active_port} failed (Port is closed or unreachable)"
                return result
    except Exception as e:
        result["success"] = False
        result["error"] = f"Socket connection error: {str(e)}"
        return result

    # 3. HTTP Probe Request
    port_suffix = f":{active_port}" if (active_scheme == "http" and active_port != 80) or (active_scheme == "https" and active_port != 443) else ""
    request_url = f"{active_scheme}://{hostname}{port_suffix}{path}"
    result["target"] = request_url

    req_start = time.time()
    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackLens-SecurityScanner/1.0"
        })
        response = session.get(request_url, timeout=8.0, allow_redirects=True, verify=False)
        result["response_time_ms"] = round((time.time() - req_start) * 1000, 1)
        result["status_code"] = response.status_code
        result["status_text"] = response.reason
        result["final_url"] = response.url
        result["protocol"] = response.url.split(":")[0].upper()
        result["headers"] = dict(response.headers)
        result["server"] = response.headers.get("Server", "Undisclosed")
        result["content_type"] = response.headers.get("Content-Type", "Unknown")
        result["content_length"] = response.headers.get("Content-Length", str(len(response.content)))

        # Redirect history
        result["redirects"] = [
            {
                "status_code": r.status_code,
                "url": r.url,
                "location": r.headers.get("Location")
            }
            for r in response.history
        ]

        # Extract page title
        if "text/html" in result["content_type"].lower():
            text = response.text[:100000]
            lower_text = text.lower()
            title_start = lower_text.find("<title>")
            if title_start != -1:
                title_start += len("<title>")
                title_end = lower_text.find("</title>", title_start)
                if title_end != -1:
                    result["page_title"] = text[title_start:title_end].strip()

        # Security Headers Evaluation
        sec_headers = {
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
            "X-Frame-Options": response.headers.get("X-Frame-Options"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
            "Referrer-Policy": response.headers.get("Referrer-Policy"),
            "Permissions-Policy": response.headers.get("Permissions-Policy"),
        }
        result["security_headers"] = {k: v for k, v in sec_headers.items() if v is not None}

    except requests.RequestException as e:
        # If HTTPS failed, attempt fallback to HTTP probe
        if target.startswith("https://") and target_info["port"] == 443:
            try:
                fallback_target = "http://" + hostname
                response = requests.get(fallback_target, timeout=6.0, allow_redirects=True, headers={"User-Agent": "AttackLens/1.0"})
                result["target"] = fallback_target
                result["port"] = 80
                result["protocol"] = "HTTP"
                result["status_code"] = response.status_code
                result["status_text"] = response.reason
                result["final_url"] = response.url
                result["headers"] = dict(response.headers)
                result["server"] = response.headers.get("Server", "Undisclosed")
                result["content_type"] = response.headers.get("Content-Type", "Unknown")
            except Exception:
                result["error"] = f"HTTP probe failed: {str(e)}"
        else:
            result["error"] = f"HTTP probe failed: {str(e)}"

    # 4. TLS Certificate Extraction (if HTTPS)
    if result["final_url"] and result["final_url"].startswith("https://"):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            family = socket.AF_INET6 if ":" in result["ip"] else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as raw_socket:
                raw_socket.settimeout(3.5)
                raw_socket.connect((result["ip"], 443))
                with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                    cipher = tls_socket.cipher()
                    version = tls_socket.version()
                    cert_bin = tls_socket.getpeercert(binary_form=True)
                    
                    # Try to get formatted dict if possible
                    cert_dict = {}
                    try:
                        ctx_ver = ssl.create_default_context()
                        with socket.create_connection((hostname, 443), timeout=3.5) as s2:
                            with ctx_ver.wrap_socket(s2, server_hostname=hostname) as s_tls:
                                cert_dict = s_tls.getpeercert() or {}
                    except Exception:
                        pass

                    subject = dict(x[0] for x in cert_dict.get("subject", [])) if cert_dict.get("subject") else {}
                    issuer = dict(x[0] for x in cert_dict.get("issuer", [])) if cert_dict.get("issuer") else {}

                    result["tls"] = {
                        "version": version,
                        "cipher": cipher[0] if cipher else "Unknown",
                        "bits": cipher[2] if cipher and len(cipher) > 2 else None,
                        "subject_cn": subject.get("commonName") or hostname,
                        "issuer_o": issuer.get("organizationName") or issuer.get("commonName") or "Unknown CA",
                        "valid_from": cert_dict.get("notBefore"),
                        "valid_until": cert_dict.get("notAfter"),
                        "san": [item[1] for item in cert_dict.get("subjectAltName", [])] if cert_dict.get("subjectAltName") else [],
                        "is_valid": True if cert_dict else False
                    }
        except Exception as e:
            result["tls"] = {
                "error": f"TLS handshake failed: {str(e)}"
            }

    result["duration_seconds"] = round(time.time() - start_time, 2)
    return result


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def http_https_detection(request):
    """
    HTTP/HTTPS Web Inspector API (Synchronous).
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

    result = perform_http_detection(target_info)
    status_code = 200 if result.get("reachable") or result.get("status_code") else 400
    return add_cors_headers(JsonResponse(result, status=status_code))


def http_detection_stream_generator(target_info):
    """Yields real-time step-by-step SSE events for HTTP/HTTPS inspection."""
    raw_target = target_info.get("raw_target") or target_info.get("target", "")
    hostname = target_info["hostname"]
    explicit_port = target_info.get("explicit_port") or (443 if target_info.get("scheme") == "https" else 80)

    # Step 1: Initializer
    yield f"data: {json.dumps({'event': 'step', 'step': 'init', 'target': raw_target, 'hostname': hostname, 'port': explicit_port, 'message': f'Initializing inspection for {hostname}...'})}\n\n"
    time.sleep(0.04)

    # Step 2: DNS
    yield f"data: {json.dumps({'event': 'step', 'step': 'dns_resolving', 'message': f'Resolving DNS for {hostname}...'})}\n\n"
    time.sleep(0.04)

    # Run inspection
    full_result = perform_http_detection(target_info)
    ip = full_result.get("ip")
    resolved_port = full_result.get("port", explicit_port)

    if ip:
        yield f"data: {json.dumps({'event': 'step', 'step': 'dns_resolved', 'ip': ip, 'message': f'Resolved {hostname} -> {ip}'})}\n\n"
    else:
        yield f"data: {json.dumps({'event': 'error', 'message': full_result.get('error', 'DNS resolution failed')})}\n\n"
        return

    time.sleep(0.04)

    # Step 3: TCP Connection
    if full_result.get("reachable"):
        yield f"data: {json.dumps({'event': 'step', 'step': 'tcp_connected', 'ip': ip, 'port': resolved_port, 'message': f'TCP handshake OK on port {resolved_port}'})}\n\n"
    else:
        yield f"data: {json.dumps({'event': 'error', 'message': full_result.get('error', f'Port {resolved_port} is closed or filtered')})}\n\n"
        return

    time.sleep(0.04)

    # Step 4: HTTP Request Probe
    if full_result.get("status_code"):
        code = full_result["status_code"]
        text = full_result.get("status_text", "")
        srv = full_result.get("server", "Unknown")
        resp_msg = f"Received HTTP {code} {text} (Server: {srv})"
        yield f"data: {json.dumps({'event': 'step', 'step': 'http_response', 'status_code': code, 'status_text': text, 'server': srv, 'protocol': full_result.get('protocol'), 'message': resp_msg})}\n\n"

    time.sleep(0.04)

    # Step 5: TLS Details
    if full_result.get("tls") and isinstance(full_result["tls"], dict) and "version" in full_result["tls"]:
        tls_info = full_result["tls"]
        v = tls_info.get("version", "TLS")
        c = tls_info.get("cipher", "Cipher")
        tls_msg = f"TLS Handshake: {v} / {c}"
        yield f"data: {json.dumps({'event': 'step', 'step': 'tls_verified', 'tls_version': v, 'cipher': c, 'message': tls_msg})}\n\n"

    time.sleep(0.04)

    # Final Complete Event
    yield f"data: {json.dumps({'event': 'complete', 'success': full_result.get('success', True), 'data': full_result})}\n\n"




@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def stream_http_detection(request):
    """
    Live Streaming HTTP/HTTPS Detection API via Server-Sent Events (SSE).
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

    response = StreamingHttpResponse(
        http_detection_stream_generator(target_info),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint & API Discovery Engine
# ─────────────────────────────────────────────────────────────────────────────

API_PATTERN_REGEX = re.compile(
    r'(?:^|/)(?:api|v[0-9]+|graphql|rest|auth|oauth|users|products|search|login|logout|register|webhooks|admin|health|status|metrics|swagger|openapi|docs|schema|token|refresh|me|profile|settings|config|upload|download|export|import|verify|reset|callback)(?:/|[?#]|$)',
    re.IGNORECASE
)

JS_PATH_REGEX = re.compile(
    r'(?:["\'`])(/(?:api|v[0-9]+|graphql|auth|users|products|search|admin|login|logout|health|status|metrics|docs|schema|token|me|profile|settings|upload|export)[a-zA-Z0-9_\-/?#&=.]*|https?://[a-zA-Z0-9_\-.]+(?:/[a-zA-Z0-9_\-/?#&=.]*)?)(?:["\'`])',
    re.IGNORECASE
)

# Comprehensive API route wordlist to actively probe — covers REST v1/v2/v3, Django, Flask, FastAPI, Express, Spring, Rails conventions
COMMON_API_PROBE_PATHS = [
    # Health & Status
    "/health", "/health/", "/healthz", "/ping", "/status", "/ready", "/live",
    "/api/health", "/api/status", "/api/ping",
    # REST API versioning patterns
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/api/v1/users", "/api/v1/user", "/api/v1/me", "/api/v1/profile",
    "/api/v1/auth", "/api/v1/auth/login", "/api/v1/auth/logout",
    "/api/v1/auth/token", "/api/v1/auth/refresh", "/api/v1/auth/register",
    "/api/v1/login", "/api/v1/logout", "/api/v1/register",
    "/api/v1/products", "/api/v1/items", "/api/v1/search",
    "/api/v1/admin", "/api/v1/settings", "/api/v1/config",
    "/api/v2/users", "/api/v2/auth/login", "/api/v2/me",
    # Authentication & Identity
    "/auth/", "/auth/login", "/auth/logout", "/auth/token", "/auth/refresh",
    "/auth/register", "/auth/me", "/auth/callback",
    "/login", "/logout", "/register", "/signup", "/signin",
    "/oauth/authorize", "/oauth/token", "/oauth/callback",
    # Admin routes
    "/admin/", "/admin/login", "/admin/api/",
    # API Documentation / Schema discovery
    "/docs", "/docs/", "/redoc", "/redoc/",
    "/swagger", "/swagger/", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/openapi/",
    "/api/schema/", "/api/docs/", "/api-docs/", "/api/swagger/",
    # Django REST Framework
    "/api/token/", "/api/token/refresh/", "/api-auth/login/",
    "/api/schema/swagger-ui/", "/api/schema/redoc/",
    # FastAPI / Starlette
    "/docs#/", "/openapi.json",
    # Spring Boot Actuator
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/metrics", "/actuator/loggers",
    # GraphQL
    "/graphql", "/graphql/", "/api/graphql",
    # Common app routes
    "/api/v1/notifications", "/api/v1/messages",
    "/api/v1/orders", "/api/v1/payments", "/api/v1/cart",
    "/api/v1/posts", "/api/v1/comments", "/api/v1/categories",
    "/api/v1/files", "/api/v1/upload", "/api/v1/download",
    "/api/v1/reports", "/api/v1/analytics", "/api/v1/logs",
    "/api/v1/roles", "/api/v1/permissions",
    # Metrics & Monitoring
    "/metrics", "/metrics/", "/_health", "/_status",
]


def is_same_scope(candidate_url: str, base_hostname: str) -> bool:
    """Checks if a URL belongs to the target domain or its subdomains."""
    try:
        p = urllib.parse.urlparse(candidate_url)
        h = (p.hostname or "").lower()
        base = base_hostname.lower()
        return h == base or h.endswith("." + base)
    except Exception:
        return False


def clean_url_path(url: str) -> str:
    """Strips fragments and normalizes URL path."""
    try:
        p = urllib.parse.urlparse(url)
        path = p.path or "/"
        query = f"?{p.query}" if p.query else ""
        return f"{p.scheme}://{p.netloc}{path}{query}"
    except Exception:
        return url


def crawl_target_endpoints(target_info, max_pages=25, event_callback=None):
    """
    Crawls authorized target scope to discover endpoints, HTML forms, JS files,
    robots.txt, sitemaps, and REST/GraphQL API paths.
    """
    hostname = target_info["hostname"]
    scheme = target_info.get("scheme") or "https"
    explicit_port = target_info.get("explicit_port")

    port_suffix = f":{explicit_port}" if (scheme == "http" and explicit_port and explicit_port != 80) or (scheme == "https" and explicit_port and explicit_port != 443) else ""
    start_url = f"{scheme}://{hostname}{port_suffix}/"

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Attack-Lens/1.0 (Authorized Security Assessment Scanner)"
    })

    # Test connectivity & establish working start URL
    try:
        resp = session.get(start_url, timeout=6.0, allow_redirects=True, verify=False)
        start_url = resp.url
        base_hostname = urllib.parse.urlparse(start_url).hostname or hostname
    except Exception:
        if scheme == "https" and not explicit_port:
            start_url = f"http://{hostname}/"
            try:
                resp = session.get(start_url, timeout=6.0, allow_redirects=True, verify=False)
                start_url = resp.url
                base_hostname = urllib.parse.urlparse(start_url).hostname or hostname
            except Exception:
                base_hostname = hostname
        else:
            base_hostname = hostname

    visited_urls = set()
    queue = [start_url]
    in_scope_endpoints = set([start_url])
    out_of_scope_endpoints = set()
    in_scope_javascript_files = set()
    out_of_scope_javascript_files = set()
    in_scope_api_paths = set()
    out_of_scope_api_paths = set()
    forms = []
    seen_form_signatures = set()
    sitemap_urls = set()
    external_domains = set()
    robots_txt_found = False

    base_origin = f"{urllib.parse.urlparse(start_url).scheme}://{urllib.parse.urlparse(start_url).netloc}"

    # Helper to register and categorize an endpoint
    def register_endpoint(raw_url: str):
        if not raw_url or raw_url.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            return
        cleaned = clean_url_path(raw_url)
        parsed = urllib.parse.urlparse(cleaned)
        if not parsed.scheme or not parsed.netloc:
            return

        host = parsed.hostname or ""
        is_api = bool(API_PATTERN_REGEX.search(parsed.path) or "api." in host.lower() or "/graphql" in parsed.path.lower())

        if is_same_scope(cleaned, base_hostname):
            in_scope_endpoints.add(cleaned)
            if is_api:
                in_scope_api_paths.add(cleaned)
        else:
            out_of_scope_endpoints.add(cleaned)
            if host:
                external_domains.add(host)
            if is_api:
                out_of_scope_api_paths.add(cleaned)

    # 1. Discover /robots.txt
    robots_url = urllib.parse.urljoin(base_origin, "/robots.txt")
    if event_callback:
        event_callback("checking_robots", f"Probing {robots_url}...")

    try:
        r_resp = session.get(robots_url, timeout=5.0, allow_redirects=True, verify=False)
        if r_resp.status_code == 200 and "text" in r_resp.headers.get("Content-Type", ""):
            robots_txt_found = True
            register_endpoint(robots_url)
            if event_callback:
                event_callback("robots_found", f"Found /robots.txt on {base_hostname}")

            for line in r_resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        path_val = parts[1].strip()
                        if path_val and not path_val.startswith("#"):
                            full_ep = clean_url_path(urllib.parse.urljoin(base_origin, path_val))
                            register_endpoint(full_ep)
                elif line.lower().startswith("sitemap:"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        sm_url = parts[1].strip()
                        if sm_url.startswith("http"):
                            sitemap_urls.add(sm_url)
                            register_endpoint(sm_url)
    except Exception:
        pass

    # 2. Discover /sitemap.xml
    sitemaps_to_check = list(sitemap_urls) or [urllib.parse.urljoin(base_origin, "/sitemap.xml")]
    for sm_url in sitemaps_to_check[:3]:
        try:
            sm_resp = session.get(sm_url, timeout=5.0, allow_redirects=True, verify=False)
            if sm_resp.status_code == 200:
                register_endpoint(sm_url)
                sitemap_urls.add(sm_url)
                if event_callback:
                    event_callback("sitemap_found", f"Discovered sitemap: {sm_url}")
                locs = re.findall(r'<loc>(https?://[^<]+)</loc>', sm_resp.text, re.IGNORECASE)
                for loc in locs:
                    loc_clean = clean_url_path(loc.strip())
                    register_endpoint(loc_clean)
                    sitemap_urls.add(loc_clean)
                    if is_same_scope(loc_clean, base_hostname) and len(queue) < max_pages * 2 and loc_clean not in queue:
                        queue.append(loc_clean)
        except Exception:
            pass

    # 3. Main Crawl Loop
    while queue and len(visited_urls) < max_pages:
        current_url = queue.pop(0)
        current_url_clean = clean_url_path(current_url)

        if current_url_clean in visited_urls:
            continue
        visited_urls.add(current_url_clean)

        if event_callback:
            event_callback("crawling_page", f"Scanning page ({len(visited_urls)}/{max_pages}): {current_url_clean}")

        try:
            time.sleep(0.02)  # polite rate-limit pacing
            page_resp = session.get(current_url_clean, timeout=6.0, allow_redirects=True, verify=False)
            final_page_url = clean_url_path(page_resp.url)
            register_endpoint(final_page_url)

            content_type = page_resp.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(page_resp.text, "html.parser")

            # Extract <a> Links
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                    continue

                resolved = clean_url_path(urllib.parse.urljoin(final_page_url, href))
                register_endpoint(resolved)

                if is_same_scope(resolved, base_hostname):
                    if resolved not in visited_urls and resolved not in queue and len(queue) < 100:
                        queue.append(resolved)

            # Extract Forms
            for form in soup.find_all("form"):
                action_raw = form.get("action") or final_page_url
                action = clean_url_path(urllib.parse.urljoin(final_page_url, action_raw))
                method = (form.get("method") or "GET").upper()

                params = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    p_name = inp.get("name")
                    if p_name:
                        p_type = inp.get("type") or inp.name
                        params.append({
                            "name": p_name,
                            "type": p_type
                        })

                form_sig = f"{method}:{action}:{','.join(sorted([p['name'] for p in params]))}"
                if form_sig not in seen_form_signatures:
                    seen_form_signatures.add(form_sig)
                    form_in_scope = is_same_scope(action, base_hostname)
                    forms.append({
                        "action": action,
                        "method": method,
                        "in_scope": form_in_scope,
                        "domain": urllib.parse.urlparse(action).hostname or base_hostname,
                        "parameters": params
                    })
                    register_endpoint(action)
                    if event_callback:
                        event_callback("form_discovered", f"Form found [{method}] -> {action}")

            # Extract <script src="...">
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    js_url = clean_url_path(urllib.parse.urljoin(final_page_url, src.strip()))
                    if is_same_scope(js_url, base_hostname):
                        in_scope_javascript_files.add(js_url)
                    else:
                        out_of_scope_javascript_files.add(js_url)
                        js_host = urllib.parse.urlparse(js_url).hostname
                        if js_host:
                            external_domains.add(js_host)
                else:
                    if script.string:
                        for match in JS_PATH_REGEX.findall(script.string):
                            m_clean = clean_url_path(urllib.parse.urljoin(base_origin, match))
                            register_endpoint(m_clean)

            # Deep inspect top discovered in-scope JS files
            for js_file in list(in_scope_javascript_files)[:5]:
                try:
                    js_resp = session.get(js_file, timeout=4.0, verify=False)
                    if js_resp.status_code == 200:
                        for match in JS_PATH_REGEX.findall(js_resp.text):
                            m_clean = clean_url_path(urllib.parse.urljoin(base_origin, match))
                            register_endpoint(m_clean)
                except Exception:
                    pass

        except Exception:
            continue

    # ── 4. Active API Route Probing (wordlist-based) ──────────────────────────
    # Many API endpoints return JSON and have no HTML links pointing to them.
    # Probe COMMON_API_PROBE_PATHS in parallel to discover routes that crawlers miss.
    if event_callback:
        event_callback("api_probing", f"Active-probing {len(COMMON_API_PROBE_PATHS)} known API route patterns...")

    def probe_path(path: str):
        """Probe a single API path; return (url, status_code) if alive, else None."""
        candidate_url = clean_url_path(urllib.parse.urljoin(base_origin, path))
        try:
            r = session.get(
                candidate_url,
                timeout=3.0,
                allow_redirects=False,
                verify=False,
            )
            # 2xx = success, 3xx = redirect (path exists), 401/403 = auth-protected (exists),
            # 405 = method not allowed (route exists but wrong method), 422 = validation error (FastAPI)
            if r.status_code in (200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 405, 422):
                return (candidate_url, r.status_code)
        except Exception:
            pass
        return None

    # Probe in parallel with a bounded thread pool so it stays fast
    with ThreadPoolExecutor(max_workers=20) as probe_executor:
        probe_futures = {probe_executor.submit(probe_path, p): p for p in COMMON_API_PROBE_PATHS}
        for future in as_completed(probe_futures):
            probe_result = future.result()
            if probe_result:
                probed_url, status_code = probe_result
                register_endpoint(probed_url)
                if event_callback:
                    event_callback("api_route_found", f"[{status_code}] {probed_url}")

    all_endpoints = sorted(list(in_scope_endpoints | out_of_scope_endpoints))
    all_api_paths = sorted(list(in_scope_api_paths | out_of_scope_api_paths))
    all_javascript_files = sorted(list(in_scope_javascript_files | out_of_scope_javascript_files))

    # Build structured discovered_endpoints list (URL + path + method + scope) for UI rendering
    discovered_endpoints_structured = []
    for ep_url in sorted(list(in_scope_endpoints)):
        parsed_ep = urllib.parse.urlparse(ep_url)
        ep_path = parsed_ep.path or "/"
        discovered_endpoints_structured.append({
            "url": ep_url,
            "path": ep_path,
            "method": "GET",
            "status_code": 200,
            "scope": "in-scope",
            "is_api": bool(API_PATTERN_REGEX.search(ep_path)),
        })

    return {
        "target": start_url,
        "hostname": base_hostname,
        "statistics": {
            "pages_scanned": len(visited_urls),
            "endpoints_found": len(all_endpoints),
            "in_scope_endpoints": len(in_scope_endpoints),
            "out_of_scope_endpoints": len(out_of_scope_endpoints),
            "javascript_files": len(all_javascript_files),
            "api_paths": len(all_api_paths),
            "in_scope_api_paths": len(in_scope_api_paths),
            "out_of_scope_api_paths": len(out_of_scope_api_paths),
            "forms": len(forms),
            "sitemap_urls": len(sitemap_urls)
        },
        "scope_summary": {
            "target_scope": base_hostname,
            "in_scope_count": len(in_scope_endpoints),
            "out_of_scope_count": len(out_of_scope_endpoints),
            "in_scope_api_count": len(in_scope_api_paths),
            "out_of_scope_api_count": len(out_of_scope_api_paths),
            "external_domains": sorted(list(external_domains))
        },
        "endpoints": all_endpoints,
        "discovered_endpoints": discovered_endpoints_structured,
        "in_scope_endpoints": sorted(list(in_scope_endpoints)),
        "out_of_scope_endpoints": sorted(list(out_of_scope_endpoints)),
        "api_paths": all_api_paths,
        "in_scope_api_paths": sorted(list(in_scope_api_paths)),
        "out_of_scope_api_paths": sorted(list(out_of_scope_api_paths)),
        "javascript_files": all_javascript_files,
        "in_scope_javascript_files": sorted(list(in_scope_javascript_files)),
        "out_of_scope_javascript_files": sorted(list(out_of_scope_javascript_files)),
        "forms": forms,
        "sitemap_urls": sorted(list(sitemap_urls)),
        "robots_txt_found": robots_txt_found
    }


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def discover_endpoints(request):
    """
    Synchronous Endpoint & Web Surface Discovery API.
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
        max_pages = int(params.get("max_pages", 20))
        max_pages = max(1, min(max_pages, 100))
    except (ValueError, TypeError):
        max_pages = 20

    result = crawl_target_endpoints(target_info, max_pages=max_pages)
    return add_cors_headers(JsonResponse(result))


def endpoint_discovery_stream_generator(target_info, max_pages=20):
    """Yields real-time SSE discovery telemetry events during crawl."""
    hostname = target_info["hostname"]
    raw_target = target_info.get("raw_target") or target_info.get("target", "")

    yield f"data: {json.dumps({'event': 'init', 'target': raw_target, 'hostname': hostname, 'message': f'Initializing endpoint discovery for {hostname}...'})}\n\n"
    time.sleep(0.04)

    events_buffer = []

    def on_event(event_type, msg):
        events_buffer.append((event_type, msg))

    # Run crawler in background/thread with live yield
    result = crawl_target_endpoints(target_info, max_pages=max_pages, event_callback=on_event)

    for ev_type, ev_msg in events_buffer:
        yield f"data: {json.dumps({'event': 'step', 'step': ev_type, 'message': ev_msg})}\n\n"
        time.sleep(0.02)

    yield f"data: {json.dumps({'event': 'complete', 'success': True, 'data': result})}\n\n"


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def stream_endpoint_discovery(request):
    """
    Live Streaming Endpoint Discovery API via Server-Sent Events (SSE).
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
        max_pages = int(params.get("max_pages", 20))
        max_pages = max(1, min(max_pages, 100))
    except (ValueError, TypeError):
        max_pages = 20

    response = StreamingHttpResponse(
        endpoint_discovery_stream_generator(target_info, max_pages=max_pages),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)