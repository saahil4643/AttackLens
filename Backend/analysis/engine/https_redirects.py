"""
HTTPS Enforcement & Redirect Chain Analyzer
"""
import socket
import ssl
import time
import urllib.parse
from typing import Dict, Any, List, Tuple
import requests
from .findings import Finding


def check_https_availability(hostname: str, port: int = 443, timeout: float = 4.0) -> Tuple[bool, Dict[str, Any]]:
    """Checks if HTTPS is reachable and basic TLS handshake completes."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()
                return True, {
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else None,
                    "bits": cipher[2] if cipher else None
                }
    except Exception:
        return False, {}


def trace_http_to_https_redirect(
    hostname: str,
    explicit_port: int = None,
    path: str = "/",
    max_redirects: int = 8,
    timeout: float = 5.0
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Finding]]:
    """
    Probes http://hostname:port/path and traces the redirect sequence step-by-step
    without blindly following infinite loops.
    """
    findings: List[Finding] = []
    finding_counter = 1

    def next_id():
        nonlocal finding_counter
        fid = f"SEC-HTTPS-{finding_counter:03d}"
        finding_counter += 1
        return fid

    http_port = explicit_port if explicit_port and explicit_port != 443 else 80
    port_str = f":{http_port}" if http_port not in (80, 443) else ""
    current_url = f"http://{hostname}{port_str}{path}"

    redirect_chain: List[Dict[str, Any]] = []
    visited_urls = set()
    final_url = current_url
    http_to_https_redirect = False
    reached_https = False
    is_http_reachable = False

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackLens/1.0"
    })

    hops = 0
    while hops < max_redirects:
        if current_url in visited_urls:
            # Loop detected
            findings.append(Finding(
                id=next_id(),
                title="Circular HTTP Redirect Loop Detected",
                category="redirects",
                severity="low",
                confidence=0.99,
                description=f"A redirect loop was encountered while following URL '{current_url}'.",
                evidence={"loop_url": current_url, "redirect_count": len(redirect_chain)},
                recommendation="Review server routing and rewrite rules to remove cyclic redirect chains."
            ))
            break

        visited_urls.add(current_url)

        try:
            resp = session.get(current_url, timeout=timeout, allow_redirects=False, verify=False)
            is_http_reachable = True
            status_code = resp.status_code
            location = resp.headers.get("Location")

            if current_url.startswith("https://"):
                reached_https = True

            hop_entry = {
                "hop": hops + 1,
                "status_code": status_code,
                "source": current_url,
                "location": location
            }
            redirect_chain.append(hop_entry)

            if status_code in (301, 302, 303, 307, 308) and location:
                # Resolve relative or protocol-relative redirect URLs
                next_url = urllib.parse.urljoin(current_url, location)
                if current_url.startswith("http://") and next_url.startswith("https://"):
                    http_to_https_redirect = True
                current_url = next_url
                hops += 1
            else:
                final_url = current_url
                break

        except Exception as e:
            # Connection failed on this hop
            break

    # Check HTTPS availability
    https_port = explicit_port if explicit_port and explicit_port != 80 else 443
    https_available, tls_info = check_https_availability(hostname, https_port)

    # Findings analysis
    if is_http_reachable:
        if not http_to_https_redirect and https_available:
            findings.append(Finding(
                id=next_id(),
                title="HTTP Requests Not Upgraded to HTTPS",
                category="https",
                severity="medium",
                confidence=0.95,
                description=f"Port 80 (HTTP) is open and accessible, but plaintext requests to 'http://{hostname}' are not automatically redirected to 'https://{hostname}'.",
                evidence={
                    "http_accessible": True,
                    "https_available": https_available,
                    "http_to_https_redirect": False,
                    "final_url": final_url
                },
                recommendation="Configure a 301 Permanent Redirect on HTTP (port 80) to forward all traffic to HTTPS (port 443)."
            ))
        elif http_to_https_redirect:
            # Great, redirected to HTTPS
            pass
    elif not https_available:
        findings.append(Finding(
            id=next_id(),
            title="HTTPS (TLS) Unavailable",
            category="https",
            severity="medium",
            confidence=0.90,
            description="The target does not support HTTPS/TLS on standard ports. Communications remain unencrypted.",
            evidence={"https_available": False},
            recommendation="Install a valid SSL/TLS certificate and enforce HTTPS."
        ))

    https_summary = {
        "available": https_available,
        "tls_info": tls_info,
        "http_to_https_redirect": http_to_https_redirect,
        "final_url": final_url,
        "redirect_count": len(redirect_chain)
    }

    return https_summary, redirect_chain, findings
