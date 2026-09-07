"""
TLS / SSL Master Scanner Orchestrator
"""
import socket
import ssl
import time
from typing import Dict, Any, List, Optional, Callable
import urllib3

from scan.views import parse_http_target
from .findings import TlsFinding
from .certificate_analyzer import analyze_certificate
from .tls_prober import probe_supported_tls_versions
from .cipher_analyzer import analyze_cipher_suite

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan_tls_security(
    raw_target: str,
    event_callback: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None
) -> Dict[str, Any]:
    """
    Executes a comprehensive, non-destructive TLS/SSL security assessment.
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
    port = explicit_port if explicit_port else 443

    if event_callback:
        event_callback("init", f"Initializing TLS/SSL security assessment for {hostname}:{port}...", {
            "hostname": hostname,
            "port": port
        })

    # 1. DNS Resolution
    resolved_ip = None
    if event_callback:
        event_callback("resolving_dns", f"Resolving DNS for {hostname}...", None)

    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ip = addr_info[0][4][0]
    except socket.gaierror:
        return {
            "success": False,
            "target": raw_target,
            "hostname": hostname,
            "port": port,
            "scan_status": "failed",
            "error": f"Could not resolve domain '{hostname}' (DNS failure)",
            "errors": [f"Could not resolve domain '{hostname}'"]
        }
    except Exception as e:
        return {
            "success": False,
            "target": raw_target,
            "hostname": hostname,
            "port": port,
            "scan_status": "failed",
            "error": f"Host resolution error: {str(e)}",
            "errors": [str(e)]
        }

    # 2. Main TLS Handshake & Certificate Extraction
    if event_callback:
        event_callback("connecting_tls", f"Establishing TLS connection with SNI to {hostname}:{port}...", {
            "ip": resolved_ip
        })

    negotiated_version = None
    negotiated_cipher = None
    cert_der = None
    https_available = False
    chain_info: Dict[str, Any] = {"status": "not_available", "length": 0}
    ocsp_info: Dict[str, Any] = {"status": "not_available"}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    all_findings_raw: List[TlsFinding] = []

    try:
        with socket.create_connection((hostname, port), timeout=6.0) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as ssock:
                https_available = True
                negotiated_version = ssock.version()
                negotiated_cipher = ssock.cipher()
                cert_der = ssock.getpeercert(binary_form=True)

                # Safe chain info inspection if supported by Python runtime
                if hasattr(ssock, "get_verified_chain") and callable(ssock.get_verified_chain):
                    try:
                        chain = ssock.get_verified_chain()
                        if chain:
                            chain_info = {
                                "status": "available",
                                "length": len(chain)
                            }
                    except Exception:
                        pass
                elif cert_der:
                    chain_info = {
                        "status": "available",
                        "length": 1,
                        "note": "Peer certificate retrieved successfully"
                    }

                # Safe OCSP stapling inspection if supported
                if hasattr(ssock, "ocsp_response") and ssock.ocsp_response:
                    ocsp_info = {"status": "observed", "length": len(ssock.ocsp_response)}
                else:
                    ocsp_info = {"status": "not_observed"}

    except (ssl.SSLError, socket.error, OSError) as e:
        err_msg = str(e)
        errors.append(f"TLS connection to {hostname}:{port} failed: {err_msg}")
        return {
            "success": False,
            "target": raw_target,
            "hostname": hostname,
            "port": port,
            "resolved_ip": resolved_ip,
            "scan_status": "failed",
            "https_available": False,
            "error": f"TLS connection failed: {err_msg}",
            "errors": errors,
            "summary": {
                "total_findings": 1,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "findings": [
                {
                    "id": "TLS-001",
                    "title": "TLS Connection Failed / HTTPS Unavailable",
                    "category": "tls",
                    "severity": "high",
                    "confidence": 0.99,
                    "description": f"Could not establish a TLS handshake on {hostname}:{port}. Error: {err_msg}",
                    "evidence": {"port": port, "error": err_msg},
                    "recommendation": "Verify that an SSL/TLS enabled web server is running and listening on the specified port."
                }
            ]
        }

    # 3. Certificate Analysis
    cert_data: Dict[str, Any] = {}
    if cert_der:
        if event_callback:
            event_callback("analyzing_certificate", "Parsing X.509 certificate, checking SANs and expiration...", None)
        cert_data, cert_findings = analyze_certificate(cert_der, hostname)
        all_findings_raw.extend(cert_findings)

    # 4. Cipher Suite Analysis
    cipher_data: Dict[str, Any] = {}
    if negotiated_cipher:
        if event_callback:
            event_callback("analyzing_ciphers", f"Analyzing negotiated cipher suite: {negotiated_cipher[0]}...", None)
        cipher_data, cipher_findings = analyze_cipher_suite(negotiated_cipher, negotiated_version)
        all_findings_raw.extend(cipher_findings)

    # 5. Multi-Version TLS Probing (TLS 1.0, 1.1, 1.2, 1.3)
    if event_callback:
        event_callback("probing_tls_versions", "Probing server support for TLS 1.0, 1.1, 1.2, and 1.3...", None)
    supported_tls, ver_details, ver_findings, ver_errors = probe_supported_tls_versions(
        hostname=hostname,
        port=port,
        timeout=3.5
    )
    all_findings_raw.extend(ver_findings)
    if ver_errors:
        errors.extend(ver_errors)
        scan_status = "partial"

    # 6. Format and Index Findings
    if event_callback:
        event_callback("evaluating_findings", "Aggregating findings and security status...", None)

    formatted_findings: List[Dict[str, Any]] = []
    for idx, f in enumerate(all_findings_raw, start=1):
        f.id = f"TLS-{idx:03d}"
        formatted_findings.append(f.to_dict())

    # Summary
    high_count = sum(1 for f in formatted_findings if f["severity"] == "high")
    med_count = sum(1 for f in formatted_findings if f["severity"] == "medium")
    low_count = sum(1 for f in formatted_findings if f["severity"] == "low")
    info_count = sum(1 for f in formatted_findings if f["severity"] == "info")

    if high_count > 0:
        tls_status = "INSECURE"
        status_color = "#f85149"
    elif med_count > 0:
        tls_status = "DEPRECATED / ATTENTION NEEDED"
        status_color = "#d29922"
    elif low_count > 0:
        tls_status = "ADEQUATE"
        status_color = "#58a6ff"
    else:
        tls_status = "SECURE"
        status_color = "#3fb950"

    scan_duration = round(time.time() - start_time, 2)

    final_result = {
        "success": True,
        "target": raw_target,
        "hostname": hostname,
        "port": port,
        "resolved_ip": resolved_ip,
        "scan_status": scan_status,
        "scan_duration_seconds": scan_duration,
        "https_available": https_available,
        "tls_status": tls_status,
        "status_color": status_color,
        "negotiated": {
            "tls_version": negotiated_version,
            "cipher": cipher_data
        },
        "supported_tls_versions": supported_tls,
        "version_probe_details": ver_details,
        "certificate": cert_data,
        "certificate_chain": chain_info,
        "ocsp_stapling": ocsp_info,
        "findings": formatted_findings,
        "summary": {
            "total_findings": len(formatted_findings),
            "high": high_count,
            "medium": med_count,
            "low": low_count,
            "info": info_count
        },
        "errors": errors
    }

    if event_callback:
        event_callback("complete", "TLS security assessment completed successfully.", final_result)

    return final_result
