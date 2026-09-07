"""
TLS Protocol Version Prober
Probes server support for specific TLS protocol versions (TLS 1.0, 1.1, 1.2, 1.3) safely.
"""
import socket
import ssl
from typing import Dict, Any, List, Tuple, Optional
from .findings import TlsFinding

VERSION_MAP = [
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]


def test_specific_tls_version(
    hostname: str,
    port: int,
    tls_version_enum: ssl.TLSVersion,
    timeout: float = 3.5
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Attempts a single TLS handshake targeting an exact minimum and maximum protocol version.
    """
    if tls_version_enum is None:
        return False, None, "Protocol version not supported by local OpenSSL runtime"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Set exact version range
    try:
        ctx.minimum_version = tls_version_enum
        ctx.maximum_version = tls_version_enum
    except (ValueError, ssl.SSLError) as e:
        return False, None, f"Local OpenSSL config restricts this version: {str(e)}"

    # Enable legacy ciphers if probing TLS 1.0/1.1
    if tls_version_enum in (getattr(ssl.TLSVersion, "TLSv1", None), getattr(ssl.TLSVersion, "TLSv1_1", None)):
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0:ALL")
        except Exception:
            pass

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as ssock:
                negotiated_ver = ssock.version()
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else None
                return True, cipher_name, None
    except (ssl.SSLError, socket.error, OSError) as e:
        return False, None, str(e)


def probe_supported_tls_versions(
    hostname: str,
    port: int = 443,
    timeout: float = 3.5
) -> Tuple[Dict[str, bool], Dict[str, Any], List[TlsFinding], List[str]]:
    """
    Probes all standard TLS protocol versions and generates security findings.
    """
    findings: List[TlsFinding] = []
    errors: List[str] = []
    finding_counter = 1

    def next_id():
        nonlocal finding_counter
        fid = f"TLS-VER-{finding_counter:03d}"
        finding_counter += 1
        return fid

    supported_versions: Dict[str, bool] = {}
    details: Dict[str, Any] = {}

    for ver_name, ver_enum in VERSION_MAP:
        if ver_enum is None:
            supported_versions[ver_name] = False
            details[ver_name] = {"supported": False, "note": "Unsupported in local Python runtime"}
            continue

        is_supported, cipher_name, err = test_specific_tls_version(
            hostname=hostname,
            port=port,
            tls_version_enum=ver_enum,
            timeout=timeout
        )
        supported_versions[ver_name] = is_supported
        details[ver_name] = {
            "supported": is_supported,
            "cipher": cipher_name,
            "error": err if not is_supported else None
        }

    # ─────────────────────────────────────────────────────────────────────────
    # FINDINGS
    # ─────────────────────────────────────────────────────────────────────────

    # 1. Deprecated TLS 1.0
    if supported_versions.get("TLSv1.0"):
        findings.append(TlsFinding(
            id=next_id(),
            title="Deprecated TLS 1.0 Supported",
            category="protocol",
            severity="medium",
            confidence=0.99,
            description="The server accepted a TLS 1.0 handshake. TLS 1.0 was formally deprecated by RFC 8996 and contains cryptographic weaknesses (e.g. BEAST, CBC padding issues).",
            evidence={
                "protocol": "TLSv1.0",
                "handshake_successful": True,
                "cipher": details.get("TLSv1.0", {}).get("cipher")
            },
            recommendation="Disable TLS 1.0 in server configuration and require TLS 1.2 or TLS 1.3."
        ))

    # 2. Deprecated TLS 1.1
    if supported_versions.get("TLSv1.1"):
        findings.append(TlsFinding(
            id=next_id(),
            title="Deprecated TLS 1.1 Supported",
            category="protocol",
            severity="medium",
            confidence=0.99,
            description="The server accepted a TLS 1.1 handshake. TLS 1.1 was formally deprecated by RFC 8996 and lacks support for modern cipher constructions.",
            evidence={
                "protocol": "TLSv1.1",
                "handshake_successful": True,
                "cipher": details.get("TLSv1.1", {}).get("cipher")
            },
            recommendation="Disable TLS 1.1 in server configuration and require TLS 1.2 or TLS 1.3."
        ))

    # 3. Modern Protocol Support
    has_tls12 = supported_versions.get("TLSv1.2", False)
    has_tls13 = supported_versions.get("TLSv1.3", False)

    if not has_tls12 and not has_tls13:
        findings.append(TlsFinding(
            id=next_id(),
            title="Modern TLS (TLS 1.2 / TLS 1.3) Not Supported",
            category="protocol",
            severity="high",
            confidence=0.95,
            description="The server did not successfully negotiate either TLS 1.2 or TLS 1.3.",
            evidence={"supported_versions": supported_versions},
            recommendation="Enable and enforce TLS 1.2 and TLS 1.3 on the server."
        ))

    return supported_versions, details, findings, errors
