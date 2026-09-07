"""
Certificate Analyzer
Extracts and validates X.509 server certificate attributes, SAN matching, and cryptographic strength.
"""
import fnmatch
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
from .findings import TlsFinding


def match_hostname(hostname: str, san_list: List[str], cn: Optional[str] = None) -> bool:
    """
    Checks if target hostname matches any Subject Alternative Name or Common Name.
    Supports standard wildcards (e.g. *.example.com matches sub.example.com).
    """
    hostname_lower = hostname.lower().strip(".")
    candidates = [s.lower().strip(".") for s in san_list]
    if cn:
        candidates.append(cn.lower().strip("."))

    for pattern in candidates:
        if pattern == hostname_lower:
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            # *.example.com matches sub.example.com but not deep.sub.example.com or example.com
            parts_host = hostname_lower.split(".")
            parts_pat = suffix.split(".")
            if len(parts_host) == len(parts_pat) + 1 and hostname_lower.endswith(f".{suffix}"):
                return True
        elif "*" in pattern:
            if fnmatch.fnmatch(hostname_lower, pattern):
                return True

    return False


def parse_name_attributes(name: x509.Name) -> Dict[str, str]:
    """Extracts common components from an X.509 Name."""
    attr_map = {}
    for attr in name:
        oid_name = attr.oid._name
        val = str(attr.value)
        if oid_name == "commonName":
            attr_map["CN"] = val
        elif oid_name == "organizationName":
            attr_map["O"] = val
        elif oid_name == "organizationalUnitName":
            attr_map["OU"] = val
        elif oid_name == "countryName":
            attr_map["C"] = val
        elif oid_name == "stateOrProvinceName":
            attr_map["ST"] = val
        elif oid_name == "localityName":
            attr_map["L"] = val
        else:
            attr_map[oid_name] = val
    return attr_map


def format_name_string(attr_map: Dict[str, str]) -> str:
    """Formats name dictionary into standard RFC string e.g. CN=example.com, O=Org, C=US."""
    order = ["CN", "O", "OU", "L", "ST", "C"]
    parts = []
    for k in order:
        if k in attr_map:
            parts.append(f"{k}={attr_map[k]}")
    for k, v in attr_map.items():
        if k not in order:
            parts.append(f"{k}={v}")
    return ", ".join(parts) if parts else "Unknown"


def analyze_certificate(
    cert_der: bytes,
    target_hostname: str
) -> Tuple[Dict[str, Any], List[TlsFinding]]:
    """
    Analyzes raw DER certificate bytes using cryptography.x509 and evaluates security attributes.
    """
    findings: List[TlsFinding] = []
    finding_counter = 1

    def next_id():
        nonlocal finding_counter
        fid = f"TLS-CRT-{finding_counter:03d}"
        finding_counter += 1
        return fid

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as e:
        return {
            "valid": False,
            "error": f"Failed to parse X.509 DER certificate: {str(e)}",
            "hostname_match": False
        }, [
            TlsFinding(
                id=next_id(),
                title="Malformed or Unparseable TLS Certificate",
                category="certificate",
                severity="high",
                confidence=0.99,
                description=f"The server presented a TLS certificate that could not be parsed: {str(e)}.",
                evidence={"error": str(e)},
                recommendation="Reinstall a valid X.509 certificate on the web server."
            )
        ]

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    # Validity & expiration calculations
    is_expired = now > not_after
    not_yet_valid = now < not_before
    is_time_valid = not is_expired and not not_yet_valid
    expires_in_days = (not_after - now).days if not is_expired else 0

    # Subject & Issuer
    subject_attrs = parse_name_attributes(cert.subject)
    issuer_attrs = parse_name_attributes(cert.issuer)
    subject_str = format_name_string(subject_attrs)
    issuer_str = format_name_string(issuer_attrs)
    common_name = subject_attrs.get("CN")

    # Subject Alternative Names (SAN)
    sans: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
            elif isinstance(name, x509.IPAddress):
                sans.append(str(name.value))
    except x509.ExtensionNotFound:
        sans = []

    # Hostname matching check
    is_hostname_match = match_hostname(target_hostname, sans, common_name)

    # Public Key Algorithm & Size
    pub_key = cert.public_key()
    pub_key_alg = "Unknown"
    pub_key_size: Optional[int] = None

    if isinstance(pub_key, rsa.RSAPublicKey):
        pub_key_alg = "RSA"
        pub_key_size = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_key_alg = f"EC ({pub_key.curve.name})"
        pub_key_size = pub_key.key_size
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        pub_key_alg = "Ed25519"
        pub_key_size = 256
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        pub_key_alg = "Ed448"
        pub_key_size = 448
    elif isinstance(pub_key, dsa.DSAPublicKey):
        pub_key_alg = "DSA"
        pub_key_size = pub_key.key_size

    # Signature Algorithm
    try:
        sig_alg = cert.signature_algorithm_oid._name
    except Exception:
        sig_alg = "Unknown"

    # Serial number
    serial_number_hex = format(cert.serial_number, "X")

    # ─────────────────────────────────────────────────────────────────────────
    # SECURITY FINDINGS EVALUATION
    # ─────────────────────────────────────────────────────────────────────────

    # 1. Expiration Checks
    if is_expired:
        findings.append(TlsFinding(
            id=next_id(),
            title="TLS Certificate Has Expired",
            category="certificate",
            severity="high",
            confidence=0.99,
            description=f"The server certificate expired on {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}. Browsers and clients will display security warnings and reject connections.",
            evidence={
                "valid_until": not_after.isoformat(),
                "current_time": now.isoformat(),
                "days_expired": abs(expires_in_days)
            },
            recommendation="Renew and install a new TLS certificate immediately."
        ))
    elif not_yet_valid:
        findings.append(TlsFinding(
            id=next_id(),
            title="TLS Certificate Not Yet Valid",
            category="certificate",
            severity="high",
            confidence=0.99,
            description=f"The server certificate is not valid until {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}.",
            evidence={
                "valid_from": not_before.isoformat(),
                "current_time": now.isoformat()
            },
            recommendation="Verify server system clock and certificate validity timeframe."
        ))
    elif expires_in_days <= 7:
        findings.append(TlsFinding(
            id=next_id(),
            title=f"TLS Certificate Expiring Soon ({expires_in_days} Days Remaining)",
            category="certificate",
            severity="medium",
            confidence=0.99,
            description=f"The certificate will expire in {expires_in_days} days on {not_after.strftime('%Y-%m-%d')}.",
            evidence={
                "valid_until": not_after.isoformat(),
                "expires_in_days": expires_in_days
            },
            recommendation="Renew the certificate promptly to prevent service outage."
        ))
    elif expires_in_days <= 30:
        findings.append(TlsFinding(
            id=next_id(),
            title=f"TLS Certificate Approaching Expiration ({expires_in_days} Days Remaining)",
            category="certificate",
            severity="low",
            confidence=0.99,
            description=f"The certificate expires within 30 days ({expires_in_days} days remaining on {not_after.strftime('%Y-%m-%d')}).",
            evidence={
                "valid_until": not_after.isoformat(),
                "expires_in_days": expires_in_days
            },
            recommendation="Schedule upcoming certificate renewal."
        ))

    # 2. Hostname Mismatch Check
    if not is_hostname_match:
        findings.append(TlsFinding(
            id=next_id(),
            title="Certificate Hostname Mismatch",
            category="certificate",
            severity="high",
            confidence=0.99,
            description=f"The target hostname '{target_hostname}' does not match any name in the certificate SAN list or Common Name.",
            evidence={
                "target_hostname": target_hostname,
                "common_name": common_name,
                "subject_alternative_names": sans
            },
            recommendation="Obtain a certificate that includes the requested domain in its Subject Alternative Names (SAN)."
        ))

    # 3. Weak Public Key Size
    if pub_key_alg == "RSA" and pub_key_size and pub_key_size < 2048:
        findings.append(TlsFinding(
            id=next_id(),
            title=f"Weak RSA Public Key Size ({pub_key_size} bits)",
            category="certificate",
            severity="high",
            confidence=0.99,
            description=f"The certificate uses an RSA key size of {pub_key_size} bits. Minimum industry standard is 2048 bits.",
            evidence={
                "public_key_algorithm": "RSA",
                "public_key_size": pub_key_size
            },
            recommendation="Reissue the certificate with an RSA key of at least 2048 bits (or ECDSA 256+ bits)."
        ))

    # 4. Weak Signature Algorithm (SHA-1 / MD5)
    sig_alg_lower = sig_alg.lower()
    if "md5" in sig_alg_lower:
        findings.append(TlsFinding(
            id=next_id(),
            title="Insecure MD5 Signature Algorithm",
            category="certificate",
            severity="high",
            confidence=0.99,
            description="The certificate was signed using MD5, which is cryptographically broken and vulnerable to collision attacks.",
            evidence={"signature_algorithm": sig_alg},
            recommendation="Replace certificate with one signed by SHA-256 or stronger."
        ))
    elif "sha1" in sig_alg_lower:
        findings.append(TlsFinding(
            id=next_id(),
            title="Deprecated SHA-1 Signature Algorithm",
            category="certificate",
            severity="medium",
            confidence=0.99,
            description="The certificate uses a SHA-1 based signature algorithm. SHA-1 is deprecated and rejected by modern browsers.",
            evidence={"signature_algorithm": sig_alg},
            recommendation="Reissue certificate with SHA-256 (e.g. sha256WithRSAEncryption or ecdsa-with-SHA256)."
        ))

    # 5. Self-Signed Certificate Check
    is_self_signed = (subject_str == issuer_str) and (cert.subject == cert.issuer)
    if is_self_signed:
        findings.append(TlsFinding(
            id=next_id(),
            title="Self-Signed TLS Certificate Observed",
            category="certificate",
            severity="medium",
            confidence=0.95,
            description="The certificate issuer matches its subject, indicating it is self-signed rather than signed by a trusted Certificate Authority (CA).",
            evidence={
                "subject": subject_str,
                "issuer": issuer_str
            },
            recommendation="Deploy a certificate issued by a recognized, trusted CA (such as Let's Encrypt or a commercial CA)."
        ))

    cert_result = {
        "valid": is_time_valid and is_hostname_match,
        "is_time_valid": is_time_valid,
        "is_expired": is_expired,
        "not_yet_valid": not_yet_valid,
        "hostname_match": is_hostname_match,
        "expires_in_days": expires_in_days,
        "valid_from": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "valid_until": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "subject": subject_str,
        "subject_attributes": subject_attrs,
        "issuer": issuer_str,
        "issuer_attributes": issuer_attrs,
        "common_name": common_name,
        "san": sans,
        "public_key_algorithm": pub_key_alg,
        "public_key_size": pub_key_size,
        "signature_algorithm": sig_alg,
        "serial_number": serial_number_hex,
        "version": cert.version.name,
        "is_self_signed": is_self_signed
    }

    return cert_result, findings
