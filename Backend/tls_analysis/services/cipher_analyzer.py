"""
Cipher Suite & Forward Secrecy Analyzer
"""
from typing import Dict, Any, List, Tuple
from .findings import TlsFinding

TLS_13_CIPHERS = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
}


def analyze_cipher_suite(
    cipher_tuple: Tuple[str, str, int],
    tls_version: str
) -> Tuple[Dict[str, Any], List[TlsFinding]]:
    """
    Analyzes the negotiated cipher suite, checks bit length, evaluates Perfect Forward Secrecy (PFS),
    and flags legacy or weak ciphers.
    """
    findings: List[TlsFinding] = []
    finding_counter = 1

    def next_id():
        nonlocal finding_counter
        fid = f"TLS-CIP-{finding_counter:03d}"
        finding_counter += 1
        return fid

    if not cipher_tuple:
        return {
            "name": "Unknown",
            "protocol": tls_version,
            "bits": None,
            "forward_secrecy": False,
            "is_aead": False
        }, []

    cipher_name, protocol, bits = cipher_tuple
    name_upper = cipher_name.upper()

    # 1. Forward Secrecy Detection
    is_tls13 = (tls_version == "TLSv1.3") or (cipher_name in TLS_13_CIPHERS)
    has_forward_secrecy = (
        is_tls13 or
        "ECDHE" in name_upper or
        "DHE" in name_upper or
        "EDH" in name_upper
    )

    # 2. AEAD Check
    is_aead = (
        is_tls13 or
        "GCM" in name_upper or
        "POLY1305" in name_upper or
        "CCM" in name_upper
    )

    # 3. Security Findings for Weak Ciphers
    if "NULL" in name_upper:
        findings.append(TlsFinding(
            id=next_id(),
            title="Insecure NULL Cipher Negotiated",
            category="cipher",
            severity="high",
            confidence=0.99,
            description="The server negotiated a plaintext (NULL) cipher suite with no encryption.",
            evidence={"cipher": cipher_name},
            recommendation="Disable NULL ciphers immediately."
        ))
    elif "RC4" in name_upper:
        findings.append(TlsFinding(
            id=next_id(),
            title="Insecure RC4 Stream Cipher Negotiated",
            category="cipher",
            severity="high",
            confidence=0.99,
            description="The server negotiated an RC4 cipher suite. RC4 is cryptographically broken and prohibited by RFC 7465.",
            evidence={"cipher": cipher_name},
            recommendation="Disable RC4 cipher suites in server configuration."
        ))
    elif "3DES" in name_upper or "DES-CBC3" in name_upper:
        findings.append(TlsFinding(
            id=next_id(),
            title="Deprecated 3DES / Sweet32 Cipher Suite Negotiated",
            category="cipher",
            severity="medium",
            confidence=0.99,
            description="The server negotiated a 3DES (Triple DES) cipher suite. 64-bit block ciphers are vulnerable to collision attacks (Sweet32 / CVE-2016-2183).",
            evidence={"cipher": cipher_name, "bits": bits},
            recommendation="Disable 3DES and prioritize AES-GCM or ChaCha20-Poly1305."
        ))
    elif bits and bits < 128:
        findings.append(TlsFinding(
            id=next_id(),
            title=f"Weak Encryption Key Length ({bits} bits)",
            category="cipher",
            severity="high",
            confidence=0.99,
            description=f"The negotiated cipher '{cipher_name}' uses only {bits} bits of encryption key length.",
            evidence={"cipher": cipher_name, "bits": bits},
            recommendation="Require at least 128-bit (or 256-bit) encryption ciphers."
        ))

    # Missing Forward Secrecy check
    if not has_forward_secrecy and not is_tls13:
        findings.append(TlsFinding(
            id=next_id(),
            title="Negotiated Cipher Lacks Perfect Forward Secrecy (PFS)",
            category="cipher",
            severity="low",
            confidence=0.95,
            description=f"The cipher '{cipher_name}' relies on static RSA key exchange without ephemeral Diffie-Hellman (ECDHE/DHE). If the server's private key is ever compromised, past recorded traffic can be decrypted.",
            evidence={"cipher": cipher_name, "forward_secrecy": False},
            recommendation="Prioritize ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) key exchange cipher suites."
        ))

    result = {
        "name": cipher_name,
        "protocol": protocol or tls_version,
        "bits": bits,
        "forward_secrecy": has_forward_secrecy,
        "is_aead": is_aead,
        "is_tls13": is_tls13
    }

    return result, findings
