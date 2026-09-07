from datetime import datetime, timedelta, timezone
from django.test import TestCase, Client
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tls_analysis.services.certificate_analyzer import analyze_certificate, match_hostname
from tls_analysis.services.cipher_analyzer import analyze_cipher_suite
from tls_analysis.services.tls_prober import probe_supported_tls_versions
from tls_analysis.services.findings import TlsFinding


def generate_test_certificate(
    common_name="example.com",
    san_list=None,
    days_valid=90,
    key_size=2048,
    is_expired=False,
    is_self_signed=True,
    hash_algorithm=hashes.SHA256()
):
    """Helper to generate in-memory X.509 DER certificates for deterministic unit tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AttackLens Test Org"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])

    now = datetime.now(timezone.utc)
    if is_expired:
        not_before = now - timedelta(days=60)
        not_after = now - timedelta(days=10)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if san_list:
        san_names = [x509.DNSName(name) for name in san_list]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )

    cert = builder.sign(private_key, hash_algorithm)
    return cert.public_bytes(serialization.Encoding.DER)


class TlsAnalysisTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_hostname_matching_logic(self):
        # Exact match
        self.assertTrue(match_hostname("example.com", ["example.com", "www.example.com"]))
        self.assertTrue(match_hostname("www.example.com", ["example.com", "www.example.com"]))
        # Wildcard match
        self.assertTrue(match_hostname("api.example.com", ["*.example.com"]))
        self.assertFalse(match_hostname("deep.sub.example.com", ["*.example.com"]))
        self.assertFalse(match_hostname("otherdomain.com", ["example.com"]))

    def test_valid_certificate_analysis(self):
        cert_der = generate_test_certificate(
            common_name="secure.example.com",
            san_list=["secure.example.com", "app.example.com"],
            days_valid=120,
            key_size=2048
        )
        cert_res, findings = analyze_certificate(cert_der, "secure.example.com")
        self.assertTrue(cert_res["valid"])
        self.assertTrue(cert_res["hostname_match"])
        self.assertFalse(cert_res["is_expired"])
        self.assertGreater(cert_res["expires_in_days"], 100)
        self.assertEqual(cert_res["public_key_algorithm"], "RSA")
        self.assertEqual(cert_res["public_key_size"], 2048)

    def test_expired_certificate_detection(self):
        cert_der = generate_test_certificate(
            common_name="expired.example.com",
            san_list=["expired.example.com"],
            is_expired=True
        )
        cert_res, findings = analyze_certificate(cert_der, "expired.example.com")
        self.assertFalse(cert_res["valid"])
        self.assertTrue(cert_res["is_expired"])
        self.assertTrue(any("Expired" in f.title and f.severity == "high" for f in findings))

    def test_certificate_expiring_soon(self):
        cert_der = generate_test_certificate(
            common_name="expiring.example.com",
            san_list=["expiring.example.com"],
            days_valid=5
        )
        cert_res, findings = analyze_certificate(cert_der, "expiring.example.com")
        self.assertTrue(any("Expiring Soon" in f.title and f.severity == "medium" for f in findings))

    def test_hostname_mismatch_finding(self):
        cert_der = generate_test_certificate(
            common_name="internal.local",
            san_list=["internal.local"]
        )
        cert_res, findings = analyze_certificate(cert_der, "public.target.com")
        self.assertFalse(cert_res["hostname_match"])
        self.assertTrue(any("Hostname Mismatch" in f.title and f.severity == "high" for f in findings))

    def test_weak_rsa_key_size_finding(self):
        cert_der = generate_test_certificate(
            common_name="weakkey.com",
            san_list=["weakkey.com"],
            key_size=1024
        )
        cert_res, findings = analyze_certificate(cert_der, "weakkey.com")
        self.assertTrue(any("Weak RSA Public Key Size" in f.title and f.severity == "high" for f in findings))

    def test_cipher_suite_analysis(self):
        # 1. Modern TLS 1.3 Cipher
        c_res, f_list = analyze_cipher_suite(("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "TLSv1.3")
        self.assertTrue(c_res["forward_secrecy"])
        self.assertTrue(c_res["is_aead"])
        self.assertEqual(len([f for f in f_list if f.severity in ("high", "medium")]), 0)

        # 2. Legacy non-PFS cipher (RSA AES128-SHA)
        c_res2, f_list2 = analyze_cipher_suite(("AES128-SHA", "TLSv1.2", 128), "TLSv1.2")
        self.assertFalse(c_res2["forward_secrecy"])
        self.assertTrue(any("Lacks Perfect Forward Secrecy" in f.title for f in f_list2))

        # 3. Insecure 3DES cipher
        c_res3, f_list3 = analyze_cipher_suite(("DES-CBC3-SHA", "TLSv1.2", 168), "TLSv1.2")
        self.assertTrue(any("3DES" in f.title and f.severity == "medium" for f in f_list3))

    def test_api_endpoint_validation(self):
        # Missing target parameter
        resp = self.client.get("/api/tls-analysis/")
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertFalse(data["success"])

        # Invalid target domain
        resp_inv = self.client.get("/api/tls-analysis/?target=invalid-non-existent-domain-999.test")
        self.assertEqual(resp_inv.status_code, 400)
        data_inv = resp_inv.json()
        self.assertEqual(data_inv["scan_status"], "failed")
