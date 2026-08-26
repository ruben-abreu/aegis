import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from io import StringIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scanners import tls_certs


class CertificateScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        now = datetime.utcnow()

        cls.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("example.com"), x509.DNSName("*.example.org")]
                ),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

    def test_extracts_san_and_common_name(self):
        identities, common_name = tls_certs.get_cert_identities(self.cert)

        self.assertEqual(common_name, "example.com")
        self.assertEqual(identities, ["example.com", "*.example.org"])

    def test_hostname_match_uses_san(self):
        with redirect_stdout(StringIO()):
            self.assertTrue(tls_certs.check_hostname_match(self.cert, "www.example.org"))
            self.assertFalse(tls_certs.check_hostname_match(self.cert, "unrelated.test"))

    def test_certificate_security_checks_pass_for_fixture(self):
        with redirect_stdout(StringIO()):
            self.assertTrue(tls_certs.check_validity(self.cert))
            self.assertTrue(tls_certs.check_key_strength(self.cert))
            self.assertTrue(tls_certs.check_signature_algorithm(self.cert))
            self.assertTrue(tls_certs.check_san_count(self.cert))
            self.assertTrue(tls_certs.check_key_usage(self.cert))
            self.assertTrue(tls_certs.check_extended_key_usage(self.cert))

    def test_fixture_is_detected_as_self_signed(self):
        with redirect_stdout(StringIO()):
            self.assertTrue(tls_certs.check_self_signed(self.cert))

    def test_certificate_evidence_contains_reproduction_and_captured_fields(self):
        evidence = tls_certs.format_certificate_evidence(
            self.cert, "example.com", port=443, tls_version="TLSv1.3"
        )

        self.assertIn("openssl s_client -connect example.com:443", evidence)
        self.assertIn("CAPTURED BY AEGIS", evidence)
        self.assertIn("Negotiated protocol: TLSv1.3", evidence)
        self.assertIn("DNS:example.com", evidence)
        self.assertIn("DNS:*.example.org", evidence)


if __name__ == "__main__":
    unittest.main()
