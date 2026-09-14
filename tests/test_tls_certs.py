import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scanners import tls_certs


class CertificateScannerTests(unittest.TestCase):
    def setUp(self):
        capture = patch.object(tls_certs, 'capture_openssl_handshake', return_value={
            'error': None, 'certificate_der': self.cert.public_bytes(Encoding.DER),
            'protocol': 'TLSv1.3', 'evidence':
            '$ openssl s_client -connect example.com:443\n'
            'verify error:num=18:self-signed certificate\n'
            'notAfter=Oct 10 00:00:00 2026 GMT\n'
            'DNS:example.com, DNS:*.example.org\n'})
        self.capture = capture.start()
        self.addCleanup(capture.stop)

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

    def test_certificate_security_checks_pass_for_fixture(self):
        with redirect_stdout(StringIO()):
            self.assertTrue(tls_certs.check_validity(self.cert))
            self.assertTrue(tls_certs.check_key_strength(self.cert))
            self.assertTrue(tls_certs.check_signature_algorithm(self.cert))
            self.assertTrue(tls_certs.check_san_count(self.cert))
            self.assertTrue(tls_certs.check_key_usage(self.cert))
            self.assertTrue(tls_certs.check_extended_key_usage(self.cert))

    def test_fixture_is_detected_as_self_signed(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertTrue(tls_certs.check_self_signed(self.cert))

        self.assertIn("Self-signed certificate", output.getvalue())
        self.assertNotIn("BitSight", output.getvalue())
        self.assertNotIn("CRITICAL", output.getvalue())

    def test_kubernetes_ingress_certificate_is_identified(self):
        name = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME,
                    "Kubernetes Ingress Controller Fake Certificate",
                )
            ]
        )
        cert = SimpleNamespace(subject=name, issuer=name)
        output = StringIO()

        with redirect_stdout(output):
            self.assertTrue(tls_certs.check_self_signed(cert))

        self.assertIn("Kubernetes Ingress self-signed certificate", output.getvalue())

    def test_1024_bit_rsa_key_is_a_warn_certificate_finding(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        cert = SimpleNamespace(public_key=lambda: key.public_key())
        output = StringIO()

        with redirect_stdout(output):
            self.assertFalse(tls_certs.check_key_strength(cert))

        self.assertIn("less than 2048 bits (1024)", output.getvalue())

    def test_large_san_list_is_a_certificate_finding(self):
        output = StringIO()
        identities = [f"host-{index}.example.com" for index in range(26)]

        with patch(
            "scanners.tls_certs.get_cert_identities",
            return_value=(identities, "example.com"),
        ):
            with redirect_stdout(output):
                self.assertFalse(tls_certs.check_san_count(object()))

        self.assertIn("26 SAN entries", output.getvalue())

    def test_certificate_scan_does_not_assess_name_mismatch(self):
        output = StringIO()
        with patch(
            "scanners.tls_certs.get_certificate",
            return_value=(self.cert, "TLSv1.3"),
        ):
            with redirect_stdout(output):
                tls_certs.run("unrelated.test")

        self.assertNotIn("NAME MISMATCH", output.getvalue())
        self.assertNotIn("Certificate Name Match", output.getvalue())
        self.assertIn("CERTIFICATE FINDINGS", output.getvalue())
        self.assertIn("ADDITIONAL SECURITY CHECKS", output.getvalue())
        self.assertNotIn("BitSight", output.getvalue())

    def test_future_date_is_not_graded_by_certificate_scanner(self):
        now = datetime.utcnow()
        future_cert = SimpleNamespace(
            not_valid_before=now + timedelta(days=30),
            not_valid_after=now + timedelta(days=120),
        )
        output = StringIO()

        with redirect_stdout(output):
            self.assertTrue(tls_certs.check_validity(future_cert))

        self.assertNotIn("not yet valid", output.getvalue())
        self.assertIn("not expired", output.getvalue())

    def test_md5_signature_is_a_certificate_finding(self):
        cert = SimpleNamespace(
            signature_algorithm_oid=SimpleNamespace(
                _name="md5WithRSAEncryption",
                dotted_string="1.2.840.113549.1.1.4",
            ),
            signature_hash_algorithm=hashes.MD5(),
        )
        output = StringIO()

        with redirect_stdout(output):
            self.assertFalse(tls_certs.check_signature_algorithm(cert))

        self.assertIn("Signature uses MD5", output.getvalue())

    def test_entrust_distrust_is_a_certificate_finding(self):
        issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Entrust Test CA")]
        )
        cert = SimpleNamespace(
            issuer=issuer,
            not_valid_before=datetime(2025, 1, 1),
            not_valid_after=datetime(2026, 1, 1),
        )
        output = StringIO()

        with redirect_stdout(output):
            self.assertFalse(tls_certs.check_ca_distrust(cert))

        self.assertIn("Entrust certificate distrusted", output.getvalue())
        self.assertNotIn("BitSight", output.getvalue())

    def test_certificate_evidence_uses_the_real_openssl_transcript(self):
        with patch.object(tls_certs, 'get_certificate', return_value=(self.cert, 'TLSv1.3')):
            with redirect_stdout(StringIO()):
                evidence = tls_certs.run('example.com')['evidence']

        self.assertIn("openssl s_client -connect example.com:443", evidence)
        self.assertEqual(evidence, self.capture.return_value['evidence'])
        self.capture.assert_called_once_with('example.com', 443)
        self.assertNotIn("CAPTURED BY AEGIS", evidence)
        self.assertIn("verify error:num=18:self-signed certificate", evidence)
        self.assertIn("DNS:example.com", evidence)
        self.assertIn("DNS:*.example.org", evidence)

    def test_failed_handshake_cannot_produce_certificate_findings(self):
        self.capture.return_value = {'error': 'No peer certificate', 'evidence':
            'no peer certificate available\nVerify return code: 0 (ok)\n'}
        output = StringIO()
        with redirect_stdout(output), patch.object(tls_certs, 'get_certificate') as other_connection:
            evidence = tls_certs.run('example.com')['evidence']
        self.assertEqual(evidence, self.capture.return_value['evidence'])
        self.assertIn('assessment unavailable', output.getvalue())
        self.assertNotIn('retrieved successfully', output.getvalue())
        self.assertNotIn('CERTIFICATE FINDINGS', output.getvalue())
        other_connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
