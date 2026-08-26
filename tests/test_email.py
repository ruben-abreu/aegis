import base64
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scanners import email


class TxtRecord:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return f'"{self.value}"'


class EmailSecurityTests(unittest.TestCase):
    @patch("scanners.email.dns.resolver.resolve")
    def test_secure_spf_record_passes(self, resolve):
        resolve.return_value = [TxtRecord("v=spf1 include:_spf.example.com -all")]
        output = StringIO()

        with redirect_stdout(output):
            email.check_spf("example.com")

        report = output.getvalue()
        self.assertIn("SPF Record Found", report)
        self.assertIn("Secure qualifier configured", report)

    @patch("scanners.email.dns.resolver.resolve")
    def test_reject_dmarc_with_reporting_passes(self, resolve):
        resolve.return_value = [
            TxtRecord("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
        ]
        output = StringIO()

        with redirect_stdout(output):
            email.check_dmarc("example.com")

        report = output.getvalue()
        self.assertIn("Policy set to REJECT", report)
        self.assertIn("Aggregate reporting target published", report)

    def test_dkim_rsa_key_size_is_parsed(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        self.assertEqual(email.get_rsa_key_size(base64.b64encode(der)), 2048)

    def test_ip_target_is_rejected_without_dns_queries(self):
        output = StringIO()

        with patch("scanners.email.check_spf") as check_spf:
            with redirect_stdout(output):
                email.run("203.0.113.10", target_type="IP Address", interactive=False)

        check_spf.assert_not_called()
        self.assertIn("requires a Domain target", output.getvalue())

    @patch("scanners.email.dns.resolver.resolve")
    def test_dns_record_is_preserved_as_technical_evidence(self, resolve):
        resolve.return_value = [TxtRecord("v=spf1 -all")]
        evidence = []

        with redirect_stdout(StringIO()):
            email.check_spf("example.com", evidence=evidence)

        transcript = email.format_email_evidence("example.com", evidence)
        self.assertIn("dig example.com txt +short", transcript)
        self.assertIn('"v=spf1 -all"', transcript)
        self.assertIn("dig example.com mx +short", transcript)


if __name__ == "__main__":
    unittest.main()
