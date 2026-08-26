import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from scanners import dns


class ARecord:
    def __init__(self, address):
        self.address = address

    def to_text(self):
        return self.address


class DnsScannerTests(unittest.TestCase):
    @patch("scanners.dns.dns.resolver.resolve")
    def test_domain_a_records_are_printed(self, resolve):
        resolve.return_value = [ARecord("203.0.113.10"), ARecord("203.0.113.11")]
        output = StringIO()

        with redirect_stdout(output):
            result = dns.run("example.com", target_type="Domain")

        report = output.getvalue()
        self.assertIn("203.0.113.10", report)
        self.assertIn("203.0.113.11", report)
        self.assertIn("dig example.com A +short", result["evidence"])
        self.assertIn("A example.com -> 203.0.113.10", result["evidence"])

    @patch("scanners.dns.dns.resolver.resolve", side_effect=Exception("lookup failed"))
    def test_domain_lookup_error_is_reported(self, resolve):
        output = StringIO()

        with redirect_stdout(output):
            dns.run("example.com", target_type="Domain")

        self.assertIn("Error resolving domain: lookup failed", output.getvalue())

    def test_ip_scan_without_api_key_explains_configuration(self):
        output = StringIO()

        with patch.object(dns, "VT_API_KEY", None):
            with redirect_stdout(output):
                result = dns.run("203.0.113.10", target_type="IP Address")

        self.assertIn("VirusTotal API key not found", output.getvalue())
        self.assertIn("API key not configured", result["evidence"])


if __name__ == "__main__":
    unittest.main()
