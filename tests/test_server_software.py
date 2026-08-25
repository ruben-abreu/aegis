import unittest
from datetime import date
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from scanners.server_software import (
    Fingerprint,
    assess_fingerprint,
    detect_from_banner,
    detect_from_http,
    grade_from_eol,
    run,
)


class FingerprintDetectionTests(unittest.TestCase):
    def test_detects_multiple_http_products(self):
        findings = detect_from_http(
            {
                "Server": "Apache/2.4.68",
                "X-Powered-By": "PHP/8.3.12",
            },
            '<meta name="generator" content="WordPress 6.9.4">',
        )

        detected = {finding.product: finding.version for finding in findings}
        self.assertEqual(detected["Apache"], "2.4.68")
        self.assertEqual(detected["PHP"], "8.3.12")
        self.assertEqual(detected["WordPress"], "6.9.4")

    def test_versioned_fingerprint_wins_over_heuristic(self):
        findings = detect_from_http(
            {},
            '<meta name="generator" content="WordPress 6.9.4"><a href="/wp-content/a.css">',
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].product, "WordPress")
        self.assertEqual(findings[0].version, "6.9.4")
        self.assertEqual(findings[0].confidence, "high")

    def test_detects_openssh_banner_and_distribution(self):
        findings = detect_from_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].product, "OpenSSH")
        self.assertEqual(findings[0].version, "9.6")
        self.assertEqual(findings[0].distribution_hint, "ubuntu")

    def test_detects_cpanel_and_whm_version(self):
        findings = detect_from_http({}, "<title>cPanel &amp; WHM 78</title>")

        self.assertEqual(findings[0].product, "cPanel")
        self.assertEqual(findings[0].version, "78")

    def test_detects_server_product_when_version_is_hidden(self):
        findings = detect_from_http({"Server": "nginx"}, "")

        self.assertEqual(findings[0].product, "NGINX")
        self.assertIsNone(findings[0].version)


class SupportAssessmentTests(unittest.TestCase):
    def test_eol_grading_boundaries(self):
        eol = date(2026, 1, 1)

        self.assertEqual(grade_from_eol(eol, date(2025, 12, 31)).grade, "GOOD")
        self.assertEqual(grade_from_eol(eol, date(2026, 1, 1)).grade, "FAIR")
        self.assertEqual(grade_from_eol(eol, date(2026, 1, 29)).grade, "WARN")
        self.assertEqual(grade_from_eol(eol, date(2027, 1, 1)).grade, "BAD")

    def test_supported_apache_is_good(self):
        finding = Fingerprint("Apache", "2.4.68", "test", "high")
        self.assertEqual(assess_fingerprint(finding, date(2026, 8, 25)).grade, "GOOD")

    def test_distribution_backport_is_neutral(self):
        finding = Fingerprint("Apache", "2.4.62", "test", "high", "ubuntu")
        assessment = assess_fingerprint(finding, date(2026, 8, 25))

        self.assertEqual(assessment.grade, "NEUTRAL")
        self.assertIn("backported", assessment.reason)

    def test_old_upstream_apache_is_bad(self):
        finding = Fingerprint("Apache", "2.4.52", "test", "high")
        self.assertEqual(assess_fingerprint(finding, date(2026, 8, 25)).grade, "BAD")

    def test_old_distro_apache_remains_neutral(self):
        finding = Fingerprint("Apache", "2.4.52", "test", "high", "debian")
        self.assertEqual(assess_fingerprint(finding, date(2026, 8, 25)).grade, "NEUTRAL")

    def test_old_nginx_without_distro_hint_is_bad(self):
        finding = Fingerprint("NGINX", "1.16.1", "test", "high")
        self.assertEqual(assess_fingerprint(finding, date(2026, 8, 25)).grade, "BAD")

    def test_unknown_version_is_neutral(self):
        finding = Fingerprint("TeamCity", "2027.1", "test", "high")
        self.assertEqual(assess_fingerprint(finding, date(2026, 8, 25)).grade, "NEUTRAL")

    def test_boa_is_bad_even_without_version(self):
        finding = Fingerprint("Boa Webserver", None, "test", "high")
        self.assertEqual(assess_fingerprint(finding, date(2026, 8, 25)).grade, "BAD")


class ScannerOutputTests(unittest.TestCase):
    @patch("scanners.server_software.fetch_http")
    def test_run_reports_detected_product_and_grade(self, fetch_http):
        fetch_http.return_value = (
            SimpleNamespace(
                url="https://example.com/",
                status_code=200,
                headers={"Server": "Apache/2.4.68"},
                text="",
            ),
            [],
        )
        output = StringIO()

        with redirect_stdout(output):
            run("example.com", port=443)

        report = output.getvalue()
        self.assertIn("Detected: Apache 2.4.68", report)
        self.assertIn("GOOD: Apache 2.4.68", report)
        self.assertIn("Catalogue source:", report)


if __name__ == "__main__":
    unittest.main()
