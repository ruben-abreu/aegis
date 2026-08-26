import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scanners import was


class FakeResponse:
    def __init__(self, headers=None, text="", url="https://example.com", status_code=200):
        self.headers = headers or {}
        self.text = text
        self.url = url
        self.status_code = status_code
        self.history = []


class WebApplicationSecurityTests(unittest.TestCase):
    def _complete_headers(self, csp):
        return {
            "Content-Security-Policy": csp,
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
        }

    def test_object_src_none_passes(self):
        response = FakeResponse(
            self._complete_headers("default-src 'self'; object-src 'none'")
        )
        output = StringIO()

        with redirect_stdout(output):
            was.check_headers(response)

        self.assertIn("CSP object-src is restricted to 'none'", output.getvalue())

    def test_missing_object_src_warns(self):
        response = FakeResponse(self._complete_headers("default-src 'self'"))
        output = StringIO()

        with redirect_stdout(output):
            was.check_headers(response)

        self.assertIn("CSP missing explicit object-src", output.getvalue())

    def test_wildcard_cors_with_credentials_fails(self):
        response = FakeResponse(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        output = StringIO()

        with redirect_stdout(output):
            was.check_cors(response)

        self.assertIn("Wildcard Access-Control-Allow-Origin with credentials", output.getvalue())

    @patch("scanners.was.requests.get")
    def test_https_downgrade_is_detected(self, requests_get):
        requests_get.return_value = SimpleNamespace(
            headers={"Location": "http://example.com/login"}
        )
        output = StringIO()

        with redirect_stdout(output):
            was.check_https_downgrade("example.com", 443)

        self.assertIn("HTTPS redirects to HTTP", output.getvalue())

    def test_mixed_content_warning_on_https_page(self):
        response = FakeResponse(text='<script src="http://cdn.example/a.js"></script>')
        output = StringIO()

        with redirect_stdout(output):
            was.check_mixed(response)

        self.assertIn("HTTP resources referenced", output.getvalue())

    def test_redirect_chain_is_reported_before_security_checks(self):
        response = FakeResponse()
        calls = []
        replacements = {
            "fetch": Mock(return_value=response),
            "print_redirect_chain": Mock(side_effect=lambda _r: calls.append("redirect")),
            "check_headers": Mock(side_effect=lambda _r: calls.append("headers")),
            "check_cors": Mock(),
            "check_https_downgrade": Mock(),
            "check_mixed": Mock(),
            "check_js": Mock(),
            "check_sri": Mock(),
        }

        with patch.multiple(was, **replacements), redirect_stdout(StringIO()):
            was.run("example.com", port=443)

        self.assertEqual(["redirect", "headers"], calls)


if __name__ == "__main__":
    unittest.main()
