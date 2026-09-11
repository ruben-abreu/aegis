import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import Mock, patch

from scanners import ports


class SmtpStarttlsTests(unittest.TestCase):
    def _smtp_client(self, has_starttls=True, greeting_code=220, ehlo_code=250):
        client = Mock()
        client.connect.return_value = (greeting_code, b"mail.example ESMTP ready")
        client.ehlo.return_value = (ehlo_code, b"SIZE 10485760\nSTARTTLS")
        client.has_extn.return_value = has_starttls
        return client

    @patch("scanners.ports.smtplib.SMTP")
    def test_starttls_advertised(self, smtp_class):
        smtp_class.return_value = self._smtp_client(has_starttls=True)

        with redirect_stdout(StringIO()):
            result = ports.check_smtp_starttls("mail.example", 25)

        self.assertTrue(result)
        smtp_class.return_value.ehlo.assert_called_once_with("aegis.local")

    @patch("scanners.ports.smtplib.SMTP")
    def test_missing_starttls_is_a_failure(self, smtp_class):
        smtp_class.return_value = self._smtp_client(has_starttls=False)
        output = StringIO()

        with redirect_stdout(output):
            result = ports.check_smtp_starttls("mail.example", 587)

        self.assertFalse(result)
        self.assertIn("STARTTLS NOT advertised", output.getvalue())

    @patch("scanners.ports.check_smtp_starttls")
    @patch("scanners.ports.test_port", return_value=True)
    def test_open_smtp_port_runs_follow_up(self, test_port, starttls_check):
        with redirect_stdout(StringIO()):
            ports.run("mail.example", port=25)

        starttls_check.assert_called_once_with("mail.example", 25, evidence=[])

    @patch("scanners.ports.check_smtp_starttls")
    @patch("scanners.ports.test_port", return_value=True)
    def test_implicit_tls_port_does_not_run_starttls(self, test_port, starttls_check):
        with redirect_stdout(StringIO()):
            ports.run("mail.example", port=465)

        starttls_check.assert_not_called()

    @patch("scanners.ports.smtplib.SMTP")
    def test_smtp_evidence_contains_ehlo_transcript(self, smtp_class):
        smtp_class.return_value = self._smtp_client(has_starttls=True)
        evidence = []

        with redirect_stdout(StringIO()):
            ports.check_smtp_starttls("mail.example", 25, evidence=evidence)

        transcript = "\n".join(evidence)
        self.assertIn("220", transcript)
        self.assertIn("> EHLO aegis.local", transcript)
        self.assertIn("250", transcript)
        self.assertNotIn("STARTTLS capability advertised:", transcript)

    @patch("scanners.ports.test_port", return_value=True)
    def test_port_run_returns_socket_evidence_without_unexecuted_commands(self, test_port):
        with redirect_stdout(StringIO()):
            result = ports.run("example.com", port=443)

        self.assertNotIn("$ nc", result["evidence"])
        self.assertNotIn("CAPTURED BY AEGIS", result["evidence"])
        self.assertIn("Result: OPEN", result["evidence"])


if __name__ == "__main__":
    unittest.main()
