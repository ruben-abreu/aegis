import unittest
from contextlib import ExitStack, redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scanners import tls_config


class TlsConfigurationTests(unittest.TestCase):
    def setUp(self):
        tls_config.reset_sslscan_cache()

    @patch("scanners.tls_config.subprocess.run")
    def test_sslscan_output_is_cached_per_target(self, subprocess_run):
        subprocess_run.return_value = SimpleNamespace(stdout="scan output", stderr="")

        first = tls_config.sslscan_output("example.com", 443)
        second = tls_config.sslscan_output("example.com", 443)

        self.assertEqual(first, second)
        subprocess_run.assert_called_once()

    def test_cipher_prompt_defaults_to_no(self):
        with patch("builtins.input", return_value=""):
            self.assertFalse(tls_config.should_check_ciphers())
        with patch("builtins.input", return_value="yes"):
            self.assertTrue(tls_config.should_check_ciphers())

    def test_tls_version_output_flags_deprecated_protocols(self):
        sslscan = "\n".join(
            (
                "TLSv1.3 enabled",
                "TLSv1.2 enabled",
                "TLSv1.1 disabled",
                "TLSv1.0 enabled",
                "SSLv3 disabled",
            )
        )
        output = StringIO()

        with patch("scanners.tls_config.sslscan_output", return_value=sslscan):
            with redirect_stdout(output):
                tls_config.check_tls_versions("example.com")

        self.assertIn("TLSv1.0 supported", output.getvalue())
        self.assertIn("Insecure protocols enabled: TLSv1.0", output.getvalue())

    def test_extended_checks_run_last_and_tls_versions_are_final(self):
        call_order = []
        check_names = (
            "check_forward_secrecy",
            "check_hsts_header",
            "check_ssl_compression",
            "check_session_resumption",
            "check_secure_renegotiation",
            "check_protocol_downgrade_protection",
            "check_cipher_suites",
            "check_dh_strength",
            "check_tls_versions",
        )

        with ExitStack() as stack:
            connection = Mock()
            stack.enter_context(
                patch("scanners.tls_config.socket.create_connection", return_value=connection)
            )
            for name in check_names:
                stack.enter_context(
                    patch.object(
                        tls_config,
                        name,
                        side_effect=lambda *args, _name=name, **kwargs: call_order.append(_name),
                    )
                )
            with redirect_stdout(StringIO()):
                tls_config.run(
                    "example.com", port=443, check_ciphers=True, interactive=False
                )

        self.assertEqual(list(check_names), call_order)
        self.assertEqual(call_order[-1], "check_tls_versions")

    def test_declining_extended_checks_skips_sslscan_checks(self):
        with ExitStack() as stack:
            stack.enter_context(
                patch("scanners.tls_config.socket.create_connection", return_value=Mock())
            )
            for name in (
                "check_forward_secrecy",
                "check_hsts_header",
                "check_ssl_compression",
                "check_session_resumption",
                "check_secure_renegotiation",
                "check_protocol_downgrade_protection",
            ):
                stack.enter_context(patch.object(tls_config, name))
            cipher = stack.enter_context(patch.object(tls_config, "check_cipher_suites"))
            dh = stack.enter_context(patch.object(tls_config, "check_dh_strength"))
            versions = stack.enter_context(patch.object(tls_config, "check_tls_versions"))

            with redirect_stdout(StringIO()):
                tls_config.run(
                    "example.com", port=443, check_ciphers=False, interactive=False
                )

        cipher.assert_not_called()
        dh.assert_not_called()
        versions.assert_not_called()


if __name__ == "__main__":
    unittest.main()
