import unittest
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from scanners import tls_config


class TlsConfigurationTests(unittest.TestCase):
    def setUp(self):
        tls_config.reset_sslscan_cache()
        capture = patch.object(tls_config, 'capture_openssl_handshake', return_value=self._handshake())
        self.capture = capture.start()
        self.addCleanup(capture.stop)

    @staticmethod
    def _handshake():
        return {
            "error": None,
            "evidence": '$ openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null\n'
                        'verify error:num=20:unable to get local issuer certificate\n',
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_protocol": "TLSv1.3",
            "cipher_bits": 256,
            "compression": "None",
            "session_ticket": True,
        }

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
                "SSLv2 enabled",
                "SSLv3 disabled",
            )
        )
        output = StringIO()

        with patch("scanners.tls_config.sslscan_output", return_value=sslscan):
            with redirect_stdout(output):
                tls_config.check_tls_versions("example.com")

        self.assertIn("TLSv1.0 supported", output.getvalue())
        self.assertIn("SSLv2 supported", output.getvalue())
        self.assertIn("Insecure protocols enabled: TLSv1.0, SSLv2", output.getvalue())

    def test_extended_checks_run_last_and_tls_versions_are_final(self):
        call_order = []
        check_names = (
            "check_hostname_match",
            "check_certificate_timing",
            "check_certificate_structure",
            "check_configuration_public_key",
            "check_certificate_chain",
            "check_forward_secrecy",
            "check_hsts_header",
            "check_ssl_compression",
            "check_session_resumption",
            "check_secure_renegotiation",
            "check_protocol_downgrade_protection",
            "check_cipher_suites",
            "check_export_ciphers",
            "check_dh_strength",
            "check_common_dh_parameters",
            "check_heartbleed",
            "check_tls_versions",
        )

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    tls_config,
                    "capture_tls_handshake",
                    return_value=self._handshake(),
                )
            )
            for name in check_names:
                stack.enter_context(
                    patch.object(
                        tls_config,
                        name,
                        side_effect=lambda *args, _name=name, **kwargs: call_order.append(_name),
                    )
                )
            output = StringIO()
            with redirect_stdout(output):
                tls_config.run(
                    "example.com", port=443, check_ciphers=True, interactive=False
                )

        self.assertEqual(list(check_names), call_order)
        self.assertEqual(call_order[-1], "check_tls_versions")
        self.assertIn("CONFIGURATION FINDINGS", output.getvalue())
        self.assertIn("OPTIONAL EXTENDED FINDINGS", output.getvalue())
        self.assertNotIn("bitsight", output.getvalue().lower())

    def test_name_mismatch_is_assessed_by_configuration_scanner(self):
        output = StringIO()
        with patch(
            "scanners.tls_config.get_cert_identities",
            return_value=(["example.com", "*.example.org"], "example.com"),
        ):
            with redirect_stdout(output):
                self.assertTrue(
                    tls_config.check_hostname_match(object(), "www.example.org")
                )
                self.assertFalse(
                    tls_config.check_hostname_match(object(), "unrelated.test")
                )

        self.assertIn("Certificate Name Match", output.getvalue())
        self.assertIn("NAME MISMATCH", output.getvalue())

    def test_future_and_overlong_certificates_are_configuration_findings(self):
        output = StringIO()
        future_cert = SimpleNamespace(
            not_valid_before=datetime(2027, 1, 1),
            not_valid_after=datetime(2030, 1, 1),
        )
        long_cert = SimpleNamespace(
            not_valid_before=datetime(2020, 1, 1),
            not_valid_after=datetime(2022, 7, 1),
        )

        with redirect_stdout(output):
            self.assertFalse(
                tls_config.check_certificate_timing(
                    future_cert, now=datetime(2026, 1, 1, tzinfo=timezone.utc)
                )
            )
            self.assertFalse(
                tls_config.check_certificate_timing(
                    long_cert, now=datetime(2020, 1, 2, tzinfo=timezone.utc)
                )
            )

        self.assertIn("issued for a date in the future", output.getvalue())
        self.assertIn("duration exceeds recommended practice", output.getvalue())
        self.assertNotIn("BitSight", output.getvalue())

    def test_weak_ec_key_is_a_configuration_finding(self):
        key = ec.generate_private_key(ec.SECP192R1())
        cert = SimpleNamespace(public_key=lambda: key.public_key())
        output = StringIO()

        with redirect_stdout(output):
            self.assertFalse(tls_config.check_configuration_public_key(cert))

        self.assertIn("less than 224 bits", output.getvalue())

    def test_sslscan_specific_bitsight_findings_are_parsed(self):
        sslscan = "\n".join(
            (
                "Accepted TLSv1.0 40 bits EXP-RC4-MD5",
                "DH prime is very commonly used",
                "Heartbleed: vulnerable",
            )
        )
        output = StringIO()

        with patch("scanners.tls_config.sslscan_output", return_value=sslscan):
            with redirect_stdout(output):
                self.assertFalse(tls_config.check_export_ciphers("example.com"))
                self.assertFalse(tls_config.check_common_dh_parameters("example.com"))
                self.assertFalse(tls_config.check_heartbleed("example.com"))

        self.assertIn("Allows insecure cipher: Export Ciphers", output.getvalue())
        self.assertIn("very commonly used", output.getvalue())
        self.assertIn("Vulnerable to Heartbleed", output.getvalue())

    def test_ecdh_size_is_not_mistaken_for_a_short_dh_prime(self):
        output = StringIO()
        sslscan = (
            "Accepted TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 "
            "Curve 25519 DHE 253"
        )

        with patch("scanners.tls_config.sslscan_output", return_value=sslscan):
            with redirect_stdout(output):
                self.assertTrue(tls_config.check_dh_strength("example.com"))

        self.assertIn("No finite-field DHE suites reported", output.getvalue())
        self.assertNotIn("less than 2048", output.getvalue())

    def test_short_finite_field_dh_prime_is_reported(self):
        output = StringIO()
        sslscan = "Accepted TLSv1.2 DHE-RSA-AES128-SHA DHE 1024"

        with patch("scanners.tls_config.sslscan_output", return_value=sslscan):
            with redirect_stdout(output):
                self.assertFalse(tls_config.check_dh_strength("example.com"))

        self.assertIn("less than 2048 bits (1024)", output.getvalue())

    def test_declining_extended_checks_skips_sslscan_checks(self):
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    tls_config,
                    "capture_tls_handshake",
                    return_value=self._handshake(),
                )
            )
            for name in (
                "check_hostname_match",
                "check_certificate_timing",
                "check_certificate_structure",
                "check_configuration_public_key",
                "check_certificate_chain",
                "check_forward_secrecy",
                "check_hsts_header",
                "check_ssl_compression",
                "check_session_resumption",
                "check_secure_renegotiation",
                "check_protocol_downgrade_protection",
            ):
                stack.enter_context(patch.object(tls_config, name))
            cipher = stack.enter_context(patch.object(tls_config, "check_cipher_suites"))
            export = stack.enter_context(patch.object(tls_config, "check_export_ciphers"))
            dh = stack.enter_context(patch.object(tls_config, "check_dh_strength"))
            common_dh = stack.enter_context(
                patch.object(tls_config, "check_common_dh_parameters")
            )
            heartbleed = stack.enter_context(patch.object(tls_config, "check_heartbleed"))
            versions = stack.enter_context(patch.object(tls_config, "check_tls_versions"))

            with redirect_stdout(StringIO()):
                tls_config.run(
                    "example.com", port=443, check_ciphers=False, interactive=False
                )

        cipher.assert_not_called()
        export.assert_not_called()
        dh.assert_not_called()
        common_dh.assert_not_called()
        heartbleed.assert_not_called()
        versions.assert_not_called()

    def test_configuration_evidence_preserves_openssl_errors_and_raw_sslscan(self):
        raw = self.capture.return_value['evidence']
        evidence = tls_config.format_tls_config_evidence(
            "example.com",
            port=443,
            openssl_raw=raw,
            sslscan_raw="TLSv1.3 enabled\nTLSv1.0 disabled",
        )

        self.assertIn("openssl s_client -connect example.com:443", evidence)
        self.assertTrue(evidence.startswith(raw))
        self.assertIn('unable to get local issuer certificate', evidence)
        self.assertIn('$ sslscan example.com', evidence)
        self.assertNotIn('CAPTURED BY AEGIS', evidence)
        self.assertNotIn('REPRODUCE MANUALLY', evidence)
        self.assertIn("TLSv1.0 disabled", evidence)

    def test_skipped_extended_checks_do_not_add_fake_sslscan_output(self):
        raw = self.capture.return_value['evidence']
        self.assertEqual(tls_config.format_tls_config_evidence('example.com', openssl_raw=raw), raw)

    def test_failed_handshake_does_not_assess_a_different_connection(self):
        self.capture.return_value = {'error': 'No peer certificate', 'evidence':
            'no peer certificate available\nVerify return code: 0 (ok)\n'}
        output = StringIO()
        with redirect_stdout(output), patch.object(tls_config, 'check_certificate_chain') as chain:
            result = tls_config.run('example.com', check_ciphers=False)
        self.capture.assert_called_once_with('example.com', 443)
        self.assertEqual(result['evidence'], self.capture.return_value['evidence'])
        self.assertIn('assessment unavailable', output.getvalue())
        self.assertNotIn('Connection successful', output.getvalue())
        chain.assert_not_called()

    def test_baseline_checks_reuse_the_supplied_handshake_without_network(self):
        handshake = dict(self._handshake(), verify_code=20,
                         verify_message='unable to get local issuer certificate',
                         compression='NONE', secure_renegotiation=True)
        with redirect_stdout(StringIO()) as output:
            self.assertFalse(tls_config.check_certificate_chain('example.com', handshake=handshake))
            self.assertTrue(tls_config.check_forward_secrecy('example.com', handshake=handshake))
            self.assertTrue(tls_config.check_ssl_compression('example.com', handshake=handshake))
            self.assertTrue(tls_config.check_session_resumption('example.com', handshake=handshake))
            self.assertTrue(tls_config.check_secure_renegotiation('example.com', handshake=handshake))
            self.assertTrue(tls_config.check_protocol_downgrade_protection('example.com', handshake=handshake))
            self.assertTrue(tls_config.check_cipher_suites('example.com', handshake=handshake))
        self.capture.assert_not_called()
        self.assertIn('unable to get local issuer certificate', output.getvalue())
        self.assertNotIn('chain reaches a trusted root', output.getvalue())


if __name__ == "__main__":
    unittest.main()
