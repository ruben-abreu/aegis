import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scanners.terminal import capture_openssl_evidence, command_output


class TerminalEvidenceTests(unittest.TestCase):
    @patch('scanners.terminal.subprocess.run')
    def test_merges_stderr_without_suppressing_verification_errors(self, run):
        raw = ('depth=0 CN=example.com\n'
               'verify error:num=20:unable to get local issuer certificate\n'
               'verify return:1\nVerify return code: 20 (unable to get local issuer certificate)\n')
        run.return_value = SimpleNamespace(stdout=raw, returncode=1)
        transcript = capture_openssl_evidence('example.com', 8443)
        self.assertTrue(transcript.endswith(raw))
        args, options = run.call_args
        self.assertEqual(args[0], ['openssl', 's_client', '-connect', 'example.com:8443',
                                  '-servername', 'example.com', '-showcerts'])
        self.assertEqual(options['stderr'], subprocess.STDOUT)
        self.assertEqual(options['stdin'], subprocess.DEVNULL)
        self.assertNotIn('shell', options)
        self.assertNotIn('2>/dev/null', transcript)
        self.assertNotIn('CAPTURED BY AEGIS', transcript)

    @patch('scanners.terminal.subprocess.run')
    def test_x509_inspects_the_actual_leaf_certificate_from_the_same_handshake(self, run):
        pem = '-----BEGIN CERTIFICATE-----\nTEST_LEAF\n-----END CERTIFICATE-----'
        chain = pem + '\n-----BEGIN CERTIFICATE-----\nTEST_ISSUER\n-----END CERTIFICATE-----'
        run.side_effect = [SimpleNamespace(stdout=chain, returncode=0),
                           SimpleNamespace(stdout='notAfter=Oct 10 00:00:00 2026 GMT\nserial=ABC\n', returncode=0)]
        transcript = capture_openssl_evidence('example.com')
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.kwargs['input'], pem + '\n')
        self.assertEqual(run.call_args.args[0][:3], ['openssl', 'x509', '-noout'])
        self.assertIn('serial=ABC', transcript)
        self.assertIn(chain, transcript)

    @patch('scanners.terminal.subprocess.run')
    def test_timeout_preserves_partial_output(self, run):
        raw = b'verify error:num=20:unable to get local issuer certificate\n'
        run.side_effect = subprocess.TimeoutExpired('openssl', 12, output=raw)
        transcript = capture_openssl_evidence('example.com')
        self.assertIn(raw.decode(), transcript)
        self.assertIn('# Command timed out after 12s.', transcript)

    @patch('scanners.terminal.subprocess.run', side_effect=FileNotFoundError('openssl not found'))
    def test_missing_binary_is_reported_without_fabricating_a_handshake(self, run):
        transcript = capture_openssl_evidence('example.com')
        self.assertIn('# Cannot run openssl:', transcript)
        self.assertNotIn('CONNECTED', transcript)
        self.assertNotIn('verify error:', transcript)

    @patch('scanners.terminal.subprocess.run')
    def test_ipv6_and_shell_metacharacters_remain_single_arguments(self, run):
        run.return_value = SimpleNamespace(stdout='connection refused\n', returncode=1)
        capture_openssl_evidence('::1', 443)
        self.assertIn('[::1]:443', run.call_args.args[0])
        capture_openssl_evidence('example.com;echo unsafe', 443)
        self.assertIn('example.com;echo unsafe:443', run.call_args.args[0])
        self.assertNotIn('shell', run.call_args.kwargs)

    @patch('scanners.terminal.subprocess.run')
    def test_successful_verification_does_not_invent_an_issuer_error(self, run):
        run.return_value = SimpleNamespace(stdout='Verify return code: 0 (ok)\n', returncode=0)
        transcript = capture_openssl_evidence('example.com')
        self.assertNotIn('unable to get local issuer certificate', transcript)
        self.assertIn('Verify return code: 0 (ok)', transcript)


if __name__ == '__main__':
    unittest.main()
