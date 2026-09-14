"""Regression coverage for shared native TLS assessment and evidence."""
import ipaddress
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scanners import terminal, tls_certs, tls_config


class SharedHandshakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.now(timezone.utc)
        cls.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(cls.key.public_key()).serial_number(12345)
                    .not_valid_before(now - timedelta(days=30))
                    .not_valid_after(now - timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName([
                        x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))
                    ]), critical=False).sign(cls.key, hashes.SHA256()))
        cls.pem = cls.cert.public_bytes(serialization.Encoding.PEM).decode()

    def capture(self, raw):
        with patch.object(terminal, 'command_output', side_effect=[raw, 'serial=3039\n']):
            return terminal.capture_openssl_handshake('127.0.0.1')

    def test_reset_with_ok_verification_and_tls13_placeholder_is_not_success(self):
        raw = ('write:errno=54\nno peer certificate available\n'
               'SSL handshake has read 0 bytes and written 1542 bytes\n'
               'New, (NONE), Cipher is (NONE)\nProtocol: TLSv1.3\n'
               'Verify return code: 0 (ok)\n')
        result = self.capture(raw)
        self.assertIsNotNone(result['error'])
        self.assertNotIn('certificate_der', result)
        self.assertIn(raw, result['evidence'])

    def test_received_certificate_without_negotiated_cipher_is_not_success(self):
        result = self.capture(self.pem + '\nNew, TLSv1.2, Cipher is (NONE)\n')
        self.assertIsNotNone(result['error'])

    def test_certificate_and_connection_fields_come_from_exact_transcript(self):
        raw = (self.pem + '\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n'
               'Compression: NONE\nSecure Renegotiation IS NOT supported\n'
               '    Verify return code: 10 (certificate has expired)\n')
        result = self.capture(raw)
        self.assertIsNone(result['error'])
        self.assertEqual(result['certificate_der'], self.cert.public_bytes(serialization.Encoding.DER))
        self.assertEqual(result['protocol'], 'TLSv1.2')
        self.assertEqual(result['verify_code'], 10)
        self.assertEqual(result['verify_message'], 'certificate has expired')
        self.assertFalse(result['secure_renegotiation'])
        self.assertIn(raw, result['evidence'])

    def test_missing_verification_result_is_not_treated_as_trusted(self):
        result = self.capture(self.pem + '\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n')
        self.assertIsNone(result['error'])
        self.assertIsNone(result['verify_code'])
        with redirect_stdout(StringIO()):
            self.assertFalse(tls_config.check_certificate_chain('localhost', handshake=result))

    @patch.object(terminal.subprocess, 'run')
    def test_ip_targets_omit_sni_but_domains_keep_it(self, run):
        run.return_value = SimpleNamespace(stdout='connection refused\n', returncode=1)
        for host in ('127.0.0.1', '::1'):
            terminal.capture_openssl_handshake(host)
            self.assertIn('-noservername', run.call_args.args[0])
            self.assertNotIn('-servername', run.call_args.args[0])
        terminal.capture_openssl_handshake('localhost')
        self.assertIn('-servername', run.call_args.args[0])
        self.assertNotIn('-noservername', run.call_args.args[0])

    @patch.object(terminal.subprocess, 'run', side_effect=FileNotFoundError('openssl missing'))
    def test_missing_openssl_does_not_fall_back_to_a_python_connection(self, run):
        for scanner in (tls_certs, tls_config):
            with self.subTest(scanner=scanner.__name__), redirect_stdout(StringIO()) as output:
                result = scanner.run('127.0.0.1')
            self.assertIn('assessment unavailable', output.getvalue())
            self.assertIn('Cannot run openssl', result['evidence'])
        self.assertEqual(run.call_count, 2)

    @patch.object(terminal.subprocess, 'run')
    def test_timeout_before_handshake_completion_does_not_assess_partial_certificate(self, run):
        run.side_effect = [subprocess.TimeoutExpired('openssl', 12, output=self.pem.encode()),
                           SimpleNamespace(stdout='serial=3039\n', returncode=0)]
        result = terminal.capture_openssl_handshake('localhost')
        self.assertIsNotNone(result['error'])
        self.assertIn('timed out', result['evidence'])

    @contextmanager
    def local_server(self, version):
        """Accept exactly one connection; another evidence connection must fail."""
        with tempfile.TemporaryDirectory(prefix='aegis-tls-test-') as directory:
            cert_path, key_path = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
            cert_path.write_text(self.pem)
            key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = version
            context.load_cert_chain(cert_path, key_path)
            names = []
            context.set_servername_callback(lambda sock, name, ctx: names.append(name))
            listener = socket.socket()
            try:
                listener.bind(('127.0.0.1', 0))
            except PermissionError:
                listener.close()
                self.skipTest('Local socket binding is not permitted in this sandbox')
            listener.listen(1)
            listener.settimeout(5)
            port = listener.getsockname()[1]
            errors = []

            def serve():
                try:
                    connection, _ = listener.accept()
                    listener.close()
                    with connection:
                        connection.settimeout(5)
                        with context.wrap_socket(connection, server_side=True) as tls:
                            tls.recv(1)
                except Exception as exc:
                    errors.append(exc)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                yield port, names
            finally:
                listener.close()
                worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for native integration tests')
    def test_native_single_connection_for_both_scanners_tls12_and_tls13(self):
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            for scanner in (tls_certs, tls_config):
                with self.subTest(version=version, scanner=scanner.__name__):
                    with self.local_server(version) as (port, names):
                        output = StringIO()
                        with redirect_stdout(output), patch.object(tls_config, 'check_hsts_header'):
                            if scanner is tls_config:
                                result = scanner.run('127.0.0.1', port=port, check_ciphers=False, interactive=False)
                            else:
                                result = scanner.run('127.0.0.1', port=port)
                    self.assertEqual(names, [None])
                    self.assertEqual(result['evidence'].count('$ openssl s_client'), 1)
                    self.assertIn('serial=3039', result['evidence'])
                    self.assertIn('certificate has expired', result['evidence'])
                    self.assertNotIn('assessment unavailable', output.getvalue())
                    if scanner is tls_certs:
                        self.assertIn('Certificate EXPIRED', output.getvalue())
                        self.assertIn('TLSv1.2' if version == ssl.TLSVersion.TLSv1_2 else 'TLSv1.3', output.getvalue())
                    else:
                        self.assertIn('certificate has expired', output.getvalue())
                        self.assertNotIn('chain reaches a trusted root', output.getvalue())


if __name__ == '__main__':
    unittest.main()
