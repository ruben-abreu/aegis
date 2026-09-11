import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

import requests
from scanners import dns, email, ports, server_software, was


class EvidenceFormatTests(unittest.TestCase):
    def test_all_other_vectors_omit_report_headings_and_unexecuted_commands(self):
        response = SimpleNamespace(url='https://example.com/', status_code=403,
                                   headers={'Server': 'nginx/1.26'}, history=[])
        outputs = {
            'was': was.format_was_evidence(response, response.url),
            'ports': ports.format_port_evidence('example.com', 25, 'tcp', True,
                       smtp_evidence=['220 mail.example', '> EHLO aegis.local', '250 STARTTLS']),
            'email': email.format_email_evidence('example.com', [';; example.com IN TXT', '"v=spf1 -all"']),
            'server_software': server_software.format_server_software_evidence('example.com', 443, response=response),
            'dns': dns.format_dns_evidence('example.com', 'Domain', ['A example.com -> 203.0.113.10']),
        }
        for scanner, output in outputs.items():
            with self.subTest(scanner=scanner):
                self.assertTrue(output)
                self.assertNotIn('CAPTURED BY AEGIS', output)
                self.assertNotIn('REPRODUCE MANUALLY', output)
                self.assertNotIn('$ ', output)
        self.assertIn('250 STARTTLS', outputs['ports'])
        self.assertIn('Server: nginx/1.26', outputs['server_software'])

    def test_http_redirects_keep_each_actual_request_and_response(self):
        first = SimpleNamespace(url='http://example.com/', status_code=302,
            headers={'Location': 'https://example.com/'},
            request=SimpleNamespace(method='GET', headers={'User-Agent': 'Aegis/0.7'}))
        final = SimpleNamespace(url='https://example.com/', status_code=403,
            headers={'Server': 'edge'}, history=[first],
            request=SimpleNamespace(method='GET', headers={'User-Agent': 'Aegis/0.7'}))
        output = was.format_was_evidence(final, first.url)
        self.assertLess(output.index('status: 302'), output.index('status: 403'))
        self.assertIn('Location: https://example.com/', output)
        self.assertIn('User-Agent: Aegis/0.7', output)
        self.assertIn('Server: edge', output)

    def test_http_connection_failures_remain_in_evidence(self):
        with patch.object(was.requests, 'get', side_effect=requests.exceptions.ConnectionError('Connection refused')):
            with redirect_stdout(StringIO()):
                result = was.run('example.com')
        self.assertIn('https://example.com', result['evidence'])
        self.assertIn('http://example.com', result['evidence'])
        self.assertIn('Connection refused', result['evidence'])

    def test_dns_query_errors_are_preserved_without_inventing_records(self):
        observed = []
        email._record_dns_evidence(observed, 's02._domainkey.example.com', 'TXT', error='NXDOMAIN')
        output = email.format_email_evidence('example.com', observed)
        self.assertIn('s02._domainkey.example.com IN TXT', output)
        self.assertIn('NXDOMAIN', output)
        self.assertNotIn('selector._domainkey', output)

    def test_server_banner_and_connection_errors_are_preserved(self):
        output = server_software.format_server_software_evidence('example.com', 22,
            errors=['TLS handshake failed'], banner='SSH-2.0-OpenSSH_9.8\r\n')
        self.assertIn('TLS handshake failed', output)
        self.assertTrue(output.endswith('SSH-2.0-OpenSSH_9.8\r\n'))


if __name__ == '__main__':
    unittest.main()
