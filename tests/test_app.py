import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class EvidencePersistenceTests(unittest.TestCase):
    def setUp(self):
        self._original_db = app.DB_FILE
        self.temp_dir = tempfile.TemporaryDirectory()
        app.DB_FILE = str(Path(self.temp_dir.name) / "aegis-test.db")
        app.init_db()

        conn = sqlite3.connect(app.DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (target, scanner, results, status) VALUES (?, ?, ?, ?)",
            ("example.com", "tls_certs", "{}", "running"),
        )
        self.scan_id = cursor.lastrowid
        conn.commit()
        conn.close()

    def tearDown(self):
        app.DB_FILE = self._original_db
        app.active_scans.clear()
        self.temp_dir.cleanup()

    def test_evidence_is_saved_and_included_in_both_exports(self):
        app.save_scan(
            self.scan_id,
            "example.com",
            "tls_certs",
            443,
            "[*] Certificate\n\033[92m[✓]\033[0m Valid",
            "completed",
            evidence="\033[96mserial=ABC123\033[0m",
        )

        client = app.app.test_client()
        json_response = client.get(f"/api/export/{self.scan_id}?format=json")
        json_payload = json.loads(json_response.get_data(as_text=True))
        self.assertEqual("serial=ABC123", json_payload["technical_evidence"])

        text_response = client.get(f"/api/export/{self.scan_id}?format=txt")
        text_payload = text_response.get_data(as_text=True)
        self.assertIn("TECHNICAL EVIDENCE", text_payload)
        self.assertIn("serial=ABC123", text_payload)

    def test_scan_thread_persists_evidence_returned_by_scanner(self):
        output_stream = app.StreamingOutput(self.scan_id)
        app.active_scans[self.scan_id] = {
            "stream": output_stream,
            "status": "running",
        }

        with patch.object(
            app.tls_certs,
            "run",
            return_value={"evidence": "Negotiated protocol: TLSv1.3"},
        ):
            app.run_scan_thread(
                self.scan_id,
                "example.com",
                "tls_certs",
                443,
                output_stream,
            )

        conn = sqlite3.connect(app.DB_FILE)
        results_json, status = conn.execute(
            "SELECT results, status FROM scans WHERE id = ?", (self.scan_id,)
        ).fetchone()
        conn.close()

        self.assertEqual("completed", status)
        self.assertEqual(
            "Negotiated protocol: TLSv1.3",
            json.loads(results_json)["evidence"],
        )


class DefaultPortTests(unittest.TestCase):
    def setUp(self):
        self.original_db = app.DB_FILE
        self.temp_dir = tempfile.TemporaryDirectory()
        app.DB_FILE = str(Path(self.temp_dir.name) / 'ports-test.db')
        app.init_db()
        self.client = app.app.test_client()

    def tearDown(self):
        app.DB_FILE = self.original_db
        app.active_scans.clear()
        self.temp_dir.cleanup()

    def start(self, scanner, target):
        with patch.object(app.threading, 'Thread') as worker:
            response = self.client.post('/api/scan', json={'scanner': scanner, 'target': target})
        return response, worker

    def test_all_port_scanners_default_to_443_and_preserve_notice_in_exports(self):
        for scanner in ('was', 'tls_config', 'tls_certs', 'ports', 'server_software'):
            with self.subTest(scanner=scanner):
                response, worker = self.start(scanner, 'example.com')
                self.assertEqual(response.status_code, 200)
                payload = response.get_json()
                self.assertEqual(payload['port'], 443)
                self.assertTrue(payload['port_defaulted'])
                worker.return_value.start.assert_called_once()
                scan_id = payload['id']
                notice = 'No port specified. Using default port 443.'
                self.assertIn(notice, self.client.get(f'/api/scan-status/{scan_id}').get_json()['output'])
                args = worker.call_args.kwargs['args']
                with patch.object(getattr(app, scanner), 'run', return_value={'evidence': 'Test evidence'}) as run:
                    app.run_scan_thread(*args)
                self.assertEqual(run.call_args.args, ('example.com',))
                self.assertEqual(run.call_args.kwargs['port'], 443)
                saved = self.client.get(f'/api/scan/{scan_id}').get_json()
                self.assertEqual(saved['results']['port'], 443)
                self.assertIn(notice, saved['results']['output'])
                self.assertIn(notice, self.client.get(f'/api/export/{scan_id}?format=txt').get_data(as_text=True))
                exported = self.client.get(f'/api/export/{scan_id}?format=json').get_json()
                self.assertIn(notice, exported['raw_output'])
                self.assertEqual(exported['port'], 443)
                self.assertFalse(exported['findings'], 'Defaulting a port is not a security finding')

    def test_explicit_ports_are_preserved_without_default_notice(self):
        for target, port in [('example.com:8443', 8443), ('example.com:443', 443), ('1.2.3.4:161/udp', 161)]:
            with self.subTest(target=target):
                response, worker = self.start('ports', target)
                payload = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertEqual(payload['port'], port)
                self.assertFalse(payload['port_defaulted'])
                self.assertEqual(worker.call_args.kwargs['args'][3], port)
                self.assertEqual(self.client.get(f"/api/scan-status/{payload['id']}").get_json()['output'], '')

    def test_email_and_explicit_dkim_names_remain_portless(self):
        for target in ('example.com', 's02._domainkey.example.com'):
            with self.subTest(target=target):
                response, worker = self.start('email', target)
                payload = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertIsNone(payload['port'])
                self.assertFalse(payload['port_defaulted'])
                self.assertIsNone(worker.call_args.kwargs['args'][3])

    def test_invalid_explicit_ports_do_not_fall_back_to_443(self):
        for suffix in ('', 'abc', '0', '-1', '65536'):
            with self.subTest(port=suffix):
                response, worker = self.start('tls_certs', f'example.com:{suffix}')
                self.assertEqual(response.status_code, 400)
                worker.assert_not_called()

    def test_default_notice_survives_scanner_failure(self):
        response, worker = self.start('tls_certs', 'example.com')
        scan_id = response.get_json()['id']
        with patch.object(app.tls_certs, 'run', side_effect=RuntimeError('Test failure')), patch('sys.__stderr__'):
            app.run_scan_thread(*worker.call_args.kwargs['args'])
        saved = self.client.get(f'/api/scan/{scan_id}').get_json()
        self.assertEqual(saved['status'], 'error')
        self.assertIn('Using default port 443', saved['results']['output'])


if __name__ == "__main__":
    unittest.main()
