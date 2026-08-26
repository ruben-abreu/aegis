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


if __name__ == "__main__":
    unittest.main()
