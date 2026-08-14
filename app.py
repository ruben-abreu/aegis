from flask import Flask, render_template, request, jsonify, Response
import sqlite3
import json
from datetime import datetime
import os
import re
import sys
import io
import traceback
from contextlib import redirect_stdout, redirect_stderr
import threading

sys.path.insert(0, os.path.dirname(__file__))

from scanners import tls_certs, tls_config, was, ports, email

app = Flask(__name__)
app.json.sort_keys = False

DB_FILE = 'aegis_results.db'
active_scans = {}

# A list (not a dict) so the order survives JSON serialisation.
SCANNERS = [
    ('was', 'Web Application Security'),
    ('tls_config', 'SSL/TLS Configuration'),
    ('tls_certs', 'SSL/TLS Certificates'),
    ('ports', 'Open Ports'),
    ('email', 'Email Security (SPF/DKIM/DMARC)'),
]

SCANNER_LABELS = dict(SCANNERS)

ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')

class StreamingOutput:
    """Collects scanner stdout/stderr for the web UI.

    Scanners write terminal colour codes; the browser re-colourises from the
    [OK]/[FAIL]/[WARN] markers, so the raw ANSI is stripped here.
    """

    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.output = []
        self.lock = threading.Lock()

    def write(self, text):
        with self.lock:
            self.output.append(ANSI_ESCAPE.sub('', text))

    def flush(self):
        pass

    def get_output(self):
        with self.lock:
            return ''.join(self.output)

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scanner TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            results TEXT,
            status TEXT
        )
    ''')
    conn.commit()
    conn.close()

def reconcile_interrupted_scans():
    """Close out scans orphaned by a crash or Ctrl+C.

    A scan's progress lives in the worker thread, so anything still marked
    'running' at startup died with the previous process and would otherwise
    sit as 'running' forever.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE scans SET status = 'interrupted' WHERE status = 'running'")
    reconciled = c.rowcount
    conn.commit()
    conn.close()

    if reconciled:
        print(f"  Marked {reconciled} interrupted scan(s) from a previous run")

@app.context_processor
def inject_footer_vars():
    return {'current_year': datetime.now().year}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scanners')
def get_scanners():
    return jsonify([{'id': key, 'label': label} for key, label in SCANNERS])

def save_scan(scan_id, target, scanner, extracted_port, output, status):
    results = {
        'target': target,
        'scanner': scanner,
        'port': extracted_port,
        'timestamp': datetime.now().isoformat(),
        'output': output
    }

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        'UPDATE scans SET results = ?, status = ? WHERE id = ?',
        (json.dumps(results), status, scan_id)
    )
    conn.commit()
    conn.close()

def run_scan_thread(scan_id, target, scanner, extracted_port, output_stream):
    try:
        with redirect_stdout(output_stream), redirect_stderr(output_stream):
            if scanner == 'was':
                was.run(target, port=extracted_port)
            elif scanner == 'tls_config':
                tls_config.run(target, port=extracted_port)
            elif scanner == 'tls_certs':
                tls_certs.run(target, port=extracted_port)
            elif scanner == 'ports':
                ports.run(target, port=extracted_port)
            elif scanner == 'email':
                email.run(target, interactive=False)
            else:
                raise ValueError(f"Unknown scanner: {scanner}")

        save_scan(scan_id, target, scanner, extracted_port,
                  output_stream.get_output(), 'completed')
        active_scans[scan_id]['status'] = 'completed'

    except Exception as e:
        error_msg = (
            f"{output_stream.get_output()}\n"
            f"[X] SCAN FAILED: {type(e).__name__}: {e}\n\n"
            f"{traceback.format_exc()}"
        )
        save_scan(scan_id, target, scanner, extracted_port, error_msg, 'error')
        active_scans[scan_id]['status'] = 'error'
        print(f"Scan {scan_id} failed: {type(e).__name__}: {e}", file=sys.__stderr__)

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target_input = data.get('target', '').strip()
    scanner = data.get('scanner')

    if not target_input or not scanner:
        return jsonify({'error': 'Missing target or scanner'}), 400

    if scanner not in SCANNER_LABELS:
        return jsonify({'error': f'Unknown scanner: {scanner}'}), 400

    if ':' not in target_input:
        return jsonify({'error': 'Format required: apple.com:443 or 1.2.3.4:161/udp'}), 400

    try:
        target, port_str = target_input.rsplit(':', 1)
        extracted_port = int(port_str.split('/')[0])
    except (ValueError, IndexError):
        return jsonify({'error': 'Invalid port format'}), 400

    if not extracted_port:
        return jsonify({'error': 'Port is required'}), 400

    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(
            'INSERT INTO scans (target, scanner, results, status) VALUES (?, ?, ?, ?)',
            (target, scanner, json.dumps({'target': target, 'scanner': scanner, 'port': extracted_port, 'timestamp': datetime.now().isoformat(), 'output': ''}), 'running')
        )
        scan_id = c.lastrowid
        conn.commit()
        conn.close()

        output_stream = StreamingOutput(scan_id)
        active_scans[scan_id] = {'stream': output_stream, 'status': 'running'}

        thread = threading.Thread(
            target=run_scan_thread,
            args=(scan_id, target, scanner, extracted_port, output_stream),
            daemon=True
        )
        thread.start()

        return jsonify({
            'id': scan_id,
            'status': 'started',
            'message': f'Scan started for {target}'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-status/<int:scan_id>')
def get_scan_status(scan_id):
    """Live progress for a running scan.

    While a scan is in flight its output only exists in the worker thread's
    in-memory buffer, so read that first and fall back to the DB once done.
    """
    try:
        active = active_scans.get(scan_id)
        if active and active['status'] == 'running':
            return jsonify({
                'id': scan_id,
                'output': active['stream'].get_output(),
                'status': 'running'
            })

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT results, status FROM scans WHERE id = ?', (scan_id,))
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'Scan not found'}), 404

        results = json.loads(row[0])
        return jsonify({
            'id': scan_id,
            'output': results.get('output', ''),
            'status': row[1]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

HISTORY_LIMIT = 50

@app.route('/api/scans')
def get_scans():
    """Recent scans plus the true stored total.

    Nothing is auto-deleted, so the total can exceed what is returned here;
    reporting it keeps the UI honest about hidden history.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(
            'SELECT id, target, scanner, timestamp, status FROM scans '
            'ORDER BY id DESC LIMIT ?', (HISTORY_LIMIT,)
        )
        scans = [
            {
                'id': row[0],
                'target': row[1],
                'scanner': row[2],
                'timestamp': row[3],
                'status': row[4],
            }
            for row in c.fetchall()
        ]
        total = c.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
        conn.close()
        return jsonify({'scans': scans, 'total': total})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans', methods=['DELETE'])
def clear_scans():
    """Wipe the whole local history. Deliberate, never automatic."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        deleted = c.execute('DELETE FROM scans').rowcount
        conn.commit()
        conn.close()
        active_scans.clear()
        return jsonify({'status': 'cleared', 'deleted': deleted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<int:scan_id>')
def get_scan(scan_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT target, scanner, timestamp, results, status FROM scans WHERE id = ?', (scan_id,))
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'Scan not found'}), 404

        results = json.loads(row[3])
        return jsonify({
            'id': scan_id,
            'target': row[0],
            'scanner': row[1],
            'timestamp': row[2],
            'results': results,
            'status': row[4]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

SEVERITY_MARKERS = [
    ('[✓]', 'pass'),
    ('[✗]', 'fail'),
    ('[!]', 'warning'),
    ('[X]', 'error'),
    ('[+]', 'info'),
]

SEPARATOR_LINE = re.compile(r'^[=\-]{3,}$')

def parse_findings(output):
    """Split raw scanner output into per-section findings.

    Scanners print a '[*] Section' header followed by [OK]/[FAIL]/[WARN]
    result lines. Wording is kept verbatim -- only the section and severity
    are attached, so exports carry the real finding text, not a rewrite.
    Banner and separator decoration is dropped.
    """
    findings = []
    section = None

    # Scans recorded before output was sanitised still carry ANSI codes,
    # which would hide the leading marker.
    for raw_line in ANSI_ESCAPE.sub('', output).splitlines():
        line = raw_line.strip()
        if not line or SEPARATOR_LINE.match(line):
            continue

        if line.startswith('[*]'):
            section = line[3:].strip()
            continue

        severity = None
        for marker, name in SEVERITY_MARKERS:
            if line.startswith(marker):
                severity = name
                line = line[len(marker):].strip()
                break

        # Before the first section header everything is title banner
        # ("TLS/SSL CERTIFICATE SECURITY", "Target: ...") which is already
        # captured in the export metadata.
        if severity is None and section is None:
            continue

        findings.append({
            'section': section,
            'severity': severity or 'detail',
            'message': line,
        })

    return findings

def load_scan_or_404(scan_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT target, scanner, timestamp, results, status FROM scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    return row

@app.route('/api/export/<int:scan_id>')
def export_scan(scan_id):
    """Customer-facing export. ?format=txt (default) or ?format=json."""
    fmt = request.args.get('format', 'txt').lower()
    if fmt not in ('txt', 'json'):
        return jsonify({'error': "format must be 'txt' or 'json'"}), 400

    row = load_scan_or_404(scan_id)
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    target, scanner, timestamp, results_json, status = row
    results = json.loads(results_json)
    raw_output = ANSI_ESCAPE.sub('', results.get('output', ''))
    port = results.get('port')
    risk_vector = SCANNER_LABELS.get(scanner, scanner)

    safe_target = re.sub(r'[^A-Za-z0-9._-]', '_', target)
    filename = f"aegis_{scanner}_{safe_target}_{scan_id}.{fmt}"

    if fmt == 'json':
        findings = parse_findings(raw_output)
        counts = {}
        for f in findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1

        payload = {
            'risk_vector': risk_vector,
            'scanner': scanner,
            'target': target,
            'port': port,
            'scanned_at': timestamp,
            'status': status,
            'summary': counts,
            'findings': findings,
            'raw_output': raw_output,
        }
        body = json.dumps(payload, indent=2, ensure_ascii=False)
        mimetype = 'application/json'
    else:
        header = (
            "=" * 68 + "\n"
            "AEGIS SECURITY ASSESSMENT\n"
            + "=" * 68 + "\n"
            f"Risk Vector : {risk_vector}\n"
            f"Target      : {target}:{port}\n"
            f"Scanned     : {timestamp}\n"
            f"Status      : {status}\n"
            + "=" * 68 + "\n\n"
        )
        body = header + raw_output.rstrip() + "\n"
        mimetype = 'text/plain'

    return Response(
        body,
        mimetype=mimetype,
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )

@app.route('/api/delete-scan/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    reconcile_interrupted_scans()
    # Port 5000 is taken by AirPlay Receiver on macOS, which answers 403.
    # Override with: AEGIS_PORT=8080 python app.py
    port = int(os.environ.get('AEGIS_PORT', 5050))
    print(f"\n  Aegis running at http://127.0.0.1:{port}\n")
    app.run(debug=True, host='127.0.0.1', port=port, threaded=True)
