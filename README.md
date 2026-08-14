# Aegis

A modular security assessment toolkit for domains and IP addresses, written in Python.
Runs either as an interactive CLI or as a local web app.

Aegis inspects a target against the same risk vectors used in security ratings —
web application security, TLS configuration, certificates, open ports and email
authentication — and reports what would count against it, with the reasoning for
each finding.

This started as a learning project and still is one: rather than a pile of small
throwaway scripts, it grows a bit every week as I pick up new ground in Python,
networking and security. It is not a replacement for a commercial scanner.

## What it checks

**Web Application Security**
Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy), CSP weaknesses such as `unsafe-inline`,
CORS wildcards with credentials, HTTPS-to-HTTP downgrades, mixed content,
Subresource Integrity on external scripts, dated JavaScript libraries, and the
full redirect chain.

**SSL/TLS Configuration**
Which protocol versions the server actually negotiates — TLS 1.0, 1.1 and SSLv3
are flagged as violations — plus cipher strength, forward secrecy,
Diffie-Hellman key size, certificate/hostname mismatch, HSTS (with `max-age`,
`includeSubDomains` and `preload`), TLS compression (CRIME), session resumption
and secure renegotiation.

**SSL/TLS Certificates**
Validity window and time to expiry, key strength (RSA and ECDSA), signature
algorithm (SHA-1 is a violation), self-signed detection, wildcard usage,
SAN and CN hostname matching, Key Usage and Extended Key Usage.

**Open Ports**
Checks a single specified port over TCP or UDP and names the service behind it.
Ports that are conventionally UDP — 53, 123, 161, 162 and others — switch to UDP
automatically, and you can force either with `161/udp` or `161/tcp`.

**Email Security**
SPF (qualifier strength, the 10-lookup limit, deprecated `ptr`), DMARC (policy,
`pct`, `rua` reporting) and DKIM (key length, SHA-1 restriction), discovered
through common selectors or one you supply.

**DNS Analysis** — CLI only
A-record lookup for domains. For IP targets it builds a passive DNS graph from
VirusTotal and filters out ISP and dynamic-hostname noise. Requires an API key.

## Requirements

- Python 3.9 or newer
- [`sslscan`](https://github.com/rbsec/sslscan) — needed by the SSL/TLS
  Configuration checks, since Python's `ssl` module refuses to negotiate the
  deprecated protocol versions we specifically want to detect

## Setup

```bash
pip install -r requirements.txt
brew install sslscan          # macOS; apt install sslscan on Debian/Ubuntu
```

The passive DNS graph needs a VirusTotal API key. It is optional — everything
else works without it:

```bash
echo "VT_API_KEY=your_api_key" > .env
```

## Running

Web interface:

```bash
python app.py
```

Then open <http://127.0.0.1:5050>.

Port 5050 is deliberate. On macOS, port 5000 belongs to the AirPlay Receiver,
which binds every interface and answers HTTP requests with `403 Forbidden` —
easy to mistake for a bug in the app. Override with `AEGIS_PORT=8080 python app.py`.

CLI:

```bash
python main.py
```

Targets accept an optional port in either interface: `example.com`,
`example.com:8443`, `1.2.3.4`, `1.2.3.4:161/udp`. Only public IPs are allowed.

## Exports

Scan results can be exported for sharing from the results panel:

- **TXT** — a short header (risk vector, target, timestamp) followed by the raw
  scanner output, unchanged.
- **JSON** — the same raw output, plus a `findings[]` array giving each result a
  section and a severity (`pass`, `fail`, `warning`, `info`, `detail`), and a
  severity count. Finding text is never reworded.

Both are also reachable directly:

```
/api/export/<scan_id>?format=txt
/api/export/<scan_id>?format=json
```

## Project layout

```text
aegis/
├── main.py              # interactive CLI
├── app.py               # Flask web app
├── requirements.txt
├── aegis_results.db     # scan history, created on first run
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── app.js
└── scanners/
    ├── was.py           # web application security
    ├── tls_config.py    # protocol versions, ciphers, DH, HSTS
    ├── tls_certs.py     # certificate inspection
    ├── ports.py         # TCP/UDP port check
    ├── email.py         # SPF / DKIM / DMARC
    └── dns.py           # DNS records, passive DNS graph
```

## Notes and limitations

Each person runs their own instance. Results are written to a local SQLite file
and never leave the machine.

There is no authentication, and the server binds to `127.0.0.1` on purpose. Do
not expose it on `0.0.0.0` or to a network as it stands.

`tls_config.py` shells out to `sslscan` once per check, so slow targets can time
out and report a false failure. Caching a single run is on the list.

Several `was.py` checks — HTTP methods, directory listing, server banner
disclosure, form action inspection, technology fingerprinting — are written but
commented out in `run()`. Uncomment them if you want them.

## Planned

- General Improvements
- AI-generated summaries and remediation guidance

## License

MIT. See [LICENSE](LICENSE).

© 2026 Ruben Abreu
