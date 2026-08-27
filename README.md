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
Referrer-Policy, Permissions-Policy), CSP weaknesses such as `unsafe-inline`
and a missing or permissive `object-src`, CORS wildcards with credentials,
HTTPS-to-HTTP downgrades, mixed content, Subresource Integrity on external
scripts, dated JavaScript libraries, and the full redirect chain.

**Server Software**
Passively fingerprints Bitsight-listed software from HTTP headers, HTML
metadata, cookies and service banners. Detected versions are compared with a
dated local snapshot of BitSight's [supported server software
catalogue](https://help.bitsighttech.com/hc/en-us/articles/360010346733-Supported-Server-Software)
and graded GOOD, FAIR, WARN, BAD or NEUTRAL. Hidden versions, reverse proxies
and distribution backports are handled conservatively rather than guessed.

**SSL/TLS Configuration**
BitSight-aligned [configuration findings](https://help.bitsighttech.com/hc/en-us/articles/17441764941719-TLS-SSL-Configurations-Finding-Messages)
cover certificate name mismatch, future-dated and
overlong certificates, malformed certificates and public keys, chain/trust
failures, weak DSA or elliptic-curve keys, export ciphers, short or commonly
reused Diffie-Hellman parameters, Heartbleed, and deprecated SSL/TLS versions
including SSLv2, SSLv3, TLS 1.0 and TLS 1.1. The chain is validated with the
local platform trust store.

Additional checks cover the active cipher, forward secrecy, HSTS (including
`max-age`, `includeSubDomains` and `preload`), TLS compression, session
resumption, secure renegotiation and downgrade protection. The slower
`sslscan` checks are optional, share one probe, and keep TLS-version
enumeration last.

Hostname matching follows RFC 6125: when a SAN extension is present it is
authoritative and the Common Name is ignored, exactly as browsers do. A
wildcard covers a single label, so `*.example.com` matches `www.example.com`
but neither `a.b.example.com` nor `example.com` itself.

**SSL/TLS Certificates**
BitSight-aligned [certificate findings](https://help.bitsighttech.com/hc/en-us/articles/17442341368087-TLS-SSL-Certificates-Finding-Messages)
cover expiration, RSA thresholds, MD2/MD5/SHA-1
signatures, self-signed and default Kubernetes Ingress certificates,
Entrust/legacy Symantec distrust indicators, and certificate scope. Wildcard
usage, Key Usage and Extended Key Usage remain available as additional
security checks rather than being presented as BitSight findings.

Certificate scope is flagged above 25 SAN entries. A long SAN list means one
private key protects many unrelated hosts, so a single key compromise or
mis-issuance affects all of them, and any one of those hosts can impersonate
the rest. Change the threshold with `MAX_SAN_ENTRIES` in `tls_certs.py`.

**Open Ports**
Checks a single specified port over TCP or UDP and names the service behind it.
Ports that are conventionally UDP — 53, 123, 161, 162 and others — switch to UDP
automatically, and you can force either with `161/udp` or `161/tcp`. When SMTP
port 25 or 587 is open, Aegis sends an `EHLO` capability query and reports
whether STARTTLS is advertised. Port 465 is excluded because it uses implicit
TLS instead of STARTTLS.

**Email Security**
SPF (qualifier strength, the 10-lookup limit, deprecated `ptr`), DMARC (policy,
`pct`, `rua` reporting) and DKIM (key length, SHA-1 restriction), discovered
through common selectors or one you supply. The web scanner accepts either the
email domain or a complete DKIM record name such as
`s02._domainkey.example.com`; a complete name is split into its selector and
base domain automatically.

**DNS Analysis** — CLI only
A-record lookup for domains. For IP targets it builds a passive DNS graph from
VirusTotal and filters out ISP and dynamic-hostname noise. Requires an API key.

## Requirements

- Python 3.9 or newer
- [`sslscan`](https://github.com/rbsec/sslscan) — needed by the optional extended
  SSL/TLS Configuration checks, since Python's `ssl` module refuses to negotiate
  the deprecated protocol versions we specifically want to detect

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

CLI targets accept an optional port: `example.com`, `example.com:8443`,
`1.2.3.4`, `1.2.3.4:161/udp`. In the web interface a port is required for all
scanners except Email Security, which accepts a bare domain such as
`example.com`. Only public IPs are allowed.

## Exports

Scan results can be exported for sharing from the results panel:

- **TXT** — a short header (risk vector, target, timestamp) followed by the raw
  scanner output, unchanged.
- **JSON** — the same raw output, plus a `findings[]` array giving each result a
  section and a severity (`pass`, `fail`, `warning`, `info`, `detail`), and a
  severity count. Finding text is never reworded.

Every web scanner includes a separate Technical Evidence pane. It shows the
team-reference commands that can reproduce the diagnosis beside the data Aegis
actually captured: certificate fields, TLS handshakes and raw `sslscan` output,
HTTP redirects and headers, socket results and SMTP transcripts, DNS email
records, or software headers and service banners. The same evidence is included
in TXT and JSON exports.

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
    ├── server_software.py # passive software fingerprinting and support status
    ├── tls_config.py    # protocol versions, ciphers, DH, HSTS, name mismatch
    ├── tls_certs.py     # certificate inspection
    ├── ports.py         # TCP/UDP port check
    ├── email.py         # SPF / DKIM / DMARC
    ├── dns.py           # DNS records, passive DNS graph
    └── hostnames.py     # RFC 6125 hostname matching, shared by both TLS scanners
```

## Testing

After installing the project dependencies, run the complete automated suite with:

```bash
python3 -m unittest discover -v
```

The tests mock network and subprocess calls, so they do not scan real targets.

## Notes and limitations

Each person runs their own instance. Results are written to a local SQLite file
and never leave the machine.

There is no authentication, and the server binds to `127.0.0.1` on purpose. Do
not expose it on `0.0.0.0` or to a network as it stands.

When selected, `tls_config.py` runs `sslscan` once per target at the end of the
scan and shares the output across the extended checks. Skipping it leaves the
faster configuration checks intact.

Several `was.py` checks — HTTP methods, directory listing, server banner
disclosure, form action inspection, technology fingerprinting — are written but
commented out in `run()`. Uncomment them if you want them.

## Planned

- General Improvements
- AI-generated summaries and remediation guidance

## License

MIT. See [LICENSE](LICENSE).

© 2026 Ruben Abreu
