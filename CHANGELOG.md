# Changelog

## Unreleased

- Technical Evidence now omits report headings and unexecuted reference commands
  across all risk vectors.
- SSL/TLS evidence contains native OpenSSL handshake and certificate output,
  including verification errors and partial output from timed-out commands.
- HTTP, DNS, SMTP and server-software evidence preserves the actual responses,
  banners and errors collected by the probes. Existing scan history is unchanged.

## 1.6.1 — 2026-09-10

- Web scans that require a port now default to 443 when the target omits it.
- The selected default is explained when starting the scan and recorded in its
  output, including saved results and exports.
- Results show the scan port alongside the risk vector.
- Explicit ports and invalid-port validation are unchanged. Email Security
  remains port-independent.
