# Aegis

A modular command-line security assessment toolkit built with Python.

Aegis is the flagship project of **Project Ascend**.

The goal is to build a professional, modular security assessment toolkit while progressively learning Python, networking, software engineering, and artificial intelligence. Instead of creating many small practice projects, Aegis evolves every week as I learn new concepts.

---

## Vision

Aegis will allow a user to assess a domain or an IP address against a variety of security checks. Eventually, the application will support:

- **DNS Analysis**
- **TLS / SSL Configuration & Certificate Inspection**
- **Open Port Detection**
- **HTTP Security Headers & Web Technology Detection**
- **Email Security** (SPF, DKIM, DMARC)
- **AI-powered Security Summaries**

The project is inspired by common security assessment techniques and is designed as a learning platform rather than a commercial security scanner.

---

## Current Features (v0.7)

- **Interactive CLI**: Menu-driven target selection interface with full user validation.
- **Dynamic Routing**: Assessment sub-menu contextually tracks the selected asset.
- **Modular Package Architecture**: Core scanner engines completely decoupled into a standalone `scanners` package using package-level imports.
- **Global Termination Execution**: Quick system-level exit capability safely embedded directly within the deep loop framework.

---

## Roadmap

### Phase 1 — Python Foundations

- [x] Interactive CLI
- [x] Target selection
- [x] Assessment menu
- [x] Project package refactoring

### Phase 2 — Networking

- [x] DNS resolution
- [x] IP lookup
- [x] Reverse DNS

### Phase 3 — HTTP Analysis

- [ ] HTTP requests
- [ ] Response headers
- [ ] Redirect detection
- [ ] Security header analysis

### Phase 4 — TLS / SSL

- [ ] Certificate inspection
- [ ] Expiration checks
- [ ] Supported TLS versions
- [ ] Cipher suite analysis

### Phase 5 — Port Scanning

- [ ] TCP port scanning
- [ ] Banner grabbing
- [ ] Service identification

### Phase 6 — Reporting

- [ ] JSON export
- [ ] CSV export
- [ ] HTML report generation

### Phase 7 — Artificial Intelligence

- [ ] AI-generated security summaries
- [ ] Suggested remediation guidance
- [ ] Executive report generation

---

## Technologies

- **Python**
- **Git**
- **GitHub**

> _Note: Additional libraries and packages will be introduced as the functional scanner mechanics drop into place._

---

## Project Structure

```text
aegis/
│
├── main.py
├── .gitignore
├── README.md
└── scanners/
    ├── dns.py
    ├── tls_certs.py
    ├── tls_config.py
    ├── was.py
    ├── ports.py
    └── email.py
```
