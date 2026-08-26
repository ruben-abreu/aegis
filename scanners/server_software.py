"""Passive server-software fingerprinting and BitSight-style support grading.

The support catalogue is a dated snapshot of BitSight's public Supported
Server Software article. It is intentionally local: scans are reproducible and
do not depend on scraping a changing web page at runtime.

Fingerprinting is best-effort. Headers and banners can be hidden or spoofed,
and Linux distributions frequently backport fixes without changing the
upstream version. Those cases are reported as NEUTRAL rather than guessed.
"""

from dataclasses import dataclass
from datetime import date
from html.parser import HTMLParser
import re
import shlex
import socket
from typing import Optional

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
END = "\033[0m"


def ok(msg):
    print(f"{GREEN}[✓]{END} {msg}")


def warn(msg):
    print(f"{YELLOW}[!]{END} {msg}")


def bad(msg):
    print(f"{RED}[✗]{END} {msg}")


CATALOG_UPDATED = date(2026, 8, 25)
CATALOG_SOURCE = (
    "https://help.bitsighttech.com/hc/en-us/articles/"
    "360010346733-Supported-Server-Software"
)

HTTPS_LIKELY_PORTS = {443, 8443, 9443, 10000, 2083, 2087, 2096}
BANNER_PORTS = {21, 22, 25, 110, 143, 587, 2222}
NON_HTTP_PORTS = {
    21,
    22,
    25,
    53,
    110,
    123,
    143,
    161,
    389,
    445,
    465,
    587,
    636,
    873,
    993,
    995,
    1433,
    1521,
    3306,
    5432,
    6379,
    27017,
}

CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
DISTRO_MARKERS = (
    "ubuntu",
    "debian",
    "rhel",
    "red hat",
    "centos",
    "rocky",
    "alma",
    "suse",
    "amazon linux",
    "amzn",
    "alpine",
)
BACKPORT_PRODUCTS = {"Apache", "NGINX", "OpenSSH", "PHP"}


@dataclass(frozen=True)
class Fingerprint:
    product: str
    version: Optional[str]
    evidence: str
    confidence: str = "medium"
    distribution_hint: Optional[str] = None


@dataclass(frozen=True)
class Assessment:
    grade: str
    reason: str
    eol_date: Optional[date] = None


class MetadataParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.generators = []
        self.title_parts = []
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "meta" and attributes.get("name", "").lower() == "generator":
            content = attributes.get("content", "").strip()
            if content:
                self.generators.append(content)
        elif tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)

    @property
    def title(self):
        return " ".join("".join(self.title_parts).split())


HEADER_PATTERNS = (
    ("Apache", re.compile(r"\bApache(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("NGINX", re.compile(r"\bnginx(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("Microsoft IIS", re.compile(r"\bMicrosoft-IIS/(\d+(?:\.\d+)?)", re.I)),
    ("Boa Webserver", re.compile(r"\bBoa(?:/|\s+)([\w.-]+)", re.I)),
    ("Embedthis Appweb", re.compile(r"\b(?:Embedthis-)?Appweb(?:/|\s+)([\w.-]+)", re.I)),
    ("Webmin", re.compile(r"\bMiniServ/(\d+(?:\.\d+)?)", re.I)),
)

HEADER_PRODUCT_MARKERS = (
    ("Apache", re.compile(r"\bApache\b", re.I)),
    ("NGINX", re.compile(r"\bnginx\b", re.I)),
    ("Microsoft IIS", re.compile(r"\bMicrosoft-IIS\b", re.I)),
    ("Boa Webserver", re.compile(r"\bBoa\b", re.I)),
    ("Embedthis Appweb", re.compile(r"\b(?:Embedthis-)?Appweb\b", re.I)),
    ("Webmin", re.compile(r"\bMiniServ\b", re.I)),
)

HTML_PATTERNS = (
    ("WordPress", re.compile(r"\bWordPress\s+v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("TeamCity", re.compile(r"\bTeamCity\s+(\d{4}\.\d+(?:\.\d+)?)", re.I)),
    ("Webmin", re.compile(r"\bWebmin\s+(\d+(?:\.\d+)+)", re.I)),
    ("cPanel", re.compile(r"\bcPanel\s*(?:&\s*WHM)?(?:\s+|/)(\d+(?:\.\d+)*)", re.I)),
    ("Kerio Connect", re.compile(r"\bKerio Connect\s+(\d+(?:\.\d+)*)", re.I)),
    ("SolarWinds Orion", re.compile(r"\bOrion(?: Platform)?\s+(\d{4}\.\d+(?:\.\d+)*)", re.I)),
)

BANNER_PATTERNS = (
    ("OpenSSH", re.compile(r"\bOpenSSH[_ -](\d+\.\d+)(?:p\d+)?", re.I)),
    ("Serv-U", re.compile(r"\bServ-U(?: FTP Server)?(?: v|/|\s+)(\d+(?:\.\d+)*)", re.I)),
    ("Kerio Connect", re.compile(r"\bKerio Connect(?: v|/|\s+)(\d+(?:\.\d+)*)", re.I)),
    ("Microsoft Exchange", re.compile(r"\bMicrosoft (?:Exchange|ESMTP).*?(20\d{2})", re.I)),
)


SUPPORTED_EXACT = {
    "Apache": {"2.4.68"},
    "cPanel": {"78"},
    "Embedthis Appweb": {"9"},
    "Kerio Connect": {"9"},
    "Microsoft IIS": {"10", "10.0"},
    "Microsoft SQL Server": {"17", "16", "14"},
    "Microsoft Windows Server": {"2019", "2016"},
    "OpenSSH": {"10.4"},
    "Serv-U": {"14", "15"},
    "TeamCity": {
        "2026.1.2",
        "2025.11",
        "2025.11.1",
        "2025.11.2",
        "2025.11.3",
        "2025.11.4",
        "2025.07",
        "2025.07.1",
        "2025.07.2",
        "2025.07.3",
    },
    "Webmin": {"2.651", "2.630", "2.021", "1.996"},
    "WordPress": {
        "6.9.4",
        "6.8.3",
        "6.7.4",
        "6.6.4",
        "6.5.7",
        "6.4.7",
        "6.3.7",
        "6.2.8",
        "6.1.9",
        "6.0.11",
        "5.9.12",
        "5.8.12",
        "5.7.14",
        "5.6.16",
        "5.5.17",
        "5.4.18",
        "5.3.20",
        "5.2.23",
        "5.1.21",
        "5.0.24",
    },
}

EOL_DATES = {
    "Apache": {
        "2.4.67": date(2026, 6, 8),
        "2.4.66": date(2026, 5, 4),
        "2.4.65": date(2025, 12, 4),
        "2.4.64": date(2025, 7, 23),
        "2.4.63": date(2025, 7, 10),
        "2.4.62": date(2025, 1, 23),
        "2.4.61": date(2024, 7, 17),
        "2.4.60": date(2024, 7, 3),
        "2.4.59": date(2024, 7, 1),
        "2.4.58": date(2024, 4, 4),
        "2.4.57": date(2023, 10, 19),
    },
    "OpenSSH": {
        "10.3": date(2026, 7, 6),
        "10.2": date(2026, 4, 2),
        "10.1": date(2025, 10, 10),
        "10.0": date(2025, 10, 6),
        "9.9": date(2025, 4, 9),
        "9.8": date(2024, 9, 19),
        "9.7": date(2024, 7, 1),
        "9.6": date(2024, 3, 11),
        "9.5": date(2023, 12, 18),
        "9.4": date(2023, 10, 4),
        "9.3": date(2023, 8, 10),
    },
    "TeamCity": {
        "2025.03.3": date(2025, 11, 27),
        "2025.03.2": date(2025, 11, 27),
        "2025.03.1": date(2025, 11, 27),
        "2025.03": date(2025, 11, 27),
        "2024.12.3": date(2025, 7, 23),
        "2024.12.2": date(2025, 7, 23),
        "2024.12.1": date(2025, 7, 23),
        "2024.12": date(2025, 7, 23),
        "2024.07.3": date(2025, 3, 20),
        "2024.07.2": date(2025, 3, 20),
        "2024.07.1": date(2025, 3, 20),
        "2024.07": date(2025, 3, 20),
    },
    "Webmin": {
        "2.650": date(2026, 6, 28),
        "2.641": date(2026, 6, 25),
        "2.621": date(2026, 3, 24),
        "2.620": date(2026, 1, 27),
        "2.610": date(2026, 1, 9),
        "2.600": date(2025, 11, 23),
        "2.520": date(2025, 11, 10),
        "2.510": date(2025, 10, 4),
        "2.501": date(2025, 9, 16),
        "2.500": date(2025, 9, 8),
        "2.402": date(2025, 9, 4),
        "2.401": date(2025, 6, 17),
        "2.400": date(2025, 6, 2),
    },
    "WordPress": {
        "6.9.3": date(2026, 3, 11),
        "6.9.2": date(2026, 3, 10),
        "6.9.1": date(2026, 3, 10),
        "6.9": date(2026, 2, 3),
        "6.8.2": date(2025, 9, 30),
        "6.8.1": date(2025, 7, 15),
        "6.8": date(2025, 4, 30),
        "6.7.3": date(2025, 9, 30),
        "6.7.2": date(2025, 4, 15),
        "6.7.1": date(2025, 2, 11),
        "6.7": date(2024, 11, 21),
        "6.6.3": date(2025, 9, 30),
        "6.6.2": date(2025, 8, 5),
    },
}


def _version_tuple(version):
    numbers = re.findall(r"\d+", version or "")
    return tuple(int(number) for number in numbers)


def _distribution_hint(text):
    lowered = text.lower()
    for marker in DISTRO_MARKERS:
        if marker in lowered:
            return marker
    return None


def _fingerprints_from_pattern(text, evidence, patterns, confidence="high"):
    findings = []
    for product, pattern in patterns:
        match = pattern.search(text)
        if match:
            findings.append(
                Fingerprint(
                    product=product,
                    version=match.group(1) if match.lastindex else None,
                    evidence=evidence,
                    confidence=confidence,
                    distribution_hint=_distribution_hint(text),
                )
            )
    return findings


def detect_from_http(headers, body):
    """Return fingerprints from an HTTP response without making a request."""
    findings = []
    normalised_headers = {str(key).lower(): str(value) for key, value in headers.items()}

    server = normalised_headers.get("server", "")
    if server:
        evidence = f"Server header: {server}"
        versioned = _fingerprints_from_pattern(server, evidence, HEADER_PATTERNS)
        findings.extend(versioned)
        versioned_products = {finding.product for finding in versioned}
        for product, marker in HEADER_PRODUCT_MARKERS:
            if product not in versioned_products and marker.search(server):
                findings.append(Fingerprint(product, None, evidence, "high"))

    powered_by = normalised_headers.get("x-powered-by", "")
    php_match = re.search(r"\bPHP/?\s*(\d+\.\d+(?:\.\d+)?)", powered_by, re.I)
    if php_match:
        findings.append(
            Fingerprint(
                "PHP",
                php_match.group(1),
                f"X-Powered-By header: {powered_by}",
                "high",
                _distribution_hint(powered_by),
            )
        )
    elif re.search(r"\bPHP\b", powered_by, re.I):
        findings.append(
            Fingerprint("PHP", None, f"X-Powered-By header: {powered_by}", "high")
        )

    parser = MetadataParser()
    try:
        parser.feed(body[:2_000_000])
    except Exception:
        pass

    for generator in parser.generators:
        findings.extend(
            _fingerprints_from_pattern(
                generator,
                f"HTML generator metadata: {generator}",
                HTML_PATTERNS,
                "high",
            )
        )

    searchable = "\n".join((parser.title, body[:500_000]))
    findings.extend(
        _fingerprints_from_pattern(
            searchable,
            "HTML title or response content",
            HTML_PATTERNS,
            "medium",
        )
    )

    lowered = searchable.lower()
    cookies = normalised_headers.get("set-cookie", "").lower()
    heuristics = (
        ("WordPress", "wordpress", "/wp-content/" in lowered or "wordpress_" in cookies),
        ("TeamCity", "teamcity", "teamcity" in lowered or "teamcity" in cookies),
        ("Webmin", "webmin", "webmin" in lowered),
        ("cPanel", "cpanel", "cpanel" in lowered or "cpanel" in cookies),
        ("SolarWinds Orion", "orion", "solarwinds orion" in lowered),
        ("Kerio Connect", "kerio", "kerio connect" in lowered),
    )
    for product, marker, detected in heuristics:
        if detected:
            findings.append(
                Fingerprint(product, None, f"HTTP content contains {marker} markers", "low")
            )

    return merge_fingerprints(findings)


def detect_from_banner(banner):
    return merge_fingerprints(
        _fingerprints_from_pattern(
            banner,
            f"Service banner: {' '.join(banner.split())[:240]}",
            BANNER_PATTERNS,
            "high",
        )
    )


def merge_fingerprints(findings):
    """Keep the strongest fingerprint for each product."""
    merged = {}
    for finding in findings:
        existing = merged.get(finding.product)
        if existing is None:
            merged[finding.product] = finding
            continue

        existing_score = (
            1 if existing.version else 0,
            CONFIDENCE_ORDER.get(existing.confidence, 0),
        )
        new_score = (
            1 if finding.version else 0,
            CONFIDENCE_ORDER.get(finding.confidence, 0),
        )
        if new_score > existing_score:
            merged[finding.product] = finding

    return sorted(merged.values(), key=lambda item: item.product.lower())


def grade_from_eol(eol_date, as_of=None):
    as_of = as_of or date.today()
    days_unsupported = (as_of - eol_date).days

    if days_unsupported < 0:
        return Assessment("GOOD", f"Supported until {eol_date.isoformat()}", eol_date)
    if days_unsupported < 28:
        return Assessment(
            "FAIR",
            f"EOL {eol_date.isoformat()} ({days_unsupported} days ago; 28-day grace period)",
            eol_date,
        )
    if days_unsupported < 365:
        return Assessment(
            "WARN",
            f"EOL {eol_date.isoformat()} ({days_unsupported} days unsupported)",
            eol_date,
        )
    return Assessment(
        "BAD",
        f"EOL {eol_date.isoformat()} ({days_unsupported} days unsupported)",
        eol_date,
    )


def assess_fingerprint(fingerprint, as_of=None):
    as_of = as_of or date.today()
    product = fingerprint.product
    version = fingerprint.version

    if product == "Boa Webserver":
        return Assessment("BAD", "Boa has not received software updates since 2015")

    if not version:
        return Assessment("NEUTRAL", "Product detected, but its version was not exposed")

    if version in SUPPORTED_EXACT.get(product, set()):
        return Assessment("GOOD", "Version is listed as supported in the local catalogue")

    eol_date = EOL_DATES.get(product, {}).get(version)
    if eol_date:
        assessment = grade_from_eol(eol_date, as_of)
        if fingerprint.distribution_hint and product in BACKPORT_PRODUCTS and assessment.grade != "GOOD":
            return Assessment(
                "NEUTRAL",
                f"Upstream status is {assessment.grade}, but the {fingerprint.distribution_hint} "
                "package may contain backported fixes",
                eol_date,
            )
        return assessment

    oldest_catalogued = {
        "Apache": (2, 4, 57),
        "OpenSSH": (9, 3),
    }.get(product)
    if oldest_catalogued and _version_tuple(version) < oldest_catalogued:
        if fingerprint.distribution_hint:
            return Assessment(
                "NEUTRAL",
                f"The upstream version is older than BitSight's retained catalogue, but "
                f"the {fingerprint.distribution_hint} package may contain backported fixes",
            )
        return Assessment(
            "BAD",
            "The upstream version is older than BitSight's retained catalogue; the article "
            "removes versions that have been EOL for over one year",
        )

    if product == "NGINX":
        if fingerprint.distribution_hint:
            return Assessment(
                "NEUTRAL",
                f"{fingerprint.distribution_hint} package detected; backport status is unknown",
            )
        if _version_tuple(version) >= (1, 18, 0):
            return Assessment("GOOD", "BitSight lists NGINX 1.18.0 and later as supported")
        return Assessment("BAD", "BitSight lists NGINX versions before 1.18.0 as legacy")

    if product == "PHP":
        if version.startswith("7.3"):
            if fingerprint.distribution_hint:
                return Assessment(
                    "NEUTRAL",
                    f"PHP 7.3 is upstream-EOL, but {fingerprint.distribution_hint} backport status is unknown",
                )
            return Assessment("BAD", "PHP 7.3 security support ended on 2021-12-06")
        return Assessment(
            "NEUTRAL",
            "BitSight says PHP support depends on OS-vendor security updates",
        )

    if product == "Microsoft IIS" and version in {"8", "8.0", "8.5"}:
        return Assessment("BAD", "BitSight lists IIS 8/8.5 support ending in 2023")

    if product == "cPanel" and version == "76":
        return Assessment("BAD", "Version 76 is listed as unsupported")

    if product == "Embedthis Appweb" and _version_tuple(version)[:1] == (8,):
        return grade_from_eol(date(2023, 11, 1), as_of)

    if product == "Serv-U":
        major = _version_tuple(version)[:1]
        if major and major[0] < 14:
            return Assessment("BAD", "BitSight lists versions before 14 as unsupported")

    return Assessment(
        "NEUTRAL",
        "Version is not present in the dated local catalogue; support status was not guessed",
    )


def fetch_http(target, port):
    primary_scheme = "https" if port in HTTPS_LIKELY_PORTS else "http"
    fallback_scheme = "http" if primary_scheme == "https" else "https"
    errors = []

    for scheme in (primary_scheme, fallback_scheme):
        default_port = 443 if scheme == "https" else 80
        authority = target if port == default_port else f"{target}:{port}"
        url = f"{scheme}://{authority}"
        try:
            response = requests.get(
                url,
                timeout=10,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Aegis/1.1"},
            )
            return response, errors
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")

    return None, errors


def read_service_banner(target, port):
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(4)
            return sock.recv(4096).decode("utf-8", errors="replace").strip(), None
    except (OSError, TimeoutError) as exc:
        return "", str(exc)


def _print_assessment(fingerprint, assessment):
    version = fingerprint.version or "version unknown"
    message = f"{assessment.grade}: {fingerprint.product} {version} — {assessment.reason}"

    if assessment.grade == "GOOD":
        ok(message)
    elif assessment.grade == "BAD":
        bad(message)
    elif assessment.grade in {"FAIR", "WARN"}:
        warn(message)
    else:
        print(f"[+] {message}")


def format_server_software_evidence(
    target, port, response=None, errors=None, banner="", banner_error=None
):
    """Return the headers/banner used for fingerprinting and reference commands."""
    host = shlex.quote(str(target))
    lines = [
        "REPRODUCE MANUALLY",
        f"$ nmap -sV --script=http-headers -Pn -p {port} {host}",
    ]

    if port not in NON_HTTP_PORTS:
        scheme = "https" if port in HTTPS_LIKELY_PORTS else "http"
        default_port = 443 if scheme == "https" else 80
        authority = target if port == default_port else f"{target}:{port}"
        lines.append(f"$ curl -IL -k {shlex.quote(f'{scheme}://{authority}')}")
    if port in BANNER_PORTS:
        lines.append(f"$ nc -n -v {host} {port}")

    lines.extend(("", "CAPTURED BY AEGIS (passive fingerprinting)"))
    if response is not None:
        lines.extend(
            (
                f"HTTP endpoint: {response.url}",
                f"HTTP status: {response.status_code}",
                "",
                "HTTP RESPONSE HEADERS",
            )
        )
        for name, value in sorted(response.headers.items(), key=lambda item: item[0].lower()):
            lines.append(f"{name}: {value}")
    elif errors:
        lines.append("HTTP probe errors:")
        lines.extend(f"- {error}" for error in errors)

    if banner:
        lines.extend(("", "SERVICE BANNER", banner))
    elif banner_error:
        lines.extend(("", f"Service banner error: {banner_error}"))

    if response is None and not errors and not banner and not banner_error:
        lines.append("No passive HTTP or service-banner probe applies to this port.")

    return "\n".join(lines)


def run(target, target_type=None, port=443):
    print("=" * 50)
    print(" SERVER SOFTWARE")
    print(f" Target: {target}")
    print(f" Port: {port}")
    print(f" Catalogue: BitSight snapshot {CATALOG_UPDATED.isoformat()}")
    print("=" * 50)

    fingerprints = []
    response = None
    errors = []
    banner = ""
    banner_error = None

    print("\n[*] Passive Fingerprinting")
    if port not in NON_HTTP_PORTS:
        response, errors = fetch_http(target, port)
        if response is not None:
            print(f"    HTTP endpoint: {response.url} ({response.status_code})")
            fingerprints.extend(detect_from_http(response.headers, response.text))
        else:
            warn("No HTTP response received on this port")
            for error in errors:
                print(f"    {error}")

    if port in BANNER_PORTS:
        banner, banner_error = read_service_banner(target, port)
        if banner:
            print(f"    Service banner: {' '.join(banner.split())[:240]}")
            fingerprints.extend(detect_from_banner(banner))
        elif banner_error:
            warn(f"Unable to read a service banner: {banner_error}")

    fingerprints = merge_fingerprints(fingerprints)

    if not fingerprints:
        print(
            "[+] NEUTRAL: No BitSight-listed server software and version could be "
            "identified from passive evidence"
        )
        print("    The service may suppress its banner or sit behind a reverse proxy.")
        print("\n" + "=" * 50)
        return {
            "evidence": format_server_software_evidence(
                target, port, response, errors, banner, banner_error
            )
        }

    for fingerprint in fingerprints:
        version = fingerprint.version or "version unknown"
        print(
            f"    Detected: {fingerprint.product} {version} "
            f"(confidence: {fingerprint.confidence})"
        )
        print(f"      Evidence: {fingerprint.evidence}")

    print("\n[*] Support Assessment")
    for fingerprint in fingerprints:
        _print_assessment(fingerprint, assess_fingerprint(fingerprint))

    print("\n[*] Coverage Notes")
    print("    Fingerprints can be hidden or spoofed; reverse proxies may conceal origin software.")
    print("    Distribution backports and unexposed patch levels are reported as NEUTRAL.")
    catalogue_age = (date.today() - CATALOG_UPDATED).days
    if catalogue_age > 180:
        warn(f"The local support catalogue is {catalogue_age} days old and should be reviewed")
    print(f"    Catalogue source: {CATALOG_SOURCE}")
    print("\n" + "=" * 50)
    return {
        "evidence": format_server_software_evidence(
            target, port, response, errors, banner, banner_error
        )
    }
