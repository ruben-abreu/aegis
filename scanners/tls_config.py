import ssl
import socket
import requests
import subprocess
import shlex
import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec

try:
    from .hostnames import first_match, get_cert_identities, hostname_matches
except ImportError:  # run directly rather than as part of the package
    from hostnames import first_match, get_cert_identities, hostname_matches

_sslscan_cache = {}

def sslscan_output(host, port=443, timeout=60):
    """One sslscan run per target, shared by every check that needs it.

    Each check used to spawn its own sslscan; on a slow target the later ones
    timed out and reported failures the server was not actually responsible
    for. Cached per run, so adding checks costs nothing.
    """
    key = (host, port)
    if key in _sslscan_cache:
        return _sslscan_cache[key]

    cmd = ["sslscan", host] if port == 443 else ["sslscan", "--port", str(port), host]
    result = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
    output = result.stdout + result.stderr
    _sslscan_cache[key] = output
    return output

def reset_sslscan_cache():
    _sslscan_cache.clear()

requests.packages.urllib3.disable_warnings()

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; BOLD="\033[1m"; END="\033[0m"

def ok(msg): print(f"{GREEN}[✓]{END} {msg}")
def warn(msg): print(f"{YELLOW}[!]{END} {msg}")
def bad(msg): print(f"{RED}[✗]{END} {msg}")

WEAK_CIPHERS = [
    "DES", "RC4", "MD5", "NULL", "EXPORT", "anon", "ADH", "AECDH"
]

STRONG_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
]


def _openssl_authority(host, port):
    host = str(host)
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return shlex.quote(authority)


def capture_tls_handshake(host, port=443):
    """Capture the negotiated values used as raw evidence in the web UI."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cipher = ssock.cipher() or ("Unknown", "Unknown", 0)
            session = getattr(ssock, "session", None)
            return {
                "protocol": ssock.version() or "Unknown",
                "cipher": cipher[0],
                "cipher_protocol": cipher[1],
                "cipher_bits": cipher[2],
                "compression": ssock.compression() or "None",
                "session_ticket": bool(session and session.has_ticket),
                "certificate_der": ssock.getpeercert(binary_form=True),
            }


def _certificate_from_handshake(handshake):
    certificate_der = (handshake or {}).get("certificate_der")
    if not certificate_der:
        return None
    try:
        return x509.load_der_x509_certificate(certificate_der)
    except (TypeError, ValueError):
        return None


def _certificate_validity_dates(cert):
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None or not_after is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return not_before, not_after


def check_hostname_match(cert, host):
    """Check whether the peer certificate identifies the requested host."""
    print("\n[*] Certificate Name Match")

    if cert is None:
        warn("Unable to inspect certificate names from the TLS handshake")
        return False

    san_identities, common_name = get_cert_identities(cert)

    if san_identities:
        shown = san_identities[:8]
        suffix = (
            f", +{len(san_identities) - len(shown)} more"
            if len(san_identities) > len(shown)
            else ""
        )
        count_label = "entry" if len(san_identities) == 1 else "entries"
        print(
            f"    SAN ({len(san_identities)} {count_label}): "
            f"{', '.join(shown)}{suffix}"
        )
        if common_name:
            print(f"    CN: {common_name} (ignored: SAN is present)")

        matched = first_match(san_identities, host)
        if matched:
            ok(f"SAN entry '{matched}' matches {host}")
            return True

        warn(f"NAME MISMATCH: no SAN entry matches {host}")
        return False

    warn("No SAN extension present (deprecated; clients require SAN)")
    if not common_name:
        warn("NAME MISMATCH: certificate has neither SAN nor Common Name")
        return False

    print(f"    CN: {common_name}")
    if hostname_matches(common_name, host):
        ok(f"CN matches {host}, but the missing SAN will still be rejected")
        return True

    warn(f"NAME MISMATCH: CN '{common_name}' does not match {host}")
    return False


def check_certificate_timing(cert, now=None):
    """BitSight configuration findings for future and overlong certificates."""
    print("\n[*] Certificate Timing")

    if cert is None:
        warn("Unable to inspect certificate dates from the TLS handshake")
        return False

    not_before, not_after = _certificate_validity_dates(cert)
    now = now or datetime.now(timezone.utc)
    passed = True

    if now < not_before:
        bad(
            "Certificate was issued for a date in the future "
            f"({not_before.strftime('%Y-%m-%d %H:%M:%S UTC')})"
        )
        passed = False
    else:
        ok("Certificate is not future-dated")

    validity_days = (not_after - not_before).days
    if not_before >= datetime(2018, 3, 1, tzinfo=timezone.utc) and validity_days > 825:
        warn(
            "Certificate duration exceeds recommended practice "
            f"({validity_days} days; maximum 825)"
        )
        passed = False
    else:
        ok(f"Certificate duration does not exceed 825 days ({validity_days} days)")

    return passed


def check_certificate_structure(cert):
    """Detect a malformed certificate or public key after the TLS handshake."""
    print("\n[*] Certificate Structure")

    if cert is None:
        bad("Malformed certificate: the peer certificate could not be parsed")
        return False

    try:
        cert.public_key()
    except (TypeError, ValueError) as exc:
        bad(f"Malformed public key: {exc}")
        return False

    ok("Certificate and public key parsed successfully")
    return True


def check_configuration_public_key(cert):
    """BitSight configuration thresholds for DSA and elliptic-curve keys."""
    print("\n[*] DSA / Elliptic-Curve Public Key")

    if cert is None:
        warn("Unable to inspect the certificate public key")
        return False

    try:
        public_key = cert.public_key()
    except (TypeError, ValueError) as exc:
        bad(f"Malformed public key: {exc}")
        return False

    if isinstance(public_key, dsa.DSAPublicKey):
        if public_key.key_size < 2048:
            warn(f"DSA public key is less than 2048 bits ({public_key.key_size})")
            return False
        ok(f"DSA public key is at least 2048 bits ({public_key.key_size})")
        return True

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        key_size = public_key.curve.key_size
        if key_size < 224:
            bad(f"Elliptic curve public key is less than 224 bits ({key_size})")
            return False
        ok(f"Elliptic curve public key is at least 224 bits ({key_size})")
        return True

    ok("No DSA or elliptic-curve configuration finding applies")
    return True


def check_certificate_chain(host, port=443):
    """Use the platform trust store to identify chain or trust-anchor failures."""
    print("\n[*] Certificate Chain and Trust")
    context = ssl.create_default_context()
    context.check_hostname = False

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                ok("Certificate chain reaches a trusted root")
                return True
    except ssl.SSLCertVerificationError as exc:
        warn("Missing intermediate certificates or untrusted root anchor")
        print(f"    Verification detail: {exc.verify_message}")
        return False
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        warn(f"Unable to verify the certificate chain: {exc}")
        return False


def format_tls_config_evidence(
    host, port=443, handshake=None, sslscan_raw=None, error=None
):
    """Format actual TLS probe values without presenting them as OpenSSL output."""
    authority = _openssl_authority(host, port)
    server_name = shlex.quote(str(host))
    sslscan_command = (
        f"sslscan {shlex.quote(str(host))}"
        if port == 443
        else f"sslscan --port {port} {shlex.quote(str(host))}"
    )
    lines = [
        "REPRODUCE MANUALLY",
        (
            f"$ openssl s_client -connect {authority} -servername {server_name} "
            "-brief </dev/null"
        ),
        (
            f"$ openssl s_client -connect {authority} -servername {server_name} "
            "-showcerts -verify_return_error </dev/null"
        ),
        (
            f"$ openssl s_client -connect {authority} -servername {server_name} "
            "</dev/null 2>/dev/null | openssl x509 -noout -subject "
            "-ext subjectAltName"
        ),
        f"$ {sslscan_command}",
        "",
        "CAPTURED BY AEGIS (Python TLS handshake)",
        f"Endpoint: {host}:{port}",
    ]

    if handshake:
        lines.extend(
            (
                f"Negotiated protocol: {handshake['protocol']}",
                f"Negotiated cipher: {handshake['cipher']}",
                f"Cipher protocol: {handshake['cipher_protocol']}",
                f"Cipher strength: {handshake['cipher_bits']} bits",
                f"TLS compression: {handshake['compression']}",
                (
                    "Session ticket on initial handshake: "
                    f"{'yes' if handshake['session_ticket'] else 'no'}"
                ),
            )
        )
        cert = _certificate_from_handshake(handshake)
        if cert is not None:
            san_identities, common_name = get_cert_identities(cert)
            not_before, not_after = _certificate_validity_dates(cert)
            try:
                public_key = cert.public_key()
                if isinstance(public_key, dsa.DSAPublicKey):
                    key_description = f"DSA ({public_key.key_size} bits)"
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_description = (
                        f"ECDSA ({public_key.curve.name}, "
                        f"{public_key.curve.key_size} bits)"
                    )
                else:
                    key_description = type(public_key).__name__
            except (TypeError, ValueError) as exc:
                key_description = f"unable to parse ({exc})"
            lines.extend(
                (
                    f"Certificate common name: {common_name or 'not present'}",
                    "Certificate SAN identities: "
                    + (", ".join(san_identities) if san_identities else "not present"),
                    f"Certificate notBefore: {not_before.isoformat()}",
                    f"Certificate notAfter: {not_after.isoformat()}",
                    f"Certificate validity span: {(not_after - not_before).days} days",
                    f"Certificate public key: {key_description}",
                )
            )
    elif error:
        lines.append(f"Handshake error: {error}")

    lines.extend(("", "RAW SSLSCAN OUTPUT"))
    if sslscan_raw:
        lines.append(sslscan_raw.strip())
    else:
        lines.append("Not captured. Extended cipher and TLS checks were not run or sslscan failed.")

    return "\n".join(lines)

def check_tls_versions(host, port=443):
    print("\n[*] TLS Version Support")

    versions_to_check = [
        ("TLSv1.3", True),
        ("TLSv1.2", True),
        ("TLSv1.1", False),
        ("TLSv1.0", False),
        ("SSLv2", False),
        ("SSLv3", False),
    ]

    supported = []
    insecure_found = []

    try:
        output = sslscan_output(host, port)

        for version_name, is_modern in versions_to_check:
            if f"{version_name}" in output:
                if "enabled" in output.split(version_name)[1].split("\n")[0].lower():
                    supported.append((version_name, is_modern))
                    if is_modern:
                        ok(f"{version_name} supported")
                    else:
                        bad(f"{version_name} supported (deprecated protocol)")
                        insecure_found.append(version_name)
                else:
                    if not is_modern:
                        ok(f"{version_name} NOT supported")

    except subprocess.TimeoutExpired:
        bad("sslscan timed out - unable to test TLS versions")
        return
    except FileNotFoundError:
        warn("sslscan not found - install with: brew install sslscan")
        return
    except Exception as e:
        warn(f"Unable to test TLS versions: {e}")
        return

    if not supported:
        bad("Unable to determine supported TLS versions")
        return

    modern_versions = [v for v, modern in supported if modern]

    if not modern_versions:
        bad("No modern TLS versions (1.2+) detected")
        return

    if insecure_found:
        bad(f"CRITICAL: Insecure protocols enabled: {', '.join(insecure_found)}")
        warn("These versions are vulnerable and must be disabled immediately")
    else:
        ok("Only modern TLS versions supported (1.2+)")

def check_cipher_suites(host, port=443):
    print("\n[*] Cipher Suite Analysis")

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else "Unknown"
                cipher_version = cipher[1] if len(cipher) > 1 else "Unknown"

                print(f"    Active Cipher: {cipher_name}")
                print(f"    Protocol: {cipher_version}")

                is_strong = any(strong in cipher_name for strong in STRONG_CIPHERS)
                is_weak = any(weak in cipher_name.upper() for weak in WEAK_CIPHERS)

                if is_weak:
                    bad(f"Weak cipher detected: {cipher_name}")
                    return False
                elif is_strong:
                    ok(f"Strong cipher in use: {cipher_name}")
                    return True
                elif "GCM" in cipher_name or "POLY1305" in cipher_name or "ChaCha" in cipher_name:
                    ok(f"Modern AEAD cipher: {cipher_name}")
                    return True
                else:
                    warn(f"Cipher strength unclear: {cipher_name}")
                    return True

    except Exception as e:
        warn(f"Unable to analyze cipher suite: {e}")
        return False

def check_hsts_header(host, port=443):
    print("\n[*] HSTS (HTTP Strict-Transport-Security)")

    try:
        url = f"https://{host}:{port}" if port != 443 else f"https://{host}"
        response = requests.get(
            url,
            timeout=10,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Aegis/0.7"}
        )

        hsts_header = response.headers.get("Strict-Transport-Security")

        if hsts_header:
            ok(f"HSTS enabled: {hsts_header}")

            max_age = None
            try:
                max_age = int(hsts_header.split("max-age=")[1].split(";")[0])
                if max_age >= 31536000:
                    ok(f"HSTS max-age is strong ({max_age} seconds / 1 year+)")
                elif max_age >= 10886400:
                    warn(f"HSTS max-age is moderate ({max_age} seconds / ~18 weeks)")
                else:
                    warn(f"HSTS max-age is weak ({max_age} seconds)")
            except (IndexError, ValueError):
                pass

            if "includeSubDomains" in hsts_header or "includeSubdomains" in hsts_header:
                ok("HSTS applies to subdomains")
            else:
                warn("HSTS does not include subdomains")

            if "preload" in hsts_header:
                ok("HSTS preload enabled")

            return True
        else:
            bad("HSTS header NOT present")
            return False

    except Exception as e:
        warn(f"Unable to check HSTS header: {e}")
        return False

def check_ssl_compression(host, port=443):
    print("\n[*] SSL/TLS Compression")

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                compression = ssock.compression()

                if compression:
                    bad(f"TLS compression enabled ({compression}) - Vulnerable to CRIME attack")
                    return False
                else:
                    ok("TLS compression disabled")
                    return True

    except Exception as e:
        warn(f"Unable to determine compression status: {e}")
        return False

def check_session_resumption(host, port=443):
    print("\n[*] Session Resumption")

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                session = ssock.session

                if session and session.has_ticket:
                    ok("Session resumption (tickets) supported")
                    return True
                elif session:
                    ok("Session resumption (cache) supported")
                    return True
                else:
                    warn("Session resumption not detected")
                    return False

    except Exception as e:
        warn(f"Unable to check session resumption: {e}")
        return False

def check_forward_secrecy(host, port=443):
    print("\n[*] Forward Secrecy (Perfect Forward Secrecy)")

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                protocol_version = ssock.version()
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else ""

                if "1.3" in protocol_version or "TLS_AES" in cipher_name:
                    ok(f"Forward Secrecy inherent in TLSv1.3: {cipher_name}")
                    return True
                elif "ECDHE" in cipher_name or "DHE" in cipher_name:
                    ok(f"Forward Secrecy enabled: {cipher_name}")
                    return True
                else:
                    bad(f"Forward Secrecy NOT detected: {cipher_name}")
                    return False

    except Exception as e:
        warn(f"Unable to check forward secrecy: {e}")
        return False

def check_secure_renegotiation(host, port=443):
    print("\n[*] Secure Renegotiation")

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                if hasattr(ssock, 'verify_client_post_handshake'):
                    ok("Secure renegotiation extension supported")
                    return True
                else:
                    warn("Unable to verify secure renegotiation support")
                    return False

    except Exception as e:
        warn(f"Unable to check renegotiation: {e}")
        return False

def check_protocol_downgrade_protection(host, port=443):
    print("\n[*] Protocol Downgrade Protection")

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                protocol_version = ssock.version()

                if protocol_version == "TLSv1.3":
                    ok("TLSv1.3 enforces best security practices")
                    return True
                elif protocol_version == "TLSv1.2":
                    ok("TLSv1.2 - Good, but TLSv1.3 preferred")
                    return True
                else:
                    warn(f"Using {protocol_version} - Consider upgrading to TLSv1.3")
                    return False

    except Exception as e:
        warn(f"Unable to check protocol version: {e}")
        return False


def check_export_ciphers(host, port=443):
    print("\n[*] Export Cipher Acceptance")
    try:
        output = sslscan_output(host, port)
        accepted = []
        for line in output.splitlines():
            lowered = line.lower()
            looks_like_suite = any(
                marker in lowered
                for marker in ("exp-", "_export_", "export40", "export56")
            )
            if "export" not in lowered and not looks_like_suite:
                continue
            if any(word in lowered for word in ("disabled", "rejected", "not accepted")):
                continue
            if "accepted" in lowered or "enabled" in lowered or looks_like_suite:
                accepted.append(line.strip())

        if accepted:
            bad("Allows insecure cipher: Export Ciphers")
            for line in accepted[:5]:
                print(f"    {line}")
            return False

        ok("No accepted export cipher suites reported")
        return True
    except Exception as exc:
        warn(f"Unable to assess export ciphers: {exc}")
        return False


def check_common_dh_parameters(host, port=443):
    print("\n[*] Common Diffie-Hellman Parameters")
    try:
        output = sslscan_output(host, port)
        findings = []
        explicit_safe_result = False
        for line in output.splitlines():
            lowered = line.lower()
            if "common" not in lowered:
                continue
            if "dh" not in lowered and "diffie-hellman" not in lowered:
                continue
            if "not common" in lowered or "no common" in lowered:
                explicit_safe_result = True
                continue
            findings.append(line.strip())

        if findings:
            bad("Diffie-Hellman prime or public key is very commonly used")
            for line in findings[:5]:
                print(f"    {line}")
            return False

        if explicit_safe_result:
            ok("Diffie-Hellman parameters are not reported as commonly reused")
            return True

        warn("sslscan did not report whether Diffie-Hellman parameters are commonly reused")
        return False
    except Exception as exc:
        warn(f"Unable to assess common Diffie-Hellman parameters: {exc}")
        return False


def check_heartbleed(host, port=443):
    print("\n[*] Heartbleed")
    try:
        output = sslscan_output(host, port)
        lines = [line.strip() for line in output.splitlines() if "heartbleed" in line.lower()]
        if not lines:
            warn("sslscan did not report a Heartbleed result")
            return False

        lowered = " ".join(lines).lower()
        if "not vulnerable" in lowered or "not affected" in lowered:
            ok("Server is not reported as vulnerable to Heartbleed")
            return True
        if "vulnerable" in lowered:
            bad("Vulnerable to Heartbleed")
            for line in lines[:3]:
                print(f"    {line}")
            return False

        warn(f"Unclear Heartbleed result: {lines[0]}")
        return False
    except Exception as exc:
        warn(f"Unable to assess Heartbleed: {exc}")
        return False


def check_dh_strength(host, port=443):
    print("\n[*] Diffie-Hellman (DH) Key Strength")

    try:
        output = sslscan_output(host, port)

        finite_field_sizes = []
        for raw_line in output.splitlines():
            line = re.sub(r"\x1b\[[0-9;]*m", "", raw_line)
            upper = line.upper()
            # ECDHE values such as "DHE 253" describe an elliptic-curve
            # exchange and must not be graded as a finite-field DH prime.
            if "ECDHE" in upper:
                continue
            finite_field_sizes.extend(
                int(size)
                for size in re.findall(r"\b(?:DHE|DH)\s+(\d{3,5})\b", upper)
            )
            finite_field_sizes.extend(
                int(size) for size in re.findall(r"\bFFDHE(\d{3,5})\b", upper)
            )

        if not finite_field_sizes:
            ok("No finite-field DHE suites reported")
            return True

        weakest = min(finite_field_sizes)
        if weakest < 512:
            bad(f"Diffie-Hellman prime is less than 512 bits ({weakest})")
            return False
        if weakest < 1024:
            bad(f"Diffie-Hellman prime is less than 1024 bits ({weakest})")
            return False
        if weakest < 2048:
            warn(f"Diffie-Hellman prime is less than 2048 bits ({weakest})")
            return False

        ok(f"Finite-field Diffie-Hellman prime is at least 2048 bits ({weakest})")
        return True

    except Exception as e:
        warn(f"Unable to check DH strength: {e}")
        return False

def should_check_ciphers(check_ciphers=None, interactive=True):
    """Resolve whether the optional, slower sslscan checks should run."""
    if check_ciphers is not None:
        return bool(check_ciphers)

    if not interactive:
        return False

    try:
        answer = input(
            "\nRun extended export-cipher, DH, Heartbleed and TLS version "
            "checks with sslscan? "
            "This can take up to a minute. [y/N]: "
        ).strip().lower()
    except EOFError:
        return False

    return answer in ("y", "yes")


def run(target, target_type=None, port=443, check_ciphers=None, interactive=True):
    print("=" * 40)
    print(" TLS/SSL CONFIGURATION")
    print(f" Target: {target}")
    print(f" Port: {port}")
    print("=" * 40)

    try:
        handshake = capture_tls_handshake(target, port)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        bad(f"Unable to connect to {target}:{port}")
        return {
            "evidence": format_tls_config_evidence(
                target, port=port, error=str(exc)
            )
        }

    print(f"\n[+] Connection successful")

    # Fresh sslscan data per run. The cache is only populated if the user opts
    # into the extended checks at the end of the scan.
    reset_sslscan_cache()

    certificate = _certificate_from_handshake(handshake)

    print("\n[+] CONFIGURATION FINDINGS")
    check_hostname_match(certificate, target)
    check_certificate_timing(certificate)
    check_certificate_structure(certificate)
    check_configuration_public_key(certificate)
    check_certificate_chain(target, port)

    print("\n[+] ADDITIONAL SECURITY CHECKS")
    check_forward_secrecy(target, port)
    check_hsts_header(target, port)
    check_ssl_compression(target, port)
    check_session_resumption(target, port)
    check_secure_renegotiation(target, port)
    check_protocol_downgrade_protection(target, port)

    print("\n[*] Optional Extended Scan")
    run_extended = should_check_ciphers(check_ciphers, interactive)
    if run_extended:
        print("    Running sslscan checks; this may take up to a minute...")
        print("\n[+] OPTIONAL ADDITIONAL CIPHER CONTEXT")
        check_cipher_suites(target, port)

        print("\n[+] OPTIONAL EXTENDED FINDINGS")
        check_export_ciphers(target, port)
        check_dh_strength(target, port)
        check_common_dh_parameters(target, port)
        check_heartbleed(target, port)
        # Keep the slow TLS version enumeration as the final test.
        check_tls_versions(target, port)
    else:
        warn("Extended cipher, DH, Heartbleed and TLS version checks skipped")

    print("\n" + "=" * 40)
    return {
        "evidence": format_tls_config_evidence(
            target,
            port=port,
            handshake=handshake,
            sslscan_raw=_sslscan_cache.get((target, port)) if run_extended else None,
        )
    }
