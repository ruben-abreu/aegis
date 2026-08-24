import ssl
import socket
import re
from urllib.parse import urlparse
import requests
import subprocess

try:
    from .hostnames import hostname_matches, first_match
except ImportError:  # run directly rather than as part of the package
    from hostnames import hostname_matches, first_match

ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')

# Above this many names on one certificate, a single stolen private key
# compromises an unreasonably large set of hosts at once.
MAX_SAN_ENTRIES = 25

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

def check_tls_versions(host, port=443):
    print("\n[*] TLS Version Support")

    versions_to_check = [
        ("TLSv1.3", True),
        ("TLSv1.2", True),
        ("TLSv1.1", False),
        ("TLSv1.0", False),
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
                        bad(f"{version_name} supported (BITSIGHT RULE VIOLATION - DEPRECATED)")
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

def parse_sslscan_identities(output):
    """Pulls (san_identities, subject_cn) out of sslscan's certificate block.

    Matched on the line prefix rather than a substring anywhere in the line, so
    an unrelated line mentioning 'DNS:' cannot overwrite the real SAN list.
    """
    san_identities = []
    subject_cn = None

    for raw_line in output.split("\n"):
        line = ANSI_ESCAPE.sub('', raw_line).strip()

        if line.startswith("Subject:"):
            subject_cn = line.split(":", 1)[1].strip() or None

        elif line.startswith("Altnames:"):
            entries = line.split(":", 1)[1].strip()
            for entry in entries.split(","):
                entry = entry.strip()
                for prefix in ("DNS:", "IP Address:", "IP:"):
                    if entry.startswith(prefix):
                        entry = entry[len(prefix):].strip()
                        break
                if entry:
                    san_identities.append(entry)

    return san_identities, subject_cn

def check_certificate_match(host, port=443):
    """Does the presented certificate identify this host?

    RFC 6125: a present SAN extension is authoritative and the Common Name is
    ignored. Checking them independently flags a mismatch on valid
    certificates whose CN names some other host in the same deployment.
    """
    print("\n[*] Certificate Hostname Match")

    try:
        san_identities, subject_cn = parse_sslscan_identities(sslscan_output(host, port))

        if san_identities:
            shown = san_identities[:8]
            print(f"    SAN ({len(san_identities)}): {', '.join(shown)}"
                  + (f", +{len(san_identities) - len(shown)} more" if len(san_identities) > len(shown) else ""))
            if subject_cn:
                print(f"    CN: {subject_cn} (ignored: SAN is present)")

            matched = first_match(san_identities, host)
            if matched:
                ok(f"SAN entry '{matched}' matches {host}")
                return True

            bad(f"NAME MISMATCH: no SAN entry matches {host}")
            return False

        if not subject_cn:
            warn("Could not read certificate identities from sslscan output")
            return False

        warn("No SAN extension present (deprecated; clients require SAN)")
        print(f"    CN: {subject_cn}")
        if hostname_matches(subject_cn, host):
            ok(f"CN matches {host}, but the missing SAN will still be rejected")
            return True

        bad(f"NAME MISMATCH: CN '{subject_cn}' does not match {host}")
        return False

    except Exception as e:
        warn(f"Unable to check certificate match: {e}")
        return False

def check_san_count(host, port=443):
    """Flags certificates covering an excessive number of names.

    A large SAN list means one shared key protects many unrelated hosts, so a
    single key compromise or mis-issuance takes all of them down together, and
    any one of those hosts can impersonate the rest.
    """
    print("\n[*] Certificate Scope (SAN count)")

    try:
        san_identities, _ = parse_sslscan_identities(sslscan_output(host, port))
        total = len(san_identities)

        if total == 0:
            warn("No SAN entries found to count")
            return False

        wildcards = sum(1 for name in san_identities if name.startswith("*."))
        detail = f"{total} name{'' if total == 1 else 's'} on this certificate"
        if wildcards:
            detail += f" ({wildcards} wildcard)"
        print(f"    {detail}")

        if total > MAX_SAN_ENTRIES:
            bad(f"EXCESSIVE SCOPE: {total} SAN entries (limit {MAX_SAN_ENTRIES})")
            warn("    -> One shared key covers many hosts; a single compromise affects them all")
            return False

        ok(f"SAN count within limit ({total}/{MAX_SAN_ENTRIES})")
        return True

    except Exception as e:
        warn(f"Unable to check SAN count: {e}")
        return False

def check_dh_strength(host, port=443):
    print("\n[*] Diffie-Hellman (DH) Key Strength")

    try:
        output = sslscan_output(host, port)

        dh_found = False
        weak_dh = False

        for line in output.split("\n"):
            if "DHE" in line or "DH" in line.upper():
                dh_found = True
                if "DHE 1024" in line or "DH 512" in line or "DH 1024" in line:
                    bad(f"Weak DH detected: {line.strip()}")
                    weak_dh = True
                elif "DHE 2048" in line or "DH 2048" in line:
                    ok(f"Acceptable DH: {line.strip()}")
                elif "DHE 4096" in line or "DH 4096" in line or "DHE" in line:
                    ok(f"Strong DH: {line.strip()}")

            if "Server Key Exchange" in line or "secp" in line or "P-256" in line:
                if "secp256r1" in line or "P-256" in line:
                    ok("Using ECDHE (elliptic curve) - strong key exchange")

        if weak_dh:
            bad("CRITICAL: Weak DH vulnerable to LOGJAM attack")
            return False
        elif dh_found:
            ok("DH key strength is acceptable")
            return True
        else:
            warn("Could not determine DH strength")
            return False

    except Exception as e:
        warn(f"Unable to check DH strength: {e}")
        return False

def run(target, target_type=None, port=443):
    print("=" * 40)
    print(" TLS/SSL CONFIGURATION")
    print(f" Target: {target}")
    print(f" Port: {port}")
    print("=" * 40)

    try:
        socket.create_connection((target, port), timeout=5).close()
    except (socket.error, TimeoutError):
        bad(f"Unable to connect to {target}:{port}")
        return

    print(f"\n[+] Connection successful")

    # Fresh sslscan data per run, then shared across the checks below.
    reset_sslscan_cache()

    check_tls_versions(target, port)
    check_cipher_suites(target, port)
    check_certificate_match(target, port)
    check_san_count(target, port)
    check_dh_strength(target, port)
    check_forward_secrecy(target, port)
    check_hsts_header(target, port)
    check_ssl_compression(target, port)
    check_session_resumption(target, port)
    check_secure_renegotiation(target, port)
    check_protocol_downgrade_protection(target, port)

    print("\n" + "=" * 40)
