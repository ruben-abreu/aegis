import ssl
import socket
import shlex
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import urllib3

try:
    from .hostnames import get_cert_identities, is_ip_address
except ImportError:  # run directly rather than as part of the package
    from hostnames import get_cert_identities, is_ip_address

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; BOLD="\033[1m"; END="\033[0m"

def ok(msg): print(f"{GREEN}[✓]{END} {msg}")
def warn(msg): print(f"{YELLOW}[!]{END} {msg}")
def bad(msg): print(f"{RED}[✗]{END} {msg}")

# Above this many names on one certificate, a single stolen private key
# compromises an unreasonably large set of hosts at once.
MAX_SAN_ENTRIES = 25


def _openssl_authority(host, port):
    host = str(host)
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return shlex.quote(authority)


def format_certificate_evidence(cert, host, port=443, tls_version=None):
    """Return reproducible certificate evidence from the certificate we parsed.

    The right-hand UI pane must not pretend that Python-generated fields are
    literal OpenSSL output. It therefore shows the equivalent command first,
    followed by the values captured by Aegis from the same TLS certificate.
    """
    authority = _openssl_authority(host, port)
    server_name = shlex.quote(str(host))
    lines = [
        "REPRODUCE MANUALLY",
        f"$ openssl s_client -connect {authority} -servername {server_name} "
        "</dev/null 2>/dev/null | \\",
        "  openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256 \\",
        "  -ext subjectAltName",
        "",
        "CAPTURED BY AEGIS (Python TLS probe)",
        f"Endpoint: {host}:{port}",
        f"Negotiated protocol: {tls_version or 'unknown'}",
        f"Subject: {cert.subject.rfc4514_string()}",
        f"Issuer: {cert.issuer.rfc4514_string()}",
    ]

    not_before, not_after = cert_validity_dates(cert)
    lines.extend(
        (
            f"notBefore={not_before.strftime('%b %d %H:%M:%S %Y GMT')}",
            f"notAfter={not_after.strftime('%b %d %H:%M:%S %Y GMT')}",
            f"serial={cert.serial_number:X}",
            f"SHA256 Fingerprint={cert.fingerprint(hashes.SHA256()).hex(':').upper()}",
        )
    )

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        lines.append(f"Public Key: RSA ({public_key.key_size} bits)")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        lines.append(
            f"Public Key: ECDSA ({public_key.curve.name}, {public_key.curve.key_size} bits)"
        )
    else:
        lines.append(f"Public Key: {type(public_key).__name__}")

    identities, _ = get_cert_identities(cert)
    lines.extend(("", "X509v3 Subject Alternative Name:"))
    if identities:
        formatted = [
            f"IP Address:{identity}" if is_ip_address(identity) else f"DNS:{identity}"
            for identity in identities
        ]
        lines.append("    " + ", ".join(formatted))
    else:
        lines.append("    Not present")

    return "\n".join(lines)

def get_certificate(host, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert)
                return cert, ssock.version()
    except Exception as e:
        print(f"{RED}[!] Unable to retrieve certificate: {e}{END}")
        return None, None

def cert_validity_dates(cert):
    """Returns (not_before, not_after) as timezone-aware UTC datetimes.

    The *_utc properties only exist on cryptography >= 42; older versions
    return naive datetimes from the non-suffixed properties.
    """
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)

    if not_before is None or not_after is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    return not_before, not_after

def check_validity(cert):
    print("\n[*] Certificate Validity")

    not_before, not_after = cert_validity_dates(cert)
    now = datetime.now(timezone.utc)

    if now < not_before:
        bad(f"Certificate not yet valid (starts {not_before.strftime('%Y-%m-%d %H:%M:%S')})")
        return False

    if now > not_after:
        bad(f"Certificate EXPIRED (expired {not_after.strftime('%Y-%m-%d %H:%M:%S')})")
        return False

    ok(f"Valid from {not_before.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')}")

    validity_days = (not_after - now).days

    if validity_days < 30:
        warn(f"Certificate expires soon ({validity_days} days remaining)")
    elif validity_days < 90:
        warn(f"Certificate expires in {validity_days} days (renew within 30 days)")
    else:
        ok(f"Sufficient validity period ({validity_days} days remaining)")

    validity_span = (not_after - not_before).days
    if validity_span > 365:
        warn(f"Certificate validity period is long ({validity_span} days). Prefer 1-year certificates.")

    return True

def check_key_strength(cert):
    print("\n[*] Key Strength & Algorithm")

    pubkey = cert.public_key()

    if isinstance(pubkey, rsa.RSAPublicKey):
        key_size = pubkey.key_size
        if key_size >= 4096:
            ok(f"RSA Key: {key_size} bits (Strong)")
        elif key_size >= 2048:
            ok(f"RSA Key: {key_size} bits (Compliant)")
        else:
            bad(f"RSA Key: {key_size} bits (WEAK - Below 2048 bits minimum)")
            return False

    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        key_size = pubkey.curve.key_size
        if key_size >= 256:
            ok(f"ECDSA Key: {key_size} bits (Strong)")
        else:
            bad(f"ECDSA Key: {key_size} bits (WEAK - Below 256 bits minimum)")
            return False
    else:
        warn(f"Unsupported key type: {type(pubkey).__name__}")
        return False

    return True

def check_signature_algorithm(cert):
    print("\n[*] Signature Algorithm")

    sig_algo = cert.signature_algorithm_oid._name
    hash_algo = cert.signature_hash_algorithm

    if isinstance(hash_algo, hashes.SHA256):
        ok(f"Signature: {sig_algo} with SHA-256 (Modern & Secure)")
        return True
    elif isinstance(hash_algo, hashes.SHA384):
        ok(f"Signature: {sig_algo} with SHA-384 (Modern & Secure)")
        return True
    elif isinstance(hash_algo, hashes.SHA512):
        ok(f"Signature: {sig_algo} with SHA-512 (Modern & Secure)")
        return True
    elif isinstance(hash_algo, hashes.SHA1):
        bad(f"Signature uses SHA-1 (DEPRECATED - Bitsight Rule Violation)")
        return False
    else:
        warn(f"Signature: {sig_algo} with {hash_algo.name}")
        return True

def check_san_count(cert):
    """Flags certificates covering an excessive number of names.

    A large SAN list means one shared key protects many unrelated hosts, so a
    single key compromise or mis-issuance takes all of them down together, and
    any one of those hosts can impersonate the rest.
    """
    print("\n[*] Certificate Scope (SAN count)")

    identities, _ = get_cert_identities(cert)
    total = len(identities)

    if total == 0:
        warn("No SAN entries to count")
        return False

    wildcards = sum(1 for name in identities if name.startswith("*."))
    detail = f"{total} name{'' if total == 1 else 's'} on this certificate"
    if wildcards:
        detail += f" ({wildcards} wildcard)"
    print(f"    {detail}")

    if total > MAX_SAN_ENTRIES:
        warn(f"EXCESSIVE SCOPE: {total} SAN entries (limit {MAX_SAN_ENTRIES})")
        warn("    -> One shared key covers many hosts; a single compromise affects them all")
        return False

    ok(f"SAN count within limit ({total}/{MAX_SAN_ENTRIES})")
    return True

def check_wildcard(cert):
    print("\n[*] Wildcard Certificate Check")

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName) and name.value.startswith("*."):
                warn(f"Wildcard certificate detected: {name.value}")
                warn("    -> Reduces security posture (compromise affects all subdomains)")
                return True
    except x509.ExtensionNotFound:
        pass

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn.startswith("*."):
            warn(f"Wildcard CN detected: {cn}")
            return True
    except (IndexError, AttributeError):
        pass

    ok("Non-wildcard certificate (better security posture)")
    return False

def check_self_signed(cert):
    print("\n[*] Self-Signed Certificate")

    if cert.issuer == cert.subject:
        bad("Certificate is SELF-SIGNED (Bitsight Grade Impact: CRITICAL)")
        warn("    -> Not trusted by major CAs, indicates misconfiguration or test environment")
        return True
    else:
        ok("Issued by trusted CA (not self-signed)")
        issuer_cn = None
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            print(f"    Issuer: {issuer_cn}")
        except (IndexError, AttributeError):
            pass
        return False


def check_key_usage(cert):
    print("\n[*] Key Usage Extension")

    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        ku = ku_ext.value

        usages = []
        if ku.digital_signature:
            usages.append("Digital Signature")
        if ku.key_encipherment:
            usages.append("Key Encipherment")
        if ku.content_commitment:
            usages.append("Content Commitment")
        if ku.data_encipherment:
            usages.append("Data Encipherment")
        if ku.key_agreement:
            usages.append("Key Agreement")
        if ku.key_cert_sign:
            usages.append("Key Cert Sign")
        if ku.crl_sign:
            usages.append("CRL Sign")

        try:
            if ku.encipher_only:
                usages.append("Encipher Only")
        except ValueError:
            pass

        try:
            if ku.decipher_only:
                usages.append("Decipher Only")
        except ValueError:
            pass

        if usages:
            ok(f"Allowed uses: {', '.join(usages)}")
        else:
            warn("No key usages defined")

        if not ku.digital_signature:
            bad("Digital Signature not allowed (required for TLS)")
            return False

        return True

    except x509.ExtensionNotFound:
        warn("Key Usage extension not present")
        return False

def check_extended_key_usage(cert):
    print("\n[*] Extended Key Usage (EKU)")

    try:
        eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        ekus = eku_ext.value

        has_tls_server = False
        for eku in ekus:
            if eku._name == "serverAuth":
                has_tls_server = True

        if has_tls_server:
            ok("Certificate authorized for TLS server authentication")
        else:
            bad("Certificate NOT authorized for TLS server use")
            return False

        return True

    except x509.ExtensionNotFound:
        warn("EKU extension not present (unrestricted usage)")
        return False

def run(target, target_type=None, port=443):
    print("=" * 40)
    print(" TLS/SSL CERTIFICATE SECURITY")
    print(f" Target: {target}")
    print(f" Port: {port}")
    print("=" * 40)

    cert, tls_version = get_certificate(target, port)

    if cert is None:
        bad("Unable to retrieve certificate from target")
        return {"evidence": "No certificate evidence was captured."}

    print(f"\n[+] Certificate retrieved successfully")
    if tls_version:
        print(f"[+] Connected via {tls_version}")

    check_validity(cert)
    check_key_strength(cert)
    check_signature_algorithm(cert)
    check_self_signed(cert)
    check_wildcard(cert)
    check_san_count(cert)
    check_key_usage(cert)
    check_extended_key_usage(cert)

    print("\n" + "=" * 40)
    return {
        "evidence": format_certificate_evidence(
            cert, target, port=port, tls_version=tls_version
        )
    }
