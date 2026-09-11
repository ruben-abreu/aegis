import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import urllib3

try:
    from .hostnames import get_cert_identities
    from .terminal import capture_openssl_evidence
except ImportError:  # run directly rather than as part of the package
    from hostnames import get_cert_identities
    from terminal import capture_openssl_evidence

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; BOLD="\033[1m"; END="\033[0m"

def ok(msg): print(f"{GREEN}[✓]{END} {msg}")
def warn(msg): print(f"{YELLOW}[!]{END} {msg}")
def bad(msg): print(f"{RED}[✗]{END} {msg}")

# Above this many names on one certificate, a single stolen private key
# compromises an unreasonably large set of hosts at once.
MAX_SAN_ENTRIES = 25



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
    """BitSight certificate finding for expiration only.

    Future issuance and total duration belong to TLS/SSL Configurations.
    """
    print("\n[*] Certificate Expiration")

    _, not_after = cert_validity_dates(cert)
    now = datetime.now(timezone.utc)

    if now > not_after:
        bad(f"Certificate EXPIRED (expired {not_after.strftime('%Y-%m-%d %H:%M:%S')})")
        return False

    ok(f"Certificate is not expired (expires {not_after.strftime('%Y-%m-%d')})")
    return True


def check_expiry_horizon(cert):
    """Supplemental renewal warning; BitSight's listed finding is expiration."""
    print("\n[*] Renewal Horizon")
    _, not_after = cert_validity_dates(cert)
    now = datetime.now(timezone.utc)
    validity_days = (not_after - now).days

    if validity_days < 30:
        warn(f"Certificate expires soon ({validity_days} days remaining)")
    elif validity_days < 90:
        warn(f"Certificate expires in {validity_days} days; plan renewal")
    else:
        ok(f"Sufficient validity period ({validity_days} days remaining)")

    return True

def check_key_strength(cert):
    """BitSight certificate thresholds for RSA public keys."""
    print("\n[*] RSA Public Key Strength")

    try:
        pubkey = cert.public_key()
    except (TypeError, ValueError):
        warn("Unable to parse RSA key; malformed public keys are assessed in Configuration")
        return True

    if isinstance(pubkey, rsa.RSAPublicKey):
        key_size = pubkey.key_size
        if key_size >= 4096:
            ok(f"RSA Key: {key_size} bits (Strong)")
        elif key_size >= 2048:
            ok(f"RSA Key: {key_size} bits (Compliant)")
        elif key_size >= 1024:
            warn(f"RSA public key is less than 2048 bits ({key_size})")
            return False
        else:
            bad(f"RSA public key is less than 1024 bits ({key_size})")
            return False
    else:
        ok("No RSA certificate finding applies to this public key")

    return True

def check_signature_algorithm(cert):
    print("\n[*] Signature Algorithm")

    sig_algo = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    try:
        hash_algo = cert.signature_hash_algorithm
        hash_name = hash_algo.name.lower()
    except Exception:
        hash_algo = None
        hash_name = sig_algo.lower()

    if "md2" in hash_name or "md2" in sig_algo.lower():
        bad("Signature uses MD2 (insecure algorithm)")
        return False
    elif isinstance(hash_algo, hashes.MD5) or "md5" in hash_name:
        bad("Signature uses MD5 (insecure algorithm)")
        return False
    elif isinstance(hash_algo, hashes.SHA256):
        ok(f"Signature: {sig_algo} with SHA-256 (Modern & Secure)")
        return True
    elif isinstance(hash_algo, hashes.SHA384):
        ok(f"Signature: {sig_algo} with SHA-384 (Modern & Secure)")
        return True
    elif isinstance(hash_algo, hashes.SHA512):
        ok(f"Signature: {sig_algo} with SHA-512 (Modern & Secure)")
        return True
    elif isinstance(hash_algo, hashes.SHA1):
        bad("Signature uses SHA-1 (deprecated insecure algorithm)")
        return False
    else:
        warn(f"Signature algorithm requires review: {sig_algo} ({hash_name or 'unknown'})")
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
        subject = cert.subject.rfc4514_string().lower()
        if (
            "kubernetes ingress controller fake certificate" in subject
            or "ingress.local" in subject
        ):
            warn("Kubernetes Ingress self-signed certificate")
            warn("    -> Replace the default ingress certificate with a trusted certificate")
            return True
        warn("Self-signed certificate")
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


def check_ca_distrust(cert):
    """Flag the issuer families explicitly named in BitSight certificate findings."""
    print("\n[*] Certificate Authority Distrust")
    issuer = cert.issuer.rfc4514_string()
    issuer_lower = issuer.lower()
    not_before, _ = cert_validity_dates(cert)

    if "entrust" in issuer_lower and not_before >= datetime(
        2024, 12, 1, tzinfo=timezone.utc
    ):
        warn("Entrust certificate distrusted by Google and Mozilla")
        print(f"    Issuer: {issuer}")
        return False

    if "entrust" in issuer_lower and not_before >= datetime(
        2024, 11, 12, tzinfo=timezone.utc
    ):
        warn("Entrust certificate distrusted by Google and Mozilla")
        print(f"    Issuer: {issuer}")
        return False

    symantec_issuers = ("symantec", "verisign", "geotrust", "thawte", "rapidssl")
    if any(name in issuer_lower for name in symantec_issuers):
        warn("Legacy Symantec-family certificate may be distrusted by Chrome")
        print(f"    Issuer: {issuer}")
        return False

    ok("No listed Entrust or legacy Symantec distrust finding detected")
    return True


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
    evidence = capture_openssl_evidence(target, port)

    if cert is None:
        bad("Unable to retrieve certificate from target")
        return {"evidence": evidence}

    print(f"\n[+] Certificate retrieved successfully")
    if tls_version:
        print(f"[+] Connected via {tls_version}")

    print("\n[+] CERTIFICATE FINDINGS")
    check_validity(cert)
    check_key_strength(cert)
    check_signature_algorithm(cert)
    check_ca_distrust(cert)
    check_self_signed(cert)
    check_san_count(cert)

    print("\n[+] ADDITIONAL SECURITY CHECKS")
    check_expiry_horizon(cert)
    check_wildcard(cert)
    check_key_usage(cert)
    check_extended_key_usage(cert)

    print("\n" + "=" * 40)
    return {
        "evidence": evidence
    }
