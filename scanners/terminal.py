"""Bounded, shell-free collection of real command output for technical evidence."""
import re
import shlex
import subprocess
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


def _text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return value or ''


def command_output(args, input_text=None, timeout=12):
    """Merge stderr at the source so verification errors retain terminal ordering."""
    options = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                   text=True, encoding='utf-8', errors='replace', timeout=timeout)
    if input_text is None:
        options['stdin'] = subprocess.DEVNULL
    else:
        options['input'] = input_text
    try:
        result = subprocess.run(args, **options)
        output = _text(result.stdout)
        if result.returncode and not output:
            return f'# {args[0]} exited with code {result.returncode}; no output returned.\n'
        return output
    except subprocess.TimeoutExpired as exc:
        # Python may provide bytes here even with text=True. Never discard
        # a verification error emitted before a slow connection timed out.
        return _text(exc.stdout) + f'\n# Command timed out after {timeout}s.\n'
    except OSError as exc:
        return f'# Cannot run {args[0]}: {exc}\n'


def capture_openssl_handshake(host, port=443):
    """Return evidence and assessed values from one and the same TLS connection.

    A verification code of zero alone is not success: s_client can print it
    after a reset without receiving any certificate or negotiating a cipher.
    """
    host = str(host)
    authority = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    args = ['openssl', 's_client', '-connect', authority]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        args += ['-servername', host]
    else:
        args += ['-noservername']
    args += ['-showcerts']
    output = command_output(args)
    transcript = f'$ {shlex.join(args)} </dev/null\n{output}'
    leaf = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', output, re.S)
    result = {'evidence': transcript, 'error': 'TLS handshake did not return a certificate and negotiated cipher.'}
    certificate_der = None
    if leaf:
        try:
            certificate_der = x509.load_pem_x509_certificate(leaf.group(0).encode()).public_bytes(Encoding.DER)
        except ValueError:
            pass
        inspect = ['openssl', 'x509', '-noout', '-subject', '-issuer', '-dates',
                   '-serial', '-fingerprint', '-sha256', '-ext', 'subjectAltName']
        # Feed the actual certificate from s_client, not reconstructed fields.
        fields = command_output(inspect, input_text=leaf.group(0) + '\n', timeout=5)
        transcript += f'\n$ {shlex.join(inspect)}\n{fields}'
    result['evidence'] = transcript
    negotiated = re.search(r'^(?:New|Reused),\s*(TLSv[\d.]+|SSLv[\d.]+),\s*Cipher is\s+(\S+)', output, re.M)
    if not certificate_der or not negotiated or negotiated[2] in ('(NONE)', '0000', 'NONE'):
        return result

    verification = re.findall(r'^\s*Verify return code:\s*(\d+)\s*\(([^\n]*)\)', output, re.M)
    compression = re.search(r'^Compression:\s*(.+)', output, re.M)
    renegotiation = re.search(r'^Secure Renegotiation (IS(?: NOT)?) supported', output, re.M)
    result.update(
        error=None,
        certificate_der=certificate_der,
        protocol=negotiated[1],
        cipher=negotiated[2],
        compression=compression[1].strip() if compression else None,
        session_ticket='TLS session ticket:' in output,
        session_id=bool(re.search(r'^\s*Session-ID:\s*[0-9A-Fa-f]+\s*$', output, re.M)),
        secure_renegotiation=(renegotiation[1] == 'IS') if renegotiation else None,
        verify_code=int(verification[-1][0]) if verification else None,
        verify_message=verification[-1][1] if verification else None,
    )
    return result


def capture_openssl_evidence(host, port=443):
    """Compatibility wrapper for callers needing only the terminal transcript."""
    return capture_openssl_handshake(host, port)['evidence']
