"""Bounded, shell-free collection of real command output for technical evidence."""
import re
import shlex
import subprocess


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


def capture_openssl_evidence(host, port=443):
    """One real handshake, followed by local inspection of that peer's leaf PEM."""
    host = str(host)
    authority = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    args = ['openssl', 's_client', '-connect', authority, '-servername', host, '-showcerts']
    output = command_output(args)
    transcript = f'$ {shlex.join(args)} </dev/null\n{output}'
    leaf = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', output, re.S)
    if leaf:
        inspect = ['openssl', 'x509', '-noout', '-subject', '-issuer', '-dates',
                   '-serial', '-fingerprint', '-sha256', '-ext', 'subjectAltName']
        # Feed the actual certificate from s_client, not reconstructed fields.
        fields = command_output(inspect, input_text=leaf.group(0) + '\n', timeout=5)
        transcript += f'\n$ {shlex.join(inspect)}\n{fields}'
    return transcript
