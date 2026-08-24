"""Hostname-to-certificate-identity matching, per RFC 6125.

Kept in one place because both the certificate and the TLS configuration
scanners need it, and because getting it wrong fails in the dangerous
direction: a plain substring test accepts 'apple.com.evil.net' as a match for
'apple.com', and fnmatch's '*' crosses dots so '*.example.com' wrongly accepts
'a.b.example.com'.
"""

import ipaddress


def is_ip_address(value):
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _normalise(name):
    # Certificate names are commonly written with a trailing root dot.
    return name.strip().rstrip('.').lower()


def hostname_matches(pattern, hostname):
    """True if a certificate identity covers hostname.

    Rules applied:
      - comparison is case-insensitive and ignores a trailing dot
      - a wildcard is only valid as the whole leftmost label ('*.example.com'),
        so 'w*.example.com' is rejected
      - a wildcard matches exactly one label: '*.example.com' covers
        'a.example.com' but neither 'a.b.example.com' nor 'example.com'
      - a wildcard needs at least two labels beneath it, which rejects '*.com'
      - IP addresses only ever match exactly
    """
    pattern = _normalise(pattern)
    hostname = _normalise(hostname)

    if not pattern or not hostname:
        return False

    if is_ip_address(hostname) or is_ip_address(pattern):
        return pattern == hostname

    if '*' not in pattern:
        return pattern == hostname

    pattern_labels = pattern.split('.')
    if pattern_labels[0] != '*':
        return False
    if '*' in '.'.join(pattern_labels[1:]):
        return False
    if len(pattern_labels) < 3:
        return False

    host_labels = hostname.split('.')
    if len(host_labels) != len(pattern_labels):
        return False

    return host_labels[1:] == pattern_labels[1:]


def first_match(patterns, hostname):
    """The first identity covering hostname, or None."""
    for pattern in patterns:
        if hostname_matches(pattern, hostname):
            return pattern
    return None
