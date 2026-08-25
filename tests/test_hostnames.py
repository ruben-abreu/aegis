import unittest

from scanners.hostnames import first_match, hostname_matches, is_ip_address


class HostnameMatchingTests(unittest.TestCase):
    def test_exact_match_is_case_insensitive_and_ignores_trailing_dot(self):
        self.assertTrue(hostname_matches("WWW.Example.COM.", "www.example.com"))

    def test_wildcard_matches_exactly_one_label(self):
        self.assertTrue(hostname_matches("*.example.com", "www.example.com"))
        self.assertFalse(hostname_matches("*.example.com", "a.b.example.com"))
        self.assertFalse(hostname_matches("*.example.com", "example.com"))

    def test_rejects_partial_and_top_level_wildcards(self):
        self.assertFalse(hostname_matches("w*.example.com", "www.example.com"))
        self.assertFalse(hostname_matches("*.com", "example.com"))

    def test_ip_addresses_only_match_exactly(self):
        self.assertTrue(is_ip_address("203.0.113.10"))
        self.assertTrue(hostname_matches("203.0.113.10", "203.0.113.10"))
        self.assertFalse(hostname_matches("*", "203.0.113.10"))

    def test_first_match_returns_the_matching_identity(self):
        identities = ["example.net", "*.example.com", "example.org"]
        self.assertEqual(first_match(identities, "www.example.com"), "*.example.com")
        self.assertIsNone(first_match(identities, "unrelated.test"))


if __name__ == "__main__":
    unittest.main()
