"""Malformed review results must fail closed without invoking revision writer."""
import unittest
from unittest.mock import patch

from ogde.core import SecurityError
from ogde.kev_review_gate import review_and_accept_signed_kev


class MalformedReviewGateTests(unittest.TestCase):
    def assert_blocked(self, review):
        with patch('ogde.kev_review_gate.review_kev_snapshot', return_value=review), \
             patch('ogde.kev_review_gate.accept_kev_attestation_locked') as writer:
            with self.assertRaises(SecurityError):
                review_and_accept_signed_kev(
                    {}, {}, {'statement': {'snapshot_sha256': 'a' * 64}},
                    state_path='unused', trusted_public_pem=b'not-used',
                    expected_signer='operator', snapshot_date='2026-11-01',
                    as_of='2026-11-05')
            writer.assert_not_called()

    def test_null_review(self):
        self.assert_blocked(None)

    def test_list_review(self):
        self.assert_blocked([])

    def test_missing_status(self):
        self.assert_blocked({'issues': []})

    def test_missing_issues(self):
        self.assert_blocked({'review_status': 'requires-human-review'})

    def test_null_issues(self):
        self.assert_blocked({'review_status': 'requires-human-review', 'issues': None})

    def test_string_issues(self):
        self.assert_blocked({'review_status': 'requires-human-review', 'issues': ''})

    def test_dict_issues(self):
        self.assert_blocked({'review_status': 'requires-human-review', 'issues': {}})

    def test_blocked_review(self):
        self.assert_blocked({'review_status': 'blocked', 'issues': ['stale']})

    def test_issues_present(self):
        self.assert_blocked({'review_status': 'requires-human-review', 'issues': ['conflict']})


if __name__ == '__main__':
    unittest.main()
