"""Precommit consistency: no trusted-state write on inconsistent review receipts."""
import unittest
from unittest.mock import patch
from ogde.core import SecurityError
from ogde.kev_review_gate import review_and_accept_signed_kev


class PrecommitDigestGateTests(unittest.TestCase):
    def call(self, review):
        with patch('ogde.kev_review_gate.review_kev_snapshot', return_value=review), \
             patch('ogde.kev_review_gate.accept_kev_attestation_locked') as writer:
            try:
                review_and_accept_signed_kev(
                    {}, {}, {'statement': {'snapshot_sha256': 'a' * 64}},
                    state_path='unused', trusted_public_pem=b'not-used',
                    expected_signer='test', snapshot_date='2026-11-01', as_of='2026-11-04')
            except SecurityError:
                pass
            else:
                self.fail('expected SecurityError')
            writer.assert_not_called()

    def test_mismatched_review_digest_never_writes(self):
        self.call({'review_status': 'requires-human-review', 'issues': [], 'digest_sha256': 'b' * 64})

    def test_missing_review_digest_never_writes(self):
        self.call({'review_status': 'requires-human-review', 'issues': []})

    def test_wrong_digest_type_never_writes(self):
        self.call({'review_status': 'requires-human-review', 'issues': [], 'digest_sha256': 123})

    def test_blocked_review_never_writes(self):
        self.call({'review_status': 'blocked', 'issues': ['stale'], 'digest_sha256': 'a' * 64})


if __name__ == '__main__':
    unittest.main()
