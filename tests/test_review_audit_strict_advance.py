"""Strict checkpoint advancement rejects no-op replay while retaining old API."""
import unittest

from ogde.review_audit import make_review_audit_record
from ogde.review_audit_chain import append_review_audit_entry
from ogde.review_audit_checkpoint import make_review_audit_checkpoint
from ogde.review_audit_continuity import verify_review_audit_continuity


class StrictAdvanceTests(unittest.TestCase):
    def setUp(self):
        self.entries = []
        for index in range(3):
            record = make_review_audit_record(
                event='evidence_review', outcome='requires_review',
                occurred_at=f'2026-11-07T09:00:0{index}Z')
            self.entries.append(append_review_audit_entry(
                record, sequence=index,
                previous_sha256=self.entries[-1]['entry_sha256'] if index else None))
        self.prior = make_review_audit_checkpoint(self.entries[:2])
        self.current = make_review_audit_checkpoint(self.entries)

    def test_strict_accepts_genuine_extension(self):
        self.assertTrue(verify_review_audit_continuity(
            self.entries, self.prior, self.current, require_advance=True))

    def test_strict_rejects_equal_checkpoint(self):
        self.assertFalse(verify_review_audit_continuity(
            self.entries[:2], self.prior, self.prior, require_advance=True))

    def test_default_preserves_equal_checkpoint(self):
        self.assertTrue(verify_review_audit_continuity(
            self.entries[:2], self.prior, self.prior))

    def test_explicit_false_preserves_equal_checkpoint(self):
        self.assertTrue(verify_review_audit_continuity(
            self.entries[:2], self.prior, self.prior, require_advance=False))

    def test_rejects_non_boolean_flag(self):
        for flag in (1, 0, None, 'true', [], {}):
            with self.subTest(flag=flag):
                self.assertFalse(verify_review_audit_continuity(
                    self.entries, self.prior, self.current, require_advance=flag))

    def test_strict_rejects_rollback(self):
        self.assertFalse(verify_review_audit_continuity(
            self.entries[:2], self.prior, self.current, require_advance=True))

    def test_strict_rejects_altered_head(self):
        altered = dict(self.current, head_sha256='0' * 64)
        self.assertFalse(verify_review_audit_continuity(
            self.entries, self.prior, altered, require_advance=True))


if __name__ == '__main__':
    unittest.main()
