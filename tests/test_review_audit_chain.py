import copy
import unittest
from ogde.review_audit import make_review_audit_record
from ogde.review_audit_chain import append_review_audit_entry, verify_review_audit_chain


class ReviewAuditChainTests(unittest.TestCase):
    def setUp(self):
        self.records = [make_review_audit_record(event='evidence_review', outcome=o,
                        occurred_at=f'2026-11-05T01:00:0{i}Z')
                        for i, o in enumerate(('requires_review', 'rejected', 'accepted'))]
        self.chain = []
        for i, record in enumerate(self.records):
            self.chain.append(append_review_audit_entry(record, sequence=i,
                              previous_sha256=self.chain[-1]['entry_sha256'] if i else None))

    def test_valid(self):
        self.assertTrue(verify_review_audit_chain(self.chain))

    def test_anchored_head(self):
        self.assertTrue(verify_review_audit_chain(self.chain, expected_head_sha256=self.chain[-1]['entry_sha256']))

    def test_reject_truncation_with_anchor(self):
        self.assertFalse(verify_review_audit_chain(self.chain[:-1], expected_head_sha256=self.chain[-1]['entry_sha256']))

    def test_reject_missing_middle(self):
        self.assertFalse(verify_review_audit_chain([self.chain[0], self.chain[2]]))

    def test_reject_reorder(self):
        self.assertFalse(verify_review_audit_chain(list(reversed(self.chain))))

    def test_reject_record_tamper(self):
        entries = copy.deepcopy(self.chain)
        entries[1]['record']['outcome'] = 'accepted'
        self.assertFalse(verify_review_audit_chain(entries))

    def test_reject_link_tamper(self):
        entries = copy.deepcopy(self.chain)
        entries[1]['previous_sha256'] = '0' * 64
        self.assertFalse(verify_review_audit_chain(entries))

    def test_reject_entry_checksum_tamper(self):
        entries = copy.deepcopy(self.chain)
        entries[1]['entry_sha256'] = '0' * 64
        self.assertFalse(verify_review_audit_chain(entries))

    def test_reject_extra_field(self):
        entries = copy.deepcopy(self.chain)
        entries[1]['customer'] = 'private'
        self.assertFalse(verify_review_audit_chain(entries))

    def test_reject_empty(self):
        self.assertFalse(verify_review_audit_chain([]))

    def test_reject_bool_sequence(self):
        with self.assertRaises(ValueError):
            append_review_audit_entry(self.records[0], sequence=True)

    def test_reject_genesis_previous(self):
        with self.assertRaises(ValueError):
            append_review_audit_entry(self.records[0], sequence=0, previous_sha256='a' * 64)

    def test_reject_non_genesis_without_previous(self):
        with self.assertRaises(ValueError):
            append_review_audit_entry(self.records[0], sequence=1)

    def test_reject_wrong_anchor(self):
        self.assertFalse(verify_review_audit_chain(self.chain, expected_head_sha256='0' * 64))

    def test_reject_wrong_type(self):
        self.assertFalse(verify_review_audit_chain(tuple(self.chain)))


if __name__ == '__main__':
    unittest.main()
