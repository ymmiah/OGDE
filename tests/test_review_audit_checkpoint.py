import copy
import unittest
from ogde.review_audit import make_review_audit_record
from ogde.review_audit_chain import append_review_audit_entry
from ogde.review_audit_checkpoint import make_review_audit_checkpoint, verify_review_audit_checkpoint


class CheckpointContractTests(unittest.TestCase):
    def setUp(self):
        self.entries = []
        for index in range(3):
            record = make_review_audit_record(event='evidence_review', outcome='rejected',
                occurred_at=f'2026-11-05T09:35:0{index}Z')
            self.entries.append(append_review_audit_entry(record, sequence=index,
                previous_sha256=self.entries[-1]['entry_sha256'] if index else None))
        self.checkpoint = make_review_audit_checkpoint(self.entries)

    def test_valid(self):
        self.assertTrue(verify_review_audit_checkpoint(self.entries, self.checkpoint))

    def test_reject_truncated(self):
        self.assertFalse(verify_review_audit_checkpoint(self.entries[:-1], self.checkpoint))

    def test_reject_changed_head(self):
        self.assertFalse(verify_review_audit_checkpoint(self.entries, dict(self.checkpoint, head_sha256='0'*64)))

    def test_reject_changed_count(self):
        self.assertFalse(verify_review_audit_checkpoint(self.entries, dict(self.checkpoint, entry_count=2)))

    def test_reject_bool_count(self):
        self.assertFalse(verify_review_audit_checkpoint(self.entries, dict(self.checkpoint, entry_count=True)))

    def test_reject_extra_field(self):
        self.assertFalse(verify_review_audit_checkpoint(self.entries, dict(self.checkpoint, customer_id='secret')))

    def test_reject_missing_field(self):
        cp = dict(self.checkpoint); del cp['head_sha256']
        self.assertFalse(verify_review_audit_checkpoint(self.entries, cp))

    def test_reject_wrong_schema(self):
        self.assertFalse(verify_review_audit_checkpoint(self.entries, dict(self.checkpoint, schema='unknown')))

    def test_reject_non_object(self):
        self.assertFalse(verify_review_audit_checkpoint(self.entries, None))

    def test_reject_modified_entry(self):
        entries = copy.deepcopy(self.entries); entries[0]['record']['outcome'] = 'accepted'
        self.assertFalse(verify_review_audit_checkpoint(entries, self.checkpoint))

    def test_reject_empty_checkpoint_creation(self):
        with self.assertRaises(ValueError):
            make_review_audit_checkpoint([])

    def test_no_mutation(self):
        before = copy.deepcopy(self.entries)
        verify_review_audit_checkpoint(self.entries, self.checkpoint)
        self.assertEqual(before, self.entries)
