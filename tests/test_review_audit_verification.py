import copy
import unittest
from ogde.review_audit import make_review_audit_record, verify_review_audit_record


class VerifyReviewAuditTests(unittest.TestCase):
    def setUp(self):
        self.record = make_review_audit_record(event='evidence_review', outcome='rejected',
                                               occurred_at='2026-11-04T11:00:00Z',
                                               evidence_sha256='a' * 64)

    def test_valid(self):
        self.assertTrue(verify_review_audit_record(self.record))

    def test_no_mutation(self):
        before = copy.deepcopy(self.record)
        verify_review_audit_record(self.record)
        self.assertEqual(before, self.record)

    def test_modified_outcome(self):
        self.assertFalse(verify_review_audit_record(dict(self.record, outcome='accepted')))

    def test_modified_evidence_digest(self):
        self.assertFalse(verify_review_audit_record(dict(self.record, evidence_sha256='b'*64)))

    def test_missing_field(self):
        record = dict(self.record)
        del record['event']
        self.assertFalse(verify_review_audit_record(record))

    def test_extra_field(self):
        self.assertFalse(verify_review_audit_record(dict(self.record, private_path='/tmp/secret')))

    def test_wrong_schema(self):
        self.assertFalse(verify_review_audit_record(dict(self.record, schema='other')))

    def test_wrong_checksum(self):
        self.assertFalse(verify_review_audit_record(dict(self.record, record_sha256='0'*64)))

    def test_noncanonical_timestamp(self):
        self.assertFalse(verify_review_audit_record(dict(self.record, occurred_at='2026-11-04T11:00:00+00:00')))

    def test_bad_type(self):
        self.assertFalse(verify_review_audit_record([]))
        self.assertFalse(verify_review_audit_record(None))

    def test_bad_field_type(self):
        self.assertFalse(verify_review_audit_record(dict(self.record, event=True)))

    def test_valid_without_digest(self):
        record = make_review_audit_record(event='checkpoint_verification', outcome='requires_review',
                                          occurred_at='2026-11-04T11:00:00+00:00')
        self.assertTrue(verify_review_audit_record(record))


if __name__ == '__main__':
    unittest.main()
