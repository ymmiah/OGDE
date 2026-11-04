import unittest
from ogde.review_audit import make_review_audit_record

class ReviewAuditTests(unittest.TestCase):
    def valid(self, **changes):
        data = dict(event='evidence_review', outcome='rejected', occurred_at='2026-11-04T07:00:00Z')
        data.update(changes)
        return make_review_audit_record(**data)

    def test_deterministic(self):
        self.assertEqual(self.valid(), self.valid())

    def test_allowlist(self):
        self.assertEqual(set(self.valid()), {'schema','event','outcome','occurred_at','evidence_sha256','record_sha256'})

    def test_all_supported_events(self):
        for event in ('evidence_review','revision_acceptance','checkpoint_verification'):
            self.assertEqual(self.valid(event=event)['event'], event)

    def test_all_outcomes(self):
        for outcome in ('accepted','rejected','requires_review'):
            self.assertEqual(self.valid(outcome=outcome)['outcome'], outcome)

    def test_reject_free_text_event(self):
        with self.assertRaises(ValueError): self.valid(event='secret=/private/file')

    def test_reject_invalid_outcome(self):
        with self.assertRaises(ValueError): self.valid(outcome='patched')

    def test_reject_naive_timestamp(self):
        with self.assertRaises(ValueError): self.valid(occurred_at='2026-11-04T07:00:00')

    def test_reject_bad_timestamp(self):
        with self.assertRaises(ValueError): self.valid(occurred_at='not a date')

    def test_reject_digest(self):
        for value in ('AB'*32, 'x'*64, 'a'*63, 123, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError): self.valid(evidence_sha256=value)

    def test_valid_digest(self):
        self.assertEqual(self.valid(evidence_sha256='a'*64)['evidence_sha256'], 'a'*64)

    def test_fingerprint_changes(self):
        self.assertNotEqual(self.valid()['record_sha256'], self.valid(outcome='accepted')['record_sha256'])

    def test_reject_extra_fields(self):
        with self.assertRaises(TypeError): self.valid(customer_name='private')

if __name__ == '__main__': unittest.main()
