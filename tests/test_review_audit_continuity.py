import copy
import unittest
from ogde.review_audit_continuity import verify_review_audit_continuity
from ogde.review_audit_checkpoint import make_review_audit_checkpoint
from ogde.review_audit_chain import append_review_audit_entry
from ogde.review_audit import make_review_audit_record

class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.chain = []
        for i in range(3):
            record = make_review_audit_record(event='evidence_review', outcome='requires_review', occurred_at=f'2026-11-06T09:00:0{i}Z')
            self.chain.append(append_review_audit_entry(record, sequence=i, previous_sha256=self.chain[-1]['entry_sha256'] if i else None))
        self.prior = make_review_audit_checkpoint(self.chain[:2])
        self.current = make_review_audit_checkpoint(self.chain)
    def check(self, entries=None, prior=None, current=None):
        return verify_review_audit_continuity(self.chain if entries is None else entries, self.prior if prior is None else prior, self.current if current is None else current)
    def test_valid_extension(self): self.assertTrue(self.check())
    def test_same_checkpoint_allowed(self): self.assertTrue(self.check(self.chain[:2], self.prior, self.prior))
    def test_rollback(self): self.assertFalse(self.check(self.chain[:2]))
    def test_wrong_prior_head(self): self.assertFalse(self.check(prior=dict(self.prior, head_sha256='0'*64)))
    def test_wrong_current_head(self): self.assertFalse(self.check(current=dict(self.current, head_sha256='0'*64)))
    def test_prior_count_exceeds_current(self): self.assertFalse(self.check(prior=dict(self.prior, entry_count=4)))
    def test_bool_prior_count(self): self.assertFalse(self.check(prior=dict(self.prior, entry_count=True)))
    def test_missing_prior_count(self):
        prior = dict(self.prior); del prior['entry_count']; self.assertFalse(self.check(prior=prior))
    def test_missing_current_count(self):
        current = dict(self.current); del current['entry_count']; self.assertFalse(self.check(current=current))
    def test_modified_prior_entry(self):
        entries = copy.deepcopy(self.chain); entries[0]['record']['outcome']='accepted'; self.assertFalse(self.check(entries))
    def test_nonlist(self): self.assertFalse(self.check(tuple(self.chain)))
    def test_nondict_checkpoint(self): self.assertFalse(self.check(prior=[]))
    def test_empty_chain(self): self.assertFalse(self.check([]))
    def test_truncated_current(self): self.assertFalse(self.check(self.chain[:2], current=self.current))
    def test_malformed_current(self): self.assertFalse(self.check(current=dict(self.current, extra='private')))

if __name__ == '__main__': unittest.main()
