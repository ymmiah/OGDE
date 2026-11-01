import copy
import hashlib
import unittest
from ogde.core import SecurityError, canonical
from ogde.kev_audit_chain import append_audit_record
from ogde.kev_checkpoint import create_audit_checkpoint, verify_audit_checkpoint


def manifest(n):
    body = {"kind": "ogde-kev-review-audit", "schema_version": 1, "finding_count": n}
    return {**body, "manifest_sha256": hashlib.sha256(canonical(body)).hexdigest()}


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.one = append_audit_record([], manifest(1))
        self.two = append_audit_record(self.one, manifest(2))

    def test_checkpoint_round_trip(self):
        checkpoint = create_audit_checkpoint(self.two)
        self.assertTrue(verify_audit_checkpoint(self.two, checkpoint))

    def test_deterministic(self):
        self.assertEqual(create_audit_checkpoint(self.two), create_audit_checkpoint(self.two))

    def test_detects_tail_truncation(self):
        with self.assertRaises(SecurityError):
            verify_audit_checkpoint(self.one, create_audit_checkpoint(self.two))

    def test_detects_rewritten_history(self):
        changed = append_audit_record([], manifest(3))
        changed = append_audit_record(changed, manifest(2))
        with self.assertRaises(SecurityError):
            verify_audit_checkpoint(changed, create_audit_checkpoint(self.two))

    def test_detects_tampered_checkpoint(self):
        checkpoint = create_audit_checkpoint(self.two)
        checkpoint["head_sha256"] = "0" * 64
        with self.assertRaises(SecurityError):
            verify_audit_checkpoint(self.two, checkpoint)

    def test_empty_chain_rejected(self):
        with self.assertRaises(SecurityError):
            create_audit_checkpoint([])

    def test_invalid_boolean_count_rejected(self):
        checkpoint = create_audit_checkpoint(self.two)
        checkpoint["record_count"] = True
        with self.assertRaises(SecurityError):
            verify_audit_checkpoint(self.two, checkpoint)

    def test_no_mutation(self):
        original = copy.deepcopy(self.two)
        verify_audit_checkpoint(self.two, create_audit_checkpoint(self.two))
        self.assertEqual(self.two, original)


if __name__ == "__main__":
    unittest.main()
