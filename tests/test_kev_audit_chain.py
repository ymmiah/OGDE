import copy
import hashlib
import unittest
from ogde.core import SecurityError, canonical
from ogde.kev_audit_chain import append_audit_record, verify_audit_chain


def manifest(value):
    body = {"kind": "ogde-kev-review-audit", "schema_version": 1,
            "snapshot_digest_sha256": "a" * 64, "review_status": "requires-human-review",
            "finding_count": value}
    return {**body, "manifest_sha256": hashlib.sha256(canonical(body)).hexdigest()}


class AuditChainTests(unittest.TestCase):
    def test_append_and_verify_two_records(self):
        chain = append_audit_record([], manifest(1))
        chain = append_audit_record(chain, manifest(2))
        self.assertEqual(len(verify_audit_chain(chain)), 2)
        self.assertEqual(chain[1]["previous_sha256"], chain[0]["record_sha256"])

    def test_deterministic(self):
        self.assertEqual(append_audit_record([], manifest(1)), append_audit_record([], manifest(1)))

    def test_no_mutation(self):
        chain = append_audit_record([], manifest(1))
        original = copy.deepcopy(chain)
        append_audit_record(chain, manifest(2))
        self.assertEqual(chain, original)

    def test_tampered_manifest_rejected(self):
        chain = append_audit_record([], manifest(1))
        chain[0]["manifest"]["finding_count"] = 99
        with self.assertRaises(SecurityError):
            verify_audit_chain(chain)

    def test_broken_previous_link_rejected(self):
        chain = append_audit_record(append_audit_record([], manifest(1)), manifest(2))
        chain[1]["previous_sha256"] = "b" * 64
        with self.assertRaises(SecurityError):
            verify_audit_chain(chain)

    def test_removed_middle_record_rejected(self):
        chain = append_audit_record(append_audit_record([], manifest(1)), manifest(2))
        with self.assertRaises(SecurityError):
            verify_audit_chain(chain[1:])

    def test_invalid_sequence_rejected(self):
        chain = append_audit_record([], manifest(1))
        chain[0]["sequence"] = True
        with self.assertRaises(SecurityError):
            verify_audit_chain(chain)

    def test_modified_record_hash_rejected(self):
        chain = append_audit_record([], manifest(1))
        chain[0]["record_sha256"] = "0" * 64
        with self.assertRaises(SecurityError):
            verify_audit_chain(chain)

    def test_invalid_manifest_rejected_on_append(self):
        bad = manifest(1)
        bad["manifest_sha256"] = "0" * 64
        with self.assertRaises(SecurityError):
            append_audit_record([], bad)


if __name__ == "__main__":
    unittest.main()
