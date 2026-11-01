"""Synthetic offline tests: no network access."""
import hashlib
import unittest
from ogde.core import SecurityError, canonical
from ogde.evidence_gate import verify_local_evidence


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.doc = {"schema_version": 1, "source": "synthetic", "records": [{"id": "CVE-2026-12345", "digest_sha256": "a" * 64}]}
        self.digest = hashlib.sha256(canonical(self.doc)).hexdigest()

    def check(self, doc=None, digest=None):
        return verify_local_evidence(self.doc if doc is None else doc, expected_sha256=self.digest if digest is None else digest, source_path="synthetic.json")

    def test_valid_receipt_is_not_authentication(self):
        receipt = self.check()
        self.assertTrue(receipt["verified_integrity"])
        self.assertFalse(receipt["publisher_authenticated"])
        self.assertEqual(receipt["decision"], "human-review")

    def test_digest_mismatch(self):
        with self.assertRaises(SecurityError):
            self.check(digest="0" * 64)

    def test_duplicate_records(self):
        doc = dict(self.doc, records=self.doc["records"] * 2)
        with self.assertRaises(SecurityError):
            self.check(doc=doc)

    def test_extra_fields_rejected(self):
        with self.assertRaises(SecurityError):
            self.check(doc=dict(self.doc, instructions="execute this"))

    def test_invalid_record_digest(self):
        doc = dict(self.doc, records=[{"id": "X", "digest_sha256": "invalid"}])
        with self.assertRaises(SecurityError):
            self.check(doc=doc)

    def test_boolean_schema_rejected(self):
        with self.assertRaises(SecurityError):
            self.check(doc=dict(self.doc, schema_version=True))


if __name__ == "__main__":
    unittest.main()
