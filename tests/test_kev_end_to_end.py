"""Integration coverage across KEV review, audit manifest, chain and local storage."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError, canonical
from ogde.kev_pipeline import review_kev_snapshot
from ogde.kev_audit import build_kev_audit_manifest
from ogde.kev_audit_chain import append_audit_record
from ogde.kev_checkpoint import create_audit_checkpoint, verify_audit_checkpoint
from ogde.kev_store import load_audit_snapshot, save_audit_snapshot


class OfflineKevEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "audit.json"
        self.snapshot = {"vulnerabilities": [
            {"cveID": "CVE-2026-12345", "dateAdded": "2026-10-25"}
        ]}
        self.digest = hashlib.sha256(canonical(self.snapshot)).hexdigest()
        self.findings = {"schema_version": 1, "findings": []}

    def review(self, **kwargs):
        params = {"expected_sha256": self.digest, "snapshot_date": "2026-10-25",
                  "as_of": "2026-11-01"}
        params.update(kwargs)
        return review_kev_snapshot(self.snapshot, self.findings, **params)

    def test_complete_offline_review_to_checkpoint(self):
        review = self.review()
        self.assertEqual(review["review_status"], "requires-human-review")
        manifest = build_kev_audit_manifest(review)
        chain = append_audit_record([], manifest)
        save_audit_snapshot(self.path, chain)
        checkpoint = create_audit_checkpoint(chain)
        self.assertTrue(verify_audit_checkpoint(load_audit_snapshot(self.path), checkpoint))
        self.assertEqual(load_audit_snapshot(self.path, checkpoint=checkpoint), chain)
        self.assertFalse(manifest["publisher_authenticated"])
        self.assertNotIn("findings", manifest)

    def test_stale_review_is_blocked_but_auditable(self):
        review = self.review(max_age_days=6)
        self.assertEqual(review["review_status"], "blocked")
        self.assertEqual(review["issues"], ["stale-snapshot"])
        manifest = build_kev_audit_manifest(review)
        self.assertEqual(manifest["review_status"], "blocked")
        chain = append_audit_record([], manifest)
        save_audit_snapshot(self.path, chain)
        self.assertEqual(load_audit_snapshot(self.path), chain)

    def test_bad_digest_never_writes_audit(self):
        with self.assertRaises(SecurityError):
            self.review(expected_sha256="0" * 64)
        self.assertFalse(self.path.exists())

    def test_tampered_disk_audit_rejected_by_checkpoint(self):
        chain = append_audit_record([], build_kev_audit_manifest(self.review()))
        save_audit_snapshot(self.path, chain)
        checkpoint = create_audit_checkpoint(chain)
        self.path.write_text("[]", encoding="utf-8")
        with self.assertRaises(SecurityError):
            load_audit_snapshot(self.path, checkpoint=checkpoint)

    def test_rewrite_after_checkpoint_detected(self):
        first = append_audit_record([], build_kev_audit_manifest(self.review()))
        checkpoint = create_audit_checkpoint(first)
        replacement = append_audit_record([], build_kev_audit_manifest(self.review(max_age_days=6)))
        with self.assertRaises(SecurityError):
            verify_audit_checkpoint(replacement, checkpoint)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX locks required")
    def test_full_pipeline_with_locked_append(self):
        from ogde.kev_locked import append_audit_locked
        manifest = build_kev_audit_manifest(self.review())
        first = append_audit_locked(self.path, manifest)
        second = append_audit_locked(self.path, manifest, checkpoint=create_audit_checkpoint(first))
        self.assertEqual(len(second), 2)
        self.assertEqual(load_audit_snapshot(self.path), second)


if __name__ == "__main__":
    unittest.main()
