import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from ogde.core import SecurityError, canonical
from ogde.kev_audit_chain import append_audit_record
from ogde.kev_checkpoint import create_audit_checkpoint
from ogde.kev_store import load_audit_snapshot, save_audit_snapshot


def manifest(n):
    body = {"kind": "ogde-kev-review-audit", "schema_version": 1, "finding_count": n}
    return {**body, "manifest_sha256": hashlib.sha256(canonical(body)).hexdigest()}


class AuditStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "audit.json"
        self.one = append_audit_record([], manifest(1))
        self.two = append_audit_record(self.one, manifest(2))

    def test_save_and_load(self):
        save_audit_snapshot(self.path, self.one)
        self.assertEqual(load_audit_snapshot(self.path), self.one)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_checked_update(self):
        save_audit_snapshot(self.path, self.one)
        save_audit_snapshot(self.path, self.two, expected_head=self.one[-1]["record_sha256"])
        self.assertEqual(load_audit_snapshot(self.path), self.two)

    def test_overwrite_without_expected_head_rejected(self):
        save_audit_snapshot(self.path, self.one)
        with self.assertRaises(SecurityError):
            save_audit_snapshot(self.path, self.two)

    def test_wrong_head_rejected(self):
        save_audit_snapshot(self.path, self.one)
        with self.assertRaises(SecurityError):
            save_audit_snapshot(self.path, self.two, expected_head="0" * 64)

    def test_valid_head_cannot_truncate_history(self):
        save_audit_snapshot(self.path, self.two)
        with self.assertRaises(SecurityError):
            save_audit_snapshot(self.path, self.one, expected_head=self.two[-1]["record_sha256"])

    def test_valid_head_cannot_replace_history(self):
        save_audit_snapshot(self.path, self.one)
        replacement = append_audit_record([], manifest(99))
        with self.assertRaises(SecurityError):
            save_audit_snapshot(self.path, replacement, expected_head=self.one[-1]["record_sha256"])

    def test_checkpoint_mismatch_rejected(self):
        save_audit_snapshot(self.path, self.one)
        with self.assertRaises(SecurityError):
            load_audit_snapshot(self.path, checkpoint=create_audit_checkpoint(self.two))

    def test_tampered_file_rejected(self):
        save_audit_snapshot(self.path, self.one)
        self.path.write_text("[]")
        with self.assertRaises(SecurityError):
            load_audit_snapshot(self.path, checkpoint=create_audit_checkpoint(self.one))

    def test_symlink_rejected(self):
        target = Path(self.temp.name) / "other"
        target.write_text("private")
        self.path.symlink_to(target)
        with self.assertRaises(SecurityError):
            save_audit_snapshot(self.path, self.one)
        with self.assertRaises(SecurityError):
            load_audit_snapshot(self.path)

    def test_world_readable_file_rejected(self):
        save_audit_snapshot(self.path, self.one)
        os.chmod(self.path, 0o644)
        with self.assertRaises(SecurityError):
            load_audit_snapshot(self.path)


if __name__ == "__main__":
    unittest.main()
