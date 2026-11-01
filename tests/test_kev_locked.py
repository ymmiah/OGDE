import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ogde.core import SecurityError, canonical
from ogde.kev_audit_chain import verify_audit_chain
from ogde.kev_checkpoint import create_audit_checkpoint
from ogde.kev_locked import append_audit_locked
from ogde.kev_store import load_audit_snapshot


def manifest(n):
    body = {"kind": "ogde-kev-review-audit", "schema_version": 1, "finding_count": n}
    return {**body, "manifest_sha256": hashlib.sha256(canonical(body)).hexdigest()}


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX locks required")
class LockedAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "audit.json"

    def test_first_and_second_append(self):
        first = append_audit_locked(self.path, manifest(1))
        second = append_audit_locked(self.path, manifest(2))
        self.assertEqual(len(second), 2)
        self.assertEqual(load_audit_snapshot(self.path), verify_audit_chain(second))
        self.assertEqual(second[0], first[0])

    def test_checkpoint_verification(self):
        first = append_audit_locked(self.path, manifest(1))
        second = append_audit_locked(self.path, manifest(2), checkpoint=create_audit_checkpoint(first))
        self.assertEqual(len(second), 2)

    def test_stale_checkpoint_rejected(self):
        first = append_audit_locked(self.path, manifest(1))
        append_audit_locked(self.path, manifest(2))
        with self.assertRaises(SecurityError):
            append_audit_locked(self.path, manifest(3), checkpoint=create_audit_checkpoint(first))

    def test_missing_snapshot_with_checkpoint_rejected(self):
        first = append_audit_locked(self.path, manifest(1))
        self.path.unlink()
        with self.assertRaises(SecurityError):
            append_audit_locked(self.path, manifest(2), checkpoint=create_audit_checkpoint(first))

    def test_symlink_lock_rejected(self):
        other = Path(self.temp.name) / "other"
        other.write_text("x")
        (Path(str(self.path) + ".lock")).symlink_to(other)
        with self.assertRaises(SecurityError):
            append_audit_locked(self.path, manifest(1))

    def test_insecure_lock_permissions_rejected(self):
        append_audit_locked(self.path, manifest(1))
        os.chmod(str(self.path) + ".lock", 0o644)
        with self.assertRaises(SecurityError):
            append_audit_locked(self.path, manifest(2))

    def test_invalid_manifest_does_not_overwrite(self):
        first = append_audit_locked(self.path, manifest(1))
        bad = manifest(2)
        bad["manifest_sha256"] = "0" * 64
        with self.assertRaises(SecurityError):
            append_audit_locked(self.path, bad)
        self.assertEqual(load_audit_snapshot(self.path), first)


if __name__ == "__main__":
    unittest.main()
