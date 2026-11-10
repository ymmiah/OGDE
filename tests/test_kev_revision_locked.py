import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ogde.core import SecurityError, canonical, public_key_id
from ogde.kev_revision_locked import accept_kev_attestation_locked
from ogde.kev_revision_state import load_kev_revision_state


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX required")
class LockedRevisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "revision.json"
        self.key = Ed25519PrivateKey.generate()
        self.pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.snapshot = {"vulnerabilities": [
            {"cveID": "CVE-2026-12345", "dateAdded": "2026-10-25"}]}

    def envelope(self, revision):
        statement = {"kind": "ogde-kev-snapshot-attestation", "schema_version": 1,
                     "signer_id": "operator-lab",
                     "snapshot_sha256": hashlib.sha256(canonical(self.snapshot)).hexdigest(),
                     "revision": revision, "valid_from": "2026-10-25", "valid_until": "2026-11-10"}
        return {"statement": statement, "signature": {
            "algorithm": "Ed25519", "key_id": public_key_id(self.key.public_key()),
            "value": base64.b64encode(self.key.sign(canonical(statement))).decode()}}

    def accept(self, revision, checkpoint=None):
        return accept_kev_attestation_locked(
            self.snapshot, self.envelope(revision), state_path=self.path,
            trusted_public_pem=self.pem, expected_signer="operator-lab", as_of="2026-11-01", checkpoint=checkpoint)

    def test_advances_and_rejects_replay(self):
        self.accept(1)
        self.accept(2)
        self.assertEqual(load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 2)
        with self.assertRaises(SecurityError):
            self.accept(2)

    def test_lock_is_private(self):
        self.accept(1)
        self.assertEqual(Path(str(self.path) + ".lock").stat().st_mode & 0o777, 0o600)

    def test_symlink_lock_rejected(self):
        other = Path(self.temp.name) / "other"
        other.write_text("x")
        Path(str(self.path) + ".lock").symlink_to(other)
        with self.assertRaises(SecurityError):
            self.accept(1)

    def test_world_readable_lock_rejected(self):
        self.accept(1)
        os.chmod(str(self.path) + ".lock", 0o644)
        with self.assertRaises(SecurityError):
            self.accept(2)
        self.assertEqual(load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 1)

    def test_fifo_lock_rejected_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO unsupported")
        os.mkfifo(str(self.path) + ".lock", 0o600)
        with self.assertRaises(SecurityError):
            self.accept(1)
        self.assertFalse(self.path.exists())

    def test_hardlinked_lock_rejected_without_advancing(self):
        self.accept(1)
        lock = Path(str(self.path) + ".lock")
        alias = Path(self.temp.name) / "lock-alias"
        os.link(lock, alias)
        with self.assertRaises(SecurityError):
            self.accept(2)
        self.assertEqual(load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 1)

    def test_replaced_lock_inode_rejected_before_state_update(self):
        import fcntl
        original_flock = fcntl.flock
        lock = Path(str(self.path) + ".lock")
        displaced = Path(self.temp.name) / "displaced-lock"

        def replace_after_acquiring(fd, operation):
            original_flock(fd, operation)
            lock.rename(displaced)
            lock.touch(mode=0o600)

        with patch("fcntl.flock", side_effect=replace_after_acquiring):
            with self.assertRaisesRegex(SecurityError, "changed during acquisition"):
                self.accept(1)
        self.assertFalse(self.path.exists())

    def test_lock_permissions_changed_during_acquisition_rejected(self):
        """A lock made group-readable while waiting cannot protect revisions."""
        import fcntl
        original_flock = fcntl.flock
        lock = Path(str(self.path) + ".lock")

        def expose_after_acquiring(fd, operation):
            original_flock(fd, operation)
            os.chmod(lock, 0o640)

        with patch("fcntl.flock", side_effect=expose_after_acquiring):
            with self.assertRaisesRegex(SecurityError, "changed during acquisition"):
                self.accept(1)
        self.assertFalse(self.path.exists())
        self.assertEqual(lock.stat().st_mode & 0o777, 0o640)

    def test_lock_hardlinked_during_acquisition_rejected(self):
        """A new hard link after flock must not advance revision state."""
        import fcntl
        original_flock = fcntl.flock
        lock = Path(str(self.path) + ".lock")
        alias = Path(self.temp.name) / "late-lock-alias"

        def link_after_acquiring(fd, operation):
            original_flock(fd, operation)
            os.link(lock, alias)

        with patch("fcntl.flock", side_effect=link_after_acquiring):
            with self.assertRaisesRegex(SecurityError, "changed during acquisition"):
                self.accept(1)
        self.assertFalse(self.path.exists())
        self.assertEqual(lock.stat().st_nlink, 2)
        self.assertTrue(alias.samefile(lock))

    def test_unlinked_lock_inode_rejected_before_state_update(self):
        import fcntl
        original_flock = fcntl.flock
        lock = Path(str(self.path) + ".lock")

        def unlink_after_acquiring(fd, operation):
            original_flock(fd, operation)
            lock.unlink()

        with patch("fcntl.flock", side_effect=unlink_after_acquiring):
            with self.assertRaisesRegex(SecurityError, "changed during acquisition"):
                self.accept(1)
        self.assertFalse(self.path.exists())

    def test_lock_replacement_preserves_existing_revision_and_checkpoint(self):
        import fcntl
        original_flock = fcntl.flock
        for action in ("replace", "unlink"):
            with self.subTest(action=action):
                # Use a fresh state directory for each simulated race.
                with tempfile.TemporaryDirectory() as directory:
                    self.path = Path(directory) / "revision.json"
                    first = self.accept(1)
                    original_bytes = self.path.read_bytes()
                    lock = Path(str(self.path) + ".lock")

                    def disrupt_after_acquiring(fd, operation):
                        original_flock(fd, operation)
                        if action == "replace":
                            lock.rename(Path(directory) / "displaced-lock")
                            lock.touch(mode=0o600)
                        else:
                            lock.unlink()

                    with patch("fcntl.flock", side_effect=disrupt_after_acquiring):
                        with self.assertRaisesRegex(SecurityError, "changed during acquisition"):
                            self.accept(2, checkpoint=first["revision_checkpoint"])
                    self.assertEqual(self.path.read_bytes(), original_bytes)
                    self.assertEqual(
                        load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 1)

    def test_invalid_signature_does_not_advance(self):
        self.accept(1)
        envelope = self.envelope(2)
        envelope["signature"]["value"] = base64.b64encode(b"x" * 64).decode()
        with self.assertRaises(SecurityError):
            accept_kev_attestation_locked(
                self.snapshot, envelope, state_path=self.path,
                trusted_public_pem=self.pem, expected_signer="operator-lab", as_of="2026-11-01")
        self.assertEqual(load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 1)


    def test_checkpointed_acceptance_returns_new_checkpoint(self):
        first = self.accept(1)
        self.assertFalse(first["previous_checkpoint_verified"])
        self.assertFalse(first["publisher_authenticated"])
        second = self.accept(2, checkpoint=first["revision_checkpoint"])
        self.assertTrue(second["previous_checkpoint_verified"])
        self.assertNotEqual(first["revision_checkpoint"], second["revision_checkpoint"])
        self.assertEqual(load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 2)

    def test_rolled_back_state_rejected_before_update(self):
        first = self.accept(1)
        old_state = self.path.read_bytes()
        second = self.accept(2, checkpoint=first["revision_checkpoint"])
        self.path.write_bytes(old_state)
        with self.assertRaises(SecurityError):
            self.accept(3, checkpoint=second["revision_checkpoint"])
        self.assertEqual(self.path.read_bytes(), old_state)

    def test_missing_state_rejected_when_checkpoint_exists(self):
        first = self.accept(1)
        self.path.unlink()
        with self.assertRaises(SecurityError):
            self.accept(2, checkpoint=first["revision_checkpoint"])
        self.assertFalse(self.path.exists())

    def test_stale_checkpoint_rejected_before_update(self):
        first = self.accept(1)
        self.accept(2, checkpoint=first["revision_checkpoint"])
        with self.assertRaises(SecurityError):
            self.accept(3, checkpoint=first["revision_checkpoint"])
        self.assertEqual(load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 2)

    def test_modified_checkpoint_rejected(self):
        first = self.accept(1)
        altered = dict(first["revision_checkpoint"])
        altered["signer_count"] = 0
        with self.assertRaises(SecurityError):
            self.accept(2, checkpoint=altered)
        self.assertEqual(load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 1)


if __name__ == "__main__":
    unittest.main()
