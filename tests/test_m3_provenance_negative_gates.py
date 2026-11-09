"""Fail-closed M3 operator-attestation tests; NOT TUF/Sigstore publisher verification.

These tests deliberately distinguish a pinned operator signature from independently
authenticated CISA provenance. No network access or publisher trust promotion.
"""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ogde.core import SecurityError, canonical, public_key_id
from ogde.kev_attestation import verify_kev_attestation
from ogde.kev_revision_state import accept_kev_attestation, load_kev_revision_state


class M3ProvenanceNegativeGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name) / "revision.json"
        self.key = Ed25519PrivateKey.generate()
        self.pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.snapshot = {
            "vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-25"}]
        }

    def signed(self, revision=1, signer="operator-lab", valid_until="2026-11-10"):
        statement = {
            "kind": "ogde-kev-snapshot-attestation",
            "schema_version": 1,
            "signer_id": signer,
            "snapshot_sha256": hashlib.sha256(canonical(self.snapshot)).hexdigest(),
            "revision": revision,
            "valid_from": "2026-10-25",
            "valid_until": valid_until,
        }
        return {
            "statement": statement,
            "signature": {
                "algorithm": "Ed25519",
                "key_id": public_key_id(self.key.public_key()),
                "value": base64.b64encode(self.key.sign(canonical(statement))).decode("ascii"),
            },
        }

    def accept(self, attestation, **overrides):
        options = {
            "state_path": self.state,
            "trusted_public_pem": self.pem,
            "expected_signer": "operator-lab",
            "as_of": "2026-11-09",
        }
        options.update(overrides)
        return accept_kev_attestation(self.snapshot, attestation, **options)

    def test_valid_operator_signature_never_claims_publisher_authentication(self):
        receipt = self.accept(self.signed())
        self.assertTrue(receipt["signature_verified"])
        self.assertIs(receipt["publisher_authenticated"], False)
        self.assertEqual(receipt["decision"], "human-review")

    def test_valid_signature_wrong_identity_does_not_create_state(self):
        with self.assertRaises(SecurityError):
            self.accept(self.signed(signer="unapproved-publisher"))
        self.assertFalse(self.state.exists())

    def test_expired_valid_signature_does_not_advance_existing_state(self):
        self.accept(self.signed())
        original = self.state.read_bytes()
        with self.assertRaises(SecurityError):
            self.accept(self.signed(revision=2, valid_until="2026-11-08"))
        self.assertEqual(self.state.read_bytes(), original)
        self.assertEqual(load_kev_revision_state(self.state)["signers"]["operator-lab"]["revision"], 1)

    def test_unapproved_signing_key_does_not_advance_existing_state(self):
        self.accept(self.signed())
        original = self.state.read_bytes()
        unknown = Ed25519PrivateKey.generate()
        unknown_pem = unknown.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with self.assertRaises(SecurityError):
            self.accept(self.signed(revision=2), trusted_public_pem=unknown_pem)
        self.assertEqual(self.state.read_bytes(), original)

    def test_unrecognised_command_field_rejected_even_when_resigned(self):
        attestation = self.signed()
        attestation["statement"]["command"] = "execute"
        attestation["signature"]["value"] = base64.b64encode(
            self.key.sign(canonical(attestation["statement"]))
        ).decode("ascii")
        with self.assertRaises(SecurityError):
            self.accept(attestation)
        self.assertFalse(self.state.exists())


    def test_locked_checkpoint_rejects_wrong_identity_without_advancing(self):
        """Exercise the production locking boundary, not just the single-writer API."""
        import os
        from ogde.kev_revision_locked import accept_kev_attestation_locked

        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("POSIX secure locks required")
        options = {
            "state_path": self.state,
            "trusted_public_pem": self.pem,
            "expected_signer": "operator-lab",
            "as_of": "2026-11-09",
        }
        first = accept_kev_attestation_locked(self.snapshot, self.signed(), **options)
        before = self.state.read_bytes()
        checkpoint = first["revision_checkpoint"]
        with self.assertRaises(SecurityError):
            accept_kev_attestation_locked(
                self.snapshot, self.signed(revision=2, signer="unapproved-publisher"),
                checkpoint=checkpoint, **options
            )
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(load_kev_revision_state(self.state)["signers"]["operator-lab"]["revision"], 1)
        second = accept_kev_attestation_locked(
            self.snapshot, self.signed(revision=2), checkpoint=checkpoint, **options
        )
        self.assertTrue(second["previous_checkpoint_verified"])
        self.assertFalse(second["publisher_authenticated"])
        self.assertEqual(load_kev_revision_state(self.state)["signers"]["operator-lab"]["revision"], 2)


    def test_locked_checkpoint_rejects_valid_replay_after_state_rollback(self):
        """An externally retained checkpoint detects rollback despite a valid signature."""
        import os
        from ogde.kev_revision_locked import accept_kev_attestation_locked

        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("POSIX secure locks required")
        options = {
            "state_path": self.state,
            "trusted_public_pem": self.pem,
            "expected_signer": "operator-lab",
            "as_of": "2026-11-09",
        }
        first = accept_kev_attestation_locked(self.snapshot, self.signed(), **options)
        older_state = self.state.read_bytes()
        second = accept_kev_attestation_locked(
            self.snapshot, self.signed(revision=2),
            checkpoint=first["revision_checkpoint"], **options
        )
        self.state.write_bytes(older_state)
        with self.assertRaises(SecurityError):
            accept_kev_attestation_locked(
                self.snapshot, self.signed(revision=3),
                checkpoint=second["revision_checkpoint"], **options
            )
        self.assertEqual(self.state.read_bytes(), older_state)


    def test_locked_checkpoint_rejects_unapproved_valid_key_rotation(self):
        """A new correctly signed key cannot silently replace a pinned signer key."""
        import os
        from ogde.kev_revision_locked import accept_kev_attestation_locked

        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("POSIX secure locks required")
        options = {
            "state_path": self.state,
            "expected_signer": "operator-lab",
            "as_of": "2026-11-09",
        }
        first = accept_kev_attestation_locked(
            self.snapshot, self.signed(), trusted_public_pem=self.pem, **options
        )
        before = self.state.read_bytes()
        replacement = Ed25519PrivateKey.generate()
        replacement_pem = replacement.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        statement = self.signed(revision=2)["statement"]
        rotated = {
            "statement": statement,
            "signature": {
                "algorithm": "Ed25519",
                "key_id": public_key_id(replacement.public_key()),
                "value": base64.b64encode(replacement.sign(canonical(statement))).decode("ascii"),
            },
        }
        with self.assertRaises(SecurityError):
            accept_kev_attestation_locked(
                self.snapshot, rotated, trusted_public_pem=replacement_pem,
                checkpoint=first["revision_checkpoint"], **options
            )
        self.assertEqual(self.state.read_bytes(), before)
        second = accept_kev_attestation_locked(
            self.snapshot, self.signed(revision=2), trusted_public_pem=self.pem,
            checkpoint=first["revision_checkpoint"], **options
        )
        self.assertTrue(second["previous_checkpoint_verified"])
        self.assertEqual(load_kev_revision_state(self.state)["signers"]["operator-lab"]["revision"], 2)


    def test_locked_checkpoint_rejects_resigned_snapshot_mismatch_without_state_change(self):
        """A correctly signed digest must still bind to the actual KEV snapshot."""
        import os
        from ogde.kev_revision_locked import accept_kev_attestation_locked

        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("POSIX secure locks required")
        options = {
            "state_path": self.state,
            "trusted_public_pem": self.pem,
            "expected_signer": "operator-lab",
            "as_of": "2026-11-09",
        }
        first = accept_kev_attestation_locked(self.snapshot, self.signed(), **options)
        before = self.state.read_bytes()
        changed_snapshot = {
            "vulnerabilities": [
                {"cveID": "CVE-2026-99999", "dateAdded": "2026-10-25"}
            ]
        }
        with self.assertRaises(SecurityError):
            accept_kev_attestation_locked(
                changed_snapshot, self.signed(revision=2),
                checkpoint=first["revision_checkpoint"], **options
            )
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(
            load_kev_revision_state(self.state)["signers"]["operator-lab"]["revision"], 1
        )
        second = accept_kev_attestation_locked(
            self.snapshot, self.signed(revision=2),
            checkpoint=first["revision_checkpoint"], **options
        )
        self.assertTrue(second["previous_checkpoint_verified"])
        self.assertFalse(second["publisher_authenticated"])


    def test_locked_checkpoint_rejects_same_revision_replay_without_mutation(self):
        """A signed replay cannot reuse an accepted revision or corrupt the checkpoint."""
        import os
        from ogde.kev_revision_locked import accept_kev_attestation_locked
        from ogde.kev_revision_checkpoint import create_kev_revision_checkpoint

        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("POSIX secure locks required")
        options = {
            "state_path": self.state,
            "trusted_public_pem": self.pem,
            "expected_signer": "operator-lab",
            "as_of": "2026-11-09",
        }
        first = accept_kev_attestation_locked(self.snapshot, self.signed(), **options)
        before = self.state.read_bytes()
        checkpoint = first["revision_checkpoint"]
        with self.assertRaises(SecurityError):
            accept_kev_attestation_locked(
                self.snapshot, self.signed(revision=1),
                checkpoint=checkpoint, **options
            )
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(
            create_kev_revision_checkpoint(load_kev_revision_state(self.state)),
            checkpoint,
        )
        second = accept_kev_attestation_locked(
            self.snapshot, self.signed(revision=2),
            checkpoint=checkpoint, **options
        )
        self.assertTrue(second["previous_checkpoint_verified"])
        self.assertFalse(second["publisher_authenticated"])


if __name__ == "__main__":
    unittest.main()
