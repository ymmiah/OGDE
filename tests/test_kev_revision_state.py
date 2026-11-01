import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ogde.core import SecurityError, canonical, public_key_id
from ogde.kev_revision_state import accept_kev_attestation, load_kev_revision_state


class RevisionStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state.json"
        self.key = Ed25519PrivateKey.generate()
        self.pem = self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.snapshot = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-25"}]}

    def envelope(self, revision=1, key=None):
        key = key or self.key
        statement = {"kind": "ogde-kev-snapshot-attestation", "schema_version": 1,
                     "signer_id": "operator-lab", "snapshot_sha256": hashlib.sha256(canonical(self.snapshot)).hexdigest(),
                     "revision": revision, "valid_from": "2026-10-25", "valid_until": "2026-11-10"}
        return {"statement": statement, "signature": {"algorithm": "Ed25519",
                "key_id": public_key_id(key.public_key()),
                "value": base64.b64encode(key.sign(canonical(statement))).decode("ascii")}}

    def accept(self, envelope=None, **kwargs):
        opts = {"state_path": self.path, "trusted_public_pem": self.pem,
                "expected_signer": "operator-lab", "as_of": "2026-11-01"}
        opts.update(kwargs)
        return accept_kev_attestation(self.snapshot, envelope or self.envelope(), **opts)

    def test_first_accept_and_advance(self):
        self.accept()
        self.accept(self.envelope(2))
        state = load_kev_revision_state(self.path)
        self.assertEqual(state["signers"]["operator-lab"]["revision"], 2)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_replay_rejected(self):
        self.accept()
        with self.assertRaises(SecurityError):
            self.accept()
        self.assertEqual(load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 1)

    def test_lower_revision_rejected(self):
        self.accept(self.envelope(3))
        with self.assertRaises(SecurityError):
            self.accept(self.envelope(2))

    def test_bad_signature_does_not_advance(self):
        self.accept()
        bad = self.envelope(2)
        bad["signature"]["value"] = base64.b64encode(b"0" * 64).decode()
        with self.assertRaises(SecurityError):
            self.accept(bad)
        self.assertEqual(load_kev_revision_state(self.path)["signers"]["operator-lab"]["revision"], 1)

    def test_key_rotation_requires_approval(self):
        self.accept()
        other = Ed25519PrivateKey.generate()
        pem = other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(SecurityError):
            self.accept(self.envelope(2, other), trusted_public_pem=pem)

    def test_symlink_state_rejected(self):
        target = Path(self.tmp.name) / "other"
        target.write_text("{}")
        self.path.symlink_to(target)
        with self.assertRaises(SecurityError):
            self.accept()

    def test_insecure_state_rejected(self):
        self.accept()
        os.chmod(self.path, 0o644)
        with self.assertRaises(SecurityError):
            load_kev_revision_state(self.path)

    def test_corrupt_state_rejected(self):
        self.accept()
        self.path.write_text("[]")
        with self.assertRaises(SecurityError):
            self.accept(self.envelope(2))


if __name__ == "__main__":
    unittest.main()
