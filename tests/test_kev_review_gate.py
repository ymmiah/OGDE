"""Signed KEV review gate: blocked reviews must not mutate trusted state."""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ogde.core import SecurityError, canonical, public_key_id
from ogde.kev_review_gate import review_and_accept_signed_kev
from ogde.kev_revision_state import load_kev_revision_state


class SignedReviewGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "revision.json"
        self.key = Ed25519PrivateKey.generate()
        self.pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.snapshot = {"vulnerabilities": [
            {"cveID": "CVE-2026-12345", "dateAdded": "2026-10-25"}]}
        self.findings = {"schema_version": 1, "findings": []}

    def envelope(self, revision=1):
        statement = {
            "kind": "ogde-kev-snapshot-attestation", "schema_version": 1,
            "signer_id": "operator-lab",
            "snapshot_sha256": hashlib.sha256(canonical(self.snapshot)).hexdigest(),
            "revision": revision, "valid_from": "2026-10-25",
            "valid_until": "2026-11-10",
        }
        return {"statement": statement, "signature": {
            "algorithm": "Ed25519", "key_id": public_key_id(self.key.public_key()),
            "value": base64.b64encode(self.key.sign(canonical(statement))).decode()}}

    def review(self, envelope=None, **kwargs):
        params = dict(state_path=self.state, trusted_public_pem=self.pem,
                      expected_signer="operator-lab", snapshot_date="2026-10-25",
                      as_of="2026-11-01", max_age_days=7)
        params.update(kwargs)
        return review_and_accept_signed_kev(
            self.snapshot, self.findings, envelope if envelope is not None else self.envelope(), **params)

    def test_review_pass_advances_state(self):
        result = self.review()
        self.assertEqual(result["decision"], "human-review")
        self.assertFalse(result["attestation"]["publisher_authenticated"])
        self.assertEqual(load_kev_revision_state(self.state)["signers"]["operator-lab"]["revision"], 1)

    def test_stale_review_does_not_create_state(self):
        with self.assertRaises(SecurityError):
            self.review(max_age_days=6)
        self.assertFalse(self.state.exists())

    def test_stale_review_does_not_advance_existing_state(self):
        self.review()
        with self.assertRaises(SecurityError):
            self.review(self.envelope(2), max_age_days=6)
        self.assertEqual(load_kev_revision_state(self.state)["signers"]["operator-lab"]["revision"], 1)

    def test_invalid_digest_does_not_create_state(self):
        envelope = self.envelope()
        envelope["statement"]["snapshot_sha256"] = "0" * 64
        with self.assertRaises(SecurityError):
            self.review(envelope)
        self.assertFalse(self.state.exists())

    def test_bad_signature_does_not_create_state(self):
        envelope = self.envelope()
        envelope["signature"]["value"] = base64.b64encode(b"0" * 64).decode()
        with self.assertRaises(SecurityError):
            self.review(envelope)
        self.assertFalse(self.state.exists())

    def test_replayed_revision_rejected(self):
        self.review()
        with self.assertRaises(SecurityError):
            self.review()
        self.assertEqual(load_kev_revision_state(self.state)["signers"]["operator-lab"]["revision"], 1)


if __name__ == "__main__":
    unittest.main()
