import base64
import hashlib
import unittest
from datetime import date
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ogde.core import SecurityError, canonical, public_key_id
from ogde.kev_attestation import verify_kev_attestation


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.snapshot = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-25"}]}
        self.statement = {
            "kind": "ogde-kev-snapshot-attestation", "schema_version": 1,
            "signer_id": "operator-lab", "snapshot_sha256": hashlib.sha256(canonical(self.snapshot)).hexdigest(),
            "revision": 2, "valid_from": "2026-10-25", "valid_until": "2026-11-10"
        }

    def envelope(self):
        return {"statement": dict(self.statement), "signature": {
            "algorithm": "Ed25519", "key_id": public_key_id(self.key.public_key()),
            "value": base64.b64encode(self.key.sign(canonical(self.statement))).decode("ascii")
        }}

    def verify(self, envelope=None, **kwargs):
        options = {"trusted_public_pem": self.pem, "expected_signer": "operator-lab",
                   "as_of": "2026-11-01", "previous_revision": 1}
        options.update(kwargs)
        return verify_kev_attestation(self.snapshot, envelope if envelope is not None else self.envelope(), **options)

    def test_valid_signature_and_snapshot(self):
        result = self.verify()
        self.assertTrue(result["signature_verified"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertEqual(result["revision"], 2)

    def test_operator_signature_never_authenticates_cisa(self):
        """A valid operator signature must not be promoted to publisher provenance."""
        result = self.verify()
        self.assertIs(result["publisher_authenticated"], False)
        self.assertEqual(result["decision"], "human-review")
        self.assertIn("not CISA as publisher", " ".join(result["limitations"]))

    def test_forged_publisher_claim_in_statement_rejected(self):
        """Signed but unsupported provenance fields must fail schema validation."""
        self.statement["publisher_authenticated"] = True
        with self.assertRaisesRegex(SecurityError, "Invalid attestation statement"):
            self.verify()

    def test_forged_publisher_claim_in_envelope_rejected(self):
        envelope = self.envelope()
        envelope["publisher_authenticated"] = True
        with self.assertRaisesRegex(SecurityError, "Invalid attestation envelope"):
            self.verify(envelope)

    def test_signature_from_other_operator_cannot_impersonate_pinned_signer(self):
        other_key = Ed25519PrivateKey.generate()
        other_pem = other_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        envelope = self.envelope()
        envelope["signature"]["key_id"] = public_key_id(other_key.public_key())
        envelope["signature"]["value"] = base64.b64encode(
            other_key.sign(canonical(self.statement))).decode("ascii")
        with self.assertRaises(SecurityError):
            self.verify(envelope, trusted_public_pem=other_pem)

    def test_tampered_snapshot_rejected(self):
        self.snapshot["vulnerabilities"][0]["cveID"] = "CVE-2026-99999"
        with self.assertRaises(SecurityError):
            self.verify()

    def test_tampered_statement_rejected(self):
        envelope = self.envelope()
        envelope["statement"]["revision"] = 3
        with self.assertRaises(SecurityError):
            self.verify(envelope)

    def test_wrong_pinned_key_rejected(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(SecurityError):
            self.verify(trusted_public_pem=other)

    def test_wrong_signer_rejected(self):
        with self.assertRaises(SecurityError):
            self.verify(expected_signer="other")

    def test_replayed_revision_rejected(self):
        with self.assertRaises(SecurityError):
            self.verify(previous_revision=2)

    def test_expired_attestation_rejected(self):
        with self.assertRaises(SecurityError):
            self.verify(as_of="2026-11-11")

    def test_future_attestation_rejected(self):
        with self.assertRaises(SecurityError):
            self.verify(as_of="2026-10-24")

    def test_invalid_date_rejected(self):
        with self.assertRaises(SecurityError):
            self.verify(as_of="2026-11-1")

    def test_boolean_revision_rejected(self):
        with self.assertRaises(SecurityError):
            self.verify(previous_revision=True)


if __name__ == "__main__":
    unittest.main()
