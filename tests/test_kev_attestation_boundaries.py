"""Offline M3 trust-boundary regression tests; no network access or publisher trust claims."""
import base64
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ogde.core import SecurityError, canonical, public_key_id
from ogde.kev_attestation import verify_kev_attestation


class KevAttestationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.snapshot = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-25"}]}
        self.statement = {
            "kind": "ogde-kev-snapshot-attestation",
            "schema_version": 1,
            "signer_id": "operator-lab",
            "snapshot_sha256": hashlib.sha256(canonical(self.snapshot)).hexdigest(),
            "revision": 2,
            "valid_from": "2026-10-25",
            "valid_until": "2026-11-10",
        }

    def verify(self, *, as_of="2026-11-01", signature_override=None, **kwargs):
        signature = {
            "algorithm": "Ed25519",
            "key_id": public_key_id(self.key.public_key()),
            "value": base64.b64encode(self.key.sign(canonical(self.statement))).decode("ascii"),
        }
        if signature_override:
            signature.update(signature_override)
        return verify_kev_attestation(
            self.snapshot, {"statement": self.statement, "signature": signature},
            trusted_public_pem=self.pem, expected_signer="operator-lab",
            as_of=as_of, previous_revision=1, **kwargs
        )

    def test_validity_window_includes_first_day_but_never_authenticates_publisher(self):
        result = self.verify(as_of="2026-10-25")
        self.assertTrue(result["signature_verified"])
        self.assertIs(result["publisher_authenticated"], False)
        self.assertEqual(result["decision"], "human-review")

    def test_validity_window_includes_last_day_but_never_authenticates_publisher(self):
        result = self.verify(as_of="2026-11-10")
        self.assertTrue(result["signature_verified"])
        self.assertIs(result["publisher_authenticated"], False)

    def test_rejects_noncanonical_statement_date_even_when_signed(self):
        self.statement["valid_from"] = "2026-10-5"
        with self.assertRaisesRegex(SecurityError, "Invalid attestation date"):
            self.verify()

    def test_rejects_unrecognised_signature_metadata(self):
        with self.assertRaisesRegex(SecurityError, "Unsupported attestation signature"):
            self.verify(signature_override={"publisher_authenticated": True})

    def test_rejects_malformed_base64_signature(self):
        with self.assertRaises(SecurityError):
            self.verify(signature_override={"value": "not-base64!"})

    def test_rejects_short_signature(self):
        with self.assertRaisesRegex(SecurityError, "Invalid signature length"):
            self.verify(signature_override={"value": base64.b64encode(b"short").decode("ascii")})


if __name__ == "__main__":
    unittest.main()
