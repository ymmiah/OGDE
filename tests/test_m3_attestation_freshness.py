"""M3 offline freshness gate: operator signatures cannot override validity policy.

This does not authenticate CISA or enable any publisher trust.
"""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ogde.core import SecurityError, canonical, public_key_id
from ogde.kev_revision_state import accept_kev_attestation


class OperatorAttestationFreshnessTests(unittest.TestCase):
    def test_resigned_future_and_overlong_validity_never_create_revision_state(self):
        key = Ed25519PrivateKey.generate()
        pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        snapshot = {
            "vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-25"}]
        }
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "revision.json"
            for start, end in (
                ("2026-11-10", "2026-11-11"),  # Not yet valid.
                ("2026-10-01", "2026-11-09"),  # Longer than 30 days.
                ("2026-10-25", "2026-11-08"),  # Expired.
            ):
                with self.subTest(start=start, end=end):
                    statement = {
                        "kind": "ogde-kev-snapshot-attestation",
                        "schema_version": 1,
                        "signer_id": "operator-lab",
                        "snapshot_sha256": hashlib.sha256(canonical(snapshot)).hexdigest(),
                        "revision": 1,
                        "valid_from": start,
                        "valid_until": end,
                    }
                    attestation = {
                        "statement": statement,
                        "signature": {
                            "algorithm": "Ed25519",
                            "key_id": public_key_id(key.public_key()),
                            "value": base64.b64encode(key.sign(canonical(statement))).decode("ascii"),
                        },
                    }
                    with self.assertRaises(SecurityError):
                        accept_kev_attestation(
                            snapshot, attestation, state_path=state,
                            trusted_public_pem=pem, expected_signer="operator-lab",
                            as_of="2026-11-09",
                        )
                    self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
