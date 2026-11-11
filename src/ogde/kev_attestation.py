"""Verify a signed KEV digest attestation against an independently pinned key.

Attests an operator-controlled signer, not CISA provenance or feed truth.
"""
from __future__ import annotations
import base64
import hashlib
import re
from datetime import date
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .core import SecurityError, canonical, public_key_id
from .kev_ingest import ingest_kev_snapshot
from .publisher_provenance import assess_publisher_provenance

_SHA = re.compile(r"[0-9a-f]{64}\Z")


def verify_kev_attestation(snapshot: object, attestation: object, *,
                           trusted_public_pem: bytes, expected_signer: str,
                           as_of: str, previous_revision: int = 0) -> dict:
    """Validate offline signed snapshot binding, validity window and monotonic revision."""
    if not isinstance(attestation, dict) or set(attestation) != {"statement", "signature"}:
        raise SecurityError("Invalid attestation envelope")
    statement, signature = attestation["statement"], attestation["signature"]
    required = {"kind", "schema_version", "signer_id", "snapshot_sha256",
                "revision", "valid_from", "valid_until"}
    if not isinstance(statement, dict) or set(statement) != required:
        raise SecurityError("Invalid attestation statement")
    if statement["kind"] != "ogde-kev-snapshot-attestation" or type(statement["schema_version"]) is not int or statement["schema_version"] != 1:
        raise SecurityError("Unsupported attestation statement")
    if not isinstance(expected_signer, str) or not expected_signer or len(expected_signer) > 100 or statement["signer_id"] != expected_signer:
        raise SecurityError("Signer identity is not independently pinned")
    digest = statement["snapshot_sha256"]
    if not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise SecurityError("Invalid attested digest")
    revision = statement["revision"]
    if type(revision) is not int or type(previous_revision) is not int or not 1 <= revision <= 2**53 or not 0 <= previous_revision < revision:
        raise SecurityError("Attestation revision is not newer than trusted state")
    try:
        today = date.fromisoformat(as_of)
        start = date.fromisoformat(statement["valid_from"])
        end = date.fromisoformat(statement["valid_until"])
        if any(d.isoformat() != s for d, s in ((today, as_of), (start, statement["valid_from"]), (end, statement["valid_until"]))):
            raise ValueError("Noncanonical date")
    except (TypeError, ValueError, AttributeError) as exc:
        raise SecurityError("Invalid attestation date") from exc
    if not start <= today <= end or end < start or (end - start).days > 30:
        raise SecurityError("Attestation is outside validity policy")
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "value"} or signature["algorithm"] != "Ed25519":
        raise SecurityError("Unsupported attestation signature")
    try:
        public = serialization.load_pem_public_key(trusted_public_pem)
        if not isinstance(public, Ed25519PublicKey) or signature["key_id"] != public_key_id(public):
            raise SecurityError("Untrusted attestation signing key")
        encoded = signature["value"]
        if not isinstance(encoded, str):
            raise SecurityError("Invalid signature encoding")
        sig = base64.b64decode(encoded, validate=True)
        if len(sig) != 64:
            raise SecurityError("Invalid signature length")
        public.verify(sig, canonical(statement))
    except (ValueError, TypeError, InvalidSignature, KeyError) as exc:
        raise SecurityError("KEV attestation signature verification failed") from exc
    receipt = ingest_kev_snapshot(snapshot, expected_sha256=digest)
    # A verified operator signature is not independent publisher provenance.
    # Route the result through the single fail-closed assessment boundary.
    provenance = assess_publisher_provenance(statement)
    return {
        "kind": "ogde-kev-attestation-verification",
        "snapshot_digest_sha256": receipt["digest_sha256"],
        "signer_id": expected_signer,
        "signer_key_id": public_key_id(public),
        "revision": revision,
        "signature_verified": True,
        "publisher_authenticated": provenance.publisher_authenticated,
        "decision": provenance.decision,
        "limitations": [
            "This verifies the independently pinned operator signer, not CISA as publisher.",
            "Signed metadata does not establish the truth, completeness or applicability of KEV entries.",
            "Replay protection requires independently protected, persistently updated revision state.",
            "The as_of date is operator supplied and is not a trusted timestamp.",
        ],
    }
