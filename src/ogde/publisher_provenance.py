"""Fail-closed, offline publisher-provenance assessment for M3.

This boundary deliberately cannot grant publisher authentication. A future
publisher-specific verifier requires independently reviewed trust anchors.
"""

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class PublisherProvenanceAssessment:
    publisher_authenticated: bool
    decision: str
    reason: str
    operator_signature_verified: bool

    def as_dict(self) -> dict[str, bool | str]:
        return {
            "publisher_authenticated": self.publisher_authenticated,
            "decision": self.decision,
            "reason": self.reason,
            "operator_signature_verified": self.operator_signature_verified,
        }


def assess_publisher_provenance(
    operator_attestation: Mapping[str, Any] | None = None,
) -> PublisherProvenanceAssessment:
    """Never infer independent publisher trust from an operator's statement.

    This function is intentionally non-promoting until an owner-approved,
    independently authenticated publisher verifier exists.
    """
    if operator_attestation is not None and not isinstance(operator_attestation, Mapping):
        raise TypeError("operator_attestation must be a mapping or None")

    return PublisherProvenanceAssessment(
        publisher_authenticated=False,
        decision="human-review",
        reason="independent-publisher-authentication-not-established",
        operator_signature_verified=False,
    )
