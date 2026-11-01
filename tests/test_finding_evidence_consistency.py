"""Offline regression checks for contradictory evidence identifiers."""
import unittest
from ogde.core import SecurityError
from ogde.finding import validate_finding


def sample():
    return {
        "schema_version": 1, "finding_id": "test-1", "confidence": "probable",
        "component": {"purl": "pkg:pypi/demo@1.0", "name": "demo", "version": "1.0"},
        "vulnerability": {"id": "CVE-2026-12345", "severity": "unknown"},
        "signals": {"kev_listed": False, "epss": None, "internet_exposed": False},
        "affected": True,
        "evidence": [{"source": "local", "record_id": "record-1", "digest_sha256": "a" * 64}],
        "limitations": ["Synthetic test only; not independently verified."],
    }


class FindingEvidenceConsistencyTests(unittest.TestCase):
    def test_single_record_is_valid(self):
        self.assertEqual(validate_finding(sample())["decision"], "human-review")

    def test_same_identity_different_digest_rejected(self):
        finding = sample()
        finding["evidence"].append({"source": "local", "record_id": "record-1", "digest_sha256": "b" * 64})
        with self.assertRaisesRegex(SecurityError, "Conflicting digests"):
            validate_finding(finding)

    def test_different_record_identity_allowed(self):
        finding = sample()
        finding["evidence"].append({"source": "local", "record_id": "record-2", "digest_sha256": "b" * 64})
        self.assertEqual(len(validate_finding(finding)["evidence"]), 2)

    def test_same_identity_same_digest_allowed(self):
        finding = sample()
        finding["evidence"].append(dict(finding["evidence"][0]))
        self.assertEqual(len(validate_finding(finding)["evidence"]), 2)


if __name__ == "__main__":
    unittest.main()
