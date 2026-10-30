"""Focused safety cases for real-world federation design, all offline and synthetic."""
from __future__ import annotations
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ogde.core import SecurityError, generate_keypair, sign_feed, canonical, read_json, write_json
from ogde.immunity import add_publisher, assess, safe_save, trusted_feed
from ogde.policy import markdown_report, validate_context
from ogde.kev import kev_index


def iso(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def v2feed(revision=1, severity="high", pub="ogde-lab", feed_id="lab-advisories"):
    now = datetime.now(timezone.utc)
    return {"schema_version": 2, "publisher_id": pub, "feed_id": feed_id, "revision": revision,
            "generated_at": iso(now), "expires_at": iso(now + timedelta(hours=12)), "advisories": [
                {"id": "OGDE-EXAMPLE-1", "title": "Synthetic test package", "severity": severity,
                 "affected": [{"purl": "pkg:pypi/synthetic-demo-lib", "versions": ["1.2.3"]}],
                 "aliases": ["CVE-2026-99999"], "references": [], "remediation": "Remove or upgrade this synthetic package"}]}


def example_sbom(version="1.2.3"):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "synthetic-demo-lib", "version": version,
         "purl": f"pkg:pypi/synthetic-demo-lib@{version}"}]}


def example_context(**kwargs):
    return {"asset_id": "demo-app", "environment": "production", "internet_exposed": True,
            "criticality": 4, "data_sensitivity": "internal", **kwargs}


class FederationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.private = self.root / "publisher.pem"
        self.public = self.root / "publisher.pub"
        self.registry = self.root / "trust.json"
        self.state = self.root / "state.json"
        generate_keypair(self.private, self.public)
        add_publisher(self.registry, public=self.public, publisher_id="ogde-lab",
                      feed_id="lab-advisories", acknowledged=True)

    def tearDown(self):
        self.tmp.cleanup()

    def assessment(self, feed=None, sbom=None, context=None, kev=None):
        return assess(self.registry, sign_feed(feed or v2feed(), self.private),
                      sbom or example_sbom(), context or example_context(), self.state, kev)

    def test_assess_signed_synthetic_feed(self):
        report = self.assessment()
        self.assertEqual(report["revision"], 1)
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["findings"][0]["priority"], "P1")
        self.assertEqual(report["findings"][0]["decision"], "human-review")

    def test_same_revision_identical_data_accepted(self):
        self.assessment()
        self.assessment()

    def test_same_revision_different_data_blocked(self):
        self.assessment()
        with self.assertRaisesRegex(SecurityError, "Equivocated"):
            self.assessment(v2feed(severity="low"))

    def test_old_revision_blocked(self):
        self.assessment(v2feed(revision=3))
        with self.assertRaisesRegex(SecurityError, "rollback"):
            self.assessment(v2feed(revision=2))

    def test_new_revision_is_accepted(self):
        self.assessment()
        self.assertEqual(self.assessment(v2feed(revision=2))["revision"], 2)

    def test_tampering_does_not_advance_state(self):
        envelope = sign_feed(v2feed(revision=7), self.private)
        envelope["payload"]["revision"] = 100
        with self.assertRaises(SecurityError):
            assess(self.registry, envelope, example_sbom(), example_context(), self.state)
        self.assertFalse(self.state.exists())

    def test_publisher_mismatch_rejected(self):
        envelope = sign_feed(v2feed(pub="evil-org"), self.private)
        with self.assertRaisesRegex(SecurityError, "No pinned"):
            trusted_feed(self.registry, envelope)

    def test_unpinned_key_rejected(self):
        other_priv = self.root / "other.pem"
        other_pub = self.root / "other.pub"
        generate_keypair(other_priv, other_pub)
        with self.assertRaisesRegex(SecurityError, "pinned trusted key"):
            trusted_feed(self.registry, sign_feed(v2feed(), other_priv))

    def test_registration_requires_explicit_trust(self):
        with self.assertRaisesRegex(SecurityError, "out-of-band"):
            add_publisher(self.root / "new.json", public=self.public, publisher_id="ogde-lab",
                          feed_id="next", acknowledged=False)

    def test_duplicate_feed_prohibited(self):
        with self.assertRaisesRegex(SecurityError, "already pinned"):
            add_publisher(self.registry, public=self.public, publisher_id="ogde-lab",
                          feed_id="lab-advisories", acknowledged=True)

    def test_untrusted_local_kevs_do_not_execute(self):
        snapshot = {"vulnerabilities": [{"cveID": "CVE-2026-99999", "dateAdded": "2026-10-01"}]}
        report = self.assessment(kev=snapshot)
        self.assertEqual(report["findings"][0]["priority"], "P1")
        self.assertIn("not verified", " ".join(report["findings"][0]["reasons"]))
        self.assertEqual(report["findings"][0]["decision"], "human-review")

    def test_no_match_is_not_false_assurance(self):
        report = self.assessment(sbom=example_sbom(version="9.9.9"))
        self.assertEqual(report["finding_count"], 0)
        self.assertTrue(any("absence" in s for s in report["limitations"]))

    def test_invalid_context_fails_without_state(self):
        with self.assertRaises(SecurityError):
            self.assessment(context={"asset_id": "x"})
        self.assertFalse(self.state.exists())

    def test_symlink_state_rejected(self):
        target = self.root / "hidden.json"
        target.write_text('{}')
        self.state.symlink_to(target)
        with self.assertRaises(SecurityError):
            self.assessment()
        self.assertEqual(target.read_text(), '{}')

    def test_trust_registry_permissions(self):
        if os.name == "posix":
            self.assertEqual(self.registry.stat().st_mode & 0o777, 0o600)

    def test_signed_v1_not_allowed_for_federation(self):
        v1 = v2feed()
        for k in ("publisher_id", "revision"):
            v1.pop(k)
        v1["schema_version"] = 1
        with self.assertRaisesRegex(SecurityError, "version 2"):
            trusted_feed(self.registry, sign_feed(v1, self.private))

    def test_cli_end_to_end_assessment_and_gate(self):
        paths = {"feed": self.root/"feed.json", "sbom": self.root/"sbom.json",
                 "context": self.root/"context.json", "out": self.root/"result.json", "markdown":self.root/"result.md"}
        write_json(paths["feed"], sign_feed(v2feed(), self.private))
        write_json(paths["sbom"], example_sbom())
        write_json(paths["context"], example_context())
        proc = subprocess.run([sys.executable, "-m", "ogde", "assess", "--registry", str(self.registry),
                               "--feed", str(paths["feed"]), "--sbom", str(paths["sbom"]),
                               "--context", str(paths["context"]), "--state", str(self.state),
                               "--out", str(paths["out"]), "--markdown", str(paths["markdown"]),
                               "--fail-on", "P2"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(read_json(paths["out"])["finding_count"], 1)
        self.assertIn("Exposure Assessment", paths["markdown"].read_text())

    def test_markdown_table_escaping(self):
        report = self.assessment()
        report["findings"][0]["advisory_id"] = "demo|evil"
        self.assertIn("demo\\|evil", markdown_report(report))


class ValidationTests(unittest.TestCase):
    def test_invalid_kev_cve(self):
        with self.assertRaises(SecurityError):
            kev_index({"vulnerabilities": [{"cveID": "not-a-cve"}]})

    def test_kev_duplicate_rejected(self):
        with self.assertRaises(SecurityError):
            kev_index({"vulnerabilities": [{"cveID": "CVE-2026-1234"}, {"cveID": "CVE-2026-1234"}]})

    def test_context_cannot_be_boolean_criticality(self):
        with self.assertRaises(SecurityError):
            validate_context({**example_context(), "criticality": True})

    def test_version_2_requires_strict_revision(self):
        with tempfile.TemporaryDirectory() as d:
            priv, pub = Path(d)/"priv", Path(d)/"pub"
            generate_keypair(priv, pub)
            with self.assertRaises(SecurityError):
                sign_feed(v2feed(revision=True), priv)

    def test_safe_save_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d)/"private"
            dest.write_text("original")
            alias = Path(d)/"alias"
            alias.symlink_to(dest)
            with self.assertRaises(SecurityError):
                safe_save(alias, {"x": 1})
            self.assertEqual(dest.read_text(), "original")

if __name__ == "__main__":
    unittest.main()
