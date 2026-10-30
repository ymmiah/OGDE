"""Finding contract, conflict rule, VEX suppression and priority order."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ogde.core import SecurityError
from ogde.finding import build_report, render_markdown

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "ab" * 32


def finding(**overrides):
    base = {
        "schema_version": 1,
        "finding_id": "F-1",
        "confidence": "confirmed",
        "component": {
            "purl": "pkg:npm/ogde-synthetic-leftpad@1.0.0",
            "name": "ogde-synthetic-leftpad",
            "version": "1.0.0",
        },
        "vulnerability": {"id": "OGDE-SYNTHETIC-1", "severity": "high"},
        "signals": {"kev_listed": False, "epss": 0.2, "internet_exposed": True},
        "affected": True,
        "evidence": [{"source": "ogde", "record_id": "synthetic-1", "digest_sha256": DIGEST}],
        "limitations": ["Synthetic demonstration record. It is not evidence of a real vulnerability."],
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merged = dict(base[key])
            merged.update(value)
            base[key] = merged
        else:
            base[key] = value
    return base


def document(*findings):
    return {"schema_version": 1, "findings": list(findings)}


def vex(status="not_affected", vuln="OGDE-SYNTHETIC-2", purl="pkg:composer/ogde/synthetic-demo@1.2.3", extra=None):
    statement = {
        "vulnerability": {"name": vuln},
        "products": [{"@id": purl}],
        "status": status,
    }
    if status == "not_affected":
        statement["justification"] = "vulnerable_code_not_present"
    if extra:
        statement.update(extra)
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.invalid/ogde/vex/test",
        "author": "OGDE test",
        "timestamp": "2026-10-30T00:00:00Z",
        "version": 1,
        "statements": [statement],
    }


class FindingContractTests(unittest.TestCase):
    def test_rejects_command_fields_and_control_characters(self):
        bad = finding()
        bad["command"] = "rm -rf /"
        with self.assertRaises(SecurityError):
            build_report(document(bad))
        bad = finding(limitations=["line one\nline two"])
        with self.assertRaises(SecurityError):
            build_report(document(bad))
        bad = finding(signals={"kev_listed": False, "epss": True, "internet_exposed": False})
        with self.assertRaises(SecurityError):
            build_report(document(bad))
        with self.assertRaises(SecurityError):
            build_report(document(finding()), epss_threshold="nan")
        suppressed = finding(confidence="suppressed")
        with self.assertRaises(SecurityError):
            build_report(document(suppressed))

    def test_priority_order_is_kev_then_epss_then_severity_then_exposure(self):
        rows = [
            finding(finding_id="exposed-high", vulnerability={"id": "OGDE-SYNTHETIC-A", "severity": "high"},
                    signals={"kev_listed": False, "epss": 0.05, "internet_exposed": True}),
            finding(finding_id="kev", vulnerability={"id": "OGDE-SYNTHETIC-B", "severity": "low"},
                    signals={"kev_listed": True, "epss": 0.01, "internet_exposed": False}),
            finding(finding_id="quiet-high", vulnerability={"id": "OGDE-SYNTHETIC-C", "severity": "high"},
                    signals={"kev_listed": False, "epss": 0.05, "internet_exposed": False}),
            finding(finding_id="epss", vulnerability={"id": "OGDE-SYNTHETIC-D", "severity": "low"},
                    signals={"kev_listed": False, "epss": 0.5, "internet_exposed": False}),
            finding(finding_id="critical", vulnerability={"id": "OGDE-SYNTHETIC-E", "severity": "critical"},
                    signals={"kev_listed": False, "epss": 0.05, "internet_exposed": True}),
        ]
        report = build_report(document(*rows), epss_threshold="0.1")
        self.assertEqual(
            [item["finding_id"] for item in report["findings"]],
            ["kev", "epss", "critical", "exposed-high", "quiet-high"],
        )
        self.assertEqual(report["findings"][0]["ranking"]["order"], 1)
        self.assertIn("meets the threshold", report["findings"][1]["ranking"]["factors"][1])
        boundary = build_report(document(finding(signals={"kev_listed": False, "epss": 0.1, "internet_exposed": False})))
        self.assertIn("meets the threshold of 0.1", boundary["findings"][0]["ranking"]["factors"][1])

    def test_conflict_keeps_both_claims(self):
        left = finding(finding_id="yes", affected=True, evidence=[{"source": "osv", "record_id": "OSV-1", "digest_sha256": DIGEST}])
        right = finding(finding_id="no", affected=False, confidence="probable",
                        evidence=[{"source": "wordfence", "record_id": "WF-1", "digest_sha256": "cd" * 32}])
        report = build_report(document(left, right))
        self.assertEqual(report["finding_count"], 2)
        self.assertTrue(all(item["confidence"] == "contested" for item in report["findings"]))
        self.assertEqual({item["affected"] for item in report["findings"]}, {True, False})
        self.assertTrue(all("has not chosen a winner" in " ".join(item["limitations"]) for item in report["findings"]))

    def test_vex_suppresses_only_exact_not_affected_statements(self):
        visible = finding(finding_id="stay")
        hidden = finding(
            finding_id="hide",
            component={"purl": "pkg:composer/ogde/synthetic-demo@1.2.3", "name": "ogde/synthetic-demo", "version": "1.2.3"},
            vulnerability={"id": "OGDE-SYNTHETIC-2", "severity": "medium"},
            signals={"kev_listed": False, "epss": None, "internet_exposed": False},
        )
        report = build_report(document(visible, hidden), vex=vex(extra={"impact_statement": "not | affected"}))
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["suppressed_count"], 1)
        self.assertEqual(report["findings"][0]["finding_id"], "stay")
        self.assertEqual(report["suppressed"][0]["confidence"], "suppressed")
        self.assertEqual(report["suppressed"][0]["vex"]["justification"], "vulnerable_code_not_present")
        different = vex(purl="pkg:composer/ogde/synthetic-demo@9.9.9")
        untouched = build_report(document(hidden), vex=different)
        self.assertEqual(untouched["finding_count"], 1)
        conflict = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://example.invalid/ogde/vex/test",
            "author": "OGDE test",
            "timestamp": "2026-10-30T00:00:00Z",
            "version": 1,
            "statements": [
                vex()["statements"][0],
                {"vulnerability": {"name": "OGDE-SYNTHETIC-2"}, "products": [{"@id": "pkg:composer/ogde/synthetic-demo@1.2.3"}], "status": "affected"},
            ],
        }
        contested = build_report(document(hidden), vex=conflict)
        self.assertEqual(contested["findings"][0]["confidence"], "contested")
        self.assertEqual(contested["suppressed_count"], 0)

    def test_empty_products_do_not_suppress_everything(self):
        hidden = finding(
            component={"purl": "pkg:composer/ogde/synthetic-demo@1.2.3", "name": "ogde/synthetic-demo", "version": "1.2.3"},
            vulnerability={"id": "OGDE-SYNTHETIC-2", "severity": "low"},
        )
        statement = vex()
        statement["statements"][0]["products"] = []
        with self.assertRaises(SecurityError):
            build_report(document(hidden), vex=statement)

    def test_markdown_escapes_owner_text_and_hides_suppressed_by_default(self):
        hidden = finding(
            finding_id="hide",
            component={"purl": "pkg:composer/ogde/synthetic-demo@1.2.3", "name": "ogde/synthetic-demo", "version": "1.2.3"},
            vulnerability={"id": "OGDE-SYNTHETIC-2", "severity": "medium"},
        )
        report = build_report(document(finding(), hidden), vex=vex(extra={"impact_statement": "not | affected"}))
        shown = {**report, "suppressed": []}
        text = render_markdown(shown)
        self.assertIn("| confirmed |", text)
        self.assertNotIn("OGDE-SYNTHETIC-2", text)
        self.assertIn("Suppressed findings: 1", text)
        audit = render_markdown(report)
        self.assertIn("not \\| affected", audit)
        self.assertTrue(report["transmitted"] is False)
        self.assertEqual(report["decision"], "human-review")

    def test_cli_audit_keeps_suppressed_findings_and_exit_code_ignores_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            markdown = Path(tmp) / "report.md"
            completed = subprocess.run(
                [sys.executable, "-m", "ogde", "report",
                 "--findings", str(ROOT / "examples" / "findings.example.json"),
                 "--vex", str(ROOT / "examples" / "vex.example.json"),
                 "--out", str(out), "--markdown", str(markdown)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn("1 visible, 1 suppressed", completed.stdout)
            saved = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(saved["suppressed_count"], 1)
            self.assertEqual(saved["suppressed"][0]["finding_id"], "F-composer")
            self.assertNotIn("F-composer", markdown.read_text(encoding="utf-8"))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            only_hidden = {
                "schema_version": 1,
                "findings": [finding(
                    component={"purl": "pkg:composer/ogde/synthetic-demo@1.2.3", "name": "ogde/synthetic-demo", "version": "1.2.3"},
                    vulnerability={"id": "OGDE-SYNTHETIC-2", "severity": "low"},
                )],
            }
            findings_path = Path(tmp) / "findings.json"
            vex_path = Path(tmp) / "vex.json"
            findings_path.write_text(json.dumps(only_hidden), encoding="utf-8")
            vex_path.write_text(json.dumps(vex()), encoding="utf-8")
            quiet = subprocess.run(
                [sys.executable, "-m", "ogde", "report", "--findings", str(findings_path), "--vex", str(vex_path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(quiet.returncode, 0, quiet.stderr)
            printed = json.loads(quiet.stdout)
            self.assertEqual(printed["finding_count"], 0)
            self.assertEqual(printed["suppressed"], [])
            self.assertEqual(printed["suppressed_count"], 1)


if __name__ == "__main__":
    unittest.main()
