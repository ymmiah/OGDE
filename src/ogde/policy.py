"""Deterministic, explainable risk triage. Only recommendations, never enforcement."""
from __future__ import annotations
import re
from .core import SecurityError

VALID_ENV = {"production", "staging", "development"}
VALID_SENSITIVITY = {"public", "internal", "restricted"}
VALID_SEVERITY = {"critical", "high", "medium", "low", "unknown"}
PRIORITY_NAMES = {"P0": "Immediate human incident triage", "P1": "Urgent remediation review", "P2": "Prioritised remediation", "P3": "Scheduled remediation", "P4": "Review and monitor"}


def validate_context(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {"asset_id", "environment", "internet_exposed", "criticality", "data_sensitivity"}:
        raise SecurityError("Asset context requires asset_id, environment, internet_exposed, criticality, data_sensitivity")
    if not isinstance(value["asset_id"], str) or not re.fullmatch(r"[\w.:-]{1,128}", value["asset_id"], re.UNICODE):
        raise SecurityError("Invalid asset identifier")
    if value["environment"] not in VALID_ENV or type(value["internet_exposed"]) is not bool or type(value["criticality"]) is not int or not (1 <= value["criticality"] <= 5) or value["data_sensitivity"] not in VALID_SENSITIVITY:
        raise SecurityError("Invalid asset context attributes")
    return dict(value)


def _priority(severity: str, context: dict, in_kev: bool):
    if severity not in VALID_SEVERITY:
        raise SecurityError("Unexpected severity")
    high_impact = context["criticality"] >= 4 or context["data_sensitivity"] == "restricted"
    exposed = context["internet_exposed"]
    production = context["environment"] == "production"
    reasons = [f"Signed publisher severity: {severity}",
               f"Locally supplied environment: {context['environment']}",
               f"Locally supplied internet exposure: {str(exposed).lower()}"]
    if in_kev:
        reasons.append("CVE listed in user-supplied CISA-format KEV snapshot; source authenticity not verified by OGDE; never definitive exploitation evidence")
        priority = "P1" if exposed or production or high_impact else "P2"
    elif severity == "critical":
        priority = "P1" if exposed or high_impact else "P2"
    elif severity == "high":
        priority = "P1" if exposed and high_impact else "P2" if exposed or high_impact else "P3"
    elif severity == "medium":
        priority = "P2" if exposed and high_impact else "P3"
    else:
        priority = "P4"
    if high_impact:
        reasons.append("Asset marked as critical/high sensitivity by its owner")
    return priority, reasons


def enrich_report(report: dict, context: dict, kev: dict | None) -> dict:
    found = []
    for finding in report["findings"]:
        aliases = {finding["advisory_id"], *finding.get("aliases", [])}
        kev_matches = sorted(aliases & kev.keys()) if kev is not None else []
        priority, reasons = _priority(finding["severity"], context, bool(kev_matches))
        enriched = dict(finding)
        enriched.update({"priority": priority, "decision": "human-review", "reasons": reasons,
                         "kev_snapshot_match": kev_matches, "recommended_action": PRIORITY_NAMES[priority]})
        found.append(enriched)
    found.sort(key=lambda f: (int(f["priority"][1:]), f["advisory_id"], f["purl"]))
    report["findings"] = found
    report["priorities"] = {p: sum(f["priority"] == p for f in found) for p in PRIORITY_NAMES}
    report["known_exploited_matches_from_unverified_snapshot"] = sum(bool(f["kev_snapshot_match"]) for f in found)
    return report


def markdown_report(report: dict) -> str:
    def cell(value):
        return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("`", "\\`")
    lines = ["# One Global Defence Ecosystem — Exposure Assessment", "", f"**Asset:** `{cell(report['asset']['asset_id'])}`",
             f"**Publisher:** `{cell(report['publisher']['publisher_id'])}`", f"**Feed revision:** {report['revision']}",
             f"**Components inspected:** {report['components_checked']}", f"**Findings:** {report['finding_count']}",
             "", "| Priority | Advisory | Component | Suggested next step |", "| --- | --- | --- | --- |"]
    for f in report["findings"]:
        lines.append("| " + " | ".join(cell(v) for v in [f["priority"], f["advisory_id"], f["purl"], f["recommended_action"]]) + " |")
    if not report["findings"]:
        lines.append("| — | No exact-version matches | — | Continue defence-in-depth |")
    lines += ["", "## Limitations", ""]
    lines += ["- " + item for item in report["limitations"]]
    lines += ["", "_All recommendations require an authorised human review. A match does not prove exploitation._", ""]
    return "\n".join(lines)
