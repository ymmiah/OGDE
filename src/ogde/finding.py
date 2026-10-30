"""Local finding contract for the v0.3 verified loop.

A finding is evidence for a person to review. It is never an instruction to a
system. This module does not fetch intelligence and does not contact a network.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from .core import SecurityError, parse_purl
from .localio import load_json_file

CONFIDENCE = {"confirmed", "probable", "contested"}
OUTPUT_CONFIDENCE = CONFIDENCE | {"suppressed"}
SEVERITY = {"critical", "high", "medium", "low", "unknown"}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
VEX_STATUS = {"not_affected", "affected", "fixed", "under_investigation"}
JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
VEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SOURCE = re.compile(r"^[a-z][a-z0-9_-]{0,32}$")
_RECORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_THRESHOLD = re.compile(r"0(?:\.\d{1,6})?|1(?:\.0{1,6})?")
_MAX_FINDINGS = 2000

_REPORT_LIMITATIONS = [
    "This report checks the local finding contract only. It does not verify a TUF or Sigstore feed.",
    "A signature would prove who signed a record, not that the claim is true.",
    "OGDE did not fetch OSV, CISA KEV, EPSS or Wordfence while building this report.",
    "Suppressed findings stay in the local audit file. They are not a deletion.",
    "Nothing in this report changes the system under assessment, and nothing was uploaded.",
]


def parse_threshold(value: object) -> float:
    """Accept the plan's default of 0.1 and any other probability from 0 to 1."""
    if isinstance(value, str):
        if not _THRESHOLD.fullmatch(value):
            raise SecurityError("EPSS threshold must be a decimal from 0 to 1")
        number = float(value)
    elif type(value) is float or type(value) is int:
        number = float(value)
    else:
        raise SecurityError("EPSS threshold must be a decimal from 0 to 1")
    if not math.isfinite(number) or number < 0 or number > 1:
        raise SecurityError("EPSS threshold must be a decimal from 0 to 1")
    return number


def _text(value: object, label: str, pattern: re.Pattern[str] | None = None, *, max_length: int = 300) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise SecurityError(f"Invalid {label}")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SecurityError(f"Invalid {label}")
    if pattern is not None and not pattern.fullmatch(value):
        raise SecurityError(f"Invalid {label}")
    return value


def _exact_keys(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise SecurityError(f"Invalid {label}")
    return value


def _number(value: object) -> float:
    if type(value) is bool or not isinstance(value, (int, float)):
        raise SecurityError("EPSS score must be a number from 0 to 1 or null")
    number = float(value)
    if not math.isfinite(number) or number < 0 or number > 1:
        raise SecurityError("EPSS score must be a number from 0 to 1 or null")
    return number


def validate_finding(value: object) -> dict:
    """Return a copy containing only the finding contract. Unknown fields are rejected."""
    item = _exact_keys(value, {
        "schema_version", "finding_id", "confidence", "component", "vulnerability",
        "signals", "affected", "evidence", "limitations",
    }, "finding")
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise SecurityError("Unsupported finding schema")
    finding_id = _text(item["finding_id"], "finding id", _ID)
    if item["confidence"] not in CONFIDENCE:
        raise SecurityError("Invalid confidence")
    component = _exact_keys(item["component"], {"purl", "name", "version"}, "component")
    purl = _text(component["purl"], "package URL", max_length=1024)
    if any(mark in purl for mark in ("?", "#", " ")):
        raise SecurityError("Package URL must not include a query, fragment or space")
    kind, name, version = parse_purl(purl)
    if version is None:
        raise SecurityError("Package URL must include a version")
    if component["name"] != name or component["version"] != version:
        raise SecurityError("Component name and version must match the package URL")
    vulnerability = _exact_keys(item["vulnerability"], {"id", "severity"}, "vulnerability")
    vuln_id = _text(vulnerability["id"], "vulnerability id", _ID)
    if vulnerability["severity"] not in SEVERITY:
        raise SecurityError("Invalid severity")
    signals = _exact_keys(item["signals"], {"kev_listed", "epss", "internet_exposed"}, "signals")
    if type(signals["kev_listed"]) is not bool or type(signals["internet_exposed"]) is not bool:
        raise SecurityError("Invalid signals")
    epss = None if signals["epss"] is None else _number(signals["epss"])
    if type(item["affected"]) is not bool:
        raise SecurityError("Invalid affected claim")
    evidence_in = item["evidence"]
    if not isinstance(evidence_in, list) or not 1 <= len(evidence_in) <= 8:
        raise SecurityError("A finding needs between 1 and 8 evidence records")
    evidence = []
    for record in evidence_in:
        fields = _exact_keys(record, {"source", "record_id", "digest_sha256"}, "evidence")
        evidence.append({
            "source": _text(fields["source"], "evidence source", _SOURCE),
            "record_id": _text(fields["record_id"], "evidence record", _RECORD),
            "digest_sha256": _text(fields["digest_sha256"], "evidence digest", _DIGEST),
        })
    limitations_in = item["limitations"]
    if not isinstance(limitations_in, list) or not 1 <= len(limitations_in) <= 6:
        raise SecurityError("A finding needs between 1 and 6 limitations")
    limitations = [_text(entry, "limitation", max_length=300) for entry in limitations_in]
    return {
        "schema_version": 1,
        "finding_id": finding_id,
        "confidence": item["confidence"],
        "assessed_confidence": item["confidence"],
        "component": {"purl": purl, "name": name, "version": version, "type": kind},
        "vulnerability": {"id": vuln_id, "severity": vulnerability["severity"]},
        "signals": {"kev_listed": signals["kev_listed"], "epss": epss, "internet_exposed": signals["internet_exposed"]},
        "affected": item["affected"],
        "evidence": evidence,
        "limitations": limitations,
        "decision": "human-review",
    }


def load_findings_document(value: object) -> list[dict]:
    document = _exact_keys(value, {"schema_version", "findings"}, "findings document")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise SecurityError("Unsupported findings schema")
    findings = document["findings"]
    if not isinstance(findings, list) or len(findings) > _MAX_FINDINGS:
        raise SecurityError("Invalid findings list")
    parsed = [validate_finding(item) for item in findings]
    ids = [item["finding_id"] for item in parsed]
    if len(ids) != len(set(ids)):
        raise SecurityError("Duplicate finding id")
    return parsed


def _validate_vex(value: object) -> list[dict]:
    document = _exact_keys(value, {"@context", "@id", "author", "timestamp", "version", "statements"}, "VEX document")
    if document["@context"] != VEX_CONTEXT:
        raise SecurityError("Unsupported VEX context")
    _text(document["@id"], "VEX id", max_length=200)
    _text(document["author"], "VEX author", max_length=200)
    timestamp = _text(document["timestamp"], "VEX timestamp", max_length=40)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp):
        raise SecurityError("VEX timestamp must be UTC ISO 8601 with trailing Z")
    if type(document["version"]) is not int or not 1 <= document["version"] <= 1_000_000:
        raise SecurityError("Invalid VEX version")
    statements = document["statements"]
    if not isinstance(statements, list) or not statements or len(statements) > 500:
        raise SecurityError("Invalid VEX statements")
    parsed = []
    for index, statement in enumerate(statements):
        allowed = {"vulnerability", "products", "status", "justification", "impact_statement"}
        if not isinstance(statement, dict) or not set(statement) <= allowed or not {"vulnerability", "products", "status"} <= set(statement):
            raise SecurityError("Invalid VEX statement")
        vulnerability = _exact_keys(statement["vulnerability"], {"name"}, "VEX vulnerability")
        products_in = statement["products"]
        if not isinstance(products_in, list) or not 1 <= len(products_in) <= 20:
            raise SecurityError("A VEX statement must name the products it covers")
        products = []
        for product in products_in:
            fields = _exact_keys(product, {"@id"}, "VEX product")
            purl = _text(fields["@id"], "VEX product", max_length=1024)
            _kind, _name, version = parse_purl(purl)
            if version is None:
                raise SecurityError("VEX product URL must include a version")
            products.append(purl)
        status = statement["status"]
        if status not in VEX_STATUS:
            raise SecurityError("Invalid VEX status")
        justification = statement.get("justification")
        if status == "not_affected":
            if justification not in JUSTIFICATIONS:
                raise SecurityError("A not_affected VEX statement needs a justification")
        elif justification is not None and justification not in JUSTIFICATIONS:
            raise SecurityError("Invalid VEX justification")
        detail = None
        if "impact_statement" in statement:
            detail = _text(statement["impact_statement"], "VEX impact statement", max_length=400)
        parsed.append({
            "statement_id": f"{document['@id']}#{index}",
            "vulnerability": _text(vulnerability["name"], "VEX vulnerability name", _ID),
            "products": products,
            "status": status,
            "justification": justification,
            "detail": detail,
        })
    return parsed


def _mark_conflicts(findings: list[dict]) -> None:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for finding in findings:
        grouped.setdefault((finding["component"]["purl"], finding["vulnerability"]["id"]), []).append(finding)
    for group in grouped.values():
        claims = {item["affected"] for item in group}
        if claims == {True, False}:
            for item in group:
                item["confidence"] = "contested"
                note = "Trusted sources disagree on whether this version is affected. OGDE has not chosen a winner."
                if note not in item["limitations"]:
                    item["limitations"].append(note)


def _apply_vex(findings: list[dict], statements: list[dict]) -> None:
    for finding in findings:
        matches = [
            statement for statement in statements
            if statement["vulnerability"] == finding["vulnerability"]["id"]
            and finding["component"]["purl"] in statement["products"]
        ]
        if not matches:
            continue
        statuses = {statement["status"] for statement in matches}
        if "not_affected" in statuses and len(statuses) > 1:
            finding["confidence"] = "contested"
            note = "VEX statements disagree about this finding. OGDE has not chosen a winner."
            if note not in finding["limitations"]:
                finding["limitations"].append(note)
            continue
        if statuses == {"not_affected"}:
            chosen = matches[0]
            finding["confidence"] = "suppressed"
            vex = {
                "statement_id": chosen["statement_id"],
                "status": "not_affected",
                "justification": chosen["justification"],
            }
            if chosen["detail"]:
                vex["detail"] = chosen["detail"]
            finding["vex"] = vex


def ranking_factors(finding: dict, threshold: float) -> list[str]:
    signals = finding["signals"]
    shown_threshold = f"{threshold:.6f}".rstrip("0").rstrip(".")
    factors = []
    if signals["kev_listed"]:
        factors.append("Local record marks the vulnerability as listed in CISA KEV. This command did not fetch the catalogue.")
    else:
        factors.append("Local record does not mark the vulnerability as listed in CISA KEV.")
    epss = signals["epss"]
    if epss is None:
        factors.append(f"No EPSS score was supplied. The threshold is {shown_threshold}.")
    else:
        score = f"{epss:.6f}".rstrip("0").rstrip(".")
        if epss >= threshold:
            factors.append(f"EPSS {score} meets the threshold of {shown_threshold}.")
        else:
            factors.append(f"EPSS {score} is below the threshold of {shown_threshold}.")
    factors.append(f"CVSS severity on the local record: {finding['vulnerability']['severity']}.")
    if signals["internet_exposed"]:
        factors.append("The local record marks the asset as internet exposed.")
    else:
        factors.append("The local record does not mark the asset as internet exposed.")
    return factors


def _rank(finding: dict, threshold: float) -> tuple:
    signals = finding["signals"]
    epss = signals["epss"]
    meets = epss is not None and epss >= threshold
    return (
        0 if signals["kev_listed"] else 1,
        0 if meets else 1,
        SEVERITY_RANK[finding["vulnerability"]["severity"]],
        0 if signals["internet_exposed"] else 1,
        finding["vulnerability"]["id"],
        finding["component"]["purl"],
        finding["finding_id"],
    )


def build_report(document: object, *, vex: object | None = None, epss_threshold: object = 0.1) -> dict:
    """Validate findings, record conflicts, apply VEX, and sort the visible ones.

    The returned report always keeps suppressed findings for the local audit.
    """
    threshold = parse_threshold(epss_threshold)
    findings = load_findings_document(document)
    _mark_conflicts(findings)
    if vex is not None:
        _apply_vex(findings, _validate_vex(vex))
    for finding in findings:
        finding["ranking"] = {"factors": ranking_factors(finding, threshold)}
    visible = [item for item in findings if item["confidence"] != "suppressed"]
    suppressed = [item for item in findings if item["confidence"] == "suppressed"]
    visible.sort(key=lambda item: _rank(item, threshold))
    suppressed.sort(key=lambda item: (item["vulnerability"]["id"], item["component"]["purl"], item["finding_id"]))
    for index, finding in enumerate(visible, start=1):
        finding["ranking"]["order"] = index
    return {
        "schema_version": 1,
        "kind": "ogde-finding-report",
        "decision": "human-review",
        "transmitted": False,
        "epss_threshold": threshold,
        "finding_count": len(visible),
        "suppressed_count": len(suppressed),
        "findings": visible,
        "suppressed": suppressed,
        "limitations": list(_REPORT_LIMITATIONS),
    }


def load_report_inputs(findings_path: str | Path, vex_path: str | Path | None = None) -> tuple[object, object | None]:
    """Read local JSON without following symlinks."""
    document = load_json_file(findings_path)
    vex = load_json_file(vex_path) if vex_path else None
    return document, vex


def _cell(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("`", "\\`")


def render_markdown(report: dict) -> str:
    """Markdown for a person. Confidence is the first column. Suppressed rows are included only when present."""
    lines = [
        "# OGDE local finding report",
        "",
        "This is a local assessment for human review. It is not proof of exploitation and it does not change any system.",
        "",
        f"**Visible findings:** {report['finding_count']}",
        f"**Suppressed findings:** {report['suppressed_count']}",
        f"**EPSS threshold:** {report['epss_threshold']}",
        "",
        "| Confidence | Vulnerability | Component | Affected | Why it is ranked here |",
        "| --- | --- | --- | --- | --- |",
    ]
    rows = report["findings"]
    if not rows:
        lines.append("| — | No visible findings | — | — | Continue defence in depth |")
    for finding in rows:
        lines.append("| " + " | ".join(_cell(value) for value in [
            finding["confidence"],
            finding["vulnerability"]["id"],
            finding["component"]["purl"],
            "yes" if finding["affected"] else "no",
            "; ".join(finding["ranking"]["factors"]),
        ]) + " |")
    if report["suppressed"]:
        lines += ["", "## Suppressed", "", "Hidden from the default view. Kept in this local audit.", ""]
        for finding in report["suppressed"]:
            vex = finding.get("vex", {})
            reason = vex.get("justification", "")
            detail = vex.get("detail")
            suffix = f" ({_cell(detail)})" if detail else ""
            lines.append(
                f"- `{_cell(finding['vulnerability']['id'])}` on `{_cell(finding['component']['purl'])}` — {_cell(reason)}{suffix}"
            )
    elif report["suppressed_count"]:
        lines += ["", f"Suppressed findings: {report['suppressed_count']}. They are omitted here and kept when the audit file is written.", ""]
    lines += ["", "## Limitations", ""]
    lines += [f"- {item}" for item in report["limitations"]]
    lines += ["", "_An authorised person decides what happens next. OGDE does not._", ""]
    text = "\n".join(lines)
    if len(text.encode("utf-8")) > 2 * 1024 * 1024:
        raise SecurityError("Markdown report exceeds 2 MiB")
    return text
