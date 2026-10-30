"""Explicitly opt-in OSV queries. No local remediation or remote scanning."""
from __future__ import annotations

import json
from urllib.request import Request, urlopen
from .core import Component, SecurityError, canonical, utc_now

API_URL = "https://api.osv.dev/v1/querybatch"
ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io"}
MAX_RESPONSE = 8 * 1024 * 1024


def query_batch(queries: list[dict]) -> list[dict]:
    payload = canonical({"queries": queries})
    req = Request(API_URL, data=payload, headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "OGDE/0.1.0"}, method="POST")
    try:
        with urlopen(req, timeout=20) as resp:
            if resp.status != 200:
                raise SecurityError(f"OSV returned status {resp.status}")
            body = resp.read(MAX_RESPONSE + 1)
    except (OSError, TimeoutError) as exc:
        raise SecurityError(f"OSV query unavailable: {type(exc).__name__}") from exc
    if len(body) > MAX_RESPONSE:
        raise SecurityError("OSV response exceeded size limit")
    try:
        result = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise SecurityError("OSV returned invalid JSON") from exc
    if not isinstance(result, dict) or not isinstance(result.get("results"), list) or len(result["results"]) != len(queries):
        raise SecurityError("OSV returned unexpected query result count")
    return result["results"]


def _as_query(c: Component) -> dict:
    name = c.name
    if c.kind == "maven":
        group, sep, artifact = name.partition("/")
        if not sep or not group or not artifact or "/" in artifact:
            raise SecurityError("Maven PURL needs group/artifact")
        name = f"{group}:{artifact}"
    return {"package": {"name": name, "ecosystem": ECOSYSTEMS[c.kind]}, "version": c.version}


def scan_osv(components: list[Component]) -> dict:
    """OSV matches a version server-side; we never infer affected version ranges."""
    supported = [c for c in components if c.kind in ECOSYSTEMS]
    unique: dict[tuple[str, str, str], Component] = {(c.kind, c.name, c.version): c for c in supported}
    if len(unique) > 1000:
        raise SecurityError("OSV query limit is 1000 packages per scan; split your inventory")
    found: list[dict] = []
    for n in range(0, len(unique), 50):
        part = list(unique.values())[n:n + 50]
        pending = [(_as_query(c), c) for c in part]
        iterations = 0
        while pending:
            iterations += 1
            if iterations > 25:
                raise SecurityError("OSV pagination exceeded safety limit; no incomplete report emitted")
            query_results = query_batch([q for q, _ in pending])
            next_pending = []
            for (query, c), result in zip(pending, query_results):
                if not isinstance(result, dict) or not isinstance(result.get("vulns", []), list):
                    raise SecurityError("Malformed OSV result")
                for vuln in result.get("vulns", []):
                    if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                        raise SecurityError("Malformed OSV vulnerability")
                    found.append({"advisory_id": vuln["id"], "purl": c.purl, "version": c.version, "modified": vuln.get("modified"), "basis": "OSV version query", "reference": "https://osv.dev/vulnerability/" + vuln["id"]})
                token = result.get("next_page_token")
                if token:
                    if not isinstance(token, str) or len(token) > 2048:
                        raise SecurityError("Invalid OSV pagination token")
                    next_pending.append(({**query, "page_token": token}, c))
            pending = next_pending
    seen = set()
    deduped = []
    for f in found:
        key = (f["advisory_id"], f["purl"], f["version"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return {"source": "OSV API", "scanned_at": utc_now(), "components_checked": len(unique), "components_skipped": len(components) - len(supported), "finding_count": len(deduped), "findings": deduped, "limitations": ["Only ecosystems supported by this client are queried", "OSV records and affected-version data may be incomplete", "Package names and versions are sent to OSV with explicit consent", "No exploitation tests or automatic fixes performed"]}
