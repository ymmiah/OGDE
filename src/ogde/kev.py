"""Locally imported KEV reference snapshot. No claim about its provenance.

CISA KEV lists CVEs known to be exploited; it does not establish that any
particular asset has been exploited or that a product/version is affected.
"""
from __future__ import annotations
import re
from .core import SecurityError

CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def kev_index(data: object) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise SecurityError("Expected a CISA-format KEV JSON snapshot")
    if len(data["vulnerabilities"]) > 20000:
        raise SecurityError("KEV snapshot exceeds entry limit")
    index = {}
    for row in data["vulnerabilities"]:
        if not isinstance(row, dict) or not isinstance(row.get("cveID"), str) or not CVE.fullmatch(row["cveID"]):
            raise SecurityError("Malformed KEV vulnerability")
        if row["cveID"] in index:
            raise SecurityError("Duplicate KEV CVE")
        index[row["cveID"]] = {
            "cve": row["cveID"],
            "date_added": row.get("dateAdded") if isinstance(row.get("dateAdded"), str) else None,
            "ransomware_campaign": row.get("knownRansomwareCampaignUse") == "Known",
        }
    return index
