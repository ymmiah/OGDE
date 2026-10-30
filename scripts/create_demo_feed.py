#!/usr/bin/env python3
"""Generate a synthetic feed with fresh UTC times for an isolated demo.

The sample advisory and CVE alias are fabricated; never use these as real CTI.
"""
from __future__ import annotations
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

def utc(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--revision", type=int, default=1)
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    feed = {
        "schema_version": 2, "publisher_id": "ogde-lab", "feed_id": "lab-advisories",
        "revision": args.revision, "generated_at": utc(now), "expires_at": utc(now + timedelta(days=1)),
        "advisories": [{"id": "OGDE-SYNTHETIC-0001", "title": "Synthetic training-only package exposure",
                        "severity": "high", "affected": [{"purl": "pkg:pypi/synthetic-demo-lib", "versions": ["1.2.3"]}],
                        "remediation": "This is a training example only. Do not infer a real vulnerability.",
                        "references": []}]
    }
    Path(args.out).write_text(json.dumps(feed, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote synthetic feed {args.out}; not real threat intelligence")

if __name__ == "__main__":
    main()
