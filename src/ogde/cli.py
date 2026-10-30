"""Minimal CLI with explicit boundaries: verify before use; ask before sharing inventory."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import sys
from pathlib import Path
from urllib.parse import quote
from . import __version__
from .core import (SecurityError, generate_keypair, parse_sbom, read_json,
                   scan_signed_feed, sign_feed, utc_now, verify_envelope, write_json)
from .ledger import append_event, verify_ledger
from .osv import scan_osv
from .immunity import add_publisher, assess, safe_save
from .policy import markdown_report


def local_inventory() -> dict:
    comps = []
    for dist in importlib.metadata.distributions():
        name, version = dist.metadata.get("Name"), dist.version
        if name and version:
            normal = name.lower().replace("_", "-")
            comps.append({"type": "library", "name": name, "version": version, "purl": f"pkg:pypi/{quote(normal, safe='-._~')}@{quote(version, safe='-._~') }"})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"timestamp": utc_now(), "tools": [{"name": "One Global Defence Ecosystem", "version": __version__}]}, "components": sorted(comps, key=lambda x: (x["name"].lower(), x["version"]))}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ogde", description="One Global Defence Ecosystem: zero-trust, local-first threat matching")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="Generate local Ed25519 signing keys; keep private key secret")
    k.add_argument("--private", required=True); k.add_argument("--public", required=True)
    s = sub.add_parser("sign", help="Create a cryptographically signed advisory feed")
    s.add_argument("--feed", required=True); s.add_argument("--private", required=True); s.add_argument("--out", required=True)
    v = sub.add_parser("verify", help="Verify signer identity, feed signature, schema, and expiry")
    v.add_argument("--feed", required=True); v.add_argument("--public", required=True)
    inv = sub.add_parser("inventory-python", help="Produce a local CycloneDX inventory from current Python environment")
    inv.add_argument("--out", required=True)
    scan = sub.add_parser("scan", help="Match local CycloneDX SBOM against a trusted signed feed")
    scan.add_argument("--feed", required=True); scan.add_argument("--public", required=True); scan.add_argument("--sbom", required=True); scan.add_argument("--out"); scan.add_argument("--ledger")
    live = sub.add_parser("scan-osv", help="Optional online version-specific OSV queries")
    live.add_argument("--sbom", required=True); live.add_argument("--confirm-inventory-sharing", action="store_true"); live.add_argument("--out")
    check = sub.add_parser("verify-ledger", help="Check local audit hash chain")
    check.add_argument("--ledger", required=True)
    trust = sub.add_parser("trust-add", help="Pin an independently verified publisher key to a feed")
    trust.add_argument("--registry", required=True); trust.add_argument("--public", required=True)
    trust.add_argument("--publisher-id", required=True); trust.add_argument("--feed-id", required=True)
    trust.add_argument("--confirm-trust-anchor", action="store_true")
    evaluate = sub.add_parser("assess", help="Verify federated feed v2, reject rollback, triage local SBOM")
    evaluate.add_argument("--registry", required=True); evaluate.add_argument("--feed", required=True)
    evaluate.add_argument("--sbom", required=True); evaluate.add_argument("--context", required=True)
    evaluate.add_argument("--state", required=True); evaluate.add_argument("--kev-file")
    evaluate.add_argument("--out"); evaluate.add_argument("--markdown"); evaluate.add_argument("--ledger")
    evaluate.add_argument("--fail-on", default="any", choices=["any", "none", "P0", "P1", "P2", "P3", "P4"],
                          help="CI gate: nonzero exit for findings at this priority or higher (default any)")
    return p


def run(args) -> int:
    if args.cmd == "trust-add":
        receipt = add_publisher(args.registry, public=args.public, publisher_id=args.publisher_id,
                                feed_id=args.feed_id, acknowledged=args.confirm_trust_anchor)
        print(json.dumps({"pinned": receipt}, indent=2)); return 0
    if args.cmd == "assess":
        report = assess(args.registry, read_json(args.feed), read_json(args.sbom),
                        read_json(args.context), args.state,
                        read_json(args.kev_file) if args.kev_file else None)
        if args.ledger:
            append_event(args.ledger, {"type": "federated-assessment", "feed_id": report["feed_id"],
                       "revision": report["revision"], "asset": report["asset"]["asset_id"],
                       "digest": report["feed_digest_sha256"], "findings": report["finding_count"]})
        if args.out:
            safe_save(args.out, report)
        else:
            print(json.dumps(report, indent=2))
        if args.markdown:
            from .immunity import safe_save_text
            safe_save_text(args.markdown, markdown_report(report))
        if args.fail_on == "none":
            return 0
        if args.fail_on == "any":
            return 2 if report["finding_count"] else 0
        return 2 if any(int(f["priority"][1:]) <= int(args.fail_on[1:]) for f in report["findings"]) else 0
    if args.cmd == "keygen":
        print("Public key SHA-256 fingerprint:", generate_keypair(args.private, args.public)); return 0
    if args.cmd == "sign":
        write_json(args.out, sign_feed(read_json(args.feed), args.private)); print(f"Signed feed written to {args.out}"); return 0
    if args.cmd == "verify":
        feed = verify_envelope(read_json(args.feed), args.public); print(json.dumps({"verified": True, "feed_id": feed["feed_id"], "advisories": len(feed["advisories"])}, indent=2)); return 0
    if args.cmd == "inventory-python":
        write_json(args.out, local_inventory()); print(f"Local inventory written to {args.out}"); return 0
    if args.cmd == "verify-ledger":
        print(json.dumps(verify_ledger(args.ledger), indent=2)); return 0
    if args.cmd == "scan":
        feed = verify_envelope(read_json(args.feed), args.public)
        report = scan_signed_feed(feed, parse_sbom(read_json(args.sbom)))
        if args.ledger:
            append_event(args.ledger, {"type": "scan", "source": report["source"], "feed_id": report["feed_id"], "components_checked": report["components_checked"], "finding_count": report["finding_count"]})
    elif args.cmd == "scan-osv":
        if not args.confirm_inventory_sharing:
            raise SecurityError("You must pass --confirm-inventory-sharing; package names and versions will be sent to OSV")
        report = scan_osv(parse_sbom(read_json(args.sbom)))
    else:
        raise SecurityError("Unsupported command")
    if args.out:
        write_json(args.out, report)
        print(f"Report written to {args.out}")
    else:
        print(json.dumps(report, indent=2))
    return 2 if report["finding_count"] else 0


def main() -> int:
    try:
        return run(parser().parse_args())
    except (SecurityError, FileNotFoundError, PermissionError, OSError) as exc:
        print(f"OGDE error: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
