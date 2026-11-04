# Audit integrity verification (M3, experimental)

The opt-in `verify_review_audit_record(record)` function checks the exact v1 schema, allowlisted fields, canonical timezone-aware timestamp, evidence digest syntax, and SHA-256 checksum. It returns a boolean without file writes or network access.

This is a **local integrity check**, not authentication: anyone able to edit a record can recompute its checksum. Store an independently authenticated checkpoint or signature under owner control before treating a record as trustworthy. Evidence hashes may reveal correlations and must not be published without review. It does not establish publisher provenance, prove an advisory is true, or authorise remediation.

This branch is stacked on `feat/m3-private-review-audit-20261104` (PR #30); review the parent before merging. It does not integrate audit storage with KEV acceptance, and the integrity check is not atomic with trusted-state writes. Existing `ogde` and legacy `odge` CLI behaviour remains unchanged.

## Verification — 4 November 2026

Local isolated feature-package verification: `PYTHONPATH=src python -m unittest discover -s tests -v`: **24 tests passed** (12 original plus 12 new); `python -m compileall -q src tests`: **passed**. This is not a full-repository test or CI verification. No live feeds, customer systems, network scans, merge or deployment.
