# M3 — Offline audit checkpoint continuity

The opt-in `verify_review_audit_continuity(entries, previous_checkpoint, current_checkpoint)` function checks that a complete current audit chain is valid, and that its prefix matches an independently retained earlier checkpoint. This rejects rollback, truncation and rewrites of the anchored prefix. An unchanged checkpoint is permitted.

**Trust boundary:** Both checkpoint objects must be independently authenticated and supplied by the owner. This module cannot establish checkpoint authenticity, publisher provenance, trusted timestamps or completeness of unrecorded events. It does not perform I/O, accept external instructions, advance KEV trusted revision state or authorise remediation. It preserves legacy `odge` and existing `ogde` interfaces.

**Verification (6 November 2026):** Python 3 local isolated feature test run with reconstructed copies of the three existing audit dependencies from accessible GitHub source: `PYTHONPATH=src python -m unittest discover -s tests -v` — **15/15 passed**; `python -m compileall -q src tests` — **passed**. These results are **not** full-repository tests or GitHub Actions CI.

**Review dependency:** stacked on `feat/m3-audit-checkpoint-contract-20261105` (PR #35), which depends on earlier audit PRs. Do not merge until dependency review and repository CI pass. No production deployment.
