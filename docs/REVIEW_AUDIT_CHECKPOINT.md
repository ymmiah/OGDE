# M3 independently retained audit checkpoint contract

The optional offline `make_review_audit_checkpoint(entries)` creates an allowlisted checkpoint with schema, entry count and SHA-256 chain head. `verify_review_audit_checkpoint(entries, checkpoint)` validates exact checkpoint fields, count, head and every chain link. Missing or malformed checkpoint fields fail closed.

**Trust boundary:** A checkpoint is **not** authenticated by this module. The owner must retain and authenticate the checkpoint independently of the mutable audit chain. An attacker who controls both can rewrite both. This code does not provide trusted time, publisher provenance, CISA authentication, storage, network access, remediation, or automatic acceptance.

No existing `ogde` or legacy `odge` interface changes. This is stacked on PR #34 (which depends on PR #31 and PR #30); no merge or deployment.

## Actual verification — 5 November 2026

12/12 isolated checkpoint tests passed using Python unittest with locally reconstructed, functionally matching audit-record and chain dependencies. `python -m compileall -q src tests` passed. This is **not** verification of the full GitHub repository or GitHub Actions; CI and complete integration testing remain outstanding.
