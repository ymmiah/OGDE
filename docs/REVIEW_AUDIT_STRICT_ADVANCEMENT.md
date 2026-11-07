# M3 — Strict audit checkpoint advancement (7 November 2026)

The existing `verify_review_audit_continuity` function accepts an optional keyword-only `require_advance=False` flag. Setting it to `True` requires the current authenticated checkpoint to contain **more entries** than the previous authenticated checkpoint, rejecting same-checkpoint replay/no-op updates. The default preserves existing behaviour and legacy `odge` interfaces. Non-boolean flag values fail closed.

## Security and trust

The caller must authenticate and retain both checkpoints independently. This guard does not authenticate publishers, verify advisory truth, prove trustworthy timestamps, detect events never recorded, or make persistence atomic. It has no network, scanning, remediation or deployment behaviour. The function is not yet wired into the KEV state writer.

## Actual verification

**7 isolated tests passed** in a local reconstruction of the changed continuity control flow, using a simplified stub for the checkpoint verifier. Python compilation passed. This is *not* execution of the complete GitHub module and is not a cryptographic, full-repository, or CI verification. Seven corresponding repository-level regression tests were committed but have not been executed here. GitHub-hosted CI must run before review approval.

This branch is stacked on PR #36; no automatic merge or deployment.
