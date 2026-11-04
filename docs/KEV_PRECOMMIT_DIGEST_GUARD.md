# Precommit digest consistency guard — M3

The review-gated KEV acceptance path now compares the digest returned by the review pipeline with the digest in the signed-attestation statement **before** invoking the locked revision-state writer. This closes a failure mode where the previous post-write consistency check could detect a mismatch only after state advancement. The post-write receipt comparison remains a defence-in-depth assertion, not a transactional rollback mechanism.

## Verification — 4 November 2026

Four isolated regression scenarios were executed locally using stubbed dependencies and a reconstructed copy of the changed review-gate logic: mismatched digest, missing digest, wrong digest type and blocked review. **4 passed**; Python compilation **passed**. This verifies the guard's control flow in isolation, **not** the complete GitHub repository, cryptographic verification, integration behaviour or CI. The committed tests use mocks around the same boundary. Full repository CI remains pending.

This change is stacked on the unmerged review-gated acceptance branch (PR #29); review and reconcile dependencies before merge. It does not introduce a new feed, alter trust anchors, scan systems, deploy, publish secrets, or change the legacy `odge` CLI. Human approval is required for consequential actions.
