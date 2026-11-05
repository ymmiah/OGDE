# M3: fail-closed malformed KEV review contract

The signed KEV acceptance gate now rejects non-object review responses and reviews with missing, null, string or object `issues` fields **before** calling the trusted revision writer. An empty list is the only acceptable issue collection, and the review status must explicitly be `requires-human-review`.

This hardens the existing review-gated acceptance path; it does not add publisher authentication, audit persistence, automatic remediation or any network operations. Existing `ogde` and legacy `odge` CLI interfaces are unchanged.

## Verification status — 5 November 2026

Nine committed regression tests cover malformed and blocked review responses and assert that the state writer is not called. **GitHub CI and full repository test execution are pending verification.** The tests are not evidence of passing until executed in the repository environment. No merge or deployment was performed.

This change is stacked on the precommit digest guard branch (PR #32), itself based on review-gated KEV acceptance (PR #29). Review and reconcile parent branches before merging. No unverified advisory is elevated to authoritative status.
