# M3 independent publisher-provenance integration gate

Status: **design and acceptance criteria only; NOT implemented or approved**. This document does not change trust anchors, authorise a feed, or make a claim that CISA publishes cryptographically signed KEV snapshots.

## Current boundary

`verify_kev_attestation` verifies a locally pinned **operator** Ed25519 signature and binds a KEV-format snapshot digest to an operator-provided revision and date. Its `publisher_authenticated: false` and `decision: human-review` outputs must remain unchanged until an independent publisher-authentication mechanism has been reviewed and integrated. The operator's `signer_id`, even when it says `CISA`, is not evidence of publisher identity. A HTTPS download, GitHub Actions signature, hash, mirror signature, or operator attestation alone is also insufficient to assert an independently authenticated CISA publisher.

## Required evidence before implementation

1. Record the publisher's **officially documented** distribution endpoint, ownership and available authenticity mechanism, with independently verifiable source evidence. Determine explicitly whether CISA offers signed KEV content or only a TLS-protected endpoint. Do not invent a CISA signing key, Sigstore identity or TUF root.
2. Specify the actual authentication guarantee: authenticated origin/transport is distinct from a content signature with independently established publisher keys. Where signed publisher content is unavailable, preserve `publisher_authenticated: false` and require human review.
3. Document an out-of-band, owner-approved trust-anchor bootstrap, key rotation and revocation procedure. Never trust keys, identities, root metadata or new URLs supplied solely by the candidate feed.
4. Define local persistent anti-rollback state, including atomic updates, restrictive permissions, independently retained recovery checkpoints, recovery after crash, and refusal to silently accept a lower revision. A self-declared revision cannot establish publisher freshness.
5. Define bounded fetch behaviour: explicit allowlisted endpoint, TLS certificate verification, redirect restrictions, timeouts, response-size limits, no credential leakage, and no publisher-supplied commands. Network access must be opt-in; local import and offline tests must continue working.
6. Record which decisions require owner approval, including enabling any newly authenticated publisher, adding `python-tuf` or `sigstore-python`, publishing trust anchors, or changing a trust policy.

## Acceptance tests (offline fixtures first)

- A correctly signed operator attestation is **not** accepted as publisher authentication.
- A feed containing a forged `publisher_authenticated` claim is rejected; no metadata field can bypass independent verification.
- An authentic snapshot from the wrong identity, endpoint or namespace is rejected.
- Tampered payloads, signature/key substitutions, expired metadata, wrong workflow identity and unsupported algorithms fail closed.
- Replay, rollback, freeze, metadata mix-and-match, and attempted state-file tampering fail closed, including after interrupted writes.
- An unavailable verification service, missing trust anchor or unverifiable provenance produces an explicit untrusted/human-review result; never silently downgrades to trust.
- Both `ogde` and `odge` entrypoints remain operational; no automatic upload, network scan, infrastructure change or response action is introduced.
- Privacy tests verify inventories and local findings are not transmitted without consent.

## Human gate and release evidence

Do not flip the publisher-authenticated flag or declare M3 complete until the owner approves the specific publisher-authentication evidence and trust anchors, independently retained rollback checkpoints exist, and CI plus security review establish the tests above. Record commit SHA, test logs and limitations in the development PR. The separate v0.3 phase gate (five pilot sites, four weeks, published false-positive rate) remains mandatory.
