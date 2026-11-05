# M3: checkpoint-verified signed KEV acceptance

**Status:** experimental, offline, human-controlled. This extends the existing
`accept_kev_attestation_locked` API without changing the legacy `odge` CLI.

## Operation

```python
from ogde.kev_revision_locked import accept_kev_attestation_locked

# snapshot and attestation are locally supplied and validated.
# trusted_public_pem must be independently authenticated and pinned.
# previous_checkpoint must be retrieved from independently protected storage.
result = accept_kev_attestation_locked(
    snapshot,
    attestation,
    state_path=".ogde-local/kev-revisions.json",
    trusted_public_pem=trusted_public_pem,
    expected_signer="operator-lab",
    as_of="2026-11-02",
    checkpoint=previous_checkpoint,  # None only for deliberate initial bootstrap
)
# Store result["revision_checkpoint"] independently, outside the state trust
# boundary, before considering this acceptance durably anchored.
```

Under the same POSIX advisory lock, the function checks that the current local
revision state exactly matches the supplied independently retained checkpoint
*before* verifying the new attestation and writing the next revision. It returns
a new checkpoint for out-of-band retention and a
`previous_checkpoint_verified` boolean.

A checkpoint is a SHA-256 consistency witness, **not** a digital signature,
trusted timestamp or CISA publisher authentication. It detects a rolled-back,
deleted or rewritten state only when the correct checkpoint is retained and
supplied independently. Supplying `None` bypasses checkpoint comparison to
preserve existing integrations; production operators must enforce their own
bootstrap and checkpoint-required policy.

## Failure handling and limitations

- Any mismatch raises `SecurityError` before accepting the new revision.
  Investigate; do not silently delete the checkpoint or reset the state.
- The local state update and external checkpoint publication are **not** one
  distributed transaction. If publication fails after a state update, stop and
  reconcile with an independently verified record; do not blindly retry using
  an older checkpoint.
- Every cooperating writer must use the locked API and preserve the stable
  sidecar lock. Locking is not a defence against a malicious filesystem owner,
  hostile ancestor directories or unreliable network filesystem locks.
- Operator-supplied `as_of` is not a trusted clock. Signed operator attestations
  are **not** proof of original CISA publication or of asset compromise.
- No network access, autonomous remediation, trust-anchor bootstrap or
  production deployment is performed.

## Verification

`tests/test_kev_revision_locked.py` covers successful checkpoint advancement,
rollback, deletion, stale checkpoint, altered checkpoint and pre-existing
signature/replay/permission checks. GitHub Actions runs the suite on proposed
changes; record actual CI results in the pull request.
