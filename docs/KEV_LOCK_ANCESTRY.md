# M3 — KEV lock ancestry hardening

The POSIX revision lock wrapper now calls the existing `validate_kev_state_path` helper **before** creating or opening the sidecar lock. Previously, the state reader/writer checked the full ancestry but the lock wrapper only checked the immediate parent; a nested symlink in an ancestor could redirect lock creation before later state validation failed.

Six regression tests cover immediate and nested symlink ancestors, target symlinks and missing directories, checking that no lock file is created. They also check that an existing state file and an existing private lock file remain unchanged when accessed through a redirected ancestor. This does not prevent time-of-check/time-of-use races if an attacker can modify parent directories. Use trusted owner-controlled directories, POSIX permissions, cooperative locking and independent revision checkpoints.

## Verification

GitHub Actions run 213 passed the full repository test and source-compilation workflow for the initial four-test commit (a52388842b469a683414019054d48ab17413929b). The two subsequent regression tests are committed but their CI execution is **not yet confirmed**; verify the new head's workflow separately. No live network scans, external feed acceptance, production deployment or change to `ogde`/`odge` interfaces.

## Follow-up hardening — 8 November 2026

The shared state-path guard additionally rejects existing directory and FIFO targets **before** the lock wrapper creates a sidecar. Two repository regression tests assert that these invalid targets leave no lock file behind. Four isolated guard tests (directory, FIFO, symlinked ancestor and valid missing target) passed on the local Python interpreter; source compilation passed. This isolated test does not exercise the complete signed KEV acceptance path. The new head commit's GitHub Actions CI was not yet available at the time of this documentation update.
