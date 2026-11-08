# M3 — KEV lock ancestry hardening

The POSIX revision lock wrapper now calls the existing `validate_kev_state_path` helper **before** creating or opening the sidecar lock. Previously, the state reader/writer checked the full ancestry but the lock wrapper only checked the immediate parent; a nested symlink in an ancestor could redirect lock creation before later state validation failed.

Four regression tests cover immediate and nested symlink ancestors, target symlinks and missing directories, checking that no lock file is created. This does not prevent time-of-check/time-of-use races if an attacker can modify parent directories. Use trusted owner-controlled directories, POSIX permissions, cooperative locking and independent revision checkpoints.

## Verification

The new tests are committed to GitHub; their execution is **not yet confirmed**. GitHub Actions must verify the complete repository suite and source compilation. No live network scans, external feed acceptance, production deployment or change to `ogde`/`odge` interfaces.
