# M3: KEV revision-state path ancestry guard

The local KEV revision-state reader and single-writer API now reject a symlink in any existing ancestor directory, not just the immediate parent. This prevents an operator-supplied nested path from silently traversing a symlink into another directory. The check is fail-closed and runs before loading or writing revision state.

**Verification — 8 November 2026:** Seven isolated path-guard regression tests passed on Python 3.13.5 (valid existing/missing files, target symlink, immediate and higher-level ancestor symlink, dangling parent symlink, missing directory). Python compilation passed. Tests used a minimal `SecurityError` stub for the standalone module; full repository integration and GitHub Actions remain unverified.

**Limitations:** Path checks are not race-free. An attacker with write access to ancestor directories could replace path components after validation. Use owner-controlled directories, appropriate filesystem permissions and independent revision checkpoints. This change does not claim to solve TOCTOU races, cryptographic publisher authentication or rollback from compromised storage. No network calls, scanning, deployment or remediation. The existing `ogde` and legacy `odge` CLI signatures are unchanged.
