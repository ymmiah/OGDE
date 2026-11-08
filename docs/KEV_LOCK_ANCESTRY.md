# M3 — KEV lock ancestry hardening

The POSIX revision lock wrapper now calls the existing `validate_kev_state_path` helper **before** creating or opening the sidecar lock. Previously, the state reader/writer checked the full ancestry but the lock wrapper only checked the immediate parent; a nested symlink in an ancestor could redirect lock creation before later state validation failed.

Six regression tests cover immediate and nested symlink ancestors, target symlinks and missing directories, checking that no lock file is created. They also check that an existing state file and an existing private lock file remain unchanged when accessed through a redirected ancestor. This does not prevent time-of-check/time-of-use races if an attacker can modify parent directories. Use trusted owner-controlled directories, POSIX permissions, cooperative locking and independent revision checkpoints.

## Verification

GitHub Actions run 213 passed the full repository test and source-compilation workflow for the initial four-test commit (a52388842b469a683414019054d48ab17413929b). The two subsequent regression tests are committed but their CI execution is **not yet confirmed**; verify the new head's workflow separately. No live network scans, external feed acceptance, production deployment or change to `ogde`/`odge` interfaces.

## Follow-up hardening — 8 November 2026

The shared state-path guard additionally rejects existing directory and FIFO targets **before** the lock wrapper creates a sidecar. Two repository regression tests assert that these invalid targets leave no lock file behind. Four isolated guard tests (directory, FIFO, symlinked ancestor and valid missing target) passed on the local Python interpreter; source compilation passed. This isolated test does not exercise the complete signed KEV acceptance path. The new head commit's GitHub Actions CI was not yet available at the time of this documentation update.

## Hardlink alias defence (8 November 2026)

The lock wrapper now requires the opened lock inode to have exactly one hard link (`fstat().st_nlink == 1`) in addition to requiring a private regular file. This prevents the cooperative lock path from aliasing an unrelated, hardlinked private file. A regression test constructs a private unrelated file, hardlinks it as the lock, invokes locked acceptance, and asserts the original file and state remain unchanged. The lock inode is inspected after opening, reducing path-substitution exposure at that check; it is **not** a defence against an attacker with write access to trusted parent directories. No new external dependencies or public interfaces were introduced.

**Verification status:** Source and regression test committed. Full repository CI for the new head has not yet been confirmed; do not treat this addition as independently validated until CI completes. The required v0.3 pilot gate is still outstanding.

## Hardlinked revision-state defence — 8 November 2026

The revision-state path guard now rejects an existing regular state file whose link count is not exactly one, before opening or creating the sidecar lock. This closes an aliasing case analogous to the lock-file hardlink defence: the same inode must not be writable through a second operator-uncontrolled path. A regression test checks that a hardlinked state target is rejected, its original bytes remain unchanged and no sidecar is created.

**Verification scope:** an independently reconstructed copy of the path-guard logic passed eight local POSIX isolated checks (hardlink, private file, public permissions, FIFO, directory, target symlink, ancestor symlink and missing target); Python compilation passed. This is **not** a test of the imported repository module or the full KEV acceptance integration. The repository could not be cloned in the local execution environment because DNS resolution for GitHub failed. GitHub Actions returned no workflow runs for the new head commit at the time checked. Full repository CI and integrated signature/checkpoint validation remain unverified. Do not merge or deploy based solely on this isolated result.
