# OGDE — One Global Defence Ecosystem

**Official short name: OGDE.** The mistaken ODGE spelling is retained only as a backwards-compatible Python import and CLI alias.

**Defend locally. Verify globally. Recover together.**

> **v0.2.2 experimental developer preview:** signed federated advisory feeds, pinned trust anchors, local anti-rollback, CycloneDX software exposure matching, explainable policy decisions and optional offline KEV reference matching. No claims of universal protection or production readiness.

## New in v0.2

- `ogde trust-add` pins an independently verified publisher key to its signed feed identity.
- `ogde assess` rejects tampered, expired, untrusted, replayed or equivocated advisory feeds, matches exact versions and produces auditable local results.
- Source material and CVE descriptions are treated as **data, never executable instructions**.
- `--fail-on P2` creates a fail-closed CI safety gate, but findings never trigger autonomous production modifications.
- The optional KEV snapshot is unverified local input; matching a CVE does not prove exploitation.
- Weekly GitHub Actions tests and Dependabot update proposals support sustainable continuous improvement.

**Quick start:** see [Federated v2 full walkthrough](docs/FEDERATION_V2.md) and [autonomy roadmap](docs/ROADMAP_AUTONOMY.md).

## Core principles

1. **Local control:** never scan or change third-party systems.
2. **Independent trust:** pin a verified publisher identity before accepting an advisory.
3. **Truth over theatrics:** a valid signature authenticates the signer, not the advisory's claims.
4. **Evidence-based decisions:** provide explainable reasons and limitations.
5. **Fail-closed design:** reject missing trust, incompatible schemas, expired feeds and rollbacks.
6. **Human approval:** no autonomous remediation.

## Legacy v0.1 workflows

The existing `scan`, `scan-osv`, `verify`, `inventory-python`, `keygen`, `sign` and `verify-ledger` commands remain supported. The original [architecture](docs/ARCHITECTURE.md) covers legacy mode.

## Contributing and reporting

Please read [SECURITY.md](SECURITY.md). Submit a minimal reproducer through GitHub private vulnerability reporting rather than publishing an exploit against an active system. Respect third-party authorisation and privacy.

**Repository:** [ymmiah/OGDE](https://github.com/ymmiah/OGDE) (source publication pending). **Licence:** MIT.

