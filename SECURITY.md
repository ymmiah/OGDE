# Security policy

OGDE is a prototype and is **not** a production incident-response authority.

- Report security issues privately through GitHub private vulnerability reporting once enabled on the repository. Do not publish exploit details against real targets.
- Do not place operational signing keys, production inventories, IP addresses, credentials or personal data in GitHub issues.
- Advisory signing keys are owned and operated by each feed publisher. Distribute trust anchors through an authenticated, independent channel; do not retrieve a key from the same untrusted URL as its advisory.
- The current ledger is single-writer and must have its hash head anchored externally for meaningful tamper evidence.
- No remote execution, production modification or automated remediation is included.

Supported prototype: v0.2.2 receives best-effort updates. v0.3 work in this tree is not a production control and has no SLA.

`ogde inventory` and `ogde report` are local. They do not upload an inventory. Collectors are not allowed to read `wp-config.php`, environment files, private keys or database contents; the tests fail if they do.

## Federated publisher security (v0.2)

Verify trust-anchor fingerprints independently before pinning. Do not accept signing keys embedded in untrusted advisories, email links or AI responses as authoritative. Protect `.ogde-local/`, revision-state files, private reports and key material. `assess` only recommends human-reviewed actions and must not be connected directly to privileged production execution. See `docs/FEDERATION_V2.md` for trust and anti-rollback limitations.
