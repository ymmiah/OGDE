# Federated immunity MVP — v0.2.2

**Status:** experimental, locally verified; do not use as sole production security control.

## Trust model

- Feed publishers generate Ed25519 keys locally. Protect private keys outside the repository.
- Asset owners independently verify the public-key fingerprint via a trusted out-of-band channel and explicitly pin a publisher ID, feed ID and public key.
- A signed feed v2 carries `publisher_id`, `feed_id`, `revision`, `generated_at`, `expires_at` and exact-version advisories. The signed `aliases` field can declare CVE IDs to join against an imported KEV snapshot.
- `assess` verifies the signature, publisher/feed binding, expiry and full schema, then locally matches a CycloneDX inventory.
- Monotonic feed revision and digest are recorded locally to prevent acceptance of older revisions or conflicting payloads for the same revision **while the local state remains trustworthy**.
- Security context and triage use locally supplied attributes. Findings produce human-review recommendations only: no blocking, patching, exploitation or scanning.
- Optional CISA-format KEV snapshots are **user supplied** and OGDE does not verify where they came from. Their matches are not proof of exploitation and cannot trigger automatic action.

## Important boundaries

- The system does not establish a globally trusted root authority, public key infrastructure, incident classification or threat actor identity.
- Publisher key rotation is intentionally not automatic. The admin must review changes and establish a new feed trust binding.
- Signed does not mean true. Feeds could contain inaccurate claims even if signatures are valid.
- State file deletion, rollback of the entire disk or a malicious local administrator defeats local rollback protection. Backup state to independently protected storage for critical applications.
- Local file-locking uses `fcntl` and therefore `assess` requires a POSIX environment. Windows users should use WSL or an equivalent Linux runner.
- Markdown/JSON reports may include sensitive inventory. They are stored with 0600 permissions on POSIX systems; protect archives and CI artifacts accordingly.
- The audit ledger is suitable for a single-process demonstration only; it is not immutable. Anchor ledger heads independently and deploy a transactional, append-only store before relying on it for multi-node evidence.
- The approved external OSV queries in v0.1 remain opt-in and share package names and versions. The federated v2 workflow is offline by default.
- This is an exact-version matcher, not a general OSV range evaluator, exploit detector or comprehensive system inventory scanner.

## File interfaces

Trust registry (private local file): `schema_version:1` and `publishers` array with signed identity pinned to public key.

Local revision state (private local file): `schema_version:1` and `feeds` keyed by feed ID with last accepted revision/digest/timestamp.

Assessment report includes `findings`, `priorities`, `publisher`, `revision`, `feed_digest_sha256`, `asset` and explicit limitations.

## Example workflow (POSIX shell)

```sh
python -m pip install -e .
mkdir -p .ogde-local
ogde keygen --private .ogde-local/dev-publisher.key --public .ogde-local/dev-publisher.pub
python scripts/create_demo_feed.py --out .ogde-local/demo-feed.json
ogde sign --feed .ogde-local/demo-feed.json --private .ogde-local/dev-publisher.key --out .ogde-local/demo-signed.json

# In a real deployment, independently verify the key before confirming trust.
ogde trust-add --registry .ogde-local/trust.json --public .ogde-local/dev-publisher.pub --publisher-id ogde-lab --feed-id lab-advisories --confirm-trust-anchor

ogde assess \
  --registry .ogde-local/trust.json --feed .ogde-local/demo-signed.json \
  --sbom examples/sbom.v2-demo.cdx.json \
  --context examples/asset-context.example.json --state .ogde-local/state.json \
  --out .ogde-local/report.json --markdown .ogde-local/report.md \
  --fail-on none
```

The demo uses an explicitly **synthetic package and advisory**, not evidence of a genuine vulnerability. No internet is required after Python dependencies have been installed.

## Exit codes

- `0`: successful; threshold not breached
- `1`: invalid input, verification failure, unavailable file or another error
- `2`: verified exact-version finding at or above the chosen `--fail-on` priority (`any` default, `none` for demonstration)

## Future engineering gates

1. Independently review all threat-model assumptions and implement fuzz/property testing.
2. Add robust transactional storage with remote anchoring and independently reviewed publisher key rotation.
3. Interoperate with standards-based advisories, VEX, CSAF and signed provenance rather than inventing more incompatible formats.
4. Build a consent-based multi-tenant API with strong isolation, audit logs, rate limits and no remote command channel.
5. Pilot on non-sensitive test assets; gather triage precision, false positives, time-to-notification and resilience metrics.
