<p align="center">
  <img src="assets/brand/ogde-logo.png" alt="OGDE — One Global Defence Ecosystem" width="480">
</p>

**OGDE** (One Global Defence Ecosystem) is an open, neutral platform for sharing verifiable cyber-defence and threat intelligence across organisations, especially those running critical infrastructure.

**Defend locally. Verify globally. Recover together.**

> **Status:** v0.2.2 is published at [ymmiah/OGDE](https://github.com/ymmiah/OGDE). It is an experimental developer preview, not a production security control. The current phase is **v0.3, the verified loop**.

## v0.3 direction

v0.3 has one job: prove a single trustworthy loop. Verified intelligence comes in, it is matched against an organisation’s own assets, and a finding comes out with a confidence level and the evidence behind it. The first assets are WordPress sites and CI/CD lockfiles. Seven gated phases follow that loop; a later phase does not start until the previous gate is met. The v0.3 gate is five pilot sites over four weeks and a published false-positive rate. That gate is not met.

Started in this tree:

- The trust layer is specified in [docs/specs/trust.md](docs/specs/trust.md). TUF and Sigstore are not implemented. v0.2.2 Ed25519 feeds remain the working verifier.
- `ogde inventory` builds a local CycloneDX inventory from a WordPress tree, `composer.lock` and `package-lock.json`. It keeps versions only and does not upload anything.
- `ogde report` checks a local finding file, applies an OpenVEX statement, and writes a prioritised report. It does not fetch OSV, KEV, EPSS or Wordfence.

The public gateway is the static page in [`site/`](site/). It collects no data. Notes for **ogde.org** are in [site/README.md](site/README.md). Phase status and open decisions are in [docs/V0.3.md](docs/V0.3.md). Brand files and stable URLs are in [assets/brand/README.md](assets/brand/README.md).

## Try v0.2.2 and the v0.3 slice

```sh
python -m pip install -e .
python -m unittest discover -s tests -v

mkdir -p .ogde-local
ogde inventory \
  --wordpress examples/demo-site/wordpress \
  --composer-lock examples/demo-site/composer.lock \
  --package-lock examples/demo-site/package-lock.json \
  --out .ogde-local/inventory.cdx.json

ogde report \
  --findings examples/findings.example.json \
  --vex examples/vex.example.json \
  --out .ogde-local/findings.json \
  --markdown .ogde-local/findings.md
```

`ogde report` exits 2 when a visible finding remains. The synthetic example does that on purpose. The v0.2.2 signed-feed walkthrough is [docs/FEDERATION_V2.md](docs/FEDERATION_V2.md).

The historical `odge` import and command are aliases of `ogde`. There is no second implementation.

## What v0.2.2 already does

- `ogde trust-add` pins a publisher key that was checked out of band.
- `ogde assess` rejects tampered, expired, untrusted, replayed or equivocated feeds, matches exact versions and writes a local result.
- Advisory text is data. It is never executed.
- `--fail-on P2` can fail a build. It never changes a production system.
- An optional KEV snapshot is unverified local input. A match is not proof of exploitation.

## Principles

1. **Local control.** Do not scan or change someone else’s systems.
2. **Independent trust.** Pin a publisher before accepting an advisory.
3. **Truth over theatrics.** A valid signature authenticates the signer, not the claim.
4. **Evidence.** Every finding should say why it is there, and what it cannot prove.
5. **Fail closed.** Reject missing trust, bad schemas, expired feeds and rollbacks.
6. **Human approval.** No autonomous remediation.

## Contributing and reporting

Please read [SECURITY.md](SECURITY.md). Report vulnerabilities privately. Do not publish an exploit against a live system.

**Repository:** [ymmiah/OGDE](https://github.com/ymmiah/OGDE). **Licence:** MIT.
