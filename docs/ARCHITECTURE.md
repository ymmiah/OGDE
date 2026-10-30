# Federated digital immunity: architecture decisions

## Trust boundaries

1. **Publisher:** controls a private Ed25519 key; issues reviewable, signed data, not executable commands.
2. **Transport:** advisory files may be copied via untrusted networks and mirrors. Integrity/authenticity is checked locally before use.
3. **Subscriber:** owns the inventory, policy and response decision. It pins public keys independently and does not hand out credentials to publishers.
4. **External intelligence:** OSV is a separate explicit opt-in path, with network availability and privacy trade-offs.
5. **Operator:** retains control of patch installation, service restart, isolation or any production action. OGDE 0.1 does not have those capabilities.

## Current MVP data flow

`SBOM + pinned key + signed feed -> deterministic validation -> exact-version matches -> JSON report -> optional audit digest`

Optional: `SBOM --explicit consent--> OSV querybatch -> JSON report`.

## Threat cases

| Threat | Current control | Residual risk |
| --- | --- | --- |
| Tampered advisory | Ed25519 verification | Compromised publisher key |
| Malicious self-signed publisher | Out-of-band trusted public key | Social engineering during trust onboarding |
| Replay of old advice | Expiry and generated timestamp checks | Signed yet still-valid superseded feeds; needs monotonic feed revision in v0.2 |
| Feed command injection | Advisory contains only data and remediation text; never executed | Operator may follow malicious advice; require human review |
| Leaked inventory | Offline scan; OSV requires separate explicit flag | Local reports disclose installed packages |
| Audit alteration | Per-record hash chain | Whole-file rewrite unless externally anchored |
| Unsafe auto-fix | No remote execution or patch application | Humans may still apply unsafe changes |
| Advisory spoofing on mirror | Pinned Ed25519 key | Unprotected key distribution and revocation |

## Next security milestones

- Add monotonic signed feed sequence and rollback protection; independently signed key rotations and revocation.
- Define an interoperable canonical JSON signature profile (e.g. RFC 8785) with cross-language test vectors.
- Add full PURL ecosystem parsing and comprehensive CycloneDX conformance checks.
- Introduce per-tenant policy gates, a central service with mutual authentication, attestations and observability.
- Pilot with a small number of consenting organisations; use independent validation and external pentesting.
- Build carefully scoped, human-approved remediation workflows with rollback, no central remote execution keys.
- Publish reproducible operational benchmarks and false-positive/false-negative studies.
