# Trust specification — v0.3

**Status: specified, not implemented.** The commands in this repository still verify v0.2.2 Ed25519 feeds. Those checks remain the test oracle. This document is the contract for the TUF and Sigstore layer. It is not permission to treat a feed as TUF-verified today.

A publisher can tell an organisation what it believes is vulnerable. It cannot tell the organisation’s systems what to do. Advisories are data. They are schema-checked and never executed.

## Roles

| Role | Holds | May | Must not |
| --- | --- | --- | --- |
| Root of trust | Offline TUF root keys, threshold 2 of 3 | Rotate top-level roles, revoke a publisher | Sign routine advisories |
| Publisher | A Sigstore identity bound to one CI workflow | Sign advisory metadata in its own namespace | Publish outside that namespace, or send a command |
| Mirror | Copies of signed metadata | Serve the files | Change them without detection |
| Organisation | A local trust policy and a pinned root | Choose publishers, set thresholds, record VEX | Be overridden by a publisher |

While OGDE has one maintainer, 2 of 3 means the founder plus two sealed backups in separate locations. Root keys are generated offline. They are not stored in this repository.

## Expiry

A stale file is rejected. It is not trusted silently.

| Metadata | Maximum age |
| --- | --- |
| Timestamp | 1 day |
| Snapshot | 7 days |
| Targets | 30 days |
| Root | 1 year |

Root metadata rotates every 12 months, and immediately after any suspected compromise. Revocation removes a publisher’s delegation. Clients drop that publisher’s advisories on the next refresh.

## Sigstore identity

Publisher signing is keyless, from a pinned GitHub Actions workflow, with a public transparency log. There is no long-lived publisher key to steal.

The pin is **unset**. No publishing workflow exists yet. Before any public feed, the client must require:

- Issuer `https://token.actions.githubusercontent.com`
- A subject bound to the specific workflow in `ymmiah/OGDE`, named in this file when that workflow is added
- A repository and ref the owner has written down

An identity that does not match the pin is rejected even if the signature verifies.

## What this layer must reject

Tests for the future client have to fail closed on all of the following. Porting the v0.2.2 cases is part of that work, not a claim that it is done.

- Tampered targets or metadata
- Expired timestamp, snapshot, targets or root
- Rollback or freeze (an older snapshot presented as current)
- Replay of a signed payload under a new name
- A valid signature from the wrong identity
- Mix-and-match of metadata from different snapshots
- Any field that is not in the advisory schema, including anything that looks like a command

## Conflict rule

When two trusted sources disagree, OGDE reports both claims, marks the finding contested, and does not pick a winner. The organisation’s policy, including a VEX statement, decides what is shown. `ogde report` implements this rule for local finding files. It does not yet apply it to a TUF repository.

## Dependencies

`python-tuf` and `sigstore-python` are the libraries to adopt. This repository does not vendor a TUF or Sigstore implementation, and this change does not add those packages. Adding them is a protected-zone change: tests for tampered, expired and malformed metadata first, then the library, with review.
