# Practical autonomy — controlled by owners

The ordering below is the v0.2 note. The current phase is the v0.3 verified loop in [V0.3.md](V0.3.md). That phase’s gate has to be met before a later phase starts.

OGDE's automation is designed to perform **checks**, **propose changes** and **verify evidence**, not to self-propagate or autonomously control infrastructure.

## What is automated in this release

- GitHub Actions validates the package on every push and pull request.
- A scheduled weekly workflow reruns offline unit and end-to-end synthetic tests on GitHub-hosted Linux.
- Dependabot may open weekly dependency/Actions update pull requests, subject to GitHub repository settings.
- Each assessment deterministically prioritises findings and can fail CI above a selected P0–P4 threshold.

## What is explicitly not automated

- Creating or modifying GitHub repositories without connector permission.
- Publishing advisory trust anchors or distributing publishers' public keys without out-of-band verification.
- Mutating production infrastructure, patching, containing network traffic, or escalating access.
- Executing an LLM-generated script, security plugin or downloaded instruction as privileged code.
- Automatically merging Dependabot PRs or bypassing human review.

## Next six milestones

1. M3: Connect an authenticated, provenance-checked CISA KEV feed and improve evidence confidence modelling.
2. M4: Add OSV-to-advisory conversion with package ecosystem validation and non-misleading affected-version interpretation.
3. M5: Build a read-only Linux agent and a WordPress inventory plugin using constrained collection and owner consent.
4. M6: Design an interoperable multi-publisher feed with documented key rollover and revocation semantics.
5. M7: Add local SQLite persistence, audit anchoring, replay protection and schema migrations.
6. M8: Release a self-hosted dashboard with human-review gates and accessible response evidence.

All milestones require tests, explicit security reviews and measurements before any claims of real-world protection.
