# Finding specification — v0.3

**Status: enforced by `ogde.finding` for local files.** A finding is not yet produced by a Wordfence or OSV match. Callers pass a local document. The module rejects anything outside this contract.

## Document

```json
{ "schema_version": 1, "findings": [] }
```

Unknown keys are rejected. A finding that arrives already marked `suppressed` is rejected. Suppression is only the result of a VEX statement, so a file cannot hide a finding by labelling it.

## Finding

| Field | Rule |
| --- | --- |
| `finding_id` | Stable identifier, no spaces or control characters. Unique in the file. |
| `confidence` | `confirmed`, `probable` or `contested` on input. Output may also be `suppressed`. |
| `component` | `purl`, `name` and `version`. The name and version must match the package URL. No query string or fragment. |
| `vulnerability` | `id` and `severity` (`critical`, `high`, `medium`, `low`, `unknown`). No free-text body in this slice, so advisory prose cannot carry an instruction. |
| `signals.kev_listed` | Boolean. It records a local claim. This command does not download CISA KEV. |
| `signals.epss` | `null` or a probability from 0 to 1. Booleans are rejected. |
| `signals.internet_exposed` | Boolean supplied locally. |
| `affected` | Boolean claim from that evidence. |
| `evidence` | 1 to 8 records: `source`, `record_id`, and a lowercase SHA-256 `digest_sha256`. |
| `limitations` | 1 to 6 short strings. Every finding says what it cannot prove. |
| `decision` | Always `human-review`. There is no action field. |

Output adds `assessed_confidence` (the value before conflict or VEX handling), `ranking.factors`, and `ranking.order` on visible findings. A suppressed finding gains a `vex` object.

## Confidence

| Level | Meaning | Default |
| --- | --- | --- |
| Confirmed | Identifier and version sit inside a trusted record, with no normalising doubt recorded by the caller. | Show and prioritise. |
| Probable | The caller had to normalise a name or version. | Show and flag for review. |
| Contested | Trusted claims disagree, or VEX statements disagree. Both claims stay. | Show both. |
| Suppressed | The owner recorded VEX `not_affected` with a justification. | Hide in the default view. Keep in the audit file. |

This slice does not decide `confirmed` versus `probable` by comparing version ranges. The caller sets that. The module does set `contested` and `suppressed`.

## Priority

Visible findings sort by this order, from the v0.3 plan. The first factor that differs wins. The factors are written onto the finding so the order can be challenged.

1. Local KEV flag true before false.
2. EPSS at or above the threshold before below. Missing EPSS counts as below. The default threshold is **0.1**.
3. CVSS severity: critical, high, medium, low, unknown.
4. Internet exposure true before false.

The threshold is an open decision after the pilot. `ogde report --epss-threshold` overrides it for one run.

## VEX

A minimal OpenVEX document:

- `@context` is `https://openvex.dev/ns/v0.2.0`. The URL is an identifier. It is not fetched.
- `status` of `not_affected` requires a justification from the OpenVEX set.
- `products[].@id` must equal the finding’s package URL, including the version. There is no fuzzy match and no statement that applies to every product.
- If one matching statement says `not_affected` and another matching statement says something else, the finding becomes contested and is not suppressed.

## Report

`kind` is `ogde-finding-report`. `transmitted` is false. `decision` is `human-review`. The JSON file written with `--out` always includes suppressed findings. Stdout and Markdown omit their bodies unless `--include-suppressed` is set. Exit code 2 means at least one visible finding. Suppressed findings do not, by themselves, fail the process.
