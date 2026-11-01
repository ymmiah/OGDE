# Offline evidence integrity gate (v0.3)

This is an additive, read-only foundation for provenance-aware intelligence ingestion. It accepts a **local** schema-v1 JSON document containing a source name and records with identifiers and SHA-256 digests. The caller must supply an independently obtained expected digest. Duplicate IDs, malformed digests, unknown fields, and digest mismatches fail closed.

**Important:** Matching SHA-256 proves only equality with the supplied digest, not publisher identity or advisory correctness. The returned receipt explicitly sets `publisher_authenticated: false` and `decision: human-review`. No trust anchor, remediation or network action is introduced. This module is not yet wired into the CLI or report engine, and it does not advance the v0.3 pilot gate.

Offline tests: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_evidence_gate.py' -v`. Full repository CI must pass before merging. Legacy `ogde` and `odge` interfaces are untouched.
