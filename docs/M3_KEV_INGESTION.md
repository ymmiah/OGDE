# M3 — Offline KEV snapshot integrity ingestion

This is the first incremental M3 ingestion component. The caller provides a **local** CISA-format KEV JSON snapshot and a SHA-256 digest obtained independently. OGDE checks canonical JSON integrity, validates unique CVE identifiers through the existing KEV parser and rejects missing or malformed `dateAdded` values. It returns a read-only receipt and CVE list for later local correlation.

**Trust limitation:** SHA-256 equality is not CISA publisher authentication, does not prove freshness, and does not prove that any particular asset is vulnerable or compromised. The receipt explicitly states `publisher_authenticated: false` and `decision: human-review`. No remote fetch, automatic action, trust-anchor change or deployment is introduced.

Tests: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_kev_ingest.py' -v`. Six synthetic tests passed in a lightweight local harness using the existing KEV parser logic; the full repository suite and CI remain required before merge.

Next: authenticated source acquisition with independently governed trust anchors, followed by local correlation and pilot false-positive measurement. The v0.3 gate remains unmet.
