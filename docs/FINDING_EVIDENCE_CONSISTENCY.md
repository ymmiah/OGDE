# Finding evidence identity consistency

This additive v0.3 hardening rejects a single finding that assigns different SHA-256 digests to the same `(source, record_id)` identity. It preserves the existing finding contract, ranking, VEX rules and legacy `ogde`/`odge` interfaces. Distinct record identities remain valid; repeated identical evidence is tolerated for compatibility.

This is **consistency validation**, not proof that an advisory is genuine. Source provenance and publisher signatures still require independent verification. No network activity, remote scanning, production changes or automatic remediation is introduced.

Verification command: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_finding_evidence_consistency.py' -v`. Full v0.3 CI and human review are required before merging. The pilot gate is not met.
