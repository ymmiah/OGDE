# M3: Offline review audit hash chain

`ogde.review_audit_chain.append_review_audit_entry` builds a deterministic, ordered chain of validated, allowlisted review records. `verify_review_audit_chain` checks record integrity, sequence continuity, predecessor hashes and an optional independently retained final hash.

The first entry has sequence `0` and no predecessor. Later entries require a lowercase SHA-256 predecessor. Callers must store records and the final head separately using owner-controlled retention and authentication. There is no file I/O, network access, key management, automatic remediation or state mutation in this module.

**Trust limitations:** SHA-256 chaining detects accidental or unauthorised modifications only when a trusted head or signed checkpoint is available outside the editable chain. Anyone able to rewrite all entries can recompute all hashes. The chain does not prove publisher identity, advisory truth, trusted time or that no events were omitted before recording. It is not yet wired to KEV acceptance or atomic persistence. Evidence digests may be correlatable and should remain private.

**Dependency:** this is stacked on the audit verification branch (PR #31, itself dependent on PR #30). Review and reconcile before merging. Legacy `ogde`/`odge` commands are unchanged.

## Actual verification — 5 November 2026

From the isolated feature archive, `PYTHONPATH=src python -m unittest discover -s tests -q`: **39 tests passed** (24 previous, 15 new). `python -m compileall -q src tests`: **passed** on Python 3.13.5. This does not verify the entire GitHub repository or its CI. No production systems were changed.
