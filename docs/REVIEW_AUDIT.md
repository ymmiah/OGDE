# Offline review audit record (experimental)

`ogde.review_audit.make_review_audit_record` builds a deterministic, allowlisted JSON-compatible record from an operator-supplied timestamp, one of three review event types, one of three outcomes, and an optional SHA-256 evidence digest. It has **no file or network side effects**. The caller decides whether, where and under what access controls to retain the record.

This is an opt-in building block, **not yet wired into KEV acceptance**. It cannot make the state write and audit storage atomic. A record hash is a tamper-evident checksum only when independently retained and authenticated; it is not a signature, trusted timestamp, source provenance or proof that an advisory is true. A SHA-256 evidence digest may still correlate records, so do not publish it without review. Never place credentials, file paths, inventory data or arbitrary user text in the record. No automatic remediation or trusted-state advancement is performed.

Example:

```python
from ogde.review_audit import make_review_audit_record
record = make_review_audit_record(event='evidence_review', outcome='requires_review', occurred_at='2026-11-04T07:00:00Z')
```

Run offline: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_review_audit.py' -v`.

Compatibility: adds a standalone module; does not modify existing `ogde` or legacy `odge` entry points. Human approval is still mandatory for consequential changes.
