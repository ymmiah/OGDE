# OSV endpoint boundary hardening

The optional OSV integration sends package names and versions only after the existing explicit consent gate. This change rejects HTTP redirects and rejects a response whose final URL differs from the configured OSV API endpoint. This is a narrow privacy boundary; it does not authenticate individual advisories, prevent the approved service from logging requests, or permit automatic response actions.

## Verification

Offline tests cover redirect refusal, final URL mismatch and normal same-endpoint responses. Tests use mocked network objects; no external system was scanned. Run `PYTHONPATH=src python -m unittest discover -s tests -q` on this branch. Full v0.3 CI must pass before merging. Existing `ogde` and `odge` interfaces are unchanged.

No production configuration, trust anchor or deployment was modified. Human review is required.
