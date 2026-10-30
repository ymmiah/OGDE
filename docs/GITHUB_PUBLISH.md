# OGDE on GitHub (`ymmiah/OGDE`)

The source is published at https://github.com/ymmiah/OGDE. v0.2.2 is on `main`. Further work lands through pull requests. The weekly verification workflow runs the offline tests and a synthetic assessment. It does not scan arbitrary hosts or apply a remediation.

## Before you commit

**Never commit signing private keys, tokens, real inventories, or local state.** `.ogde-local/` and the legacy `.odge-local/` are ignored, alongside common key formats. Inspect `git status` before committing.

Enable private vulnerability reporting, protect the default branch, and require the test workflow for merges.
