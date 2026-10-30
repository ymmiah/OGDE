# Publish OGDE to GitHub (`ymmiah/OGDE`)

The `ymmiah/OGDE` repository already exists at https://github.com/ymmiah/OGDE, but the connected GitHub app returned HTTP 403 (`Resource not accessible by integration`) when creating a feature branch. **This source archive has not been pushed.**

## Recommended: publish to the existing repository

1. Sign in to GitHub as `ymmiah` and clone the existing repository:

   ```bash
   git clone https://github.com/ymmiah/OGDE.git
   cd OGDE
   ```

2. Extract the supplied OGDE v0.2.2 source ZIP or TAR.GZ. Copy the **contents** of its `OGDE/` directory into your cloned repository, preserving `.github/` and `.gitignore`, but not replacing the cloned repository's `.git/` directory. Review the changes before committing.

3. Run the tests, stage, commit and push:

   ```bash
   python -m pip install -e .
   python -m unittest discover -s tests -v
   python -m ogde --version
   git status
   git add -A
   git commit -m "feat: publish OGDE v0.2.2 digital immunity MVP"
   git push origin main
   ```

4. Review the files on GitHub. Enable private vulnerability reporting, protect the default branch, and require CI checks and appropriate reviews for future changes.

**Never commit signing private keys, tokens, real sensitive inventories, or local state.** `.ogde-local/` and the legacy `.odge-local/` are ignored, alongside common key formats, but inspect `git status` before committing.

## Direct GitHub development

The standard GitHub integration in ChatGPT is read-only: connecting or increasing repository visibility does not grant it branch creation or push rights. Use Git on your machine or a separate development environment such as Codex with an authorised GitHub connection. Review all changes and CI output before merging. GitHub's user-level `push: true` does not establish that the ChatGPT integration token has write access; its test branch creation returned 403.

The GitHub Actions scheduled-verification workflow performs weekly synthetic checks once this source is published. It does not scan arbitrary public hosts or execute production remediation.
