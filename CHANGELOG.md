## Unreleased — start of the v0.3 verified loop

- Add the OGDE brand files under `assets/brand/` (master JPEG, transparent PNG, traced SVG, icon and favicon) and use the logo on the README.
- Collapse the leftover `odge` package to an import alias of `ogde`. The command name `odge` still works.
- Add a static gateway in `site/` for ogde.org, with no sign-in and no data collection.
- Specify the v0.3 trust layer, finding contract, threat model and data-source register. TUF and Sigstore are not implemented in this change.
- `ogde inventory` reads WordPress version headers and Composer/npm lockfiles into a local CycloneDX file. It does not upload anything.
- `ogde report` checks local findings, records conflicts, applies OpenVEX suppression and writes a prioritised audit.
- Bump `actions/setup-python` to 7.1.0, matching the open Dependabot pull request.

## 0.2.2 — Restore canonical OGDE project name

- Correct the official project and repository name to **OGDE — One Global Defence Ecosystem** (`ymmiah/OGDE`).
- `ogde` is again the canonical Python package and CLI entrypoint; `odge` is a backwards-compatible import and command alias.
- Refresh readme, GitHub publication guidance, tests, example identifiers, demo scripts, and CI schedules.
- No change to production remediation policy or advisory-signature trust requirements.

## 0.2.1 — Previous ODGE spelling (superseded)

- Previous developer preview temporarily used ODGE as the official short name.
- Python `odge` and `ogde` interfaces were both present. The spelling is corrected in 0.2.2.

