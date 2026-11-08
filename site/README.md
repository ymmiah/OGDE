# OGDE public website — GitHub Pages

A static public site for One Global Defence Ecosystem. It explains the verified-intelligence loop, the four product areas, what the command-line preview actually does, and which workstreams are still planned. The page stays HTML and CSS. It does not collect data.

**Source:** `site/index.html`, `site/styles.css`, canonical assets in `assets/brand/`.

## Preview

From repository root:

```sh
python -m http.server 8080
```

Visit `http://localhost:8080/site/`. The source page references brand assets one directory above; the publish script rewrites those paths for production.

## Build

```sh
bash site/prepare-publish.sh
python -m http.server 8080 --directory site/public
```

Visit `http://localhost:8080/`. The build copies canonical brand assets into `site/public/assets/brand/`, creates `CNAME` containing `ogde.org`, and `.nojekyll`. It retains the Cloudflare `_headers` file, although **GitHub Pages does not enforce Cloudflare's `_headers` file**.

## GitHub Pages deployment

1. Merge the reviewed website pull request into `main` (not automatic).
2. In **GitHub → repository Settings → Pages → Build and deployment**, select **GitHub Actions**.
3. Run the `Publish OGDE website to GitHub Pages` workflow (or push a matching site change to `main`).
4. The project URL is expected to be `https://ymmiah.github.io/OGDE/` until the custom domain is configured and DNS resolves.
5. In **Settings → Pages → Custom domain**, set `ogde.org` if not already populated by the `CNAME` artifact.
6. In Cloudflare DNS for `ogde.org`, add the **current GitHub Pages apex records from GitHub's official documentation**. Do not infer that DNS has already been changed. Initially set Cloudflare proxy to **DNS only** for certificate issuance if necessary. After the domain resolves and GitHub provisions its certificate, enable **Enforce HTTPS**.
7. Optionally configure `www.ogde.org` using GitHub's documented `www` CNAME target and redirect rules. Do not configure wildcard DNS records.

GitHub Pages publishing requires repository permissions, Pages settings and DNS configuration by an authorised owner. A merged PR alone does not prove the public domain is live.

## Security and privacy

- Static HTML/CSS only; no JavaScript, forms, cookies, telemetry or third-party fonts.
- No login or user inventory collection.
- Existing repo `LICENSE` is MIT; the website does not change licensing.
- Source information is intentionally clear about planned versus implemented capabilities.
- Security updates, pull-request review and production deployment remain separate gates.
- This is a **public information website**, not the operational OGDE dashboard or intelligence API.

## Maintenance

Update roadmap/status copy when engineering milestones actually pass verification. Do not imply a pilot, public feed, customer agent or production defence network exists before evidence is available.
