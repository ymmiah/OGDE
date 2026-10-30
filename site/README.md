# ogde.org gateway

`site/` is a static landing page for OGDE. It explains the mission, the current status and how to try the command-line preview. It has no sign-in, no forms, no scripts and no analytics.

The page uses the brand files in `../assets/brand/` so a local preview from the repository root resolves the logo. A publish build copies those same files next to the HTML. Do not keep a second copy of the logo in git.

## Preview locally

From the repository root:

```sh
python -m http.server 8080
```

Open `http://127.0.0.1:8080/site/`.

## Build a publish directory

```sh
bash site/prepare-publish.sh
```

That writes `site/public/`, which is git-ignored. The HTML there points at `assets/brand/` inside the publish directory. Those files are copies produced at build time from `assets/brand/`.

`site/public/_headers` is included for Cloudflare Pages. It sets a content security policy that allows no scripts, no frames and no form submissions.

## Domain

`ogde.org` is registered. DNS is hosted on Cloudflare. There are no records yet, so the name does not serve this site until the owner adds some.

Do not add records until the host is chosen. The host’s own instructions are the source for the exact names and targets; hard-coded addresses go stale.

### Cloudflare Pages

This matches the existing DNS host and needs no origin server.

1. Create a Pages project from `ymmiah/OGDE`.
2. Framework preset: none.
3. Build command: `bash site/prepare-publish.sh`
4. Build output directory: `site/public`
5. Add the custom domain `ogde.org` in the Pages project. On the same Cloudflare account, Pages can create the DNS records in the empty zone.
6. Leave Cloudflare Web Analytics and Email Address Obfuscation off. Both inject scripts, and this site is written to load none.
7. Optional: add `www.ogde.org` as a redirect to the apex. That is an owner choice.

Production deploys should track `main` only after the brand files are on that branch, because the page documents the raw URLs on `main`.

### GitHub Pages

Use the same build output.

1. Run `bash site/prepare-publish.sh` in a workflow, or on a `gh-pages` branch that contains only `site/public`.
2. In the repository Pages settings, choose that output and request the custom domain `ogde.org`.
3. Add the DNS records GitHub shows at that moment to the Cloudflare zone. Do not copy old address lists from memory.
4. Enable HTTPS once the certificate is issued.

GitHub Pages from `/docs` or from the repository root will not put this page at the apex without a build, because `index.html` lives in `site/`.

## Still to decide

The owner chooses the host. This directory does not turn on a deployment by itself.
