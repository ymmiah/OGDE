# OGDE Website

Public site for **OGDE — One Global Defence Ecosystem**. The address is **ogde.org**. This page is static HTML and CSS. It does not collect data, and it does not change the repository name, the brand, or DNS.

**Source:** `site/index.html`, `site/styles.css`, canonical artwork in `assets/brand/`.

## Preview

From the repository root:

```sh
python -m http.server 8080
```

Open `http://localhost:8080/site/`. Brand images use `../assets/brand/`.

```sh
bash site/prepare-publish.sh
python -m http.server 8080 --directory site/public
```

Open `http://localhost:8080/`. The script rewrites those image paths to `assets/brand/`, copies the logo files, and writes `CNAME` (`ogde.org`) and `.nojekyll`. GitHub Pages does not apply the Cloudflare `_headers` file. For an Actions publish, GitHub also ignores the `CNAME` file. The custom domain has to be saved in Pages settings. It is already set to `ogde.org`.

## Current GitHub status

Checked against the repository API on 8 November 2026, after 13:35 GMT. This file does not change those settings.

| Item | Value |
| --- | --- |
| Pages source | Still **Deploy from a branch**: `feat/m3-kev-revision-state-2026-11-01`, path `/`. Not GitHub Actions. |
| Custom domain | `ogde.org` is saved. Recorded site URL: `http://ogde.org/`. |
| Enforce HTTPS | Off. |
| Environment | [`github-pages`](https://github.com/ymmiah/OGDE/settings/environments/github-pages) allows deployment only from `feat/m3-kev-revision-state-2026-11-01`. `main` is not on that list. |
| Latest Actions attempt | [Run 42481438098](https://github.com/ymmiah/OGDE/actions/runs/42481438098), attempt 2, 12:46:33Z–12:46:37Z, commit `8dcb97b38c9db036d0240ab9631b191ec9a70c8f`. Build was already green. [Deploy job 128735179951](https://github.com/ymmiah/OGDE/actions/runs/42481438098/job/128735179951) failed before a runner started. |

The check annotation is: **Branch "main" is not allowed to deploy to github-pages due to environment protection rules.**

That rule is doing what it was set to do. Do not rename the environment, delete the branch policy, or push an empty commit to get past it. Add `main` to the allowed list, then run the workflow again.

The environment screen is **not** under Pages. It is **Settings → Environments → github-pages**.

## Owner steps

1. Open [Environment: github-pages](https://github.com/ymmiah/OGDE/settings/environments/github-pages). Under deployment branches, **add `main`**. Leave the existing branch rule in place.
2. Open [Pages settings](https://github.com/ymmiah/OGDE/settings/pages). Under **Build and deployment**, choose **GitHub Actions** instead of the branch `feat/m3-kev-revision-state-2026-11-01`.
3. Leave the custom domain as `ogde.org`. Do not turn on **Enforce HTTPS** until GitHub shows a certificate. It is off now. A certificate needs the DNS records below, which are entered in Cloudflare, not in this repository.
4. After steps 1 and 2, run [Deploy OGDE Website](https://github.com/ymmiah/OGDE/actions/workflows/pages.yml) on `main`, or re-run [42481438098](https://github.com/ymmiah/OGDE/actions/runs/42481438098). Until step 1 is done, a run from `main` fails in a few seconds with the message above.

Merging a documentation change retriggers this workflow because it watches `site/**` and `.github/workflows/pages.yml` on `main`. That run will fail the same way until `main` is allowed.

## DNS, entered in Cloudflare

Do this only after `ogde.org` is saved on the Pages screen. It already is. Use **DNS only** (grey cloud). An orange-cloud proxy publishes Cloudflare addresses, and GitHub will not issue a certificate unless the public answers are the GitHub addresses below. GitHub does not require a TTL. Its sample lookup shows 3600. There is no CAA record required today. If you add CAA later, one record must allow `letsencrypt.org`. Do not add a wildcard such as `*.ogde.org`.

The addresses are from [Managing a custom domain for your GitHub Pages site](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site). `www` points at `ymmiah.github.io`, not `ymmiah.github.io/OGDE`. With `ogde.org` as the custom domain, GitHub redirects `www` to the apex.

| Type | Name | Value | Proxy |
| --- | --- | --- | --- |
| A | `@` | `185.199.108.153` | DNS only |
| A | `@` | `185.199.109.153` | DNS only |
| A | `@` | `185.199.110.153` | DNS only |
| A | `@` | `185.199.111.153` | DNS only |
| AAAA | `@` | `2606:50c0:8000::153` | DNS only |
| AAAA | `@` | `2606:50c0:8001::153` | DNS only |
| AAAA | `@` | `2606:50c0:8002::153` | DNS only |
| AAAA | `@` | `2606:50c0:8003::153` | DNS only |
| CNAME | `www` | `ymmiah.github.io` | DNS only |

A domain-verification TXT value is not stored in this repository. If GitHub asks for one, copy it from your profile **Settings → Pages** after adding `ogde.org`. The host it shows is `_github-pages-challenge-ymmiah.ogde.org`. Do not invent the value.

## Security and privacy

- Static HTML and CSS only. No JavaScript, forms, cookies, telemetry, or third-party fonts.
- No sign-in and no inventory upload.
- The software licence is MIT. This site does not change it.
- Planned product areas are labelled as planned. The five-site pilot is not claimed as done.
- This is the public website, not the OGDE console or a live intelligence feed.
