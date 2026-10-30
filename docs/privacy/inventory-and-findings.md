# Privacy review — inventory and findings

This is the review for the fields added with the first v0.3 slice. Collectors are allow-listed. A field that is not in this list is not emitted. Adding another field means updating this note and the tests.

No field is sent off the machine by `ogde inventory` or `ogde report`.

## Read, but not kept

| Location | Why it is opened | What is kept |
| --- | --- | --- |
| `wp-includes/version.php`, first 8 KiB | WordPress core version | The `$wp_version` literal, if it matches a version token |
| Top-level `*.php` in each plugin directory, first 8 KiB, except `index.php` | WordPress plugin version | The `Version` header only. Plugin Name, description and file body are discarded. Subdirectories are not opened. |
| `wp-content/themes/<slug>/style.css`, first 8 KiB | Theme version | The `Version` header only |
| `composer.lock` | PHP dependencies | `packages` and `packages-dev` name and version |
| `package-lock.json` (lockfileVersion 2 or 3) | npm dependencies | Package name, version, and the boolean `dev` flag |

`dist.url`, `resolved`, integrity hashes, scripts, authors and licences are parsed only as far as JSON requires and are not copied into the inventory. Tests cover a URL that contains a token.

## Never opened

The tests refuse the run, or prove the path was not opened, for `wp-config.php`, `.env`, private key names (`id_rsa` and the other names in the collector), database dumps, and files reached through a symlink. There is no database driver and no network client in these modules.

Local filesystem paths are not written into the inventory. A report file is still sensitive, because it lists what is installed. It is written with private permissions.

## Emitted inventory fields

- CycloneDX `bomFormat`, `specVersion`, `version`
- `metadata.timestamp`, `metadata.tools[].name`, `metadata.tools[].version`
- `metadata.properties`: `ogde:inventory-scope=local-only`, `ogde:transmitted=false`, and a fixed collector note when a WordPress root was scanned
- `components[].type`, `name`, `version`, `purl`
- `components[].properties`: `ogde:dependency-scope` of `runtime` or `dev` for lockfile packages

## Emitted finding fields

The finding contract is [the specification](../specs/finding.md). It carries package URLs, vulnerability ids, a KEV flag, an EPSS number or null, an exposure flag, evidence ids and digests, limitations, confidence, and an optional VEX justification. It does not carry advisory prose, commands, or host names.

Suppressed findings remain in the `--out` audit file so a later review can see why they were hidden. They are omitted from the default Markdown view.
