"""Read-only local inventories for the v0.3 verified loop.

Collectors emit CycloneDX version metadata and nothing else. They do not open
secrets, uploads, database files or configuration that holds credentials, and
they do not send data anywhere.

WordPress plugins are read only at the top level of each plugin directory.
The only header field kept is ``Version``.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .core import SecurityError, utc_now
from .localio import load_json_file, read_nofollow

_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,80}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_COMPOSER_NAME = re.compile(r"^[a-z0-9](?:[_.-]?[a-z0-9]+)*/[a-z0-9](?:[_.-]?[a-z0-9]+)*$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")
_WP_VERSION = re.compile(r"""\$wp_version\s*=\s*'([^']*)'""")
_HEADER_VERSION = re.compile(r"(?im)^[ \t]*(?:\*[ \t]*)?Version[ \t]*:[ \t]*([^\r\n]*)$")

_HEADER_BYTES = 8192
_MAX_PLUGINS = 2000
_MAX_THEMES = 500
_MAX_PHP_FILES = 30
_MAX_COMPONENTS = 10000

_FORBIDDEN_NAMES = {
    "wp-config.php",
    "wp-config-sample.php",
    ".env",
    "shadow",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "authorized_keys",
    "credentials.json",
    "secrets.json",
}
_FORBIDDEN_SUFFIXES = (
    ".pem", ".key", ".p12", ".pfx", ".kdbx", ".sql", ".sqlite", ".sqlite3", ".env",
)
_SKIP_PLUGIN_FILES = {"index.php"}


def _forbidden_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in _FORBIDDEN_NAMES or lowered.startswith(".env"):
        return True
    return lowered.endswith(_FORBIDDEN_SUFFIXES)


def _version(value: object, label: str) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise SecurityError(f"Unreadable {label}")
    return value


def _decode_header(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeError as exc:
        raise SecurityError(f"Unreadable {label}") from exc


def _purl(kind: str, name: str, version: str) -> str:
    encoded = "/".join(quote(part, safe="") for part in name.split("/"))
    return f"pkg:{kind}/{encoded}@{quote(version, safe='')}"


def _component(kind: str, name: str, version: str, component_type: str, scope: str | None) -> dict:
    component = {
        "type": component_type,
        "name": name,
        "version": version,
        "purl": _purl(kind, name, version),
    }
    if scope is not None:
        component["properties"] = [{"name": "ogde:dependency-scope", "value": scope}]
    return component


def _require_directory(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise SecurityError(f"Refusing to follow a symlinked {label}")
    if not path.is_dir():
        raise SecurityError(f"{label} must be a directory")
    return path


def _child(root: Path, relative: str) -> Path:
    path = root.joinpath(*relative.split("/"))
    if path.is_symlink():
        raise SecurityError("Refusing to follow a symlink in the inventory")
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
    except OSError as exc:
        raise SecurityError("Inventory path cannot be resolved") from exc
    if not resolved.is_relative_to(root_resolved):
        raise SecurityError("Inventory path escapes the root")
    if _forbidden_name(path.name):
        raise SecurityError(f"Refusing to read {path.name}")
    return path


def _read_header(root: Path, relative: str, label: str) -> str:
    path = _child(root, relative)
    if not path.is_file():
        raise SecurityError(f"Missing {label}")
    return _decode_header(read_nofollow(path, _HEADER_BYTES), label)


def _wordpress_core(root: Path) -> dict:
    text = _read_header(root, "wp-includes/version.php", "WordPress version file")
    match = _WP_VERSION.search(text)
    if match is None:
        raise SecurityError("WordPress version was not found in wp-includes/version.php")
    version = _version(match.group(1), "WordPress version")
    return _component("wordpress", "core", version, "application", None)


def _header_version(text: str, label: str) -> str:
    match = _HEADER_VERSION.search(text)
    if match is None:
        raise SecurityError(f"Unreadable version header for {label}")
    return _version(match.group(1).strip(), f"version header for {label}")


def _plugin_version(root: Path, directory: Path, slug: str) -> str:
    php_files = []
    for entry in directory.iterdir():
        if entry.is_symlink():
            raise SecurityError("Refusing to follow a symlink in the inventory")
        if not entry.is_file():
            continue
        if entry.name in _SKIP_PLUGIN_FILES or not entry.name.endswith(".php"):
            continue
        if _forbidden_name(entry.name) or _forbidden_name(entry.stem):
            raise SecurityError(f"Refusing to read {entry.name}")
        php_files.append(entry.name)
    if len(php_files) > _MAX_PHP_FILES:
        raise SecurityError(f"Plugin {slug} has too many top-level PHP files")
    found: list[str] = []
    for name in sorted(php_files):
        text = _read_header(root, f"wp-content/plugins/{slug}/{name}", f"plugin {slug}")
        if _HEADER_VERSION.search(text) is None:
            continue
        found.append(name)
    chosen: str | None = None
    if f"{slug}.php" in found:
        chosen = f"{slug}.php"
    elif len(found) == 1:
        chosen = found[0]
    elif len(found) > 1:
        raise SecurityError(f"Plugin {slug} has more than one version header")
    if chosen is None:
        raise SecurityError(f"Plugin {slug} has no version header")
    text = _read_header(root, f"wp-content/plugins/{slug}/{chosen}", f"plugin {slug}")
    return _header_version(text, f"plugin {slug}")


def _single_file_plugin(root: Path, name: str) -> dict:
    slug = name[:-4]
    if slug in _SKIP_PLUGIN_FILES or not _SLUG.fullmatch(slug) or _forbidden_name(name) or _forbidden_name(slug):
        raise SecurityError("Refusing to read a plugin file")
    text = _read_header(root, f"wp-content/plugins/{name}", f"plugin {slug}")
    version = _header_version(text, f"plugin {slug}")
    return _component("wordpress", f"plugin/{slug}", version, "library", None)


def _wordpress_plugins(root: Path) -> list[dict]:
    plugins = root / "wp-content" / "plugins"
    if not plugins.exists():
        return []
    _require_directory(plugins, "plugins directory")
    components = []
    slugs: set[str] = set()
    entries = sorted(plugins.iterdir(), key=lambda item: item.name)
    if len(entries) > _MAX_PLUGINS:
        raise SecurityError("Plugin directory is too large")
    for entry in entries:
        if entry.name.startswith(".") or entry.name in _SKIP_PLUGIN_FILES:
            continue
        if entry.is_symlink():
            raise SecurityError("Refusing to follow a symlink in the inventory")
        if entry.is_dir():
            if not _SLUG.fullmatch(entry.name):
                raise SecurityError("Plugin directory name is not an allowed slug")
            if entry.name in slugs:
                raise SecurityError(f"Duplicate plugin slug {entry.name}")
            slugs.add(entry.name)
            version = _plugin_version(root, entry, entry.name)
            components.append(_component("wordpress", f"plugin/{entry.name}", version, "library", None))
        elif entry.is_file() and entry.name.endswith(".php"):
            if _forbidden_name(entry.name) or _forbidden_name(entry.stem):
                raise SecurityError(f"Refusing to read {entry.name}")
            slug = entry.name[:-4]
            if not _SLUG.fullmatch(slug):
                continue
            component = _single_file_plugin(root, entry.name)
            if slug in slugs:
                raise SecurityError(f"Duplicate plugin slug {slug}")
            slugs.add(slug)
            components.append(component)
    return components


def _wordpress_themes(root: Path) -> list[dict]:
    themes = root / "wp-content" / "themes"
    if not themes.exists():
        return []
    _require_directory(themes, "themes directory")
    components = []
    entries = sorted(themes.iterdir(), key=lambda item: item.name)
    if len(entries) > _MAX_THEMES:
        raise SecurityError("Theme directory is too large")
    for entry in entries:
        if entry.name.startswith("."):
            continue
        if entry.is_symlink():
            raise SecurityError("Refusing to follow a symlink in the inventory")
        if not entry.is_dir():
            continue
        if not _SLUG.fullmatch(entry.name):
            raise SecurityError("Theme directory name is not an allowed slug")
        version = _header_version(
            _read_header(root, f"wp-content/themes/{entry.name}/style.css", f"theme {entry.name}"),
            f"theme {entry.name}",
        )
        components.append(_component("wordpress", f"theme/{entry.name}", version, "library", None))
    return components


def _lock_path(path: str, expected: str) -> Path:
    file_path = Path(path)
    if file_path.name != expected or _forbidden_name(file_path.name):
        raise SecurityError(f"Expected a file named {expected}")
    if file_path.is_symlink():
        raise SecurityError("Refusing to follow a symlinked lockfile")
    return file_path


def _composer_packages(items: object, scope: str) -> list[dict]:
    if not isinstance(items, list):
        raise SecurityError("composer.lock packages must be a list")
    components = []
    for item in items:
        if not isinstance(item, dict):
            raise SecurityError("composer.lock package must be an object")
        name = item.get("name")
        version = item.get("version")
        if not isinstance(name, str) or not _COMPOSER_NAME.fullmatch(name):
            raise SecurityError("Lockfile package name is not an allowed identifier")
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise SecurityError("Lockfile package version is not an allowed identifier")
        components.append(_component("composer", name, version, "library", scope))
    return components


def collect_composer_lock(path: str) -> list[dict]:
    document = load_json_file(_lock_path(path, "composer.lock"))
    if not isinstance(document, dict) or "packages" not in document:
        raise SecurityError("composer.lock is missing packages")
    components = _composer_packages(document.get("packages"), "runtime")
    if "packages-dev" in document:
        components.extend(_composer_packages(document.get("packages-dev"), "dev"))
    return components


def _npm_from_path(package_path: str) -> str | None:
    if package_path == "":
        return None
    parts = package_path.split("/")
    if "node_modules" not in parts:
        raise SecurityError("Unsupported package-lock path")
    index = len(parts) - 1 - parts[::-1].index("node_modules")
    rest = parts[index + 1:]
    if len(rest) == 1:
        return rest[0]
    if len(rest) == 2 and rest[0].startswith("@") and len(rest[0]) > 1:
        return "/".join(rest)
    raise SecurityError("Unsupported package-lock path")


def _npm_component(name: str, version: object, scope: str, *, root: bool) -> dict | None:
    if root and (not isinstance(name, str) or not isinstance(version, str) or not _NPM_NAME.fullmatch(name) or not _VERSION.fullmatch(version)):
        return None
    if not isinstance(name, str) or not _NPM_NAME.fullmatch(name):
        raise SecurityError("Lockfile package name is not an allowed identifier")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise SecurityError("Lockfile package version is not an allowed identifier")
    return _component("npm", name, version, "application" if root else "library", scope)


def collect_package_lock(path: str) -> list[dict]:
    document = load_json_file(_lock_path(path, "package-lock.json"))
    if not isinstance(document, dict):
        raise SecurityError("package-lock.json must be an object")
    lock_version = document.get("lockfileVersion")
    if type(lock_version) is not int or lock_version not in (2, 3):
        raise SecurityError("package-lock.json must use lockfileVersion 2 or 3")
    packages = document.get("packages")
    if not isinstance(packages, dict):
        raise SecurityError("package-lock.json is missing packages")
    components = []
    for package_path, item in packages.items():
        if not isinstance(package_path, str) or not isinstance(item, dict):
            raise SecurityError("package-lock.json packages are malformed")
        if "version" not in item:
            continue
        dev_flag = item.get("dev", False)
        if type(dev_flag) is not bool:
            raise SecurityError("package-lock.json dev flag must be a boolean")
        scope = "dev" if dev_flag else "runtime"
        derived = _npm_from_path(package_path)
        if derived is None:
            component = _npm_component(item.get("name"), item.get("version"), scope, root=True)
        else:
            name = item.get("name", derived)
            if name != derived:
                raise SecurityError("package-lock.json package name does not match its path")
            component = _npm_component(derived, item.get("version"), scope, root=False)
        if component is not None:
            components.append(component)
    return components


def _dedupe(components: list[dict]) -> list[dict]:
    if len(components) > _MAX_COMPONENTS:
        raise SecurityError("Inventory has too many components")
    by_purl: dict[str, dict] = {}
    for component in components:
        previous = by_purl.get(component["purl"])
        if previous is not None and previous != component:
            raise SecurityError("The same package URL was collected with different metadata")
        by_purl[component["purl"]] = component
    return [by_purl[key] for key in sorted(by_purl)]


def collect_inventory(*, wordpress: str | None = None, composer_lock: str | None = None, package_lock: str | None = None) -> dict:
    """Build a CycloneDX 1.5 inventory. At least one source is required.

    The result contains versions and package URLs only. Local paths are not recorded.
    """
    if not any((wordpress, composer_lock, package_lock)):
        raise SecurityError("Pass at least one of wordpress, composer.lock or package-lock.json")
    components: list[dict] = []
    if wordpress is not None:
        root = _require_directory(Path(wordpress), "WordPress root")
        components.append(_wordpress_core(root))
        components.extend(_wordpress_plugins(root))
        components.extend(_wordpress_themes(root))
    if composer_lock is not None:
        components.extend(collect_composer_lock(composer_lock))
    if package_lock is not None:
        components.extend(collect_package_lock(package_lock))
    components = _dedupe(components)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": utc_now(),
            "tools": [{"name": "One Global Defence Ecosystem", "version": __version__}],
            "properties": [
                {"name": "ogde:inventory-scope", "value": "local-only"},
                {"name": "ogde:transmitted", "value": "false"},
            ],
        },
        "components": components,
    }
    if wordpress is not None:
        bom["metadata"]["properties"].append({
            "name": "ogde:collector-note",
            "value": "WordPress plugin headers are read only from top-level PHP files. Only the Version field is kept.",
        })
    return bom
