"""Trust and exact-version exposure matching. No network, subprocesses or remote actions."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_JSON_BYTES = 10 * 1024 * 1024
SEVERITIES = {"critical", "high", "medium", "low", "unknown"}

class SecurityError(ValueError):
    """Fail-closed input or trust validation error."""


def _unique_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise SecurityError(f"Duplicate JSON key: {k}")
        out[k] = v
    return out


def read_json(path: str | Path) -> object:
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise SecurityError("Input exceeds the 10 MiB limit")
    try:
        return json.loads(data, object_pairs_hook=_unique_pairs, parse_constant=lambda x: (_ for _ in ()).throw(SecurityError("Invalid numeric constant")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SecurityError(f"Invalid JSON: {exc}") from exc


def canonical(obj: object) -> bytes:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SecurityError(f"Cannot canonicalise JSON: {exc}") from exc


def write_json(path: str | Path, payload: object) -> None:
    Path(path).write_bytes(json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n")


def _date(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SecurityError(f"{label} must be UTC ISO 8601 with trailing Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SecurityError(f"Invalid {label}") from exc
    if parsed.utcoffset().total_seconds() != 0:
        raise SecurityError(f"Invalid UTC {label}")
    return parsed


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _string(obj, key, *, maxlen=1024):
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > maxlen:
        raise SecurityError(f"Invalid or missing {key}")
    return value


def parse_purl(purl: str) -> tuple[str, str, str | None]:
    """Parse a limited PURL subset; does not claim full PURL validation."""
    if not isinstance(purl, str) or len(purl) > 1024 or not purl.startswith("pkg:") or any(c.isspace() for c in purl):
        raise SecurityError("Invalid package URL")
    no_subpath = purl.split("#", 1)[0].split("?", 1)[0]
    head, mark, version = no_subpath.rpartition("@")
    base = head if mark else no_subpath
    kind, slash, name = base[4:].partition("/")
    if not slash or not re.fullmatch(r"[a-zA-Z0-9.+-]+", kind) or not name or (bool(mark) and not version):
        raise SecurityError("Unsupported package URL")
    name = unquote(name)
    if any(p in ("", ".", "..") for p in name.split("/")) or "\\" in name:
        raise SecurityError("Invalid package path")
    if kind.lower() == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif kind.lower() == "npm":
        name = name.lower()
    return kind.lower(), name, version if mark else None


def validate_feed(feed: object) -> dict:
    if not isinstance(feed, dict):
        raise SecurityError("Unexpected feed structure")
    schema = feed.get("schema_version")
    if type(schema) is not int or schema not in (1, 2):
        raise SecurityError("Unsupported feed schema")
    allowed = {"schema_version", "feed_id", "generated_at", "expires_at", "advisories"}
    if schema == 2:
        allowed |= {"publisher_id", "revision"}
        _string(feed, "publisher_id", maxlen=100)
        if type(feed.get("revision")) is not int or not (1 <= feed["revision"] <= 2**53):
            raise SecurityError("Revision must be a positive integer")
    if set(feed) - allowed:
        raise SecurityError("Unexpected feed structure")
    _string(feed, "feed_id", maxlen=100)
    generated = _date(feed.get("generated_at"), "generated_at")
    expires = _date(feed.get("expires_at"), "expires_at")
    if expires <= generated or expires <= datetime.now(timezone.utc):
        raise SecurityError("Feed expired or has invalid validity window")
    if generated > datetime.now(timezone.utc).replace(microsecond=0) and (generated - datetime.now(timezone.utc)).total_seconds() > 300:
        raise SecurityError("Feed creation timestamp is too far in the future")
    entries = feed.get("advisories")
    if not isinstance(entries, list) or len(entries) > 5000:
        raise SecurityError("Advisories must be a list of at most 5000 entries")
    seen = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) - {"id", "title", "severity", "affected", "remediation", "references", "aliases"}:
            raise SecurityError("Unexpected advisory structure")
        adv_id = _string(item, "id", maxlen=150)
        if adv_id in seen:
            raise SecurityError("Duplicate advisory id")
        seen.add(adv_id)
        _string(item, "title", maxlen=300)
        if item.get("severity") not in SEVERITIES:
            raise SecurityError("Invalid advisory severity")
        _string(item, "remediation", maxlen=2000)
        affected = item.get("affected")
        if not isinstance(affected, list) or not affected or len(affected) > 1000:
            raise SecurityError("Advisory must identify 1–1000 affected component entries")
        for comp in affected:
            if not isinstance(comp, dict) or set(comp) != {"purl", "versions"}:
                raise SecurityError("Affected component must have purl and versions")
            if parse_purl(comp["purl"])[2] is not None:
                raise SecurityError("Advisory purl must not contain a version")
            if not isinstance(comp["versions"], list) or not comp["versions"] or len(comp["versions"]) > 1000 or any(not isinstance(v, str) or not v or len(v) > 100 for v in comp["versions"]):
                raise SecurityError("Affected versions must be explicit, nonempty strings")
        aliases = item.get("aliases", [])
        if not isinstance(aliases, list) or len(aliases) > 100 or any(
            not isinstance(alias, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", alias) for alias in aliases
        ) or len(aliases) != len(set(aliases)):
            raise SecurityError("Invalid advisory CVE aliases")
        links = item.get("references", [])
        if not isinstance(links, list) or len(links) > 20 or any(not isinstance(u, str) or not u.startswith("https://") or len(u) > 2048 for u in links):
            raise SecurityError("References must be HTTPS links")
    return feed


def public_key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _write_new(path: str | Path, data: bytes, *, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def generate_keypair(private_path: str | Path, public_path: str | Path) -> str:
    if Path(private_path).exists() or Path(public_path).exists():
        raise SecurityError("Refusing to overwrite an existing key")
    key = Ed25519PrivateKey.generate()
    secret = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    public = key.public_key()
    pubdata = public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    _write_new(private_path, secret, mode=0o600)
    try:
        _write_new(public_path, pubdata, mode=0o644)
    except BaseException:
        Path(private_path).unlink(missing_ok=True)
        raise
    return public_key_id(public)


def sign_feed(feed: object, private_path: str | Path) -> dict:
    validate_feed(feed)
    try:
        key = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise SecurityError("Could not read Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SecurityError("Signing key must be Ed25519")
    signature = key.sign(canonical(feed))
    return {"payload": feed, "signature": {"algorithm": "Ed25519", "key_id": public_key_id(key.public_key()), "value": base64.b64encode(signature).decode("ascii")}}


def verify_envelope_bytes(envelope: object, public_pem: bytes) -> dict:
    """Verify with an explicitly pinned trust anchor, never a key supplied in the envelope."""
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise SecurityError("Invalid signed envelope")
    sig = envelope["signature"]
    if not isinstance(sig, dict) or set(sig) != {"algorithm", "key_id", "value"} or sig.get("algorithm") != "Ed25519":
        raise SecurityError("Unsupported signature format")
    try:
        public = serialization.load_pem_public_key(public_pem)
    except (ValueError, TypeError) as exc:
        raise SecurityError("Could not load trusted public key") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise SecurityError("Trusted public key must be Ed25519")
    if sig.get("key_id") != public_key_id(public):
        raise SecurityError("Advisory key is not the pinned trusted key")
    try:
        encoded = sig["value"]
        if not isinstance(encoded, str):
            raise ValueError("Signature type")
        signature = base64.b64decode(encoded, validate=True)
        if len(signature) != 64:
            raise ValueError("Signature length")
        public.verify(signature, canonical(envelope["payload"]))
    except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
        raise SecurityError("Invalid advisory signature") from exc
    return validate_feed(envelope["payload"])


def verify_envelope(envelope: object, public_path: str | Path) -> dict:
    try:
        public_pem = Path(public_path).read_bytes()
    except OSError as exc:
        raise SecurityError("Could not read trusted public key") from exc
    return verify_envelope_bytes(envelope, public_pem)

@dataclass(frozen=True)
class Component:
    kind: str
    name: str
    version: str
    purl: str


def parse_sbom(bom: object) -> list[Component]:
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("components"), list):
        raise SecurityError("Provide a CycloneDX JSON SBOM with components")
    components: list[Component] = []
    def traverse(items, depth: int):
        if depth > 15:
            raise SecurityError("SBOM nesting exceeds limit")
        for item in items:
            if len(components) > 50000:
                raise SecurityError("SBOM has too many components")
            if not isinstance(item, dict):
                raise SecurityError("Invalid SBOM component")
            purl = item.get("purl")
            version = item.get("version")
            if purl:
                kind, name, purl_version = parse_purl(purl)
                if not isinstance(version, str) or not version:
                    version = purl_version
                elif purl_version and version != purl_version:
                    raise SecurityError("SBOM component version disagrees with PURL")
                if not version or len(version) > 100:
                    raise SecurityError("SBOM component requires a valid version")
                components.append(Component(kind, name, version, purl))
            children = item.get("components", [])
            if children:
                if not isinstance(children, list):
                    raise SecurityError("Invalid nested components")
                traverse(children, depth + 1)
    traverse(bom["components"], 0)
    return components


def scan_signed_feed(feed: dict, components: list[Component]) -> dict:
    index: dict[tuple[str, str, str], list[Component]] = {}
    for c in components:
        index.setdefault((c.kind, c.name, c.version), []).append(c)
    findings = []
    for adv in feed["advisories"]:
        for affected in adv["affected"]:
            kind, name, _ = parse_purl(affected["purl"])
            for version in affected["versions"]:
                for comp in index.get((kind, name, version), []):
                    findings.append({"advisory_id": adv["id"], "title": adv["title"], "severity": adv["severity"], "purl": comp.purl, "version": comp.version, "remediation": adv["remediation"], "references": adv.get("references", []), "aliases": adv.get("aliases", []), "basis": "exact-version match against verified advisory"})
    return {"source": "signed-feed", "feed_id": feed["feed_id"], "scanned_at": utc_now(), "components_checked": len(components), "finding_count": len(findings), "findings": findings, "limitations": ["Exact versions only; absence of findings does not demonstrate absence of vulnerabilities", "Only components present in the provided SBOM are assessed", "The signer's trustworthiness must be established independently"]}
