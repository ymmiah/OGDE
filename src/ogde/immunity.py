"""Federated trust anchors, anti-rollback and local assessment. No remote control.

Only the caller can install publisher trust. Signed data is never a command.
The Linux/macOS file lock serialises reads and writes across local processes.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import (SecurityError, canonical, parse_sbom, public_key_id, read_json,
                   scan_signed_feed, utc_now, verify_envelope_bytes)

IDENTIFIER = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,99}$")


def safe_save(path: str | Path, obj: object, *, overwrite: bool = True) -> None:
    """Atomic fsync + replacement with private permissions; existing symlinks refused."""
    dest = Path(path)
    if dest.is_symlink():
        raise SecurityError("Refusing to write through symlink")
    if not overwrite and dest.exists():
        raise SecurityError("Refusing to replace existing file")
    data = json.dumps(obj, indent=2, ensure_ascii=False, allow_nan=False).encode() + b"\n"
    if len(data) > 10 * 1024 * 1024:
        raise SecurityError("Output exceeds 10 MiB")
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".ogde-", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if not overwrite and dest.exists():
            raise SecurityError("Refusing to replace existing file")
        os.replace(temp_name, dest)
        dirfd = os.open(dest.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        Path(temp_name).unlink(missing_ok=True)


def safe_save_text(path: str | Path, text: str) -> None:
    """Write sensitive assessment text with private file permissions."""
    dest = Path(path)
    if dest.is_symlink():
        raise SecurityError("Refusing to write through symlink")
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".ogde-", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, dest)
    finally:
        Path(temp_name).unlink(missing_ok=True)


def _load_registry(store: str | Path) -> dict:
    path = Path(store)
    registry = read_json(path) if path.exists() else {"schema_version": 1, "publishers": []}
    if not isinstance(registry, dict) or set(registry) != {"schema_version", "publishers"} or type(registry["schema_version"]) is not int or registry["schema_version"] != 1:
        raise SecurityError("Invalid trust registry schema")
    publishers = registry["publishers"]
    if not isinstance(publishers, list) or len(publishers) > 100:
        raise SecurityError("Invalid trust registry size")
    seen = set()
    for p in publishers:
        if not isinstance(p, dict) or set(p) != {"feed_id", "publisher_id", "key_id", "public_key_pem"}:
            raise SecurityError("Malformed trust entry")
        if not all(isinstance(p[k], str) and IDENTIFIER.fullmatch(p[k]) for k in ("feed_id", "publisher_id")):
            raise SecurityError("Invalid publisher identifiers")
        pair = (p["feed_id"], p["publisher_id"])
        if pair in seen:
            raise SecurityError("Duplicate trust entry")
        seen.add(pair)
        try:
            key = serialization.load_pem_public_key(p["public_key_pem"].encode("ascii"))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise SecurityError("Invalid trusted public key") from exc
        if not isinstance(key, Ed25519PublicKey) or public_key_id(key) != p["key_id"]:
            raise SecurityError("Trust entry key fingerprint mismatch")
    return registry


def add_publisher(store: str | Path, *, public: str | Path, publisher_id: str, feed_id: str, acknowledged: bool) -> dict:
    if not acknowledged:
        raise SecurityError("Key pinning requires --confirm-trust-anchor after out-of-band verification")
    if not all(isinstance(x, str) and IDENTIFIER.fullmatch(x) for x in (publisher_id, feed_id)):
        raise SecurityError("Invalid publisher or feed ID")
    try:
        pem = Path(public).read_bytes()
        key = serialization.load_pem_public_key(pem)
    except (OSError, ValueError, TypeError) as exc:
        raise SecurityError("Invalid publisher key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SecurityError("Publisher key must be Ed25519")
    registry = _load_registry(store)
    if any(p["feed_id"] == feed_id for p in registry["publishers"]):
        raise SecurityError("Feed already pinned. Key rotation needs a separate, reviewed procedure")
    if len(registry["publishers"]) == 100:
        raise SecurityError("Publisher limit reached")
    entry = {"feed_id": feed_id, "publisher_id": publisher_id,
             "key_id": public_key_id(key), "public_key_pem": pem.decode("ascii")}
    registry["publishers"].append(entry)
    safe_save(store, registry)
    return {k: entry[k] for k in ("feed_id", "publisher_id", "key_id")}


def trusted_feed(registry_path: str | Path, envelope: object) -> tuple[dict, dict]:
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
        raise SecurityError("Invalid advisory envelope")
    payload = envelope["payload"]
    if payload.get("schema_version") != 2:
        raise SecurityError("Federated mode requires version 2 feeds with revision numbers")
    feed_id, publisher_id = payload.get("feed_id"), payload.get("publisher_id")
    if not all(isinstance(x, str) and IDENTIFIER.fullmatch(x) for x in (feed_id, publisher_id)):
        raise SecurityError("Invalid signed feed identifiers")
    matches = [p for p in _load_registry(registry_path)["publishers"] if p["feed_id"] == feed_id and p["publisher_id"] == publisher_id]
    if len(matches) != 1:
        raise SecurityError("No pinned trust anchor for this feed and publisher")
    pinned = matches[0]
    feed = verify_envelope_bytes(envelope, pinned["public_key_pem"].encode("ascii"))
    return feed, {k: pinned[k] for k in ("feed_id", "publisher_id", "key_id")}


@contextmanager
def _locked_state(path: str | Path):
    lock = Path(str(path) + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    if lock.is_symlink():
        raise SecurityError("Unsafe state lock symlink")
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "r+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            yield
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    finally:
        pass


def _check_and_update_revision(state_path: str | Path, feed: dict, digest: str) -> None:
    state_file = Path(state_path)
    with _locked_state(state_file):
        state = read_json(state_file) if state_file.exists() else {"schema_version": 1, "feeds": {}}
        if not isinstance(state, dict) or set(state) != {"schema_version", "feeds"} or state["schema_version"] != 1 or not isinstance(state["feeds"], dict) or len(state["feeds"]) > 100:
            raise SecurityError("Invalid revision state")
        key = feed["feed_id"]
        previous = state["feeds"].get(key)
        if previous is not None:
            if not isinstance(previous, dict) or set(previous) != {"publisher_id", "revision", "digest", "generated_at"}:
                raise SecurityError("Corrupt revision state")
            if previous["publisher_id"] != feed["publisher_id"]:
                raise SecurityError("Feed publisher unexpectedly changed")
            if feed["revision"] < previous["revision"]:
                raise SecurityError("Signed feed rollback blocked")
            if feed["revision"] == previous["revision"] and digest != previous["digest"]:
                raise SecurityError("Equivocated feed revision blocked")
            if feed["revision"] > previous["revision"] and feed["generated_at"] < previous["generated_at"]:
                raise SecurityError("Feed timestamp went backwards")
        state["feeds"][key] = {"publisher_id": feed["publisher_id"], "revision": feed["revision"], "digest": digest, "generated_at": feed["generated_at"]}
        safe_save(state_file, state)


def assess(registry_path: str | Path, envelope: object, sbom: object,
           context: dict, state_path: str | Path, kev_snapshot: object | None = None) -> dict:
    """Fail-closed locally, then record monotonic signed revision. Never modifies assets."""
    from .policy import enrich_report, validate_context
    from .kev import kev_index
    feed, signer = trusted_feed(registry_path, envelope)
    components = parse_sbom(sbom)
    local_context = validate_context(context)
    index = kev_index(kev_snapshot) if kev_snapshot is not None else None
    report = scan_signed_feed(feed, components)
    report.update({"publisher": signer, "revision": feed["revision"], "feed_digest_sha256": hashlib.sha256(canonical(envelope)).hexdigest(), "asset": local_context})
    report = enrich_report(report, local_context, index)
    _check_and_update_revision(state_path, feed, report["feed_digest_sha256"])
    report["limitations"].extend([
        "Publisher public keys must be verified out of band; a valid signature alone does not prove a claim",
        "Manual response only; no remote scanning, global telemetry or automatic production changes",
        "Rollback protection assumes local state is protected from deletion and restoration of stale copies",
    ])
    return report
