"""Chained local audit log: tamper-evident only if a chain head is anchored externally."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from .core import SecurityError, canonical, _unique_pairs, utc_now

ZERO = "0" * 64


def digest(record: dict) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


def verify_ledger(path: str | Path) -> dict:
    previous = ZERO
    count = 0
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    raise SecurityError(f"Blank audit record at line {count + 1}")
                record = json.loads(line, object_pairs_hook=_unique_pairs)
                if not isinstance(record, dict) or set(record) != {"sequence", "timestamp", "previous", "event", "hash"}:
                    raise SecurityError("Malformed audit record")
                if record["sequence"] != count + 1 or record["previous"] != previous:
                    raise SecurityError(f"Audit chain broken at line {count + 1}")
                contents = {k: record[k] for k in ("sequence", "timestamp", "previous", "event")}
                if digest(contents) != record["hash"]:
                    raise SecurityError(f"Audit record modified at line {count + 1}")
                previous = record["hash"]
                count += 1
    except (json.JSONDecodeError, UnicodeError, TypeError) as exc:
        raise SecurityError("Invalid audit ledger encoding") from exc
    return {"events": count, "head_hash": previous, "notice": "Anchor head_hash in independent storage to detect complete ledger rewriting"}


def append_event(path: str | Path, event: dict) -> dict:
    """Single-process demo only. Production requires serialised, locked and immutable storage."""
    p = Path(path)
    if p.exists():
        state = verify_ledger(p)
        count, prev = state["events"], state["head_hash"]
    else:
        count, prev = 0, ZERO
    row = {"sequence": count + 1, "timestamp": utc_now(), "previous": prev, "event": event}
    row["hash"] = digest(row)
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(canonical(row).decode("utf-8") + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return row
