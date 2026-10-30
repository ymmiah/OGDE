"""Local file reads that do not follow symlinks and do not echo file contents."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .core import MAX_JSON_BYTES, SecurityError


def read_nofollow(path: str | Path, limit: int) -> bytes:
    """Read at most ``limit`` bytes. Symlinks are refused before they are opened."""
    if limit < 1:
        raise SecurityError("Invalid read limit")
    file_path = Path(path)
    if file_path.is_symlink():
        raise SecurityError("Refusing to follow a symlink")
    if not file_path.is_file():
        raise SecurityError("Local file is missing")
    if not hasattr(os, "O_NOFOLLOW"):
        raise SecurityError("This platform cannot refuse symlink follows")
    try:
        fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise SecurityError("Refusing to read a local path") from exc
    try:
        chunks: list[bytes] = []
        remaining = limit
        while remaining > 0:
            blob = os.read(fd, remaining)
            if not blob:
                break
            chunks.append(blob)
            remaining -= len(blob)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _pairs(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise SecurityError("Duplicate JSON key")
        seen[key] = value
    return seen


def load_json_file(path: str | Path) -> object:
    """Parse a local JSON file. Parse failures do not include file contents."""
    data = read_nofollow(path, MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise SecurityError("Input exceeds the 10 MiB limit")
    try:
        return json.loads(
            data,
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(SecurityError("Invalid JSON in local file")),
        )
    except SecurityError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SecurityError("Invalid JSON in local file") from exc
