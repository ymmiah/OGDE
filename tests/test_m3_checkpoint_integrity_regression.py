"""M3 checkpoint regression tests: no local state is a trust anchor.

These tests use only temporary, owner-controlled directories and never
contact a publisher or promote an advisory to trusted status.
"""
import os

import pytest

from ogde.core import SecurityError
from ogde.m3_checkpoint import checkpoint_digest, read_checkpoint, write_checkpoint


def test_checkpoint_requires_independently_supplied_digest(tmp_path):
    path = tmp_path / "revision.json"
    digest = write_checkpoint(path, 4)
    assert digest == checkpoint_digest(4)
    assert read_checkpoint(path, expected_digest=digest) == 4
    with pytest.raises(SecurityError):
        read_checkpoint(path, expected_digest="0" * 64)


def test_checkpoint_rejects_local_content_tampering(tmp_path):
    path = tmp_path / "revision.json"
    digest = write_checkpoint(path, 4)
    path.write_bytes(b'{"revision":5,"schema_version":1}\n')
    with pytest.raises(SecurityError):
        read_checkpoint(path, expected_digest=digest)


def test_checkpoint_refuses_overwrite_and_revision_rollback(tmp_path):
    path = tmp_path / "revision.json"
    write_checkpoint(path, 4)
    with pytest.raises(SecurityError):
        write_checkpoint(path, 5, previous_revision=4)
    with pytest.raises(SecurityError):
        write_checkpoint(tmp_path / "other.json", 4, previous_revision=4)
    with pytest.raises(SecurityError):
        write_checkpoint(tmp_path / "negative.json", 3, previous_revision=4)


def test_checkpoint_rejects_invalid_digest_and_revision_types(tmp_path):
    path = tmp_path / "revision.json"
    for revision in (True, 0, -1, 2**53 + 1, 1.5):
        with pytest.raises(SecurityError):
            checkpoint_digest(revision)
    for supplied in (None, "A" * 64, "f" * 63, "g" * 64):
        with pytest.raises(SecurityError):
            read_checkpoint(path, expected_digest=supplied)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_checkpoint_rejects_world_readable_state(tmp_path):
    path = tmp_path / "revision.json"
    digest = write_checkpoint(path, 1)
    path.chmod(0o644)
    with pytest.raises(SecurityError):
        read_checkpoint(path, expected_digest=digest)
