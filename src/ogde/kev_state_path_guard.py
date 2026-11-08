"""Fail-closed local state-path guard; never resolves symlinked ancestors."""
import stat
from pathlib import Path
from .core import SecurityError


def validate_kev_state_path(path: str | Path) -> Path:
    """Reject a state target with any symlink in its existing ancestry."""
    target = Path(path).absolute()
    if target.is_symlink():
        raise SecurityError("Refusing revision state symlink")
    for parent in target.parents:
        if parent.is_symlink():
            raise SecurityError("Refusing symlink in revision state directory ancestry")
    # Reject existing non-files before the lock wrapper creates a sidecar.
    # lstat also avoids following a replaced target symlink here.
    if target.exists():
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise SecurityError("Revision state target must be a regular file")
        if info.st_mode & 0o077:
            raise SecurityError("Revision state target must be private")
    if not target.parent.is_dir():
        raise SecurityError("Revision state directory is invalid")
    return target
