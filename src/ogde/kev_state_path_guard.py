"""Fail-closed local state-path guard; never resolves symlinked ancestors."""
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
    if not target.parent.is_dir():
        raise SecurityError("Revision state directory is invalid")
    return target
