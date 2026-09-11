"""Portable identifier validation and contained-path resolution."""

import re
from pathlib import Path, PureWindowsPath

from .errors import ContainmentError, ValidationError


_IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_WINDOWS_DEVICE_NAMES = frozenset(
    ["con", "prn", "aux", "nul"]
    + ["com{0}".format(number) for number in range(1, 10)]
    + ["lpt{0}".format(number) for number in range(1, 10)]
)


def validate_identifier(value: str, field: str) -> str:
    """Return a portable identifier unchanged, or reject it lexically."""
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValidationError("invalid {0}".format(field))
    if value.endswith(".") or value.split(".", 1)[0].lower() in _WINDOWS_DEVICE_NAMES:
        raise ValidationError("invalid {0}".format(field))
    return value


def resolve_inside(root: Path, *parts: str) -> Path:
    """Resolve validated relative components and prove they remain below *root*."""
    resolved_root = Path(root).resolve(strict=False)
    candidate = resolved_root
    for part in parts:
        part_path = Path(part)
        if part_path.is_absolute() or PureWindowsPath(part).is_absolute():
            raise ContainmentError("invalid absolute path component")
        try:
            validate_identifier(part, "path component")
        except ValidationError as error:
            raise ContainmentError("invalid path component") from error
        candidate = candidate / part

    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as error:
        raise ContainmentError("candidate path escapes the permitted root") from error
    return resolved_candidate
