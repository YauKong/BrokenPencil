"""Explicit fixture/real provenance gates for vault operations."""

import json
import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .errors import ValidationError
from .paths import validate_identifier


class OperationScope(str, Enum):
    FIXTURE = "fixture"
    REAL = "real"


@dataclass(frozen=True)
class AuthorizationGate:
    scope: OperationScope
    authorization_ref: Optional[str]


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _resolved_existing_directory(root: Path) -> Path:
    try:
        resolved = Path(root).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValidationError("memory root must be an existing directory") from error
    if not resolved.is_dir():
        raise ValidationError("memory root must be an existing directory")
    return resolved


def _read_fixture_marker(root: Path) -> object:
    marker = root / ".agent-memory-fixture.json"
    try:
        metadata = os.lstat(marker)
    except OSError as error:
        raise ValidationError("fixture marker is required") from error
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or attributes & reparse_flag
        or metadata.st_size > 4096
    ):
        raise ValidationError("invalid fixture marker")
    try:
        raw = marker.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValidationError("invalid fixture marker") from error


def require_operation_gate(
    root: Path,
    gate: AuthorizationGate,
    operation: str,
) -> Path:
    """Validate explicit scope/provenance and return the selected root."""
    try:
        validate_identifier(operation, "operation")
    except ValidationError as error:
        raise ValidationError("invalid operation") from error
    if not isinstance(gate, AuthorizationGate) or not isinstance(
        gate.scope, OperationScope
    ):
        raise ValidationError("invalid operation scope")

    if gate.scope is OperationScope.REAL:
        if (
            not isinstance(gate.authorization_ref, str)
            or not gate.authorization_ref.strip()
        ):
            raise ValidationError("authorization reference is required for real scope")
        return _resolved_existing_directory(root)

    resolved = _resolved_existing_directory(root)
    marker = _read_fixture_marker(resolved)
    if not isinstance(marker, dict) or set(marker) != {
        "fixture_id",
        "fixture_version",
    }:
        raise ValidationError("invalid fixture marker")
    try:
        validate_identifier(marker.get("fixture_id"), "fixture marker id")
    except ValidationError as error:
        raise ValidationError("invalid fixture marker") from error
    if type(marker.get("fixture_version")) is not int or marker["fixture_version"] != 1:
        raise ValidationError("invalid fixture marker")
    return resolved
