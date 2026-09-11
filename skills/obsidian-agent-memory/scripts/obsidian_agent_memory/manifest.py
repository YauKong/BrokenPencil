"""Strict loading for the portable Skill pack manifest."""

import json
import re
from pathlib import Path, PureWindowsPath
from typing import Dict, Iterable, List, Mapping, Tuple

from .errors import ValidationError
from .models import ManifestFile, PackManifest
from .paths import validate_identifier


_ACTIVE_MEMBERS = (
    "obsidian-agent-memory",
    "obsidian-agent-memory-init",
    "obsidian-agent-memory-route",
    "obsidian-agent-memory-collaboration",
    "obsidian-agent-memory-query",
    "obsidian-agent-memory-add",
    "obsidian-agent-memory-summary",
    "obsidian-agent-memory-maintain",
    "obsidian-agent-memory-upgrade",
)
_REMOVED_WRITER = "obsidian-agent-memory-" + "writer"
_TOP_LEVEL_KEYS = frozenset(
    {
        "name",
        "version",
        "minimum_python",
        "schema_versions",
        "active_members",
        "removed_members",
        "required_capabilities",
        "optional_capabilities",
        "release_archive",
        "release_checksum",
        "release_manifest",
        "files",
    }
)
_VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z"
)
_PYTHON_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_FORBIDDEN_CHARACTERS = frozenset('<>:"|?*')
_WINDOWS_DEVICE_STEMS = frozenset(
    ("CON", "PRN", "AUX", "NUL")
    + tuple("COM{0}".format(index) for index in range(1, 10))
    + tuple("LPT{0}".format(index) for index in range(1, 10))
)


def _pairs_object(pairs: Iterable[Tuple[str, object]]) -> Dict[str, object]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("duplicate pack manifest key")
        value[key] = item
    return value


def _require_string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("invalid pack manifest {0}".format(field))
    return value


def _require_list(value: object, field: str) -> List[object]:
    if not isinstance(value, list):
        raise ValidationError("invalid pack manifest {0}".format(field))
    return value


def _portable_path_is_safe(value: object, basename_only: bool = False) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or PureWindowsPath(value).is_absolute()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    if basename_only and "/" in value:
        return False

    parts = value.split("/")
    for component in parts:
        if (
            component in ("", ".", "..")
            or component.endswith((" ", "."))
            or any(character in _WINDOWS_FORBIDDEN_CHARACTERS for character in component)
            or component.split(".", 1)[0].upper() in _WINDOWS_DEVICE_STEMS
        ):
            return False
    return True


def _validated_identifiers(value: object, field: str) -> Tuple[str, ...]:
    items = _require_list(value, field)
    result = []
    for item in items:
        text = _require_string(item, field)
        result.append(validate_identifier(text, field))
    if tuple(result) != tuple(sorted(result)) or len(result) != len(set(result)):
        raise ValidationError("invalid pack manifest {0}".format(field))
    return tuple(result)


def _validated_schema_versions(value: object) -> Tuple[int, ...]:
    items = _require_list(value, "schema_versions")
    if any(type(item) is not int or item <= 0 for item in items):
        raise ValidationError("invalid pack manifest schema_versions")
    versions = tuple(items)
    if versions != tuple(sorted(set(versions))) or 2 not in versions:
        raise ValidationError("invalid pack manifest schema_versions")
    return versions


def _validate_manifest_path(value: object) -> str:
    path = _require_string(value, "files.path")
    if not _portable_path_is_safe(path):
        raise ValidationError("invalid pack manifest file path")
    return path


def _validated_files(value: object) -> Tuple[ManifestFile, ...]:
    items = _require_list(value, "files")
    result = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValidationError("invalid pack manifest file")
        path = _validate_manifest_path(item["path"])
        sha256 = _require_string(item["sha256"], "files.sha256")
        if not _SHA256_PATTERN.fullmatch(sha256):
            raise ValidationError("invalid pack manifest file hash")
        result.append(ManifestFile(path, sha256))
    paths = tuple(item.path for item in result)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise ValidationError("invalid pack manifest file order")
    return tuple(result)


def _validated_release_basename(value: object, field: str) -> str:
    basename = _require_string(value, field)
    if (
        basename != basename.strip(" \t")
        or not _portable_path_is_safe(basename, basename_only=True)
    ):
        raise ValidationError("invalid pack manifest {0}".format(field))
    return basename


def _convert_manifest(document: Mapping[str, object]) -> PackManifest:
    if set(document) != _TOP_LEVEL_KEYS:
        raise ValidationError("invalid pack manifest keys")

    name = validate_identifier(_require_string(document["name"], "name"), "pack name")
    version = _require_string(document["version"], "version")
    if not _VERSION_PATTERN.fullmatch(version):
        raise ValidationError("invalid pack manifest version")

    minimum_python = _require_string(document["minimum_python"], "minimum_python")
    match = _PYTHON_PATTERN.fullmatch(minimum_python)
    if match is None or (int(match.group(1)), int(match.group(2))) < (3, 9):
        raise ValidationError("invalid pack manifest minimum_python")

    schema_versions = _validated_schema_versions(document["schema_versions"])

    active_items = _require_list(document["active_members"], "active_members")
    if any(not isinstance(item, str) for item in active_items):
        raise ValidationError("invalid pack manifest active_members")
    active_members = tuple(active_items)
    if active_members != _ACTIVE_MEMBERS:
        raise ValidationError("invalid pack manifest active_members")

    removed_members = _validated_identifiers(document["removed_members"], "removed_members")
    if (
        _REMOVED_WRITER not in removed_members
        or set(active_members).intersection(removed_members)
        or _REMOVED_WRITER in active_members
    ):
        raise ValidationError("invalid pack manifest removed_members")

    required_capabilities = _validated_identifiers(
        document["required_capabilities"], "required_capabilities"
    )
    optional_capabilities = _validated_identifiers(
        document["optional_capabilities"], "optional_capabilities"
    )
    if set(required_capabilities).intersection(optional_capabilities):
        raise ValidationError("invalid pack manifest capabilities")

    release_archive = _validated_release_basename(
        document["release_archive"], "release_archive"
    )
    release_checksum = _validated_release_basename(
        document["release_checksum"], "release_checksum"
    )
    release_manifest = _validated_release_basename(
        document["release_manifest"], "release_manifest"
    )
    release_stem = "{0}-{1}".format(name, version)
    expected_release_names = (
        release_stem + ".zip",
        release_stem + ".zip.sha256",
        release_stem + "-manifest.json",
    )
    if (release_archive, release_checksum, release_manifest) != expected_release_names:
        raise ValidationError("invalid pack manifest release names")

    return PackManifest(
        name=name,
        version=version,
        minimum_python=minimum_python,
        schema_versions=schema_versions,
        active_members=active_members,
        removed_members=removed_members,
        required_capabilities=required_capabilities,
        optional_capabilities=optional_capabilities,
        release_archive=release_archive,
        release_checksum=release_checksum,
        release_manifest=release_manifest,
        files=_validated_files(document["files"]),
    )


def load_pack_manifest(path: Path) -> PackManifest:
    """Load one exact PackManifest JSON document or raise ValidationError."""
    try:
        content = Path(path).read_bytes().decode("utf-8")
        document = json.loads(content, object_pairs_hook=_pairs_object)
    except ValidationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("invalid pack manifest JSON") from error
    if not isinstance(document, dict):
        raise ValidationError("invalid pack manifest document")
    return _convert_manifest(document)
