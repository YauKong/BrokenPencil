"""Strict release metadata loading, collection, refresh, and validation."""

import hashlib
import json
import os
import re
import stat
from dataclasses import replace
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Tuple

from obsidian_agent_memory import (
    ConflictError,
    Finding,
    ManifestFile,
    PackManifest,
    ValidationError,
    load_pack_manifest,
    resolve_inside,
    validate_identifier,
)
from obsidian_agent_memory.manifest import _portable_path_is_safe

from .io import (
    _assert_plain_components,
    atomic_write,
    canonical_json_bytes,
)
from .models import RemovalProfile, RemovalProfileSet


_REMOVED_WRITER = "obsidian-agent-memory-" + "writer"
ACTIVE_MEMBERS = (
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
REMOVED_MEMBERS = (_REMOVED_WRITER,)
REQUIRED_CAPABILITIES = ()
OPTIONAL_CAPABILITIES = ("obsidian-cli", "obsidian-knowledge-base")
_PACK_NAME = "obsidian-agent-memory-skill-pack"
_VERSION = "2.0.1"
# Persisted plans and rollback state from the preceding release remain readable.
SUPPORTED_LIFECYCLE_VERSIONS = ("2.0.0", _VERSION)
_MINIMUM_PYTHON = "3.9"
_SCHEMA_VERSIONS = (1, 2)
_RELEASE_ARCHIVE = "obsidian-agent-memory-skill-pack-" + _VERSION + ".zip"
_RELEASE_CHECKSUM = _RELEASE_ARCHIVE + ".sha256"
_RELEASE_MANIFEST = "obsidian-agent-memory-skill-pack-" + _VERSION + "-manifest.json"
_REMOVAL_PROFILE_ID = "installed-unmanaged-v1-2026-08-30"
_REMOVAL_DIRECTORIES = (
    "obsidian-agent-memory",
    "obsidian-agent-memory-add",
    "obsidian-agent-memory-collaboration",
    "obsidian-agent-memory-init",
    "obsidian-agent-memory-maintain",
    "obsidian-agent-memory-query",
    "obsidian-agent-memory-route",
    "obsidian-agent-memory-summary",
    "obsidian-agent-memory-upgrade",
    _REMOVED_WRITER,
    _REMOVED_WRITER + "/agents",
    _REMOVED_WRITER + "/scripts",
    "obsidian-agent-memory/designs",
    "obsidian-agent-memory/plans",
    "obsidian-agent-memory/references",
    "obsidian-agent-memory/scripts",
)
_REMOVAL_FILES = (
    ManifestFile(
        "obsidian-agent-memory-add/SKILL.md",
        "b8f7c28fef2d396100287a2557fd4413eff6881eb229df7feaea86c9165bec9d",
    ),
    ManifestFile(
        "obsidian-agent-memory-collaboration/SKILL.md",
        "1a73b2a600ff336248741145743c531e4602fd2d0863ade458990e600809291c",
    ),
    ManifestFile(
        "obsidian-agent-memory-init/SKILL.md",
        "f226988c25a66332b648018efe055a065e1f1ba60c340a2752681190a478ec31",
    ),
    ManifestFile(
        "obsidian-agent-memory-maintain/SKILL.md",
        "1be3e82ce39859c95c4d12eab86e68e5efbd60708fcf9ae8ef106a463522fefc",
    ),
    ManifestFile(
        "obsidian-agent-memory-query/SKILL.md",
        "ac449140365cbb52cb6c2d10f721ee50f098d7e4ddbb20a100fc38e54ace2348",
    ),
    ManifestFile(
        "obsidian-agent-memory-route/SKILL.md",
        "18fe176f75e1fac63f76d9eadd46c3bd861dd9f0e9165b31e03338f69b26de9a",
    ),
    ManifestFile(
        "obsidian-agent-memory-summary/SKILL.md",
        "39d37a6840b598c264ca0cb7d8fb5e0208f6deae374a44f30f78a13b53ddb8a0",
    ),
    ManifestFile(
        "obsidian-agent-memory-upgrade/SKILL.md",
        "f216ce285d0a94f1e00fad7019f44ba810bd00cd8a1bf81d43c2dffccc85924b",
    ),
    ManifestFile(
        _REMOVED_WRITER + "/SKILL.md",
        "a81e4a99edfa939d8b733d7528b30e591da8605409055dd06933bf667ed7c0c2",
    ),
    ManifestFile(
        _REMOVED_WRITER + "/agents/openai.yaml",
        "634fae20b5526dbca8458f480e9c2d758204bd1a6e0deb53d2c653e4d6bacf9c",
    ),
    ManifestFile(
        _REMOVED_WRITER + "/scripts/create_session_summary.py",
        "dda64e7798b523ee2c3d8861fc79d8d1f1ba74cefdfa9437449caf2dac930b19",
    ),
    ManifestFile(
        "obsidian-agent-memory/SKILL.md",
        "ad80787eaececae75c03d91193c92ab0ac2ace603633ca84a17f31fbb2b5225c",
    ),
    ManifestFile(
        "obsidian-agent-memory/designs/2026-08-03-collaboration-skill-design.md",
        "1e8db536a6db78aeb5844e71a6ab93cec8e1ffd4b14f2154b2c51b740400696e",
    ),
    ManifestFile(
        "obsidian-agent-memory/designs/2026-08-03-collaboration-skill-tdd.md",
        "d3a9d7b489f475d1f51d2e40ef74ad9b50b9657cb260dae363d6bbbf5c6543d6",
    ),
    ManifestFile(
        "obsidian-agent-memory/plans/2026-08-03-collaboration-skill.md",
        "73cd9203e4b61b51130568b26c1e7b9f1077118c33a61e9ed504c16d5646730b",
    ),
    ManifestFile(
        "obsidian-agent-memory/references/project-story-template.md",
        "c2de48f6b5261b7e3a608b8fa0f483baa2870176487d20a87da2adfa87ca80b6",
    ),
    ManifestFile(
        "obsidian-agent-memory/references/schema.md",
        "827535ac70941bfbc76bed20cd86dea2a6eabdfd7f6f356821a8b3c52c42bf67",
    ),
    ManifestFile(
        "obsidian-agent-memory/references/session-template.md",
        "c7a8b343fbc24629e89897b992af21e3d40dd97103d9bdff5c7523521335441b",
    ),
    ManifestFile(
        "obsidian-agent-memory/references/source-priority.md",
        "b45c334a512f1de85a61c54926b77785ae6dad17fcb159072a3cb515de2bfbab",
    ),
    ManifestFile(
        "obsidian-agent-memory/scripts/create_session_summary.py",
        "dda64e7798b523ee2c3d8861fc79d8d1f1ba74cefdfa9437449caf2dac930b19",
    ),
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_REQUIRED_PAYLOAD_PATHS = frozenset(
    (
        "skills/obsidian-agent-memory/scripts/vault_migrate.py",
        "skills/obsidian-agent-memory/scripts/vault_maintain.py",
        "skills/obsidian-agent-memory/scripts/obsidian_agent_memory/cli_migrate.py",
        "skills/obsidian-agent-memory/scripts/obsidian_agent_memory/cli_maintain.py",
        "tools/vault_migrate.py",
        "tools/vault_maintain.py",
    )
)
_WRITER_LITERAL = "obsidian-agent-memory-" + "writer"
_WRITER_ALLOWED_PATHS = frozenset(
    (
        "removal-profiles.json",
        "skills/obsidian-agent-memory/references/v1-to-v2-migration.md",
        "docs/release-and-authorization.md",
    )
)


def _pairs_object(pairs: Iterable[Tuple[str, object]]) -> Dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("duplicate removal profile key")
        result[key] = value
    return result


def _require_list(value: object, field: str) -> List[object]:
    if not isinstance(value, list):
        raise ValidationError("invalid removal profile {0}".format(field))
    return value


def _validate_directory_path(value: object) -> str:
    if not isinstance(value, str) or not _portable_path_is_safe(value):
        raise ValidationError("invalid removal profile directory")
    parts = value.split("/")
    resolve_inside(Path(os.path.abspath(os.sep)), *parts)
    return value


def _validate_file(value: object) -> ManifestFile:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValidationError("invalid removal profile file")
    path = value["path"]
    sha256 = value["sha256"]
    if not isinstance(path, str) or not _portable_path_is_safe(path):
        raise ValidationError("invalid removal profile file path")
    parent_parts = path.split("/")[:-1]
    if parent_parts:
        resolve_inside(Path(os.path.abspath(os.sep)), *parent_parts)
    if not isinstance(sha256, str) or not _SHA256_PATTERN.fullmatch(sha256):
        raise ValidationError("invalid removal profile file hash")
    return ManifestFile(path, sha256)


def load_removal_profiles(path: Path) -> RemovalProfileSet:
    """Load the one exact, recognized unmanaged-1.x family profile."""
    source = Path(os.path.abspath(os.fspath(path)))
    try:
        _assert_plain_components(source, allow_missing=False)
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("removal profile source is not a regular file")
        text = source.read_bytes().decode("utf-8")
        document = json.loads(text, object_pairs_hook=_pairs_object)
    except ValidationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("invalid removal profile JSON") from error
    if not isinstance(document, dict) or set(document) != {"schema_version", "profiles"}:
        raise ValidationError("invalid removal profile keys")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValidationError("invalid removal profile schema_version")

    profiles = []
    profile_ids = []
    for value in _require_list(document["profiles"], "profiles"):
        if not isinstance(value, dict) or set(value) != {
            "profile_id",
            "directories",
            "files",
        }:
            raise ValidationError("invalid removal profile entry")
        profile_id = value["profile_id"]
        if not isinstance(profile_id, str):
            raise ValidationError("invalid removal profile profile_id")
        validate_identifier(profile_id, "removal profile_id")
        directories = tuple(
            _validate_directory_path(item)
            for item in _require_list(value["directories"], "directories")
        )
        files = tuple(
            _validate_file(item) for item in _require_list(value["files"], "files")
        )
        if directories != tuple(sorted(set(directories))):
            raise ValidationError("invalid removal profile directory order")
        file_paths = tuple(item.path for item in files)
        if file_paths != tuple(sorted(set(file_paths))):
            raise ValidationError("invalid removal profile file order")
        profiles.append(RemovalProfile(profile_id, directories, files))
        profile_ids.append(profile_id)
    if len(profile_ids) != len(set(profile_ids)):
        raise ValidationError("duplicate removal profile_id")
    result = RemovalProfileSet(1, tuple(profiles))
    expected = RemovalProfileSet(
        1,
        (RemovalProfile(_REMOVAL_PROFILE_ID, _REMOVAL_DIRECTORIES, _REMOVAL_FILES),),
    )
    if result != expected:
        raise ValidationError("unrecognized unmanaged legacy family profile")
    return result


def _is_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def _payload_excluded(relative: str) -> bool:
    parts = relative.split("/")
    return bool(
        "__pycache__" in parts
        or relative.endswith(".pyc")
        or relative == "tests/unit/test_evaluation_evidence.py"
        or relative.startswith("tests/evaluations/")
        or any(
            part.startswith(".") and ".pending-" in part
            or ".candidate-" in part
            or part.endswith(".tmp")
            for part in parts
        )
    )


def _hash_payload_file(root: Path, path: Path) -> ManifestFile:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValidationError("payload path cannot be inspected") from error
    relative = path.relative_to(root).as_posix()
    if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError("payload path is not a regular contained file")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValidationError("payload path cannot be read") from error
    return ManifestFile(relative, hashlib.sha256(raw).hexdigest())


def _collect_tree(root: Path, relative_root: str) -> List[ManifestFile]:
    scan_root = root / relative_root
    try:
        root_metadata = scan_root.lstat()
    except FileNotFoundError:
        return []
    except OSError as error:
        raise ValidationError("payload root cannot be inspected") from error
    if _is_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValidationError("payload root is not a plain directory")
    result = []
    for current_text, directory_names, file_names in os.walk(
        str(scan_root), topdown=True, followlinks=False
    ):
        current = Path(current_text)
        retained = []
        for name in sorted(directory_names):
            candidate = current / name
            relative = candidate.relative_to(root).as_posix()
            try:
                metadata = candidate.lstat()
            except OSError as error:
                raise ValidationError("payload directory cannot be inspected") from error
            if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
                raise ValidationError("payload directory is a reparse point")
            if not _payload_excluded(relative) and relative != "tests/evaluations":
                retained.append(name)
        directory_names[:] = retained
        for name in sorted(file_names):
            candidate = current / name
            relative = candidate.relative_to(root).as_posix()
            try:
                metadata = candidate.lstat()
            except OSError as error:
                raise ValidationError("payload file cannot be inspected") from error
            if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
                raise ValidationError("payload file is not a plain regular file")
            if _payload_excluded(relative):
                continue
            result.append(_hash_payload_file(root, candidate))
    return result


def collect_manifest_files(repo_root: Path) -> Tuple[ManifestFile, ...]:
    """Hash the deterministic release payload, excluding source-only evidence."""
    root = Path(os.path.abspath(os.fspath(repo_root)))
    _assert_plain_components(root, allow_missing=False)
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise ValidationError("repository root cannot be inspected") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ValidationError("repository root is not a directory")

    result = []
    for relative_root in ("skills", "tools", "tests"):
        result.extend(_collect_tree(root, relative_root))
    for relative in (
        ".gitattributes",
        ".gitignore",
        "README.md",
        "VERSION",
        "removal-profiles.json",
        "docs/release-and-authorization.md",
        "docs/vault-migration-operations.md",
    ):
        candidate = root.joinpath(*relative.split("/"))
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ValidationError("payload root file cannot be inspected") from error
        result.append(_hash_payload_file(root, candidate))
    return tuple(sorted(result, key=lambda item: item.path))


def _header_is_fixed(manifest: PackManifest) -> bool:
    return (
        manifest.name == _PACK_NAME
        and manifest.version == _VERSION
        and manifest.minimum_python == _MINIMUM_PYTHON
        and manifest.schema_versions == _SCHEMA_VERSIONS
        and manifest.active_members == ACTIVE_MEMBERS
        and manifest.removed_members == REMOVED_MEMBERS
        and manifest.required_capabilities == REQUIRED_CAPABILITIES
        and manifest.optional_capabilities == OPTIONAL_CAPABILITIES
        and manifest.release_archive == _RELEASE_ARCHIVE
        and manifest.release_checksum == _RELEASE_CHECKSUM
        and manifest.release_manifest == _RELEASE_MANIFEST
    )


def _manifest_document(manifest: PackManifest) -> Mapping[str, object]:
    return {
        "active_members": list(manifest.active_members),
        "files": [
            {"path": item.path, "sha256": item.sha256} for item in manifest.files
        ],
        "minimum_python": manifest.minimum_python,
        "name": manifest.name,
        "optional_capabilities": list(manifest.optional_capabilities),
        "release_archive": manifest.release_archive,
        "release_checksum": manifest.release_checksum,
        "release_manifest": manifest.release_manifest,
        "removed_members": list(manifest.removed_members),
        "required_capabilities": list(manifest.required_capabilities),
        "schema_versions": list(manifest.schema_versions),
        "version": manifest.version,
    }


def refresh_pack_manifest(repo_root: Path, check: bool = False) -> PackManifest:
    """Refresh only ``pack.json.files`` or reject source drift in check mode."""
    root = Path(os.path.abspath(os.fspath(repo_root)))
    manifest_path = root / "pack.json"
    manifest = load_pack_manifest(manifest_path)
    if not _header_is_fixed(manifest):
        raise ValidationError("pack manifest fixed header drift")
    refreshed = replace(manifest, files=collect_manifest_files(root))
    desired = canonical_json_bytes(_manifest_document(refreshed))
    try:
        current = manifest_path.read_bytes()
    except OSError as error:
        raise ValidationError("pack manifest cannot be read") from error
    if current != desired:
        if check:
            raise ConflictError("pack manifest files are out of date")
        atomic_write(
            manifest_path,
            desired,
            "refresh-pack-manifest",
            "replace-files",
            hashlib.sha256(current).hexdigest(),
        )
    return refreshed


def _finding(code: str, path: str, message: str) -> Finding:
    return Finding(code, "error", path, message)


def _sorted_findings(findings: Iterable[Finding]) -> Tuple[Finding, ...]:
    return tuple(
        sorted(
            set(findings),
            key=lambda item: (item.severity, item.code, item.path, item.message),
        )
    )


def validate_release_metadata(
    repo_root: Path, manifest: PackManifest
) -> Tuple[Finding, ...]:
    """Validate fixed release metadata without repairing or printing."""
    root = Path(os.path.abspath(os.fspath(repo_root)))
    findings = []
    try:
        version = (root / "VERSION").read_bytes()
    except OSError:
        version = None
    if version != (_VERSION + "\n").encode("ascii"):
        findings.append(
            _finding("release-version-invalid", "VERSION", "release version bytes differ")
        )
    if not _header_is_fixed(manifest):
        findings.append(
            _finding(
                "release-header-invalid",
                "pack.json",
                "release header differs from the fixed " + _VERSION + " contract",
            )
        )

    try:
        collected = collect_manifest_files(root)
    except ValidationError:
        collected = None
        findings.append(
            _finding(
                "release-payload-invalid",
                ".",
                "release payload contains an invalid path or entry",
            )
        )
    if collected is not None and collected != manifest.files:
        findings.append(
            _finding(
                "release-files-drift",
                "pack.json",
                "manifest files differ from the deterministic payload",
            )
        )

    try:
        load_removal_profiles(root / "removal-profiles.json")
    except ValidationError:
        findings.append(
            _finding(
                "removal-profile-invalid",
                "removal-profiles.json",
                "legacy removal profile differs from the recognized whole family",
            )
        )

    declared_paths = frozenset(item.path for item in manifest.files)
    for relative in sorted(_REQUIRED_PAYLOAD_PATHS - declared_paths):
        findings.append(
            _finding(
                "release-entrypoint-missing",
                relative,
                "required installed or clone entrypoint is not manifested",
            )
        )

    for item in manifest.files:
        candidate = root.joinpath(*item.path.split("/"))
        try:
            text = candidate.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _WRITER_LITERAL not in text:
            continue
        if item.path.startswith("tests/") or item.path in _WRITER_ALLOWED_PATHS:
            continue
        findings.append(
            _finding(
                "removed-member-present",
                item.path,
                "removed member is exposed outside removal or migration evidence",
            )
        )
    return _sorted_findings(findings)
