"""Read-only Skill pack install planning and reviewed plan documents."""

import hashlib
import json
import os
import re
import stat
import ctypes
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from obsidian_agent_memory import (
    AgentMemoryError,
    ConflictError,
    Finding,
    LockBusyError,
    ManifestFile,
    PackManifest,
    ValidationError,
    load_pack_manifest,
    validate_identifier,
    validate_repository,
)
from obsidian_agent_memory.manifest import _portable_path_is_safe

from .io import (
    _assert_plain_components,
    _is_reparse,
    atomic_publish_exclusive,
    canonical_json_bytes,
)
from .metadata import (
    ACTIVE_MEMBERS,
    REMOVED_MEMBERS,
    SUPPORTED_LIFECYCLE_VERSIONS,
    load_removal_profiles,
    validate_release_metadata,
)
from .models import (
    LifecycleAction,
    LifecycleBlocker,
    LifecyclePlan,
    LifecycleResult,
    RemovalProfile,
    SkillRootSelection,
)
from .release import _regular_bytes, verified_release_source
from .roots import resolve_skill_roots


_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_PACK_NAME = "obsidian-agent-memory-skill-pack"
_PLAN_KEYS = frozenset(
    (
        "actions",
        "actor",
        "blockers",
        "from_version",
        "installed_state_sha256",
        "legacy_profile_id",
        "occurred_at",
        "operation",
        "pack_name",
        "schema_version",
        "skills_root",
        "source",
        "source_revision",
        "state_root",
        "target_digest",
        "target_revision",
        "to_version",
        "transaction_id",
    )
)
_ACTION_KEYS = frozenset(
    (
        "action_id",
        "expected_files",
        "kind",
        "member",
        "source_relative",
        "target_relative",
    )
)
_BLOCKER_KEYS = frozenset(("code", "message", "path"))
_FILE_KEYS = frozenset(("path", "sha256"))
_INSTALLED_KEYS = frozenset(
    (
        "actor",
        "authorization_ref",
        "directories",
        "files",
        "occurred_at",
        "pack_name",
        "pack_version",
        "schema_version",
        "skills_root",
        "source_revision",
        "target_digest",
        "transaction_id",
    )
)
_ACTION_KINDS = frozenset(
    (
        "create-skills-root",
        "archive-member",
        "activate-member",
        "write-installed-state",
        "archive-installed-state",
    )
)


@dataclass(frozen=True)
class _Inventory:
    directories: Tuple[str, ...]
    files: Tuple[ManifestFile, ...]


@dataclass(frozen=True)
class _InstalledState:
    raw: bytes
    document: Mapping[str, object]
    inventory: _Inventory


@dataclass(frozen=True)
class _SourceContext:
    root: Path
    locator: str
    revision: str
    manifest: PackManifest


def _pairs_object(pairs: Iterable[Tuple[str, object]]) -> Dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("duplicate lifecycle JSON key")
        result[key] = value
    return result


def _json_document(raw: bytes, name: str) -> Mapping[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_object)
    except ValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("invalid {0} JSON".format(name)) from error
    if not isinstance(value, dict):
        raise ValidationError("invalid {0} document".format(name))
    return value


def _validate_timestamp(value: str, field: str) -> str:
    if not isinstance(value, str) or not _TIMESTAMP_PATTERN.fullmatch(value):
        raise ValidationError("invalid {0}".format(field))
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        raise ValidationError("invalid {0}".format(field)) from error
    return value


def _validate_nonblank(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise ValidationError("invalid {0}".format(field))
    return value


def _validate_sha256(value: object, field: str, optional: bool = False) -> Optional[str]:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise ValidationError("invalid {0}".format(field))
    return value


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _raise_findings(findings: Tuple[Finding, ...]) -> None:
    if any(item.severity == "error" for item in findings):
        raise ValidationError("release source validation failed")


def _source_revision(root: Path, manifest: PackManifest) -> str:
    records = []
    paths = tuple(sorted(("pack.json",) + tuple(item.path for item in manifest.files)))
    for relative_path in paths:
        raw = _regular_bytes(root.joinpath(*relative_path.split("/")), "release source")
        records.append(
            {
                "path": relative_path,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        )
    return hashlib.sha256(canonical_json_bytes(records)).hexdigest()


def _validate_source_location(path: Path, selection: SkillRootSelection) -> Path:
    source = Path(os.path.abspath(os.fspath(path)))
    _assert_plain_components(source, allow_missing=False)
    lock_directory = selection.target_lock_path.parent
    for protected in (
        selection.skills_root,
        selection.state_root,
        lock_directory,
        selection.target_lock_path,
    ):
        if _overlaps(source, protected):
            raise ValidationError("release source overlaps lifecycle roots")
    return source


@contextmanager
def _validated_source(
    source: Path,
    selection: SkillRootSelection,
    checksum_path: Optional[Path],
    release_manifest_path: Optional[Path],
) -> Iterator[_SourceContext]:
    locator = _validate_source_location(source, selection)
    try:
        metadata = locator.lstat()
    except OSError as error:
        raise ValidationError("release source cannot be inspected") from error
    if _is_reparse(metadata):
        raise ValidationError("release source is a link or reparse point")

    if stat.S_ISDIR(metadata.st_mode):
        if checksum_path is not None or release_manifest_path is not None:
            raise ValidationError("directory source does not accept release sidecars")
        manifest = load_pack_manifest(locator / "pack.json")
        _raise_findings(validate_repository(locator, manifest))
        _raise_findings(validate_release_metadata(locator, manifest))
        yield _SourceContext(
            locator,
            str(locator),
            _source_revision(locator, manifest),
            manifest,
        )
        return

    if not stat.S_ISREG(metadata.st_mode):
        raise ValidationError("release source must be a directory or archive")
    if checksum_path is None or release_manifest_path is None:
        raise ValidationError("archive source requires both release sidecars")
    checksum = _validate_source_location(Path(checksum_path), selection)
    release_manifest = _validate_source_location(Path(release_manifest_path), selection)
    with verified_release_source(locator, checksum, release_manifest) as verified:
        manifest = load_pack_manifest(verified.source_root / "pack.json")
        yield _SourceContext(
            verified.source_root,
            str(locator),
            verified.artifacts.content_revision,
            manifest,
        )


def _scan_member(root: Path, skills_root: Path) -> _Inventory:
    directories: List[str] = []
    files: List[ManifestFile] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            metadata = directory.lstat()
        except OSError as error:
            raise ValidationError("target member cannot be inspected") from error
        if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise ValidationError("target member is not an ordinary directory")
        directories.append(directory.relative_to(skills_root).as_posix())
        try:
            entries = tuple(sorted(os.scandir(str(directory)), key=lambda item: item.name))
        except OSError as error:
            raise ValidationError("target member cannot be enumerated") from error
        for entry in reversed(entries):
            path = Path(entry.path)
            try:
                entry_metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ValidationError("target entry cannot be inspected") from error
            if _is_reparse(entry_metadata):
                raise ValidationError("target entry is a link or reparse point")
            if stat.S_ISDIR(entry_metadata.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(entry_metadata.st_mode):
                raise ValidationError("target entry is not a regular file")
            raw = _regular_bytes(path, "target member")
            files.append(
                ManifestFile(
                    path.relative_to(skills_root).as_posix(),
                    hashlib.sha256(raw).hexdigest(),
                )
            )
    return _Inventory(tuple(sorted(directories)), tuple(sorted(files, key=lambda item: item.path)))


def _target_inventory(
    selection: SkillRootSelection, manifest: PackManifest
) -> _Inventory:
    skills_root = selection.skills_root
    try:
        root_metadata = skills_root.lstat()
    except FileNotFoundError:
        return _Inventory((), ())
    except OSError as error:
        raise ValidationError("skills_root cannot be inspected") from error
    if _is_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValidationError("skills_root is not an ordinary directory")

    directories: List[str] = []
    files: List[ManifestFile] = []
    for member in manifest.active_members + manifest.removed_members:
        path = skills_root / member
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ValidationError("target family cannot be inspected") from error
        inventory = _scan_member(path, skills_root)
        directories.extend(inventory.directories)
        files.extend(inventory.files)
    return _Inventory(
        tuple(sorted(directories)), tuple(sorted(files, key=lambda item: item.path))
    )


def _manifest_files(value: object, field: str) -> Tuple[ManifestFile, ...]:
    if not isinstance(value, list):
        raise ValidationError("invalid {0}".format(field))
    result = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _FILE_KEYS:
            raise ValidationError("invalid {0}".format(field))
        path = item["path"]
        digest = item["sha256"]
        if not isinstance(path, str) or not _portable_path_is_safe(path):
            raise ValidationError("invalid {0} path".format(field))
        _validate_sha256(digest, field + " hash")
        result.append(ManifestFile(path, digest))
    paths = tuple(item.path for item in result)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise ValidationError("invalid {0} order".format(field))
    return tuple(result)


def _directories(value: object, field: str) -> Tuple[str, ...]:
    if not isinstance(value, list):
        raise ValidationError("invalid {0}".format(field))
    result = tuple(value)
    if any(not isinstance(item, str) or not _portable_path_is_safe(item) for item in result):
        raise ValidationError("invalid {0}".format(field))
    if result != tuple(sorted(result)) or len(result) != len(set(result)):
        raise ValidationError("invalid {0} order".format(field))
    return result


def _read_installed_state(
    selection: SkillRootSelection, manifest: Optional[PackManifest]
) -> Optional[_InstalledState]:
    path = selection.state_root / "installed.json"
    try:
        raw = _regular_bytes(path, "installed state")
    except ValidationError:
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        raise
    document = _json_document(raw, "installed state")
    if set(document) != _INSTALLED_KEYS or document["schema_version"] != 1:
        raise ValidationError("invalid installed state keys or schema")
    if canonical_json_bytes(document) != raw:
        raise ValidationError("installed state is not canonical")
    expected_name = manifest.name if manifest is not None else _PACK_NAME
    if document["pack_name"] != expected_name:
        raise ValidationError("installed pack name mismatch")
    pack_version = _validate_nonblank(document["pack_version"], "installed version")
    if pack_version not in SUPPORTED_LIFECYCLE_VERSIONS:
        raise ValidationError("installed pack version mismatch")
    validate_identifier(document["transaction_id"], "installed transaction_id")
    validate_identifier(document["actor"], "installed actor")
    _validate_timestamp(document["occurred_at"], "installed occurred_at")
    _validate_nonblank(document["authorization_ref"], "installed authorization_ref")
    _validate_sha256(document["source_revision"], "installed source_revision")
    if document["skills_root"] != str(selection.skills_root):
        raise ValidationError("installed Skill root binding mismatch")
    if document["target_digest"] != selection.target_digest:
        raise ValidationError("installed target digest mismatch")
    inventory = _Inventory(
        _directories(document["directories"], "installed directories"),
        _manifest_files(document["files"], "installed files"),
    )
    return _InstalledState(raw, document, inventory)


def _state_binding_blockers(selection: SkillRootSelection) -> Tuple[LifecycleBlocker, ...]:
    root = selection.state_root
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        return ()
    except OSError:
        return (
            LifecycleBlocker("state-inventory", str(root), "state root cannot be inspected"),
        )
    if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        return (
            LifecycleBlocker("state-inventory", str(root), "state root is not an ordinary directory"),
        )
    blockers = []
    try:
        entries = tuple(root.iterdir())
    except OSError:
        return (
            LifecycleBlocker("state-inventory", str(root), "state root cannot be enumerated"),
        )
    for entry in entries:
        if entry.name == "installed.json":
            continue
        if entry.name == "transactions":
            try:
                transaction_metadata = entry.lstat()
                transaction_roots = tuple(entry.iterdir())
            except OSError:
                blockers.append(
                    LifecycleBlocker(
                        "state-inventory",
                        str(entry),
                        "transaction inventory cannot be inspected",
                    )
                )
                continue
            if _is_reparse(transaction_metadata) or not stat.S_ISDIR(
                transaction_metadata.st_mode
            ):
                blockers.append(
                    LifecycleBlocker(
                        "state-inventory",
                        str(entry),
                        "transactions is not an ordinary directory",
                    )
                )
                continue
            for transaction_root in transaction_roots:
                try:
                    validate_identifier(transaction_root.name, "transaction_id")
                    _validate_retained_transaction(transaction_root, selection)
                except ValidationError as error:
                    blockers.append(
                        LifecycleBlocker(
                            "state-inventory", str(transaction_root), str(error)
                        )
                    )
            continue
        blockers.append(
            LifecycleBlocker(
                "state-inventory",
                str(entry),
                "unknown or unresolved lifecycle state",
            )
        )
    return tuple(sorted(blockers, key=lambda item: (item.code, item.path, item.message)))


def _validate_retained_transaction(
    transaction_root: Path, selection: SkillRootSelection
) -> None:
    try:
        metadata = transaction_root.lstat()
    except OSError as error:
        raise ValidationError("transaction cannot be inspected") from error
    if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValidationError("transaction is not an ordinary directory")
    allowed = frozenset(
        (
            "journal.json",
            "result.json",
            "stage",
            "rollback",
            "recoveries",
            "recovery-evidence",
        )
    )
    try:
        children = tuple(transaction_root.iterdir())
    except OSError as error:
        raise ValidationError("transaction cannot be enumerated") from error
    if any(child.name not in allowed for child in children):
        raise ValidationError("unknown transaction inventory")
    for path in transaction_root.rglob("*"):
        try:
            path_metadata = path.lstat()
        except OSError as error:
            raise ValidationError("transaction entry cannot be inspected") from error
        if _is_reparse(path_metadata) or not (
            stat.S_ISDIR(path_metadata.st_mode) or stat.S_ISREG(path_metadata.st_mode)
        ):
            raise ValidationError("transaction contains a link or special entry")
    journal_raw = _regular_bytes(transaction_root / "journal.json", "lifecycle journal")
    journal = _json_document(journal_raw, "lifecycle journal")
    if canonical_json_bytes(journal) != journal_raw:
        raise ValidationError("lifecycle journal is not canonical")
    if (
        journal.get("schema_version") != 1
        or journal.get("transaction_id") != transaction_root.name
        or journal.get("skills_root") != str(selection.skills_root)
        or journal.get("state_root") != str(selection.state_root)
        or journal.get("target_digest") != selection.target_digest
        or journal.get("status") not in ("committed", "rolled-back")
    ):
        raise ValidationError("lifecycle journal binding is invalid")
    result_document = journal.get("result")
    desired_sha256 = journal.get("desired_result_sha256")
    if not isinstance(result_document, dict):
        raise ValidationError("terminal lifecycle result is missing")
    _validate_sha256(desired_sha256, "desired_result_sha256")
    expected_result = canonical_json_bytes(result_document)
    if hashlib.sha256(expected_result).hexdigest() != desired_sha256:
        raise ValidationError("terminal lifecycle result digest mismatch")
    result_raw = _regular_bytes(transaction_root / "result.json", "lifecycle result")
    if result_raw != expected_result:
        raise ValidationError("materialized lifecycle result mismatch")


def _target_revision(inventory: _Inventory, installed_sha256: Optional[str]) -> str:
    document = {
        "directories": list(inventory.directories),
        "files": [
            {"path": item.path, "sha256": item.sha256} for item in inventory.files
        ],
        "installed_state_sha256": installed_sha256,
    }
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def _profile_matches(inventory: _Inventory, profile: RemovalProfile) -> bool:
    return inventory.directories == profile.directories and inventory.files == profile.files


def _source_member_files(manifest: PackManifest, member: str) -> Tuple[ManifestFile, ...]:
    prefix = "skills/" + member + "/"
    values = []
    for item in manifest.files:
        if item.path.startswith(prefix):
            values.append(ManifestFile(item.path[len("skills/") :], item.sha256))
    return tuple(sorted(values, key=lambda item: item.path))


def _target_member_files(inventory: _Inventory, member: str) -> Tuple[ManifestFile, ...]:
    prefix = member + "/"
    return tuple(item for item in inventory.files if item.path.startswith(prefix))


def _actions(
    mode: str,
    transaction_id: str,
    manifest: PackManifest,
    target: _Inventory,
    installed_sha256: Optional[str],
    skills_root_exists: bool,
) -> Tuple[LifecycleAction, ...]:
    result = []

    def append(kind, member, source_relative, target_relative, expected_files=()):
        result.append(
            LifecycleAction(
                "{0:03d}-{1}".format(len(result) + 1, kind),
                kind,
                member,
                source_relative,
                target_relative,
                tuple(expected_files),
            )
        )

    rollback = "transactions/{0}/rollback/previous".format(transaction_id)
    if mode == "fresh" and not skills_root_exists:
        append("create-skills-root", None, None, ".")
    if mode in ("managed", "unmanaged"):
        members = manifest.active_members
        if mode == "unmanaged":
            members = members + manifest.removed_members
        for member in members:
            append(
                "archive-member",
                member,
                member,
                rollback + "/skills/" + member,
                _target_member_files(target, member),
            )
    if mode == "managed":
        append(
            "archive-installed-state",
            None,
            "installed.json",
            rollback + "/installed.json",
            (ManifestFile("installed.json", installed_sha256),),
        )
    for member in manifest.active_members:
        append(
            "activate-member",
            member,
            "skills/" + member,
            member,
            _source_member_files(manifest, member),
        )
    append("write-installed-state", None, None, "installed.json")
    return tuple(result)


def _blocked_plan(
    source: _SourceContext,
    selection: SkillRootSelection,
    transaction_id: str,
    actor: str,
    occurred_at: str,
    target_revision: str,
    installed_sha256: Optional[str],
    blockers: Tuple[LifecycleBlocker, ...],
) -> LifecyclePlan:
    return LifecyclePlan(
        1,
        "install",
        transaction_id,
        actor,
        occurred_at,
        source.manifest.name,
        None,
        source.manifest.version,
        source.locator,
        source.revision,
        target_revision,
        installed_sha256,
        selection.skills_root,
        selection.state_root,
        selection.target_digest,
        None,
        (),
        tuple(sorted(blockers, key=lambda item: (item.code, item.path, item.message))),
    )


def _plan_from_source(
    source: _SourceContext,
    selection: SkillRootSelection,
    transaction_id: str,
    actor: str,
    occurred_at: str,
) -> LifecyclePlan:
    state_blockers = list(_state_binding_blockers(selection))
    try:
        target = _target_inventory(selection, source.manifest)
    except ValidationError as error:
        target = _Inventory((), ())
        state_blockers.append(
            LifecycleBlocker("target-inventory", str(selection.skills_root), str(error))
        )
    installed = None
    installed_sha256 = None
    try:
        installed = _read_installed_state(selection, source.manifest)
        if installed is not None:
            installed_sha256 = hashlib.sha256(installed.raw).hexdigest()
    except ValidationError as error:
        installed_path = selection.state_root / "installed.json"
        try:
            installed_sha256 = hashlib.sha256(
                _regular_bytes(installed_path, "installed state")
            ).hexdigest()
        except ValidationError:
            installed_sha256 = None
        state_blockers.append(
            LifecycleBlocker("installed-state", str(installed_path), str(error))
        )
    revision = _target_revision(target, installed_sha256)
    if state_blockers:
        return _blocked_plan(
            source,
            selection,
            transaction_id,
            actor,
            occurred_at,
            revision,
            installed_sha256,
            tuple(state_blockers),
        )

    mode = None
    from_version = None
    legacy_profile_id = None
    if not target.directories and not target.files and installed is None:
        mode = "fresh"
    elif installed is not None:
        if installed.inventory == target:
            mode = "managed"
            from_version = installed.document["pack_version"]
        else:
            state_blockers.append(
                LifecycleBlocker(
                    "managed-inventory",
                    str(selection.skills_root),
                    "active family differs from installed state",
                )
            )
    else:
        profile_set = load_removal_profiles(source.root / "removal-profiles.json")
        matches = tuple(
            profile for profile in profile_set.profiles if _profile_matches(target, profile)
        )
        if len(matches) == 1:
            mode = "unmanaged"
            legacy_profile_id = matches[0].profile_id
        else:
            state_blockers.append(
                LifecycleBlocker(
                    "unmanaged-inventory",
                    str(selection.skills_root),
                    "target is not one exact recognized unmanaged family",
                )
            )

    if state_blockers or mode is None:
        return _blocked_plan(
            source,
            selection,
            transaction_id,
            actor,
            occurred_at,
            revision,
            installed_sha256,
            tuple(state_blockers),
        )
    actions = _actions(
        mode,
        transaction_id,
        source.manifest,
        target,
        installed_sha256,
        selection.skills_root.exists(),
    )
    return LifecyclePlan(
        1,
        "install",
        transaction_id,
        actor,
        occurred_at,
        source.manifest.name,
        from_version,
        source.manifest.version,
        source.locator,
        source.revision,
        revision,
        installed_sha256,
        selection.skills_root,
        selection.state_root,
        selection.target_digest,
        legacy_profile_id,
        actions,
        (),
    )


def plan_install(
    source: Path,
    selection: SkillRootSelection,
    transaction_id: str,
    actor: str,
    occurred_at: str,
    checksum_path: Optional[Path] = None,
    release_manifest_path: Optional[Path] = None,
) -> LifecyclePlan:
    """Return one deterministic install plan without writing target or state."""
    validate_identifier(transaction_id, "transaction_id")
    validate_identifier(actor, "actor")
    _validate_timestamp(occurred_at, "occurred_at")
    if not isinstance(selection, SkillRootSelection):
        raise ValidationError("invalid Skill root selection")
    resolved = resolve_skill_roots(
        selection.skills_root, None, {}, selection.state_root
    )
    if (
        resolved.skills_root != selection.skills_root
        or resolved.state_root != selection.state_root
        or resolved.target_digest != selection.target_digest
        or resolved.target_lock_path != selection.target_lock_path
    ):
        raise ValidationError("Skill root selection binding mismatch")
    with _validated_source(
        Path(source), selection, checksum_path, release_manifest_path
    ) as validated:
        return _plan_from_source(
            validated, selection, transaction_id, actor, occurred_at
        )


def _uninstall_target_inventory(selection: SkillRootSelection) -> _Inventory:
    skills_root = selection.skills_root
    try:
        metadata = skills_root.lstat()
    except FileNotFoundError:
        return _Inventory((), ())
    except OSError as error:
        raise ValidationError("skills_root cannot be inspected") from error
    if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValidationError("skills_root is not an ordinary directory")
    directories = []
    files = []
    for member in ACTIVE_MEMBERS + REMOVED_MEMBERS:
        member_root = skills_root / member
        try:
            member_root.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ValidationError("target family cannot be inspected") from error
        inventory = _scan_member(member_root, skills_root)
        directories.extend(inventory.directories)
        files.extend(inventory.files)
    return _Inventory(
        tuple(sorted(directories)), tuple(sorted(files, key=lambda item: item.path))
    )


def _uninstall_actions(
    transaction_id: str,
    target: _Inventory,
    installed_sha256: str,
) -> Tuple[LifecycleAction, ...]:
    actions = []
    rollback = "transactions/{0}/rollback/previous".format(transaction_id)
    for member in ACTIVE_MEMBERS:
        actions.append(
            LifecycleAction(
                "{0:03d}-archive-member".format(len(actions) + 1),
                "archive-member",
                member,
                member,
                rollback + "/skills/" + member,
                _target_member_files(target, member),
            )
        )
    actions.append(
        LifecycleAction(
            "010-archive-installed-state",
            "archive-installed-state",
            None,
            "installed.json",
            rollback + "/installed.json",
            (ManifestFile("installed.json", installed_sha256),),
        )
    )
    return tuple(actions)


def plan_uninstall(
    selection: SkillRootSelection,
    transaction_id: str,
    actor: str,
    occurred_at: str,
) -> LifecyclePlan:
    """Return a strict managed-family uninstall plan without writing state."""
    validate_identifier(transaction_id, "transaction_id")
    validate_identifier(actor, "actor")
    _validate_timestamp(occurred_at, "occurred_at")
    if not isinstance(selection, SkillRootSelection):
        raise ValidationError("invalid Skill root selection")
    resolved = resolve_skill_roots(
        selection.skills_root, None, {}, selection.state_root
    )
    if (
        resolved.skills_root != selection.skills_root
        or resolved.state_root != selection.state_root
        or resolved.target_digest != selection.target_digest
        or resolved.target_lock_path != selection.target_lock_path
    ):
        raise ValidationError("Skill root selection binding mismatch")

    blockers = list(_state_binding_blockers(selection))
    try:
        target = _uninstall_target_inventory(selection)
    except ValidationError as error:
        target = _Inventory((), ())
        blockers.append(
            LifecycleBlocker("target-inventory", str(selection.skills_root), str(error))
        )
    installed = None
    installed_sha256 = None
    try:
        installed = _read_installed_state(selection, None)
        if installed is not None:
            installed_sha256 = hashlib.sha256(installed.raw).hexdigest()
    except ValidationError as error:
        blockers.append(
            LifecycleBlocker(
                "installed-state",
                str(selection.state_root / "installed.json"),
                str(error),
            )
        )
    if installed is None:
        blockers.append(
            LifecycleBlocker(
                "managed-ownership",
                str(selection.state_root / "installed.json"),
                "managed installed state is required",
            )
        )
    else:
        if installed.inventory != target:
            blockers.append(
                LifecycleBlocker(
                    "managed-inventory",
                    str(selection.skills_root),
                    "active family differs from installed state",
                )
            )
        if any(member not in target.directories for member in ACTIVE_MEMBERS):
            blockers.append(
                LifecycleBlocker(
                    "managed-inventory",
                    str(selection.skills_root),
                    "active family is incomplete",
                )
            )
        if any(
            path == member or path.startswith(member + "/")
            for member in REMOVED_MEMBERS
            for path in target.directories
        ):
            blockers.append(
                LifecycleBlocker(
                    "active-removed-member",
                    str(selection.skills_root),
                    "removed member is active",
                )
            )
    target_revision = _target_revision(target, installed_sha256)
    sorted_blockers = tuple(
        sorted(blockers, key=lambda item: (item.code, item.path, item.message))
    )
    actions = (
        _uninstall_actions(transaction_id, target, installed_sha256)
        if not sorted_blockers and installed_sha256 is not None
        else ()
    )
    return LifecyclePlan(
        1,
        "uninstall",
        transaction_id,
        actor,
        occurred_at,
        _PACK_NAME,
        installed.document["pack_version"] if installed is not None else None,
        None,
        None,
        None,
        target_revision,
        installed_sha256,
        selection.skills_root,
        selection.state_root,
        selection.target_digest,
        None,
        actions,
        sorted_blockers,
    )


def _file_document(item: ManifestFile) -> Mapping[str, object]:
    return {"path": item.path, "sha256": item.sha256}


def _action_document(action: LifecycleAction) -> Mapping[str, object]:
    return {
        "action_id": action.action_id,
        "expected_files": [_file_document(item) for item in action.expected_files],
        "kind": action.kind,
        "member": action.member,
        "source_relative": action.source_relative,
        "target_relative": action.target_relative,
    }


def _blocker_document(blocker: LifecycleBlocker) -> Mapping[str, object]:
    return {"code": blocker.code, "message": blocker.message, "path": blocker.path}


def _plan_document(plan: LifecyclePlan) -> Mapping[str, object]:
    return {
        "actions": [_action_document(item) for item in plan.actions],
        "actor": plan.actor,
        "blockers": [_blocker_document(item) for item in plan.blockers],
        "from_version": plan.from_version,
        "installed_state_sha256": plan.installed_state_sha256,
        "legacy_profile_id": plan.legacy_profile_id,
        "occurred_at": plan.occurred_at,
        "operation": plan.operation,
        "pack_name": plan.pack_name,
        "schema_version": plan.schema_version,
        "skills_root": str(plan.skills_root),
        "source": plan.source,
        "source_revision": plan.source_revision,
        "state_root": str(plan.state_root),
        "target_digest": plan.target_digest,
        "target_revision": plan.target_revision,
        "to_version": plan.to_version,
        "transaction_id": plan.transaction_id,
    }


def _relative_path(value: object, field: str, allow_dot: bool = False) -> str:
    if allow_dot and value == ".":
        return value
    if not isinstance(value, str) or not _portable_path_is_safe(value):
        raise ValidationError("invalid {0}".format(field))
    path = PurePosixPath(value)
    if path.as_posix() != value:
        raise ValidationError("invalid {0}".format(field))
    return value


def _optional_relative(value: object, field: str) -> Optional[str]:
    if value is None:
        return None
    return _relative_path(value, field)


def _parse_action(value: object) -> LifecycleAction:
    if not isinstance(value, dict) or set(value) != _ACTION_KEYS:
        raise ValidationError("invalid lifecycle action")
    action_id = validate_identifier(value["action_id"], "action_id")
    kind = value["kind"]
    if kind not in _ACTION_KINDS:
        raise ValidationError("invalid lifecycle action kind")
    member = value["member"]
    if member is not None:
        validate_identifier(member, "action member")
    source_relative = _optional_relative(value["source_relative"], "action source")
    target_relative = _relative_path(
        value["target_relative"], "action target", allow_dot=kind == "create-skills-root"
    )
    expected_files = _manifest_files(value["expected_files"], "action expected files")
    return LifecycleAction(
        action_id, kind, member, source_relative, target_relative, expected_files
    )


def _parse_blocker(value: object) -> LifecycleBlocker:
    if not isinstance(value, dict) or set(value) != _BLOCKER_KEYS:
        raise ValidationError("invalid lifecycle blocker")
    code = validate_identifier(value["code"], "blocker code")
    path = _validate_nonblank(value["path"], "blocker path")
    message = _validate_nonblank(value["message"], "blocker message")
    return LifecycleBlocker(code, path, message)


def _require_action(
    action: LifecycleAction,
    position: int,
    kind: str,
    member: Optional[str],
    source_relative: Optional[str],
    target_relative: str,
) -> None:
    if (
        action.action_id != "{0:03d}-{1}".format(position, kind)
        or action.kind != kind
        or action.member != member
        or action.source_relative != source_relative
        or action.target_relative != target_relative
    ):
        raise ValidationError("lifecycle action sequence mismatch")
    if member is not None and kind in ("archive-member", "activate-member"):
        prefix = member + "/"
        if any(not item.path.startswith(prefix) for item in action.expected_files):
            raise ValidationError("lifecycle member inventory mismatch")


def _validate_install_actions(
    actions: Tuple[LifecycleAction, ...],
    transaction_id: str,
    from_version: Optional[str],
    installed_sha256: Optional[str],
    legacy_profile_id: Optional[str],
) -> None:
    if from_version is not None:
        mode = "managed"
    elif legacy_profile_id is not None:
        mode = "unmanaged"
    else:
        mode = "fresh"
    position = 1
    if mode == "fresh" and actions and actions[0].kind == "create-skills-root":
        _require_action(actions[0], position, "create-skills-root", None, None, ".")
        if actions[0].expected_files:
            raise ValidationError("Skill root creation cannot own files")
        position += 1
    if mode in ("managed", "unmanaged"):
        members = ACTIVE_MEMBERS + (REMOVED_MEMBERS if mode == "unmanaged" else ())
        for member in members:
            if position > len(actions):
                raise ValidationError("incomplete archive action sequence")
            action = actions[position - 1]
            _require_action(
                action,
                position,
                "archive-member",
                member,
                member,
                "transactions/{0}/rollback/previous/skills/{1}".format(
                    transaction_id, member
                ),
            )
            position += 1
    if mode == "managed":
        if position > len(actions):
            raise ValidationError("missing installed-state archive action")
        action = actions[position - 1]
        if (
            action.action_id != "{0:03d}-archive-installed-state".format(position)
            or action.kind != "archive-installed-state"
            or action.member is not None
            or action.source_relative != "installed.json"
            or action.target_relative
            != "transactions/{0}/rollback/previous/installed.json".format(
                transaction_id
            )
            or action.expected_files
            != (ManifestFile("installed.json", installed_sha256),)
        ):
            raise ValidationError("installed-state archive action mismatch")
        position += 1
    for member in ACTIVE_MEMBERS:
        if position > len(actions):
            raise ValidationError("incomplete activation action sequence")
        _require_action(
            actions[position - 1],
            position,
            "activate-member",
            member,
            "skills/" + member,
            member,
        )
        position += 1
    if position != len(actions):
        raise ValidationError("unexpected install action count")
    final = actions[position - 1]
    _require_action(
        final,
        position,
        "write-installed-state",
        None,
        None,
        "installed.json",
    )
    if final.expected_files:
        raise ValidationError("installed-state write action cannot own source files")


def _validate_uninstall_actions(
    actions: Tuple[LifecycleAction, ...],
    transaction_id: str,
    installed_sha256: str,
) -> None:
    if len(actions) != 10:
        raise ValidationError("unexpected uninstall action count")
    rollback = "transactions/{0}/rollback/previous".format(transaction_id)
    for position, member in enumerate(ACTIVE_MEMBERS, 1):
        _require_action(
            actions[position - 1],
            position,
            "archive-member",
            member,
            member,
            rollback + "/skills/" + member,
        )
    final = actions[-1]
    if (
        final.action_id != "010-archive-installed-state"
        or final.kind != "archive-installed-state"
        or final.member is not None
        or final.source_relative != "installed.json"
        or final.target_relative != rollback + "/installed.json"
        or final.expected_files
        != (ManifestFile("installed.json", installed_sha256),)
    ):
        raise ValidationError("installed-state archive action mismatch")


def _parse_plan_document(document: Mapping[str, object]) -> LifecyclePlan:
    if set(document) != _PLAN_KEYS or document["schema_version"] != 1:
        raise ValidationError("invalid lifecycle plan keys or schema")
    operation = document["operation"]
    if operation not in ("install", "uninstall"):
        raise ValidationError("invalid lifecycle plan operation")
    transaction_id = validate_identifier(document["transaction_id"], "transaction_id")
    actor = validate_identifier(document["actor"], "actor")
    occurred_at = _validate_timestamp(document["occurred_at"], "occurred_at")
    pack_name = _validate_nonblank(document["pack_name"], "pack_name")
    if pack_name != _PACK_NAME:
        raise ValidationError("invalid lifecycle pack name")
    source = document["source"]
    if operation == "install":
        if not isinstance(source, str) or not Path(source).is_absolute():
            raise ValidationError("invalid lifecycle source")
        source_revision = _validate_sha256(
            document["source_revision"], "source_revision"
        )
    else:
        if source is not None or document["source_revision"] is not None:
            raise ValidationError("uninstall plan cannot name a release source")
        source_revision = None
    target_revision = _validate_sha256(document["target_revision"], "target_revision")
    installed_sha256 = _validate_sha256(
        document["installed_state_sha256"], "installed_state_sha256", optional=True
    )
    target_digest = _validate_sha256(document["target_digest"], "target_digest")
    skills_value = document["skills_root"]
    state_value = document["state_root"]
    if not isinstance(skills_value, str) or not isinstance(state_value, str):
        raise ValidationError("invalid lifecycle roots")
    selection = resolve_skill_roots(Path(skills_value), None, {}, Path(state_value))
    if (
        str(selection.skills_root) != skills_value
        or str(selection.state_root) != state_value
        or selection.target_digest != target_digest
    ):
        raise ValidationError("lifecycle plan target binding mismatch")
    if operation == "install":
        normalized_source = Path(source).resolve(strict=False)
        if str(normalized_source) != source:
            raise ValidationError("lifecycle source is not normalized")
        for protected in (
            selection.skills_root,
            selection.state_root,
            selection.target_lock_path.parent,
            selection.target_lock_path,
        ):
            if _overlaps(normalized_source, protected):
                raise ValidationError("lifecycle source overlaps managed roots")
    from_version = document["from_version"]
    to_version = document["to_version"]
    legacy_profile_id = document["legacy_profile_id"]
    if from_version is not None:
        if _validate_nonblank(from_version, "from_version") not in SUPPORTED_LIFECYCLE_VERSIONS:
            raise ValidationError("invalid lifecycle prior version")
    if operation == "install":
        if _validate_nonblank(to_version, "to_version") not in SUPPORTED_LIFECYCLE_VERSIONS:
            raise ValidationError("invalid lifecycle target version")
    elif to_version is not None:
        raise ValidationError("uninstall target version must be absent")
    if legacy_profile_id is not None:
        validate_identifier(legacy_profile_id, "legacy_profile_id")
    actions_value = document["actions"]
    blockers_value = document["blockers"]
    if not isinstance(actions_value, list) or not isinstance(blockers_value, list):
        raise ValidationError("invalid lifecycle plan collections")
    actions = tuple(_parse_action(item) for item in actions_value)
    blockers = tuple(_parse_blocker(item) for item in blockers_value)
    action_ids = tuple(item.action_id for item in actions)
    if action_ids != tuple(sorted(action_ids)) or len(action_ids) != len(set(action_ids)):
        raise ValidationError("lifecycle actions are not sorted and unique")
    blocker_order = tuple((item.code, item.path, item.message) for item in blockers)
    if blocker_order != tuple(sorted(blocker_order)):
        raise ValidationError("lifecycle blockers are not sorted")
    if blockers and actions:
        raise ValidationError("blocked lifecycle plan contains actions")
    if not blockers and operation == "install":
        if (from_version is None) != (installed_sha256 is None):
            raise ValidationError("managed install fields are inconsistent")
        if legacy_profile_id is not None and from_version is not None:
            raise ValidationError("install mode fields are inconsistent")
        _validate_install_actions(
            actions,
            transaction_id,
            from_version,
            installed_sha256,
            legacy_profile_id,
        )
    elif not blockers:
        if (
            from_version not in SUPPORTED_LIFECYCLE_VERSIONS
            or installed_sha256 is None
            or legacy_profile_id is not None
        ):
            raise ValidationError("managed uninstall fields are inconsistent")
        _validate_uninstall_actions(actions, transaction_id, installed_sha256)
    return LifecyclePlan(
        1,
        operation,
        transaction_id,
        actor,
        occurred_at,
        pack_name,
        from_version,
        to_version,
        source,
        source_revision,
        target_revision,
        installed_sha256,
        selection.skills_root,
        selection.state_root,
        target_digest,
        legacy_profile_id,
        actions,
        blockers,
    )


def _plan_bytes(plan: LifecyclePlan) -> bytes:
    raw = canonical_json_bytes(_plan_document(plan))
    parsed = _json_document(raw, "lifecycle plan")
    if _parse_plan_document(parsed) != plan:
        raise ValidationError("lifecycle plan is not canonical")
    return raw


def write_lifecycle_plan(plan: LifecyclePlan, path: Path) -> Path:
    """Exclusively publish one canonical reviewed plan outside managed roots."""
    if not isinstance(plan, LifecyclePlan):
        raise ValidationError("invalid lifecycle plan")
    target = Path(os.path.abspath(os.fspath(path)))
    _assert_plain_components(target.parent, allow_missing=True)
    lock_directory = plan.skills_root.parent / ".obsidian-agent-memory-pack-target-locks"
    for protected in (plan.skills_root, plan.state_root, lock_directory):
        if _overlaps(target, protected):
            raise ValidationError("reviewed plan path overlaps lifecycle roots")
    raw = _plan_bytes(plan)
    token = hashlib.sha256(raw).hexdigest()
    candidate = target.with_name("." + target.name + ".candidate-" + token)
    atomic_publish_exclusive(target, raw, candidate)
    return target


def load_lifecycle_plan(path: Path) -> LifecyclePlan:
    """Strictly load one canonical reviewed lifecycle plan."""
    source = Path(os.path.abspath(os.fspath(path)))
    raw = _regular_bytes(source, "lifecycle plan")
    document = _json_document(raw, "lifecycle plan")
    if canonical_json_bytes(document) != raw:
        raise ValidationError("lifecycle plan is not canonical")
    return _parse_plan_document(document)


def _lifecycle_checkpoint(stage: str) -> None:
    del stage


def _lock_checkpoint(stage: str, path: Path) -> None:
    del stage, path


def _windows_open(path: Path, disposition: int) -> int:
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(path),
        0x80000000 | 0x40000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        disposition,
        0x00000080,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        if error in (80, 183):
            raise FileExistsError(error, "path already exists", str(path))
        if error in (2, 3):
            raise FileNotFoundError(error, "path not found", str(path))
        raise OSError(error, "CreateFileW failed", str(path))
    try:
        return msvcrt.open_osfhandle(
            handle, os.O_RDWR | getattr(os, "O_BINARY", 0)
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


class _Lease:
    def __init__(self, descriptor: int):
        self.descriptor = descriptor
        self.held = False
        self.closed = False

    @classmethod
    def create(cls, path: Path) -> "_Lease":
        if os.name == "nt":
            return cls(_windows_open(path, 1))
        return cls(os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600))

    @classmethod
    def open(cls, path: Path) -> "_Lease":
        if os.name == "nt":
            return cls(_windows_open(path, 3))
        return cls(os.open(str(path), os.O_RDWR))

    def write_all(self, raw: bytes) -> None:
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        os.ftruncate(self.descriptor, 0)
        view = memoryview(raw)
        while view:
            written = os.write(self.descriptor, view)
            if written <= 0:
                raise OSError("short lifecycle lock write")
            view = view[written:]
        os.fsync(self.descriptor)

    def read_all(self) -> bytes:
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        chunks = []
        while True:
            chunk = os.read(self.descriptor, 65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    def acquire(self) -> bool:
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        self.held = True
        return True

    def close(self) -> None:
        if self.closed:
            return
        try:
            if self.held:
                os.lseek(self.descriptor, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(self.descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self.descriptor, fcntl.LOCK_UN)
                self.held = False
        finally:
            os.close(self.descriptor)
            self.closed = True


@dataclass
class _HeldLock:
    canonical_path: Path
    candidate_path: Path
    raw: bytes
    lease: _Lease


def _ensure_directory(path: Path) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir()
        _assert_plain_components(directory, allow_missing=False)
        from .io import _fsync_directory

        _fsync_directory(directory.parent)


def _lock_document(
    kind: str,
    selection: SkillRootSelection,
    plan: LifecyclePlan,
    reviewed_plan_sha256: str,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
    operation: str = "install",
) -> Mapping[str, object]:
    return {
        "authorization_ref_sha256": hashlib.sha256(
            authorization_ref.encode("utf-8")
        ).hexdigest(),
        "created_at": operation_occurred_at,
        "kind": kind,
        "operation": operation,
        "operation_actor": operation_actor,
        "reviewed_plan_sha256": reviewed_plan_sha256,
        "schema_version": 1,
        "skills_root": str(selection.skills_root),
        "state_root": str(selection.state_root),
        "target_digest": selection.target_digest,
        "transaction_id": plan.transaction_id,
    }


def _publish_lock(path: Path, document: Mapping[str, object]) -> _HeldLock:
    raw = canonical_json_bytes(document)
    candidate = path.with_name(
        "." + path.name + ".candidate-" + hashlib.sha256(raw).hexdigest()
    )
    lease = None
    published = False
    try:
        lease = _Lease.create(candidate)
        lease.write_all(raw)
        _lock_checkpoint("candidate-fsynced", path)
        if not lease.acquire():
            raise LockBusyError("lifecycle lock candidate is busy")
        os.link(str(candidate), str(path))
        published = True
        _lock_checkpoint("canonical-linked", path)
        from .io import _fsync_directory

        _fsync_directory(path.parent)
        _lock_checkpoint("canonical-directory-fsynced", path)
        return _HeldLock(path, candidate, raw, lease)
    except FileExistsError as error:
        raise LockBusyError("lifecycle target is busy") from error
    except (OSError, AgentMemoryError):
        raise
    finally:
        if not published and lease is not None:
            lease.close()
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass


def _release_lock(held: _HeldLock) -> None:
    from .io import _fsync_directory

    if held.lease.read_all() != held.raw:
        raise ConflictError("lifecycle lock bytes changed")
    try:
        if not os.path.samefile(str(held.canonical_path), str(held.candidate_path)):
            raise ConflictError("lifecycle lock identity changed")
    except OSError as error:
        raise ConflictError("lifecycle lock identity cannot be verified") from error
    _lock_checkpoint("before-canonical-unlink", held.canonical_path)
    held.canonical_path.unlink()
    _fsync_directory(held.canonical_path.parent)
    _lock_checkpoint("canonical-unlinked", held.canonical_path)
    held.candidate_path.unlink()
    _fsync_directory(held.candidate_path.parent)
    _lock_checkpoint("candidate-unlinked", held.canonical_path)
    held.lease.close()
    _lock_checkpoint("lease-released", held.canonical_path)


class _JournalWriter:
    def __init__(
        self,
        path: Path,
        transaction_id: str,
        expected_sha256: Optional[str] = None,
    ):
        self.path = path
        self.transaction_id = transaction_id
        self.expected_sha256 = expected_sha256
        self.counter = 0

    def publish(self, document: Mapping[str, object], purpose: str) -> str:
        from .io import atomic_write

        self.counter += 1
        raw = canonical_json_bytes(document)
        atomic_write(
            self.path,
            raw,
            self.transaction_id,
            "{0:03d}-{1}".format(self.counter, purpose),
            self.expected_sha256,
        )
        self.expected_sha256 = hashlib.sha256(raw).hexdigest()
        return self.expected_sha256


def _copy_source_to_stage(source: _SourceContext, stage_root: Path) -> None:
    from .io import _fsync_directory

    paths = tuple(
        sorted(("pack.json",) + tuple(item.path for item in source.manifest.files))
    )
    stage_root.mkdir(parents=True)
    for relative_path in paths:
        raw = _regular_bytes(
            source.root.joinpath(*relative_path.split("/")), "release stage source"
        )
        output = stage_root.joinpath(*relative_path.split("/"))
        output.parent.mkdir(parents=True, exist_ok=True)
        _assert_plain_components(output.parent, allow_missing=False)
        with output.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(str(output), 0o644)
    directories = sorted(
        (path for path in stage_root.rglob("*") if path.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    )
    for directory in directories:
        _fsync_directory(directory)
    _fsync_directory(stage_root)
    staged_manifest = load_pack_manifest(stage_root / "pack.json")
    _raise_findings(validate_repository(stage_root, staged_manifest))
    _raise_findings(validate_release_metadata(stage_root, staged_manifest))


def _action_inventory(root: Path, skills_root: Path) -> Tuple[ManifestFile, ...]:
    return _scan_member(root, skills_root).files


def _move_directory(
    source: Path,
    destination: Path,
    expected_files: Tuple[ManifestFile, ...],
    inventory_root: Path,
) -> None:
    from .io import _fsync_directory

    if _action_inventory(source, inventory_root) != expected_files:
        raise ConflictError("lifecycle action source inventory changed")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ConflictError("lifecycle action destination is occupied")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _assert_plain_components(destination.parent, allow_missing=False)
    os.replace(str(source), str(destination))
    _fsync_directory(source.parent)
    if destination.parent != source.parent:
        _fsync_directory(destination.parent)


def _installed_document(
    selection: SkillRootSelection,
    plan: LifecyclePlan,
    inventory: _Inventory,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
) -> Mapping[str, object]:
    return {
        "actor": operation_actor,
        "authorization_ref": authorization_ref,
        "directories": list(inventory.directories),
        "files": [_file_document(item) for item in inventory.files],
        "occurred_at": operation_occurred_at,
        "pack_name": plan.pack_name,
        "pack_version": plan.to_version,
        "schema_version": 1,
        "skills_root": str(selection.skills_root),
        "source_revision": plan.source_revision,
        "target_digest": selection.target_digest,
        "transaction_id": plan.transaction_id,
    }


def _result_document(
    result: LifecycleResult,
    selection: SkillRootSelection,
) -> Mapping[str, object]:
    return {
        "actor": result.actor,
        "authorization_ref": result.authorization_ref,
        "moved_paths": list(result.moved_paths),
        "occurred_at": result.occurred_at,
        "rollback_path": str(result.rollback_path),
        "schema_version": 1,
        "skills_root": str(selection.skills_root),
        "state_root": str(selection.state_root),
        "status": result.status,
        "target_digest": result.target_digest,
        "transaction_id": result.transaction_id,
        "version": result.version,
    }


def _validate_apply_inputs(
    source: Path,
    plan: LifecyclePlan,
    reviewed_plan_sha256: str,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
    checksum_path: Optional[Path],
    release_manifest_path: Optional[Path],
) -> Tuple[SkillRootSelection, object]:
    if not isinstance(plan, LifecyclePlan):
        raise ValidationError("invalid lifecycle plan")
    validate_identifier(operation_actor, "operation_actor")
    _validate_timestamp(operation_occurred_at, "operation_occurred_at")
    _validate_nonblank(authorization_ref, "authorization_ref")
    _validate_sha256(reviewed_plan_sha256, "reviewed_plan_sha256")
    canonical_plan = _plan_bytes(plan)
    if hashlib.sha256(canonical_plan).hexdigest() != reviewed_plan_sha256:
        raise ValidationError("reviewed lifecycle plan digest mismatch")
    if plan.blockers:
        raise ConflictError("blocked lifecycle plan cannot be applied")
    selection = resolve_skill_roots(plan.skills_root, None, {}, plan.state_root)
    if (
        selection.target_digest != plan.target_digest
        or selection.target_lock_path.parent
        != plan.skills_root.parent / ".obsidian-agent-memory-pack-target-locks"
    ):
        raise ValidationError("lifecycle plan root binding changed")
    transaction_root = selection.state_root / "transactions" / plan.transaction_id
    if transaction_root.exists():
        raise ConflictError("lifecycle transaction already exists")
    for lock_path in (selection.target_lock_path, selection.state_root / "lifecycle.lock"):
        try:
            lock_path.lstat()
        except FileNotFoundError:
            continue
        raise LockBusyError("lifecycle target is busy")
    source_context = _validated_source(
        Path(source), selection, checksum_path, release_manifest_path
    )
    return selection, source_context


def _execute_install_actions(
    source: _SourceContext,
    selection: SkillRootSelection,
    plan: LifecyclePlan,
    journal: Dict[str, object],
    writer: _JournalWriter,
    stage_root: Path,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
) -> Tuple[Tuple[str, ...], str]:
    from .io import _fsync_directory, atomic_write

    completed = []
    moved_paths = []
    installed_sha256 = None
    for action in plan.actions:
        journal["current_action"] = _action_document(action)
        journal["completed_action_ids"] = list(completed)
        writer.publish(journal, "before-" + action.action_id)
        if action.kind == "create-skills-root":
            try:
                selection.skills_root.lstat()
            except FileNotFoundError:
                selection.skills_root.mkdir()
                _fsync_directory(selection.skills_root.parent)
            else:
                raise ConflictError("reviewed absent Skill root is occupied")
        elif action.kind == "archive-member":
            _move_directory(
                selection.skills_root / action.source_relative,
                selection.state_root.joinpath(*action.target_relative.split("/")),
                action.expected_files,
                selection.skills_root,
            )
            moved_paths.append(action.target_relative)
        elif action.kind == "archive-installed-state":
            installed = selection.state_root / "installed.json"
            raw = _regular_bytes(installed, "installed state")
            if hashlib.sha256(raw).hexdigest() != plan.installed_state_sha256:
                raise ConflictError("installed state changed before archive")
            destination = selection.state_root.joinpath(*action.target_relative.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise ConflictError("installed-state archive is occupied")
            os.replace(str(installed), str(destination))
            _fsync_directory(installed.parent)
            _fsync_directory(destination.parent)
            moved_paths.append(action.target_relative)
        elif action.kind == "activate-member":
            _move_directory(
                stage_root.joinpath(*action.source_relative.split("/")),
                selection.skills_root / action.target_relative,
                action.expected_files,
                stage_root / "skills",
            )
            moved_paths.append(action.target_relative)
        elif action.kind == "write-installed-state":
            active = _target_inventory(selection, source.manifest)
            expected_files = tuple(
                item
                for planned in plan.actions
                if planned.kind == "activate-member"
                for item in planned.expected_files
            )
            if active.files != tuple(sorted(expected_files, key=lambda item: item.path)):
                raise ConflictError("activated family inventory differs from source")
            installed_raw = canonical_json_bytes(
                _installed_document(
                    selection,
                    plan,
                    active,
                    operation_actor,
                    operation_occurred_at,
                    authorization_ref,
                )
            )
            atomic_write(
                selection.state_root / "installed.json",
                installed_raw,
                plan.transaction_id,
                "installed-state",
                None,
            )
            installed_sha256 = hashlib.sha256(installed_raw).hexdigest()
        else:
            raise ValidationError("unsupported install action")
        completed.append(action.action_id)
        journal["completed_action_ids"] = list(completed)
        journal["current_action"] = None
        writer.publish(journal, "after-" + action.action_id)
    if installed_sha256 is None:
        raise ConflictError("install did not publish installed state")
    return tuple(moved_paths), installed_sha256


def apply_install(
    source: Path,
    plan: LifecyclePlan,
    reviewed_plan_sha256: str,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
    checksum_path: Optional[Path] = None,
    release_manifest_path: Optional[Path] = None,
) -> LifecycleResult:
    """Apply one reviewed whole-family install plan as a durable transaction."""
    selection, source_manager = _validate_apply_inputs(
        source,
        plan,
        reviewed_plan_sha256,
        operation_actor,
        operation_occurred_at,
        authorization_ref,
        checksum_path,
        release_manifest_path,
    )
    target_lock = None
    state_lock = None
    terminal = False
    with source_manager as validated:
        current_plan = _plan_from_source(
            validated,
            selection,
            plan.transaction_id,
            plan.actor,
            plan.occurred_at,
        )
        if current_plan != plan:
            raise ConflictError("reviewed lifecycle plan was invalidated")
        _ensure_directory(selection.target_lock_path.parent)
        _ensure_directory(selection.state_root)
        target_lock = _publish_lock(
            selection.target_lock_path,
            _lock_document(
                "target",
                selection,
                plan,
                reviewed_plan_sha256,
                operation_actor,
                operation_occurred_at,
                authorization_ref,
            ),
        )
        try:
            state_lock = _publish_lock(
                selection.state_root / "lifecycle.lock",
                _lock_document(
                    "state",
                    selection,
                    plan,
                    reviewed_plan_sha256,
                    operation_actor,
                    operation_occurred_at,
                    authorization_ref,
                ),
            )
            transaction_root = (
                selection.state_root / "transactions" / plan.transaction_id
            )
            _ensure_directory(transaction_root)
            journal_path = transaction_root / "journal.json"
            writer = _JournalWriter(journal_path, plan.transaction_id)
            journal = {
                "authorization_ref": authorization_ref,
                "completed_action_ids": [],
                "current_action": None,
                "installed_state_sha256": plan.installed_state_sha256,
                "operation": "install",
                "operation_actor": operation_actor,
                "operation_occurred_at": operation_occurred_at,
                "plan": _plan_document(plan),
                "planning_actor": plan.actor,
                "planning_occurred_at": plan.occurred_at,
                "reviewed_plan_sha256": reviewed_plan_sha256,
                "schema_version": 1,
                "skills_root": str(selection.skills_root),
                "source_revision": plan.source_revision,
                "stage_barrier_sha256": None,
                "state_root": str(selection.state_root),
                "status": "prepared",
                "target_digest": selection.target_digest,
                "target_revision": plan.target_revision,
                "transaction_id": plan.transaction_id,
            }
            writer.publish(journal, "prepared")
            stage_root = transaction_root / "stage" / "pack"
            _copy_source_to_stage(validated, stage_root)
            journal["stage_barrier_sha256"] = validated.revision
            writer.publish(journal, "stage-barrier")
            current_target = _target_inventory(selection, validated.manifest)
            try:
                current_installed = _read_installed_state(selection, validated.manifest)
            except ValidationError as error:
                raise ConflictError("installed state changed before activation") from error
            current_installed_sha256 = (
                hashlib.sha256(current_installed.raw).hexdigest()
                if current_installed is not None
                else None
            )
            if (
                _target_revision(current_target, current_installed_sha256)
                != plan.target_revision
                or current_installed_sha256 != plan.installed_state_sha256
            ):
                raise ConflictError("target revision changed before activation")
            journal["status"] = "applying"
            writer.publish(journal, "applying")
            moved_paths, installed_sha256 = _execute_install_actions(
                validated,
                selection,
                plan,
                journal,
                writer,
                stage_root,
                operation_actor,
                operation_occurred_at,
                authorization_ref,
            )
            rollback_path = transaction_root / "rollback"
            result = LifecycleResult(
                "installed",
                plan.transaction_id,
                plan.to_version,
                moved_paths,
                rollback_path,
                operation_actor,
                operation_occurred_at,
                authorization_ref,
                selection.target_digest,
            )
            result_document = _result_document(result, selection)
            result_raw = canonical_json_bytes(result_document)
            terminal_target = _target_inventory(selection, validated.manifest)
            journal["status"] = "committed"
            journal["current_action"] = None
            journal["result"] = result_document
            journal["terminal_installed_state_sha256"] = installed_sha256
            journal["terminal_target_revision"] = _target_revision(
                terminal_target, installed_sha256
            )
            journal["predecessor_result_sha256"] = None
            journal["desired_result_sha256"] = hashlib.sha256(result_raw).hexdigest()
            writer.publish(journal, "committed")
            from .io import atomic_write

            atomic_write(
                transaction_root / "result.json",
                result_raw,
                plan.transaction_id,
                "result-committed",
                None,
            )
            terminal = True
            _lifecycle_checkpoint("before-state-lock-release")
            _release_lock(state_lock)
            state_lock = None
            _lifecycle_checkpoint("before-target-lock-release")
            _release_lock(target_lock)
            target_lock = None
            return result
        finally:
            if not terminal:
                if state_lock is not None:
                    state_lock.lease.close()
                if target_lock is not None:
                    target_lock.lease.close()
            elif state_lock is not None or target_lock is not None:
                if state_lock is not None:
                    state_lock.lease.close()
                if target_lock is not None:
                    target_lock.lease.close()


def _validate_uninstall_apply_inputs(
    plan: LifecyclePlan,
    reviewed_plan_sha256: str,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
) -> SkillRootSelection:
    if not isinstance(plan, LifecyclePlan) or plan.operation != "uninstall":
        raise ValidationError("invalid uninstall lifecycle plan")
    validate_identifier(operation_actor, "operation_actor")
    _validate_timestamp(operation_occurred_at, "operation_occurred_at")
    _validate_nonblank(authorization_ref, "authorization_ref")
    _validate_sha256(reviewed_plan_sha256, "reviewed_plan_sha256")
    canonical_plan = _plan_bytes(plan)
    if hashlib.sha256(canonical_plan).hexdigest() != reviewed_plan_sha256:
        raise ValidationError("reviewed lifecycle plan digest mismatch")
    if plan.blockers:
        raise ConflictError("blocked lifecycle plan cannot be applied")
    selection = resolve_skill_roots(plan.skills_root, None, {}, plan.state_root)
    if selection.target_digest != plan.target_digest:
        raise ValidationError("lifecycle plan root binding changed")
    transaction_root = selection.state_root / "transactions" / plan.transaction_id
    if transaction_root.exists():
        raise ConflictError("lifecycle transaction already exists")
    for lock_path in (selection.target_lock_path, selection.state_root / "lifecycle.lock"):
        try:
            lock_path.lstat()
        except FileNotFoundError:
            continue
        raise LockBusyError("lifecycle target is busy")
    current_plan = plan_uninstall(
        selection,
        plan.transaction_id,
        plan.actor,
        plan.occurred_at,
    )
    if current_plan != plan:
        raise ConflictError("reviewed lifecycle plan was invalidated")
    return selection


def _execute_uninstall_actions(
    selection: SkillRootSelection,
    plan: LifecyclePlan,
    journal: Dict[str, object],
    writer: _JournalWriter,
) -> Tuple[str, ...]:
    from .io import _fsync_directory

    completed = []
    moved_paths = []
    for action in plan.actions:
        journal["current_action"] = _action_document(action)
        journal["completed_action_ids"] = list(completed)
        writer.publish(journal, "before-" + action.action_id)
        if action.kind == "archive-member":
            _move_directory(
                selection.skills_root / action.source_relative,
                selection.state_root.joinpath(*action.target_relative.split("/")),
                action.expected_files,
                selection.skills_root,
            )
        elif action.kind == "archive-installed-state":
            active = _uninstall_target_inventory(selection)
            if active.directories or active.files:
                raise ConflictError("active family remains before installed-state archive")
            installed = selection.state_root / "installed.json"
            raw = _regular_bytes(installed, "installed state")
            if hashlib.sha256(raw).hexdigest() != plan.installed_state_sha256:
                raise ConflictError("installed state changed before archive")
            destination = selection.state_root.joinpath(
                *action.target_relative.split("/")
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise ConflictError("installed-state archive is occupied")
            os.replace(str(installed), str(destination))
            _fsync_directory(installed.parent)
            _fsync_directory(destination.parent)
        else:
            raise ValidationError("unsupported uninstall action")
        moved_paths.append(action.target_relative)
        completed.append(action.action_id)
        journal["completed_action_ids"] = list(completed)
        journal["current_action"] = None
        writer.publish(journal, "after-" + action.action_id)
    return tuple(moved_paths)


def apply_uninstall(
    plan: LifecyclePlan,
    reviewed_plan_sha256: str,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
) -> LifecycleResult:
    """Apply one reviewed strict managed-family uninstall plan."""
    selection = _validate_uninstall_apply_inputs(
        plan,
        reviewed_plan_sha256,
        operation_actor,
        operation_occurred_at,
        authorization_ref,
    )
    _ensure_directory(selection.target_lock_path.parent)
    _ensure_directory(selection.state_root)
    target_lock = _publish_lock(
        selection.target_lock_path,
        _lock_document(
            "target",
            selection,
            plan,
            reviewed_plan_sha256,
            operation_actor,
            operation_occurred_at,
            authorization_ref,
            "uninstall",
        ),
    )
    state_lock = None
    try:
        state_lock = _publish_lock(
            selection.state_root / "lifecycle.lock",
            _lock_document(
                "state",
                selection,
                plan,
                reviewed_plan_sha256,
                operation_actor,
                operation_occurred_at,
                authorization_ref,
                "uninstall",
            ),
        )
        current_target = _uninstall_target_inventory(selection)
        current_installed = _read_installed_state(selection, None)
        current_installed_sha256 = (
            hashlib.sha256(current_installed.raw).hexdigest()
            if current_installed is not None
            else None
        )
        if (
            current_installed is None
            or current_installed.inventory != current_target
            or current_installed_sha256 != plan.installed_state_sha256
            or _target_revision(current_target, current_installed_sha256)
            != plan.target_revision
        ):
            raise ConflictError("target revision changed before uninstall")
        transaction_root = selection.state_root / "transactions" / plan.transaction_id
        _ensure_directory(transaction_root)
        writer = _JournalWriter(
            transaction_root / "journal.json", plan.transaction_id
        )
        journal = {
            "authorization_ref": authorization_ref,
            "completed_action_ids": [],
            "current_action": None,
            "installed_state_sha256": plan.installed_state_sha256,
            "operation": "uninstall",
            "operation_actor": operation_actor,
            "operation_occurred_at": operation_occurred_at,
            "plan": _plan_document(plan),
            "planning_actor": plan.actor,
            "planning_occurred_at": plan.occurred_at,
            "reviewed_plan_sha256": reviewed_plan_sha256,
            "schema_version": 1,
            "skills_root": str(selection.skills_root),
            "source_revision": None,
            "stage_barrier_sha256": None,
            "state_root": str(selection.state_root),
            "status": "prepared",
            "target_digest": selection.target_digest,
            "target_revision": plan.target_revision,
            "transaction_id": plan.transaction_id,
        }
        writer.publish(journal, "prepared")
        journal["status"] = "applying"
        writer.publish(journal, "applying")
        moved_paths = _execute_uninstall_actions(selection, plan, journal, writer)
        terminal_target = _uninstall_target_inventory(selection)
        if terminal_target.directories or terminal_target.files:
            raise ConflictError("uninstall left an active family member")
        try:
            (selection.state_root / "installed.json").lstat()
        except FileNotFoundError:
            pass
        else:
            raise ConflictError("uninstall left installed state active")
        result = LifecycleResult(
            "uninstalled",
            plan.transaction_id,
            None,
            moved_paths,
            transaction_root / "rollback",
            operation_actor,
            operation_occurred_at,
            authorization_ref,
            selection.target_digest,
        )
        result_document = _result_document(result, selection)
        result_raw = canonical_json_bytes(result_document)
        journal["status"] = "committed"
        journal["current_action"] = None
        journal["result"] = result_document
        journal["terminal_installed_state_sha256"] = None
        journal["terminal_target_revision"] = _target_revision(terminal_target, None)
        journal["predecessor_result_sha256"] = None
        journal["desired_result_sha256"] = hashlib.sha256(result_raw).hexdigest()
        writer.publish(journal, "committed")
        from .io import atomic_write

        atomic_write(
            transaction_root / "result.json",
            result_raw,
            plan.transaction_id,
            "result-committed",
            None,
        )
        _lifecycle_checkpoint("before-state-lock-release")
        _release_lock(state_lock)
        state_lock = None
        _lifecycle_checkpoint("before-target-lock-release")
        _release_lock(target_lock)
        target_lock = None
        return result
    finally:
        if state_lock is not None:
            state_lock.lease.close()
        if target_lock is not None:
            target_lock.lease.close()


def _load_journal(
    selection: SkillRootSelection, transaction_id: str
) -> Tuple[Path, bytes, Dict[str, object], LifecyclePlan]:
    transaction_root = selection.state_root / "transactions" / transaction_id
    path = transaction_root / "journal.json"
    raw = _regular_bytes(path, "lifecycle journal")
    document = _json_document(raw, "lifecycle journal")
    if canonical_json_bytes(document) != raw:
        raise ValidationError("lifecycle journal is not canonical")
    if (
        document.get("schema_version") != 1
        or document.get("transaction_id") != transaction_id
        or document.get("skills_root") != str(selection.skills_root)
        or document.get("state_root") != str(selection.state_root)
        or document.get("target_digest") != selection.target_digest
    ):
        raise ValidationError("lifecycle journal binding mismatch")
    plan_value = document.get("plan")
    if not isinstance(plan_value, dict):
        raise ValidationError("lifecycle journal plan is missing")
    plan = _parse_plan_document(plan_value)
    if (
        plan.transaction_id != transaction_id
        or plan.skills_root != selection.skills_root
        or plan.state_root != selection.state_root
        or plan.target_digest != selection.target_digest
    ):
        raise ValidationError("journaled lifecycle plan binding mismatch")
    reviewed = document.get("reviewed_plan_sha256")
    _validate_sha256(reviewed, "reviewed_plan_sha256")
    if hashlib.sha256(_plan_bytes(plan)).hexdigest() != reviewed:
        raise ValidationError("journaled lifecycle plan digest mismatch")
    return transaction_root, raw, dict(document), plan


def _validate_operation_inputs(
    selection: SkillRootSelection,
    transaction_id: str,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
) -> SkillRootSelection:
    if not isinstance(selection, SkillRootSelection):
        raise ValidationError("invalid Skill root selection")
    validate_identifier(transaction_id, "transaction_id")
    validate_identifier(operation_actor, "operation_actor")
    _validate_timestamp(operation_occurred_at, "operation_occurred_at")
    _validate_nonblank(authorization_ref, "authorization_ref")
    resolved = resolve_skill_roots(
        selection.skills_root, None, {}, selection.state_root
    )
    if (
        resolved.target_digest != selection.target_digest
        or resolved.target_lock_path != selection.target_lock_path
    ):
        raise ValidationError("Skill root selection binding mismatch")
    return resolved


def _authorization_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_new_authorization(
    journal: Mapping[str, object], transaction_root: Path, authorization_ref: str
) -> None:
    used = set()
    for key in ("authorization_ref", "rollback_authorization_ref"):
        value = journal.get(key)
        if isinstance(value, str):
            used.add(_authorization_hash(value))
    recoveries = transaction_root / "recoveries"
    if recoveries.is_dir():
        for path in recoveries.glob("*.json"):
            try:
                event = _json_document(
                    _regular_bytes(path, "lifecycle recovery event"),
                    "lifecycle recovery event",
                )
            except ValidationError:
                raise
            value = event.get("authorization_ref")
            if isinstance(value, str):
                used.add(_authorization_hash(value))
    if _authorization_hash(authorization_ref) in used:
        raise ConflictError("lifecycle authorization reference was already used")


def _terminal_result_bytes(
    transaction_root: Path, journal: Mapping[str, object]
) -> bytes:
    result = journal.get("result")
    desired = journal.get("desired_result_sha256")
    if not isinstance(result, dict):
        raise ValidationError("terminal lifecycle result is missing")
    _validate_sha256(desired, "desired_result_sha256")
    raw = canonical_json_bytes(result)
    if hashlib.sha256(raw).hexdigest() != desired:
        raise ValidationError("terminal lifecycle result digest mismatch")
    path = transaction_root / "result.json"
    try:
        current = _regular_bytes(path, "lifecycle result")
    except ValidationError:
        try:
            path.lstat()
        except FileNotFoundError:
            return raw
        raise
    if current != raw:
        predecessor = journal.get("predecessor_result_sha256")
        current_sha256 = hashlib.sha256(current).hexdigest()
        if predecessor is None or current_sha256 != predecessor:
            raise ConflictError("materialized lifecycle result drifted")
    return raw


def _validate_terminal_endpoints(
    selection: SkillRootSelection,
    plan: LifecyclePlan,
    journal: Mapping[str, object],
) -> None:
    expected_installed_sha256 = journal.get("terminal_installed_state_sha256")
    _validate_sha256(
        expected_installed_sha256,
        "terminal_installed_state_sha256",
        optional=True,
    )
    installed_path = selection.state_root / "installed.json"
    if expected_installed_sha256 is None:
        try:
            installed_path.lstat()
        except FileNotFoundError:
            installed_sha256 = None
        else:
            raise ConflictError("terminal installed state drifted")
    else:
        installed = _regular_bytes(installed_path, "installed state")
        installed_sha256 = hashlib.sha256(installed).hexdigest()
        if installed_sha256 != expected_installed_sha256:
            raise ConflictError("terminal installed state drifted")
    manifest = (
        load_pack_manifest(Path(plan.source) / "pack.json")
        if plan.source is not None and Path(plan.source).is_dir()
        else None
    )
    if manifest is None:
        member_names = ACTIVE_MEMBERS + REMOVED_MEMBERS
        directories = []
        files = []
        for member in member_names:
            path = selection.skills_root / member
            if not path.exists():
                continue
            inventory = _scan_member(path, selection.skills_root)
            directories.extend(inventory.directories)
            files.extend(inventory.files)
        current = _Inventory(
            tuple(sorted(directories)), tuple(sorted(files, key=lambda item: item.path))
        )
    else:
        current = _target_inventory(selection, manifest)
    if _target_revision(current, installed_sha256) != journal.get(
        "terminal_target_revision"
    ):
        raise ConflictError("terminal active family drifted")


def _publish_operation_locks(
    selection: SkillRootSelection,
    plan: LifecyclePlan,
    journal: Mapping[str, object],
    operation: str,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
) -> Tuple[_HeldLock, _HeldLock]:
    reviewed = journal["reviewed_plan_sha256"]
    for path in (selection.target_lock_path, selection.state_root / "lifecycle.lock"):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise LockBusyError("lifecycle target is busy")
    target = _publish_lock(
        selection.target_lock_path,
        _lock_document(
            "target",
            selection,
            plan,
            reviewed,
            operation_actor,
            operation_occurred_at,
            authorization_ref,
            operation,
        ),
    )
    try:
        state = _publish_lock(
            selection.state_root / "lifecycle.lock",
            _lock_document(
                "state",
                selection,
                plan,
                reviewed,
                operation_actor,
                operation_occurred_at,
                authorization_ref,
                operation,
            ),
        )
    except BaseException:
        _release_lock(target)
        raise
    return target, state


def _reverse_preflight(
    selection: SkillRootSelection,
    plan: LifecyclePlan,
    journal: Mapping[str, object],
    transaction_root: Path,
) -> None:
    _validate_terminal_endpoints(selection, plan, journal)
    completed = tuple(journal.get("completed_action_ids", ()))
    if completed != tuple(action.action_id for action in plan.actions):
        raise ConflictError("terminal journal has incomplete actions")
    rollback = transaction_root / "rollback" / "previous"
    if plan.operation == "uninstall":
        for member in ACTIVE_MEMBERS:
            try:
                (selection.skills_root / member).lstat()
            except FileNotFoundError:
                continue
            raise ConflictError("uninstall rollback target member is occupied")
        try:
            (selection.state_root / "installed.json").lstat()
        except FileNotFoundError:
            pass
        else:
            raise ConflictError("uninstall rollback installed state is occupied")
    for action in plan.actions:
        if action.kind == "archive-member":
            source = rollback / "skills" / action.member
            if _action_inventory(source, rollback / "skills") != action.expected_files:
                raise ConflictError("rollback member evidence drifted")
        elif action.kind == "archive-installed-state":
            raw = _regular_bytes(rollback / "installed.json", "prior installed state")
            if hashlib.sha256(raw).hexdigest() != plan.installed_state_sha256:
                raise ConflictError("prior installed-state evidence drifted")
    reverted = transaction_root / "rollback" / "reverted"
    if reverted.exists():
        raise ConflictError("rollback reverted endpoint is occupied")


def _reverse_actions(
    selection: SkillRootSelection,
    plan: LifecyclePlan,
    transaction_root: Path,
) -> Tuple[str, ...]:
    from .io import _fsync_directory

    previous = transaction_root / "rollback" / "previous"
    reverted = transaction_root / "rollback" / "reverted"
    moved = []
    for action in reversed(plan.actions):
        if action.kind == "write-installed-state":
            source = selection.state_root / "installed.json"
            destination = reverted / "installed.json"
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(str(source), str(destination))
            _fsync_directory(source.parent)
            _fsync_directory(destination.parent)
            moved.append(destination.relative_to(selection.state_root).as_posix())
        elif action.kind == "activate-member":
            source = selection.skills_root / action.member
            destination = reverted / "skills" / action.member
            _move_directory(
                source,
                destination,
                action.expected_files,
                selection.skills_root,
            )
            moved.append(destination.relative_to(selection.state_root).as_posix())
        elif action.kind == "archive-installed-state":
            source = previous / "installed.json"
            destination = selection.state_root / "installed.json"
            if destination.exists():
                raise ConflictError("installed-state restore destination is occupied")
            os.replace(str(source), str(destination))
            _fsync_directory(source.parent)
            _fsync_directory(destination.parent)
            moved.append("installed.json")
        elif action.kind == "archive-member":
            source = previous / "skills" / action.member
            destination = selection.skills_root / action.member
            _move_directory(
                source,
                destination,
                action.expected_files,
                previous / "skills",
            )
            moved.append(action.member)
        elif action.kind == "create-skills-root":
            try:
                selection.skills_root.rmdir()
            except OSError as error:
                raise ConflictError("fresh Skill root is not empty after rollback") from error
            _fsync_directory(selection.skills_root.parent)
    return tuple(moved)


def rollback_lifecycle(
    selection: SkillRootSelection,
    transaction_id: str,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
) -> LifecycleResult:
    selection = _validate_operation_inputs(
        selection,
        transaction_id,
        operation_actor,
        operation_occurred_at,
        authorization_ref,
    )
    transaction_root, journal_raw, journal, plan = _load_journal(
        selection, transaction_id
    )
    if journal.get("status") != "committed":
        raise ConflictError("only a committed lifecycle may be rolled back")
    _require_new_authorization(journal, transaction_root, authorization_ref)
    _reverse_preflight(selection, plan, journal, transaction_root)
    result_before = _terminal_result_bytes(transaction_root, journal)
    target_lock, state_lock = _publish_operation_locks(
        selection,
        plan,
        journal,
        "rollback",
        operation_actor,
        operation_occurred_at,
        authorization_ref,
    )
    try:
        _reverse_preflight(selection, plan, journal, transaction_root)
        writer = _JournalWriter(
            transaction_root / "journal.json",
            transaction_id,
            hashlib.sha256(journal_raw).hexdigest(),
        )
        moved = _reverse_actions(selection, plan, transaction_root)
        result = LifecycleResult(
            "rolled-back",
            transaction_id,
            plan.from_version,
            moved,
            transaction_root / "rollback",
            operation_actor,
            operation_occurred_at,
            authorization_ref,
            selection.target_digest,
        )
        result_document = _result_document(result, selection)
        desired_raw = canonical_json_bytes(result_document)
        journal["status"] = "rolled-back"
        journal["rollback_actor"] = operation_actor
        journal["rollback_occurred_at"] = operation_occurred_at
        journal["rollback_authorization_ref"] = authorization_ref
        journal["result"] = result_document
        journal["predecessor_result_sha256"] = hashlib.sha256(result_before).hexdigest()
        journal["desired_result_sha256"] = hashlib.sha256(desired_raw).hexdigest()
        journal["terminal_installed_state_sha256"] = plan.installed_state_sha256
        if plan.installed_state_sha256 is None:
            current_inventory = _target_inventory(
                selection, load_pack_manifest(Path(plan.source) / "pack.json")
            )
            journal["terminal_target_revision"] = _target_revision(
                current_inventory, None
            )
        else:
            restored = _regular_bytes(
                selection.state_root / "installed.json", "restored installed state"
            )
            restored_inventory = _Inventory(
                _directories(
                    _json_document(restored, "restored installed state")["directories"],
                    "restored directories",
                ),
                _manifest_files(
                    _json_document(restored, "restored installed state")["files"],
                    "restored files",
                ),
            )
            journal["terminal_target_revision"] = _target_revision(
                restored_inventory, hashlib.sha256(restored).hexdigest()
            )
        writer.publish(journal, "rolled-back")
        from .io import atomic_write

        atomic_write(
            transaction_root / "result.json",
            desired_raw,
            transaction_id,
            "result-rolled-back",
            hashlib.sha256(result_before).hexdigest(),
        )
        _lifecycle_checkpoint("before-state-lock-release")
        _release_lock(state_lock)
        state_lock = None
        _lifecycle_checkpoint("before-target-lock-release")
        _release_lock(target_lock)
        target_lock = None
        return result
    finally:
        if state_lock is not None:
            state_lock.lease.close()
        if target_lock is not None:
            target_lock.lease.close()


def _adopt_lock(
    path: Path,
    selection: SkillRootSelection,
    transaction_id: str,
    authorization_ref: str,
) -> _HeldLock:
    raw = _regular_bytes(path, "lifecycle lock")
    document = _json_document(raw, "lifecycle lock")
    if (
        document.get("schema_version") != 1
        or document.get("transaction_id") != transaction_id
        or document.get("skills_root") != str(selection.skills_root)
        or document.get("state_root") != str(selection.state_root)
        or document.get("target_digest") != selection.target_digest
    ):
        raise ConflictError("lifecycle lock binding mismatch")
    if document.get("authorization_ref_sha256") == _authorization_hash(
        authorization_ref
    ):
        raise ConflictError("lifecycle authorization reference was already used")
    candidate = path.with_name(
        "." + path.name + ".candidate-" + hashlib.sha256(raw).hexdigest()
    )
    try:
        if not os.path.samefile(str(path), str(candidate)):
            raise ConflictError("lifecycle lock candidate identity mismatch")
    except OSError as error:
        raise ConflictError("lifecycle lock candidate is missing") from error
    lease = _Lease.open(candidate)
    if not lease.acquire():
        lease.close()
        raise LockBusyError("lifecycle lock owner is still live")
    if lease.read_all() != raw:
        lease.close()
        raise ConflictError("lifecycle lock changed during adoption")
    return _HeldLock(path, candidate, raw, lease)


def recover_lifecycle(
    selection: SkillRootSelection,
    transaction_id: str,
    operation_actor: str,
    operation_occurred_at: str,
    authorization_ref: str,
) -> LifecycleResult:
    selection = _validate_operation_inputs(
        selection,
        transaction_id,
        operation_actor,
        operation_occurred_at,
        authorization_ref,
    )
    transaction_root, journal_raw, journal, plan = _load_journal(
        selection, transaction_id
    )
    if journal.get("status") not in ("committed", "rolled-back"):
        raise ConflictError("lifecycle journal is not terminal")
    _require_new_authorization(journal, transaction_root, authorization_ref)
    target_lock = _adopt_lock(
        selection.target_lock_path, selection, transaction_id, authorization_ref
    )
    state_lock = None
    try:
        try:
            (selection.state_root / "lifecycle.lock").lstat()
        except FileNotFoundError:
            state_lock = None
        else:
            state_lock = _adopt_lock(
                selection.state_root / "lifecycle.lock",
                selection,
                transaction_id,
                authorization_ref,
            )
        _validate_terminal_endpoints(selection, plan, journal)
        desired_result = _terminal_result_bytes(transaction_root, journal)
        result_path = transaction_root / "result.json"
        try:
            current_result = _regular_bytes(result_path, "lifecycle result")
        except ValidationError:
            try:
                result_path.lstat()
            except FileNotFoundError:
                current_result = None
            else:
                raise
        if current_result != desired_result:
            from .io import atomic_write

            atomic_write(
                result_path,
                desired_result,
                transaction_id,
                "result-recovery",
                hashlib.sha256(current_result).hexdigest()
                if current_result is not None
                else None,
            )
        event = {
            "actor": operation_actor,
            "adopted_state_lock_sha256": hashlib.sha256(state_lock.raw).hexdigest()
            if state_lock is not None
            else None,
            "adopted_target_lock_sha256": hashlib.sha256(target_lock.raw).hexdigest(),
            "authorization_ref": authorization_ref,
            "kind": "recover",
            "occurred_at": operation_occurred_at,
            "schema_version": 1,
            "skills_root": str(selection.skills_root),
            "state_root": str(selection.state_root),
            "target_digest": selection.target_digest,
            "terminal_journal_sha256": hashlib.sha256(journal_raw).hexdigest(),
            "transaction_id": transaction_id,
        }
        event_raw = canonical_json_bytes(event)
        event_id = hashlib.sha256(
            canonical_json_bytes(
                {
                    "actor": operation_actor,
                    "authorization_ref": authorization_ref,
                    "kind": "recover",
                    "occurred_at": operation_occurred_at,
                    "transaction_id": transaction_id,
                }
            )
        ).hexdigest()
        event_path = transaction_root / "recoveries" / (event_id + ".json")
        candidate = event_path.with_name(
            "." + event_path.name + ".candidate-" + hashlib.sha256(event_raw).hexdigest()
        )
        atomic_publish_exclusive(event_path, event_raw, candidate)
        if state_lock is not None:
            _release_lock(state_lock)
            state_lock = None
        _release_lock(target_lock)
        target_lock = None
        result_document = journal["result"]
        return LifecycleResult(
            "recovered",
            transaction_id,
            result_document.get("version"),
            (),
            transaction_root / "rollback",
            operation_actor,
            operation_occurred_at,
            authorization_ref,
            selection.target_digest,
        )
    finally:
        if state_lock is not None:
            state_lock.lease.close()
        if target_lock is not None:
            target_lock.lease.close()
