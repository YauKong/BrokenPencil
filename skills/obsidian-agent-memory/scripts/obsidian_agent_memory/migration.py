"""Deterministic, no-follow vault detection for reviewed migration planning."""

import contextlib
import hashlib
import hmac
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, FrozenSet, Iterable, Iterator, List, Literal, Mapping, Optional, Tuple, Union

from . import projections as _projections
from . import transactions as _transactions
from .catalog import load_catalog
from .errors import ConflictError, LockBusyError, PlanInvalidatedError, ValidationError
from .models import Finding, RecordCandidate, RecordEnvelope, RootWriteGuard, TransactionContext
from .operation_scope import AuthorizationGate, OperationScope, require_operation_gate
from .paths import validate_identifier
from .records import (
    _validate_timestamp,
    compute_body_sha256,
    normalize_body,
    record_relative_path,
)


_FIXTURE_MARKER = ".agent-memory-fixture.json"
_ROOT_ANCHOR = ".agent-memory-root-write.anchor"
_ROOT_ANCHOR_BYTES = b'{"purpose":"root-write-namespace","schema_version":1}\n'
_ANCHOR_CANDIDATE = _ROOT_ANCHOR + ".candidate"
_ROOT_GUARD = ".agent-memory-root-write.lock"
_RECOVERY_ROOT = ".agent-memory-root-write-recoveries"
_EXCLUDED_DIRECTORIES = frozenset(
    (".agent-memory/transactions", ".agent-memory/state/locks")
)
_GENERATED_INDEX_PATHS = frozenset(
    (
        "_index/home.md",
        "_index/memory-map.md",
        "_index/stale-or-uncertain.md",
    )
)
_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_HASH_CHUNK_SIZE = 1024 * 1024
_JSON_SIZE_LIMIT = 4 * 1024 * 1024
_APPLIED_JOURNAL_INVENTORY_LIMIT = 10_000
_lstat = os.lstat


class VaultGeneration(str, Enum):
    V1 = "v1"
    V2 = "v2"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class SourceCategory(str, Enum):
    CONTRACT = "contract"
    INDEX = "index"
    AUXILIARY_VIEW = "auxiliary-view"
    PROJECT_OVERVIEW = "project-overview"
    LEGACY_FOCUS = "legacy-focus"
    SESSION = "session"
    STORY = "story"
    DECISION = "decision"
    PREFERENCE = "preference"
    RUNBOOK = "runbook"
    META = "meta"
    RAW_SOURCE = "raw-source"
    EMBEDDED_KNOWLEDGE = "embedded-knowledge"
    SCHEMA_2_STATE = "schema-2-state"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SourceEntry:
    relative_path: str
    sha256: str
    size: int
    category: SourceCategory


@dataclass(frozen=True)
class VaultDetection:
    generation: VaultGeneration
    source_revision: str
    entries: Tuple[SourceEntry, ...]
    findings: Tuple[Finding, ...]


@dataclass(frozen=True)
class SnapshotEntry:
    relative_path: str
    sha256: str
    size: int
    snapshot_path: str


@dataclass(frozen=True)
class MigrationSnapshot:
    snapshot_id: str
    source_revision: str
    entries: Tuple[SnapshotEntry, ...]


class MigrationActionKind(str, Enum):
    RECORD = "record"
    RAW_SOURCE = "raw-source"
    FOCUS_PROPOSAL = "focus-proposal"
    EMBEDDED_KNOWLEDGE_REVIEW = "embedded-knowledge-review"
    PRESERVE = "preserve"
    REGENERATE_PROJECTION = "regenerate-projection"
    UNRESOLVED_PROPOSAL = "unresolved-proposal"


class UnresolvedClassification(str, Enum):
    AMBIGUOUS_OWNER = "ambiguous-owner"
    LEGACY_PROJECT_ID_MAPPING_REQUIRED = "legacy-project-id-mapping-required"
    LEGACY_FOCUS_INPUT = "legacy-focus-input"
    EMBEDDED_KNOWLEDGE_EXTERNAL = "embedded-knowledge-external"
    UNKNOWN_FORMAT = "unknown-format"


@dataclass(frozen=True)
class MigrationAction:
    action_id: str
    kind: MigrationActionKind
    source_path: str
    source_sha256: str
    target_path: Optional[str]
    record_type: Optional[str]
    owner_scope: Optional[str]
    project_id: Optional[str]
    memory_id: Optional[str]
    projection_effects: Tuple[str, ...]
    unresolved_classification: Optional[UnresolvedClassification]
    reason: str


@dataclass(frozen=True)
class ProjectIdMapping:
    source_project_id: str
    target_project_id: str


@dataclass(frozen=True)
class MigrationPlan:
    plan_id: str
    from_schema: int
    to_schema: int
    source_revision: str
    actor: str
    created_at: str
    authorization_ref: Optional[str]
    project_id_mappings: Tuple[ProjectIdMapping, ...]
    actions: Tuple[MigrationAction, ...]
    findings: Tuple[Finding, ...]


@dataclass(frozen=True)
class MigrationBundle:
    bundle_dir: Path
    detection: VaultDetection
    snapshot: MigrationSnapshot
    plan: MigrationPlan
    bundle_sha256: str


@dataclass(frozen=True)
class MigrationResult:
    status: Literal["applied", "already-applied", "rolled-back", "proposed"]
    transaction_id: str
    source_revision: str
    reviewed_bundle_sha256: str
    plan_authorization_ref: Optional[str]
    apply_authorization_ref: Optional[str]
    rollback_authorization_ref: Optional[str]
    created_paths: Tuple[str, ...]
    replaced_paths: Tuple[str, ...]
    archived_paths: Tuple[str, ...]
    proposal_paths: Tuple[str, ...]


@dataclass(frozen=True)
class MigrationVerification:
    valid: bool
    source_revision: str
    bundle_sha256: str
    projection_paths: Tuple[str, ...]
    findings: Tuple[Finding, ...]


@dataclass(frozen=True)
class AppliedMigrationProposalBinding:
    proposal_path: str
    proposal_after_sha256: str
    apply_transaction_id: str
    journal_path: str
    journal_sha256: str
    plan_id: str
    reviewed_bundle_sha256: str
    source_revision: str


@dataclass(frozen=True)
class _InventoryResult:
    entries: Tuple[SourceEntry, ...]
    findings: Tuple[Finding, ...]
    generated_paths: FrozenSet[str]
    anchor_present: bool
    anchor_valid: bool


def _unsafe(metadata) -> bool:
    return bool(
        stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0) & _REPARSE_FLAG
        or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode))
    )


def _require_safe(metadata, label: str) -> None:
    if _unsafe(metadata):
        raise ValidationError("unsafe filesystem entry: {0}".format(label))


def _validate_selected_path(original_root: Path, selected_root: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(original_root)))
    chain = list(reversed(absolute.parents)) + [absolute]
    for candidate in chain:
        try:
            metadata = _lstat(candidate)
        except OSError as error:
            raise ValidationError("memory root must be an existing directory") from error
        _require_safe(metadata, "selected root or ancestor")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValidationError("unsafe filesystem entry: selected root or ancestor")
    try:
        resolved = absolute.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValidationError("memory root must be an existing directory") from error
    if resolved != selected_root:
        raise ValidationError("unsafe filesystem entry: selected root alias")


def _hash_regular_file(path: Path, expected_metadata) -> Tuple[str, int, bytes]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValidationError("unable to read vault entry safely") from error
    digest = hashlib.sha256()
    prefix = bytearray()
    total = 0
    try:
        observed = os.fstat(descriptor)
        _require_safe(observed, "opened vault file")
        if not stat.S_ISREG(observed.st_mode):
            raise ValidationError("unsafe filesystem entry: opened vault file")
        for field in ("st_dev", "st_ino"):
            expected = getattr(expected_metadata, field, None)
            actual = getattr(observed, field, None)
            if expected not in (None, 0) and actual not in (None, 0) and expected != actual:
                raise ValidationError("vault entry changed during inventory")
        while True:
            chunk = os.read(descriptor, _HASH_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if len(prefix) < 512:
                prefix.extend(chunk[: 512 - len(prefix)])
    finally:
        os.close(descriptor)
    if total != expected_metadata.st_size:
        raise ValidationError("vault entry changed during inventory")
    return digest.hexdigest(), total, bytes(prefix)


def _category(relative_path: str) -> SourceCategory:
    parts = PurePosixPath(relative_path).parts
    if relative_path in ("AGENTS.md", "README.md"):
        return SourceCategory.CONTRACT
    if relative_path.startswith(".agent-memory/") or relative_path.startswith(
        "_records/"
    ):
        return SourceCategory.SCHEMA_2_STATE
    if relative_path in (_ANCHOR_CANDIDATE, _ROOT_GUARD) or relative_path.startswith(
        ".agent-memory-root-write.candidate-"
    ):
        return SourceCategory.SCHEMA_2_STATE
    if not parts:
        return SourceCategory.UNKNOWN
    if parts[0] == "_index":
        if relative_path == "_index/current-focus.md":
            return SourceCategory.LEGACY_FOCUS
        if relative_path in _GENERATED_INDEX_PATHS:
            return SourceCategory.INDEX
        if len(parts) == 2 and parts[1].endswith(".base"):
            return SourceCategory.AUXILIARY_VIEW
        return SourceCategory.UNKNOWN
    if parts[0] == "projects" and len(parts) >= 3:
        if len(parts) == 3 and parts[2] == "overview.md":
            return SourceCategory.PROJECT_OVERVIEW
        if len(parts) == 3 and parts[2] == "current-focus.md":
            return SourceCategory.LEGACY_FOCUS
        if parts[2] == "sessions":
            return SourceCategory.SESSION
        if parts[2] == "stories":
            return SourceCategory.STORY
        if parts[2] == "decisions":
            return SourceCategory.DECISION
        if parts[2] == "raw":
            return SourceCategory.RAW_SOURCE
    if parts[0] == "preferences":
        return SourceCategory.PREFERENCE
    if parts[0] == "skills":
        return SourceCategory.RUNBOOK
    if parts[0] == "meta":
        return SourceCategory.META
    if parts[0] == "knowledge":
        return SourceCategory.EMBEDDED_KNOWLEDGE
    return SourceCategory.UNKNOWN


def _is_generated_projection(prefix: bytes) -> bool:
    return prefix.startswith(b"---\ngenerated: true\nprojection_version: 2\n")


def _valid_recovery_tree(path: Path) -> bool:
    try:
        with os.scandir(path) as stream:
            operations = sorted(stream, key=lambda value: value.name)
        for operation in operations:
            metadata = _lstat(operation.path)
            _require_safe(metadata, _RECOVERY_ROOT + "/" + operation.name)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or len(operation.name) != 64
                or any(character not in "0123456789abcdef" for character in operation.name)
            ):
                return False
            with os.scandir(operation.path) as stream:
                children = sorted(stream, key=lambda value: value.name)
            allowed = {
                "000-prepared.json",
                "010-new-guard-published.json",
                "020-old-artifact-removed.json",
                "old-artifact.bin",
            }
            if not children or any(child.name not in allowed for child in children):
                return False
            for child in children:
                child_metadata = _lstat(child.path)
                _require_safe(
                    child_metadata,
                    _RECOVERY_ROOT + "/" + operation.name + "/" + child.name,
                )
                if not stat.S_ISREG(child_metadata.st_mode):
                    return False
        return True
    except OSError as error:
        raise ValidationError("unable to inspect root recovery evidence") from error


def _source_revision(entries: Tuple[SourceEntry, ...]) -> str:
    payload = [
        {"path": item.relative_path, "sha256": item.sha256, "size": item.size}
        for item in sorted(entries, key=lambda value: value.relative_path)
    ]
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _inventory_vault(
    selected_root: Path,
    original_root: Path,
    external_work_dir: Optional[Path] = None,
    ignored_guard_paths: FrozenSet[str] = frozenset(),
) -> _InventoryResult:
    _validate_selected_path(original_root, selected_root)
    excluded_external = None
    if external_work_dir is not None:
        excluded_external = Path(external_work_dir).resolve(strict=False)

    entries: List[SourceEntry] = []
    findings: List[Finding] = []
    generated_paths = set()
    anchor_present = False
    anchor_valid = False
    stack = [(selected_root, "")]
    while stack:
        directory, prefix = stack.pop()
        try:
            with os.scandir(directory) as stream:
                children = sorted(stream, key=lambda value: value.name, reverse=True)
        except OSError as error:
            raise ValidationError("unable to inventory selected vault") from error
        for child in children:
            relative_path = child.name if not prefix else prefix + "/" + child.name
            path = Path(child.path)
            if relative_path in ignored_guard_paths:
                continue
            try:
                metadata = _lstat(path)
            except OSError as error:
                raise ValidationError("vault entry changed during inventory") from error
            _require_safe(metadata, relative_path)
            if stat.S_ISDIR(metadata.st_mode):
                if excluded_external is not None and path.resolve(strict=False) == excluded_external:
                    continue
                if relative_path in _EXCLUDED_DIRECTORIES:
                    continue
                if relative_path == _RECOVERY_ROOT:
                    if _valid_recovery_tree(path):
                        continue
                    findings.append(
                        Finding(
                            "invalid-root-recovery-evidence",
                            "error",
                            relative_path,
                            "root-write recovery evidence has unknown or incomplete inventory",
                        )
                    )
                stack.append((path, relative_path))
                continue

            if relative_path == _FIXTURE_MARKER:
                continue
            digest, size, content_prefix = _hash_regular_file(path, metadata)
            if relative_path == _ROOT_ANCHOR:
                anchor_present = True
                anchor_valid = size == len(_ROOT_ANCHOR_BYTES) and content_prefix == _ROOT_ANCHOR_BYTES
                if not anchor_valid:
                    findings.append(
                        Finding(
                            "invalid-root-anchor",
                            "error",
                            relative_path,
                            "root-write namespace anchor bytes are malformed",
                        )
                    )
                continue

            category = _category(relative_path)
            entry = SourceEntry(relative_path, digest, size, category)
            entries.append(entry)
            if _is_generated_projection(content_prefix):
                generated_paths.add(relative_path)
            if category is SourceCategory.EMBEDDED_KNOWLEDGE:
                findings.append(
                    Finding(
                        "knowledge-base-migration-required",
                        "warning",
                        relative_path,
                        "embedded knowledge requires a separate Knowledge Base migration decision",
                    )
                )
            elif category is SourceCategory.UNKNOWN:
                findings.append(
                    Finding(
                        "unknown-source-entry",
                        "warning",
                        relative_path,
                        "vault entry has no deterministic legacy classification",
                    )
                )
            if relative_path == _ANCHOR_CANDIDATE:
                state = (
                    "complete-prefix"
                    if content_prefix == _ROOT_ANCHOR_BYTES and size == len(_ROOT_ANCHOR_BYTES)
                    else "partial-prefix"
                    if _ROOT_ANCHOR_BYTES.startswith(content_prefix)
                    else "malformed"
                )
                findings.append(
                    Finding(
                        "root-write-anchor-candidate-present",
                        "error",
                        relative_path,
                        "root-write anchor candidate is {0} and requires lease review".format(state),
                    )
                )
            elif relative_path == _ROOT_GUARD or relative_path.startswith(
                ".agent-memory-root-write.candidate-"
            ):
                findings.append(
                    Finding(
                        "root-write-guard-present",
                        "error",
                        relative_path,
                        "root-write guard requires owner and process verification",
                    )
                )

    ordered_entries = tuple(sorted(entries, key=lambda value: value.relative_path))
    ordered_findings = tuple(
        sorted(findings, key=lambda value: (value.severity, value.code, value.path, value.message))
    )
    return _InventoryResult(
        ordered_entries,
        ordered_findings,
        frozenset(generated_paths),
        anchor_present,
        anchor_valid,
    )


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _read_json(root: Path, relative_path: str):
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    metadata = _lstat(path)
    _require_safe(metadata, relative_path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _JSON_SIZE_LIMIT:
        raise ValidationError("invalid Schema-2 state")
    _, _, prefix = _hash_regular_file(path, metadata)
    if metadata.st_size > len(prefix):
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise ValidationError("invalid Schema-2 state") from error
    else:
        raw = prefix
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValidationError("invalid Schema-2 state") from error


def _valid_catalog(value, entry_paths: FrozenSet[str]) -> bool:
    if (
        not isinstance(value, dict)
        or set(value) != {"records", "revision", "schema_version"}
        or value.get("schema_version") != 2
        or type(value.get("revision")) is not int
        or value["revision"] < 0
        or not isinstance(value.get("records"), dict)
    ):
        return False
    for memory_id, record in value["records"].items():
        try:
            validate_identifier(memory_id, "memory_id")
        except ValidationError:
            return False
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "memory_id",
                "owner_scope",
                "project",
                "record_type",
                "relative_path",
                "revision",
            }
            or record.get("memory_id") != memory_id
            or not isinstance(record.get("owner_scope"), str)
            or record.get("record_type")
            not in {"session", "story", "decision", "preference", "runbook", "migration", "maintenance"}
            or type(record.get("revision")) is not int
            or record["revision"] <= 0
            or not isinstance(record.get("relative_path"), str)
            or record["relative_path"] not in entry_paths
        ):
            return False
    return True


def _valid_v2_state(root: Path, inventory: _InventoryResult) -> bool:
    paths = frozenset(entry.relative_path for entry in inventory.entries)
    required = {
        "AGENTS.md",
        "README.md",
        ".agent-memory/config.json",
        ".agent-memory/schema.json",
        ".agent-memory/state/catalog.json",
    }
    if not inventory.anchor_present or not inventory.anchor_valid or not required.issubset(paths):
        return False
    try:
        config = _read_json(root, ".agent-memory/config.json")
        schema = _read_json(root, ".agent-memory/schema.json")
        catalog = _read_json(root, ".agent-memory/state/catalog.json")
    except (OSError, ValidationError):
        return False
    return (
        config == {"schema_version": 2}
        and schema == {"schema_version": 2}
        and _valid_catalog(catalog, paths)
    )


def _detect_generation(
    root: Path,
    inventory: _InventoryResult,
) -> Tuple[VaultGeneration, Tuple[Finding, ...]]:
    paths = frozenset(entry.relative_path for entry in inventory.entries)
    schema_markers = bool(
        {".agent-memory/schema.json", ".agent-memory/state/catalog.json"} & paths
        or any(path.startswith("_records/") for path in paths)
    )
    owner_categories = {
        SourceCategory.SESSION,
        SourceCategory.STORY,
        SourceCategory.DECISION,
        SourceCategory.PREFERENCE,
        SourceCategory.RUNBOOK,
        SourceCategory.META,
    }
    live_legacy_owners = any(
        entry.category in owner_categories
        and entry.relative_path not in inventory.generated_paths
        for entry in inventory.entries
    )
    findings = list(inventory.findings)
    if schema_markers:
        if _valid_v2_state(root, inventory) and not live_legacy_owners:
            generation = VaultGeneration.V2
        else:
            generation = VaultGeneration.PARTIAL
            findings.append(
                Finding(
                    "partial-schema-2-state",
                    "error",
                    ".agent-memory",
                    "Schema-2 markers coexist with missing, invalid, or legacy owner state",
                )
            )
    else:
        recognized = any(
            entry.category
            not in {
                SourceCategory.CONTRACT,
                SourceCategory.INDEX,
                SourceCategory.UNKNOWN,
                SourceCategory.SCHEMA_2_STATE,
            }
            for entry in inventory.entries
        )
        if recognized:
            generation = VaultGeneration.V1
        else:
            generation = VaultGeneration.UNKNOWN
            findings.append(
                Finding(
                    "unrecognized-vault",
                    "warning",
                    ".",
                    "vault has no recognized v1 or valid Schema-2 memory state",
                )
            )
    return generation, tuple(
        sorted(findings, key=lambda value: (value.severity, value.code, value.path, value.message))
    )


def _detect_vault_gated(selected_root: Path, original_root: Path) -> VaultDetection:
    inventory = _inventory_vault(selected_root, original_root)
    generation, findings = _detect_generation(selected_root, inventory)
    return VaultDetection(
        generation,
        _source_revision(inventory.entries),
        inventory.entries,
        findings,
    )


def _detect_vault_under_guard(
    selected_root: Path,
    original_root: Path,
    context: TransactionContext,
    guard: RootWriteGuard,
) -> VaultDetection:
    _transactions._require_guard(selected_root, context, guard)
    ignored = frozenset(
        (
            _ROOT_ANCHOR,
            _ROOT_GUARD,
            _transactions._root_candidate(selected_root, context.transaction_id).name,
        )
    )
    inventory = _inventory_vault(
        selected_root,
        original_root,
        ignored_guard_paths=ignored,
    )
    generation, findings = _detect_generation(selected_root, inventory)
    return VaultDetection(
        generation,
        _source_revision(inventory.entries),
        inventory.entries,
        findings,
    )


def detect_vault(root: Path, gate: AuthorizationGate) -> VaultDetection:
    selected_root = require_operation_gate(root, gate, "migration-detect")
    return _detect_vault_gated(selected_root, Path(root))


def _portable_relative(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValidationError("invalid {0}".format(field))
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or posix.as_posix() != value
        or any(part in ("", ".", "..") for part in posix.parts)
    ):
        raise ValidationError("invalid {0}".format(field))
    return value


def _projection_path(value: str) -> str:
    _portable_relative(value, "projection effect")
    parts = PurePosixPath(value).parts
    if value in {
        "_index/current-focus.md",
        "_index/home.md",
        "_index/memory-map.md",
        "_index/stale-or-uncertain.md",
    }:
        return value
    if len(parts) == 3 and parts[0] == "projects" and parts[2] in {
        "overview.md",
        "current-focus.md",
    }:
        validate_identifier(parts[1], "project_id")
        return value
    if len(parts) == 4 and parts[0] == "projects" and parts[2] == "stories":
        validate_identifier(parts[1], "project_id")
        if not parts[3].endswith(".md"):
            raise ValidationError("invalid projection effect")
        validate_identifier(parts[3][:-3], "memory_id")
        return value
    raise ValidationError("invalid projection effect")


def _json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def _finding_dict(value: Finding) -> dict:
    return {
        "code": value.code,
        "message": value.message,
        "path": value.path,
        "severity": value.severity,
    }


def _source_entry_dict(value: SourceEntry) -> dict:
    return {
        "category": value.category.value,
        "relative_path": value.relative_path,
        "sha256": value.sha256,
        "size": value.size,
    }


def _snapshot_entry_dict(value: SnapshotEntry) -> dict:
    return {
        "relative_path": value.relative_path,
        "sha256": value.sha256,
        "size": value.size,
        "snapshot_path": value.snapshot_path,
    }


def _action_dict(value: MigrationAction) -> dict:
    return {
        "action_id": value.action_id,
        "kind": value.kind.value,
        "memory_id": value.memory_id,
        "owner_scope": value.owner_scope,
        "project_id": value.project_id,
        "projection_effects": list(value.projection_effects),
        "reason": value.reason,
        "record_type": value.record_type,
        "source_path": value.source_path,
        "source_sha256": value.source_sha256,
        "target_path": value.target_path,
        "unresolved_classification": (
            value.unresolved_classification.value
            if value.unresolved_classification is not None
            else None
        ),
    }


def _project_id_mapping_dict(value: ProjectIdMapping) -> dict:
    return {
        "source_project_id": value.source_project_id,
        "target_project_id": value.target_project_id,
    }


def _detection_dict(value: VaultDetection) -> dict:
    return {
        "entries": [_source_entry_dict(item) for item in value.entries],
        "findings": [_finding_dict(item) for item in value.findings],
        "generation": value.generation.value,
        "schema_version": 1,
        "source_revision": value.source_revision,
    }


def _snapshot_dict(value: MigrationSnapshot) -> dict:
    return {
        "entries": [_snapshot_entry_dict(item) for item in value.entries],
        "schema_version": 1,
        "snapshot_id": value.snapshot_id,
        "source_revision": value.source_revision,
    }


def _plan_dict(value: MigrationPlan) -> dict:
    return {
        "actions": [_action_dict(item) for item in value.actions],
        "actor": value.actor,
        "authorization_ref": value.authorization_ref,
        "created_at": value.created_at,
        "findings": [_finding_dict(item) for item in value.findings],
        "from_schema": value.from_schema,
        "plan_id": value.plan_id,
        "project_id_mappings": [
            _project_id_mapping_dict(item) for item in value.project_id_mappings
        ],
        "schema_version": 2,
        "source_revision": value.source_revision,
        "to_schema": value.to_schema,
    }


def _write_exclusive(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_snapshot_file(
    source: Path,
    destination: Path,
    expected: SourceEntry,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = os.open(source, source_flags)
    destination_descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    source_digest = hashlib.sha256()
    copied_digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(source_descriptor)
        _require_safe(metadata, expected.relative_path)
        if not stat.S_ISREG(metadata.st_mode):
            raise PlanInvalidatedError("migration source changed during snapshot")
        while True:
            chunk = os.read(source_descriptor, _HASH_CHUNK_SIZE)
            if not chunk:
                break
            source_digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_descriptor, chunk[offset:])
                if written <= 0:
                    raise OSError("short snapshot write")
                copied_digest.update(chunk[offset : offset + written])
                offset += written
                size += written
        os.fsync(destination_descriptor)
    finally:
        os.close(source_descriptor)
        os.close(destination_descriptor)
    if (
        size != expected.size
        or source_digest.hexdigest() != expected.sha256
        or copied_digest.hexdigest() != expected.sha256
    ):
        raise PlanInvalidatedError("migration source changed during snapshot")


def _record_details(entry: SourceEntry, project_id: Optional[str]):
    parts = PurePosixPath(entry.relative_path).parts
    if entry.category in {
        SourceCategory.SESSION,
        SourceCategory.STORY,
        SourceCategory.DECISION,
    }:
        if len(parts) < 4 or parts[0] != "projects" or project_id is None:
            raise ValidationError("invalid project legacy record path")
    if entry.category is SourceCategory.SESSION:
        return "session", "project.{0}.session".format(project_id), project_id
    if entry.category is SourceCategory.STORY:
        return "story", "project.{0}.story".format(project_id), project_id
    if entry.category is SourceCategory.DECISION:
        return "decision", "project.{0}.decision".format(project_id), project_id
    if entry.category is SourceCategory.PREFERENCE:
        return "preference", "user.preference", None
    if entry.category is SourceCategory.RUNBOOK:
        return "runbook", "agent.runbook", None
    if entry.category is SourceCategory.META:
        record_type = "maintenance" if "maintenance" in parts else "migration"
        return record_type, "meta.{0}".format(record_type), None
    raise ValidationError("legacy entry is not a record owner")


@dataclass(frozen=True)
class LegacyOwnerCandidate:
    candidate_memory_id: str
    owner_scope: str
    project_id: Optional[str]
    record_type: str


def derive_legacy_owner_candidate(
    entry: SourceEntry,
    project_id_mappings: Tuple[ProjectIdMapping, ...],
) -> Optional[LegacyOwnerCandidate]:
    digest = hashlib.sha256(
        (entry.relative_path + "\0" + entry.sha256).encode("utf-8")
    ).hexdigest()
    source_project_id = _source_project_id(entry)
    project_id = _effective_project_id(source_project_id, project_id_mappings)
    if entry.category not in {
        SourceCategory.SESSION,
        SourceCategory.STORY,
        SourceCategory.DECISION,
        SourceCategory.PREFERENCE,
        SourceCategory.RUNBOOK,
        SourceCategory.META,
    } or (source_project_id is not None and project_id is None):
        return None
    record_type, owner_scope, project_id = _record_details(entry, project_id)
    return LegacyOwnerCandidate(
        "migr-" + digest[:24], owner_scope, project_id, record_type
    )


def _source_project_id(entry: SourceEntry) -> Optional[str]:
    parts = PurePosixPath(entry.relative_path).parts
    if len(parts) >= 3 and parts[0] == "projects":
        return parts[1]
    return None


def _detected_project_ids(detection: VaultDetection) -> Tuple[str, ...]:
    return tuple(
        sorted(
            {
                project_id
                for entry in detection.entries
                for project_id in [_source_project_id(entry)]
                if project_id is not None
            }
        )
    )


ProjectIdMapInput = Optional[
    Union[Mapping[str, str], Iterable[Tuple[str, str]], Iterable[ProjectIdMapping]]
]


def _normalize_project_id_mappings(
    detection: VaultDetection,
    project_id_map: ProjectIdMapInput,
) -> Tuple[ProjectIdMapping, ...]:
    if project_id_map is None:
        raw_items = ()
    elif isinstance(project_id_map, Mapping):
        raw_items = tuple(project_id_map.items())
    else:
        try:
            raw_items = tuple(project_id_map)
        except TypeError as error:
            raise ValidationError("invalid project id mappings") from error

    detected = frozenset(_detected_project_ids(detection))
    seen = set()
    mappings = []
    for item in raw_items:
        if isinstance(item, ProjectIdMapping):
            source_project_id = item.source_project_id
            target_project_id = item.target_project_id
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            source_project_id, target_project_id = item
        else:
            raise ValidationError("invalid project id mapping")
        if not isinstance(source_project_id, str) or source_project_id not in detected:
            raise ValidationError("project id mapping source was not detected")
        if source_project_id in seen:
            raise ValidationError("duplicate project id mapping source")
        seen.add(source_project_id)
        validate_identifier(target_project_id, "target_project_id")
        if source_project_id == target_project_id:
            raise ValidationError("project id mapping is a no-op")
        if source_project_id.casefold() == target_project_id.casefold():
            raise ValidationError("case-only project id alias")
        mappings.append(ProjectIdMapping(source_project_id, target_project_id))

    normalized = tuple(
        sorted(mappings, key=lambda item: (item.source_project_id, item.target_project_id))
    )
    by_source = {
        item.source_project_id: item.target_project_id for item in normalized
    }
    by_target: Dict[str, str] = {}
    for source_project_id in _detected_project_ids(detection):
        target_project_id = by_source.get(source_project_id)
        if target_project_id is None:
            try:
                target_project_id = validate_identifier(source_project_id, "project_id")
            except ValidationError:
                continue
        prior_source = by_target.get(target_project_id)
        if prior_source is not None and prior_source != source_project_id:
            raise ValidationError("effective project id collision")
        by_target[target_project_id] = source_project_id
    return normalized


def _effective_project_id(
    source_project_id: Optional[str],
    project_id_mappings: Tuple[ProjectIdMapping, ...],
) -> Optional[str]:
    if source_project_id is None:
        return None
    for mapping in project_id_mappings:
        if mapping.source_project_id == source_project_id:
            return mapping.target_project_id
    try:
        return validate_identifier(source_project_id, "project_id")
    except ValidationError:
        return None


def _record_target(
    memory_id: str,
    record_type: str,
    owner_scope: str,
    project_id: Optional[str],
    source_sha256: str,
    created_at: str,
) -> str:
    envelope = RecordEnvelope(
        memory_id=memory_id,
        record_type=record_type,
        schema_version=2,
        owner_scope=owner_scope,
        project=project_id,
        revision=1,
        supersedes=None,
        created_at=created_at,
        observed_at=created_at,
        source="migration-snapshot",
        source_revision=source_sha256,
        body_sha256=source_sha256,
    )
    return record_relative_path(envelope).as_posix()


def _record_effects(
    record_type: str,
    project_id: Optional[str],
    memory_id: str,
) -> Tuple[str, ...]:
    values = {
        "_index/home.md",
        "_index/memory-map.md",
        "_index/stale-or-uncertain.md",
    }
    if project_id is not None:
        values.update(
            {
                "_index/current-focus.md",
                "projects/{0}/current-focus.md".format(project_id),
                "projects/{0}/overview.md".format(project_id),
            }
        )
        if record_type == "story":
            values.add("projects/{0}/stories/{1}.md".format(project_id, memory_id))
    return tuple(sorted(_projection_path(item) for item in values))


def _ambiguous_owner_paths(
    snapshot: MigrationSnapshot,
    bundle_dir: Path,
    detection: VaultDetection,
) -> FrozenSet[str]:
    owner_categories = {
        SourceCategory.SESSION,
        SourceCategory.STORY,
        SourceCategory.DECISION,
        SourceCategory.PREFERENCE,
        SourceCategory.RUNBOOK,
        SourceCategory.META,
    }
    categories = {entry.relative_path: entry.category for entry in detection.entries}
    lines: Dict[str, List[str]] = {}
    for entry in snapshot.entries:
        if categories.get(entry.relative_path) not in owner_categories:
            continue
        raw = (bundle_dir / entry.snapshot_path).read_bytes()
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        for line in text.splitlines():
            value = line.strip()
            if not value or value.startswith("#") or value.lower().startswith("source:"):
                continue
            lines.setdefault(value, []).append(entry.relative_path)
    ambiguous = set()
    for paths in lines.values():
        if len(set(paths)) > 1:
            ambiguous.update(paths)
    return frozenset(ambiguous)


def _entry_action(
    entry: SourceEntry,
    ambiguous: FrozenSet[str],
    project_id_mappings: Tuple[ProjectIdMapping, ...],
    created_at: str,
) -> MigrationAction:
    digest = hashlib.sha256(
        (entry.relative_path + "\0" + entry.sha256).encode("utf-8")
    ).hexdigest()
    action_id = "action-" + digest[:20]
    memory_id = "migr-" + digest[:24]
    source_project_id = _source_project_id(entry)
    project_id = _effective_project_id(source_project_id, project_id_mappings)
    if source_project_id is not None and project_id is None:
        return MigrationAction(
            action_id,
            MigrationActionKind.UNRESOLVED_PROPOSAL,
            entry.relative_path,
            entry.sha256,
            None,
            None,
            None,
            None,
            None,
            (),
            UnresolvedClassification.LEGACY_PROJECT_ID_MAPPING_REQUIRED,
            "legacy project identifier requires an explicit reviewed mapping",
        )
    if entry.relative_path in ambiguous:
        return MigrationAction(
            action_id,
            MigrationActionKind.UNRESOLVED_PROPOSAL,
            entry.relative_path,
            entry.sha256,
            None,
            None,
            None,
            None,
            None,
            (),
            UnresolvedClassification.AMBIGUOUS_OWNER,
            "the same legacy fact appears beneath competing owner paths",
        )
    if entry.category in {
        SourceCategory.SESSION,
        SourceCategory.STORY,
        SourceCategory.DECISION,
        SourceCategory.PREFERENCE,
        SourceCategory.RUNBOOK,
        SourceCategory.META,
    }:
        candidate = derive_legacy_owner_candidate(entry, project_id_mappings)
        if candidate is None:
            raise ValidationError("legacy entry is not a record owner")
        record_type = candidate.record_type
        owner_scope = candidate.owner_scope
        project_id = candidate.project_id
        memory_id = candidate.candidate_memory_id
        target = _record_target(
            memory_id,
            record_type,
            owner_scope,
            project_id,
            entry.sha256,
            created_at,
        )
        return MigrationAction(
            action_id,
            MigrationActionKind.RECORD,
            entry.relative_path,
            entry.sha256,
            target,
            record_type,
            owner_scope,
            project_id,
            memory_id,
            _record_effects(record_type, project_id, memory_id),
            None,
            "legacy page has one deterministic path-based canonical owner",
        )
    if entry.category is SourceCategory.RAW_SOURCE:
        parts = PurePosixPath(entry.relative_path).parts
        if project_id is None or len(parts) < 4:
            raise ValidationError("invalid project raw source path")
        return MigrationAction(
            action_id,
            MigrationActionKind.RAW_SOURCE,
            entry.relative_path,
            entry.sha256,
            PurePosixPath("_sources", "projects", project_id, *parts[2:]).as_posix(),
            None,
            None,
            None,
            None,
            (),
            None,
            "raw provenance is copied without becoming a fact owner",
        )
    if entry.category is SourceCategory.CONTRACT:
        return MigrationAction(
            action_id,
            MigrationActionKind.PRESERVE,
            entry.relative_path,
            entry.sha256,
            entry.relative_path,
            None,
            None,
            None,
            None,
            (),
            None,
            "root contract is preserved as migration evidence",
        )
    if entry.category is SourceCategory.AUXILIARY_VIEW:
        return MigrationAction(
            action_id,
            MigrationActionKind.PRESERVE,
            entry.relative_path,
            entry.sha256,
            entry.relative_path,
            None,
            None,
            None,
            None,
            (),
            None,
            "legacy auxiliary view is preserved without becoming a fact owner",
        )
    if entry.category in {SourceCategory.INDEX, SourceCategory.PROJECT_OVERVIEW}:
        effect = entry.relative_path
        if entry.category is SourceCategory.PROJECT_OVERVIEW:
            if project_id is None:
                raise ValidationError("invalid project overview path")
            effect = "projects/{0}/overview.md".format(project_id)
        effect = _projection_path(effect)
        return MigrationAction(
            action_id,
            MigrationActionKind.REGENERATE_PROJECTION,
            entry.relative_path,
            entry.sha256,
            effect,
            None,
            None,
            None,
            None,
            (effect,),
            None,
            "legacy browse page is regenerated from canonical state",
        )
    if entry.category is SourceCategory.LEGACY_FOCUS:
        effects = {"_index/current-focus.md"}
        parts = PurePosixPath(entry.relative_path).parts
        if len(parts) == 3 and parts[0] == "projects":
            if project_id is None:
                raise ValidationError("invalid project focus path")
            effects.add("projects/{0}/current-focus.md".format(project_id))
        return MigrationAction(
            action_id,
            MigrationActionKind.FOCUS_PROPOSAL,
            entry.relative_path,
            entry.sha256,
            None,
            None,
            None,
            None,
            None,
            tuple(sorted(_projection_path(item) for item in effects)),
            UnresolvedClassification.LEGACY_FOCUS_INPUT,
            "legacy focus is review input and never a durable fact owner",
        )
    if entry.category is SourceCategory.EMBEDDED_KNOWLEDGE:
        return MigrationAction(
            action_id,
            MigrationActionKind.EMBEDDED_KNOWLEDGE_REVIEW,
            entry.relative_path,
            entry.sha256,
            None,
            None,
            None,
            None,
            None,
            (),
            UnresolvedClassification.EMBEDDED_KNOWLEDGE_EXTERNAL,
            "embedded knowledge requires a separate Knowledge Base decision",
        )
    return MigrationAction(
        action_id,
        MigrationActionKind.UNRESOLVED_PROPOSAL,
        entry.relative_path,
        entry.sha256,
        None,
        None,
        None,
        None,
        None,
        (),
        UnresolvedClassification.UNKNOWN_FORMAT,
        "legacy entry has no strict path-based owner classification",
    )


def _evidence_actions(
    detection: VaultDetection,
    snapshot: MigrationSnapshot,
    snapshot_sha256: str,
    created_at: str,
    project_id_mappings: Tuple[ProjectIdMapping, ...],
) -> Tuple[MigrationAction, ...]:
    base_digest = hashlib.sha256(
        ("snapshot.json\0" + snapshot_sha256).encode("utf-8")
    ).hexdigest()
    migration_id = "migr-" + base_digest[:24]
    values = [
        MigrationAction(
            "action-" + base_digest[:20],
            MigrationActionKind.RECORD,
            "snapshot.json",
            snapshot_sha256,
            _record_target(
                migration_id,
                "migration",
                "meta.migration",
                None,
                snapshot_sha256,
                created_at,
            ),
            "migration",
            "meta.migration",
            None,
            migration_id,
            _record_effects("migration", None, migration_id),
            None,
            "snapshot manifest owns migration provenance only",
        )
    ]
    for source_project_id in _detected_project_ids(detection):
        project_id = _effective_project_id(source_project_id, project_id_mappings)
        if project_id is None:
            continue
        digest = hashlib.sha256(
            ("snapshot.json\0" + snapshot_sha256 + "\0" + project_id).encode("utf-8")
        ).hexdigest()
        memory_id = "migr-session-" + project_id + "-" + digest[:12]
        values.append(
            MigrationAction(
                "action-" + digest[:20],
                MigrationActionKind.RECORD,
                "snapshot.json",
                snapshot_sha256,
                _record_target(
                    memory_id,
                    "session",
                    "project.{0}.session".format(project_id),
                    project_id,
                    snapshot_sha256,
                    created_at,
                ),
                "session",
                "project.{0}.session".format(project_id),
                project_id,
                memory_id,
                _record_effects("session", project_id, memory_id),
                None,
                "snapshot manifest supplies project migration chronology",
            )
        )
    return tuple(values)


def _build_plan(
    detection: VaultDetection,
    snapshot: MigrationSnapshot,
    actor: str,
    created_at: str,
    authorization_ref: Optional[str],
    bundle_dir: Path,
    snapshot_sha256: str,
    project_id_map: ProjectIdMapInput = None,
) -> MigrationPlan:
    project_id_mappings = _normalize_project_id_mappings(detection, project_id_map)
    ambiguous = _ambiguous_owner_paths(snapshot, bundle_dir, detection)
    actions = [
        _entry_action(entry, ambiguous, project_id_mappings, created_at)
        for entry in detection.entries
    ]
    detected_source_path_keys = {
        entry.relative_path.casefold() for entry in detection.entries
    }
    if any(
        action.kind is MigrationActionKind.RAW_SOURCE
        and action.target_path is not None
        and action.target_path.casefold() != action.source_path.casefold()
        and action.target_path.casefold() in detected_source_path_keys
        for action in actions
    ):
        raise ValidationError("raw source target is occupied by a different source")
    actions.extend(
        _evidence_actions(
            detection,
            snapshot,
            snapshot_sha256,
            created_at,
            project_id_mappings,
        )
    )
    findings = list(detection.findings)
    for project_id in _detected_project_ids(detection):
        if _effective_project_id(project_id, project_id_mappings) is not None:
            continue
        findings.append(
            Finding(
                "legacy-project-id-mapping-required",
                "warning",
                "projects/{0}".format(project_id),
                "legacy project identifier requires an explicit reviewed mapping",
            )
        )
    for path in sorted(ambiguous):
        findings.append(
            Finding(
                "ambiguous-owner",
                "warning",
                path,
                "repeated legacy fact appears beneath competing owner paths",
            )
        )
    return MigrationPlan(
        snapshot.snapshot_id,
        1,
        2,
        detection.source_revision,
        actor,
        created_at,
        authorization_ref,
        project_id_mappings,
        tuple(sorted(actions, key=lambda value: (value.source_path, value.kind.value, value.action_id))),
        tuple(
            sorted(
                findings,
                key=lambda value: (value.severity, value.code, value.path, value.message),
            )
        ),
    )


def _overlaps(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _validate_context(context: TransactionContext) -> None:
    if not isinstance(context, TransactionContext):
        raise ValidationError("invalid transaction context")
    validate_identifier(context.transaction_id, "transaction_id")
    validate_identifier(context.actor, "actor")
    _validate_timestamp(context.occurred_at, "occurred_at")


def plan_v1_to_v2(
    root: Path,
    work_dir: Path,
    context: TransactionContext,
    gate: AuthorizationGate,
    project_id_map: ProjectIdMapInput = None,
) -> MigrationBundle:
    _validate_context(context)
    selected_root = require_operation_gate(root, gate, "migration-plan")
    resolved_work = Path(work_dir).resolve(strict=False)
    bundle_dir = (resolved_work / context.transaction_id).resolve(strict=False)
    if _overlaps(resolved_work, selected_root) or _overlaps(bundle_dir, selected_root):
        raise ValidationError("migration bundle must be outside source root")
    if bundle_dir.exists():
        raise ValidationError("migration bundle already exists")
    if resolved_work.exists() and not resolved_work.is_dir():
        raise ValidationError("migration work directory must be a directory")

    detection = _detect_vault_gated(selected_root, Path(root))
    if detection.generation is not VaultGeneration.V1:
        raise ValidationError("source vault is not an unmigrated v1 root")
    project_id_mappings = _normalize_project_id_mappings(detection, project_id_map)
    resolved_work.mkdir(parents=True, exist_ok=True)
    bundle_dir.mkdir(exist_ok=False)
    try:
        snapshot_entries = []
        for entry in detection.entries:
            snapshot_path = "snapshot/files/" + entry.relative_path
            _portable_relative(snapshot_path, "snapshot path")
            _copy_snapshot_file(
                selected_root.joinpath(*PurePosixPath(entry.relative_path).parts),
                bundle_dir.joinpath(*PurePosixPath(snapshot_path).parts),
                entry,
            )
            snapshot_entries.append(
                SnapshotEntry(
                    entry.relative_path,
                    entry.sha256,
                    entry.size,
                    snapshot_path,
                )
            )
        snapshot = MigrationSnapshot(
            context.transaction_id,
            detection.source_revision,
            tuple(snapshot_entries),
        )
        _write_exclusive(bundle_dir / "detection.json", _json_bytes(_detection_dict(detection)))
        snapshot_bytes = _json_bytes(_snapshot_dict(snapshot))
        _write_exclusive(bundle_dir / "snapshot.json", snapshot_bytes)
        snapshot_sha256 = hashlib.sha256(snapshot_bytes).hexdigest()
        plan = _build_plan(
            detection,
            snapshot,
            context.actor,
            context.occurred_at,
            gate.authorization_ref,
            bundle_dir,
            snapshot_sha256,
            project_id_mappings,
        )
        _write_exclusive(bundle_dir / "plan.json", _json_bytes(_plan_dict(plan)))
        return load_migration_bundle(bundle_dir)
    except BaseException:
        if bundle_dir.exists():
            shutil.rmtree(bundle_dir)
        raise


@dataclass(frozen=True)
class _BundleFile:
    sha256: str
    size: int
    path: Path


def _bundle_inventory(root: Path) -> Dict[str, _BundleFile]:
    selected = root.resolve(strict=True)
    _validate_selected_path(root, selected)
    values = {}
    stack = [(selected, "")]
    while stack:
        directory, prefix = stack.pop()
        try:
            with os.scandir(directory) as stream:
                children = sorted(stream, key=lambda item: item.name, reverse=True)
        except OSError as error:
            raise ValidationError("invalid migration bundle inventory") from error
        for child in children:
            relative = child.name if not prefix else prefix + "/" + child.name
            metadata = _lstat(child.path)
            _require_safe(metadata, relative)
            path = Path(child.path)
            if stat.S_ISDIR(metadata.st_mode):
                stack.append((path, relative))
            else:
                digest, size, _ = _hash_regular_file(path, metadata)
                values[relative] = _BundleFile(digest, size, path)
    return values


def _strict_json(bundle_path: _BundleFile, name: str):
    if bundle_path.size > _JSON_SIZE_LIMIT:
        raise ValidationError("invalid {0}".format(name))
    try:
        raw = bundle_path.path.read_bytes()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValidationError("invalid {0}".format(name)) from error
    if _json_bytes(value) != raw:
        raise ValidationError("invalid canonical {0}".format(name))
    return value


def _strict_json_bytes(raw: bytes, name: str):
    if not isinstance(raw, bytes) or len(raw) > _JSON_SIZE_LIMIT:
        raise ValidationError("invalid {0}".format(name))
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValidationError("invalid {0}".format(name)) from error
    if _json_bytes(value) != raw:
        raise ValidationError("invalid canonical {0}".format(name))
    return value


def _exact_dict(value, keys, name):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValidationError("invalid {0}".format(name))
    return value


def _parse_finding(value) -> Finding:
    _exact_dict(value, ("code", "message", "path", "severity"), "finding")
    if value["severity"] not in ("error", "warning"):
        raise ValidationError("invalid finding")
    for key in ("code", "message", "path"):
        if not isinstance(value[key], str):
            raise ValidationError("invalid finding")
    return Finding(value["code"], value["severity"], value["path"], value["message"])


def _parse_detection(value) -> VaultDetection:
    _exact_dict(
        value,
        ("entries", "findings", "generation", "schema_version", "source_revision"),
        "detection",
    )
    if value["schema_version"] != 1 or not isinstance(value["entries"], list):
        raise ValidationError("invalid detection")
    try:
        generation = VaultGeneration(value["generation"])
        entries = tuple(
            SourceEntry(
                _exact_dict(
                    item,
                    ("category", "relative_path", "sha256", "size"),
                    "source entry",
                )["relative_path"],
                item["sha256"],
                item["size"],
                SourceCategory(item["category"]),
            )
            for item in value["entries"]
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValidationError("invalid detection") from error
    if not isinstance(value["findings"], list):
        raise ValidationError("invalid detection")
    findings = tuple(_parse_finding(item) for item in value["findings"])
    detection = VaultDetection(generation, value["source_revision"], entries, findings)
    if (
        entries != tuple(sorted(entries, key=lambda item: item.relative_path))
        or detection.source_revision != _source_revision(entries)
    ):
        raise ValidationError("invalid detection")
    for entry in entries:
        _portable_relative(entry.relative_path, "source path")
        if (
            not isinstance(entry.sha256, str)
            or len(entry.sha256) != 64
            or any(character not in "0123456789abcdef" for character in entry.sha256)
            or type(entry.size) is not int
            or entry.size < 0
        ):
            raise ValidationError("invalid source entry")
    return detection


def _parse_snapshot(value) -> MigrationSnapshot:
    _exact_dict(
        value,
        ("entries", "schema_version", "snapshot_id", "source_revision"),
        "snapshot",
    )
    if value["schema_version"] != 1 or not isinstance(value["entries"], list):
        raise ValidationError("invalid snapshot")
    validate_identifier(value["snapshot_id"], "snapshot_id")
    entries = []
    for item in value["entries"]:
        _exact_dict(
            item,
            ("relative_path", "sha256", "size", "snapshot_path"),
            "snapshot entry",
        )
        relative = _portable_relative(item["relative_path"], "snapshot source path")
        snapshot_path = _portable_relative(item["snapshot_path"], "snapshot path")
        if snapshot_path != "snapshot/files/" + relative:
            raise ValidationError("invalid snapshot entry")
        entries.append(SnapshotEntry(relative, item["sha256"], item["size"], snapshot_path))
    result = MigrationSnapshot(value["snapshot_id"], value["source_revision"], tuple(entries))
    if result.entries != tuple(sorted(result.entries, key=lambda item: item.relative_path)):
        raise ValidationError("invalid snapshot")
    return result


def _parse_action(value) -> MigrationAction:
    _exact_dict(
        value,
        (
            "action_id",
            "kind",
            "memory_id",
            "owner_scope",
            "project_id",
            "projection_effects",
            "reason",
            "record_type",
            "source_path",
            "source_sha256",
            "target_path",
            "unresolved_classification",
        ),
        "migration action",
    )
    try:
        kind = MigrationActionKind(value["kind"])
        unresolved = (
            UnresolvedClassification(value["unresolved_classification"])
            if value["unresolved_classification"] is not None
            else None
        )
    except ValueError as error:
        raise ValidationError("invalid migration action") from error
    if not isinstance(value["projection_effects"], list):
        raise ValidationError("invalid migration action")
    effects = tuple(_projection_path(item) for item in value["projection_effects"])
    if effects != tuple(sorted(set(effects))):
        raise ValidationError("invalid migration action")
    _portable_relative(value["source_path"], "action source path")
    if value["target_path"] is not None:
        _portable_relative(value["target_path"], "action target path")
    return MigrationAction(
        value["action_id"],
        kind,
        value["source_path"],
        value["source_sha256"],
        value["target_path"],
        value["record_type"],
        value["owner_scope"],
        value["project_id"],
        value["memory_id"],
        effects,
        unresolved,
        value["reason"],
    )


def _parse_project_id_mapping(value) -> ProjectIdMapping:
    _exact_dict(
        value,
        ("source_project_id", "target_project_id"),
        "project id mapping",
    )
    if not isinstance(value["source_project_id"], str) or not isinstance(
        value["target_project_id"], str
    ):
        raise ValidationError("invalid project id mapping")
    return ProjectIdMapping(
        value["source_project_id"],
        value["target_project_id"],
    )


def _parse_plan(value) -> MigrationPlan:
    common_keys = (
        "actions",
        "actor",
        "authorization_ref",
        "created_at",
        "findings",
        "from_schema",
        "plan_id",
        "schema_version",
        "source_revision",
        "to_schema",
    )
    if not isinstance(value, dict):
        raise ValidationError("invalid plan")
    schema_version = value.get("schema_version")
    if schema_version == 1:
        _exact_dict(value, common_keys, "plan")
        project_id_mappings = ()
    elif schema_version == 2:
        _exact_dict(value, common_keys + ("project_id_mappings",), "plan")
        if not isinstance(value["project_id_mappings"], list):
            raise ValidationError("invalid plan")
        project_id_mappings = tuple(
            _parse_project_id_mapping(item)
            for item in value["project_id_mappings"]
        )
    else:
        raise ValidationError("invalid plan")
    if (
        value["from_schema"] != 1
        or value["to_schema"] != 2
        or not isinstance(value["actions"], list)
        or not isinstance(value["findings"], list)
    ):
        raise ValidationError("invalid plan")
    validate_identifier(value["plan_id"], "plan_id")
    validate_identifier(value["actor"], "actor")
    _validate_timestamp(value["created_at"], "created_at")
    if value["authorization_ref"] is not None and not isinstance(
        value["authorization_ref"], str
    ):
        raise ValidationError("invalid plan")
    return MigrationPlan(
        value["plan_id"],
        1,
        2,
        value["source_revision"],
        value["actor"],
        value["created_at"],
        value["authorization_ref"],
        project_id_mappings,
        tuple(_parse_action(item) for item in value["actions"]),
        tuple(_parse_finding(item) for item in value["findings"]),
    )


def _bundle_digest(files: Dict[str, _BundleFile]) -> str:
    payload = [
        {"path": path, "sha256": item.sha256, "size": item.size}
        for path, item in sorted(files.items())
    ]
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _load_migration_bundle_from_bytes(
    bundle_dir: Path,
    captured_files: Mapping[str, bytes],
) -> MigrationBundle:
    """Validate one already captured complete bundle without further path reads."""
    files = {
        path: _BundleFile(hashlib.sha256(raw).hexdigest(), len(raw), Path(bundle_dir) / path)
        for path, raw in captured_files.items()
    }
    controls = {"detection.json", "snapshot.json", "plan.json"}
    if not controls.issubset(files):
        raise ValidationError("migration bundle inventory is incomplete")
    detection = _parse_detection(_strict_json_bytes(captured_files["detection.json"], "detection"))
    snapshot = _parse_snapshot(_strict_json_bytes(captured_files["snapshot.json"], "snapshot"))
    plan = _parse_plan(_strict_json_bytes(captured_files["plan.json"], "plan"))
    expected_paths = controls | {entry.snapshot_path for entry in snapshot.entries}
    if set(files) != expected_paths:
        raise ValidationError("migration bundle inventory has extra or missing entries")
    if (
        detection.source_revision != snapshot.source_revision
        or snapshot.source_revision != plan.source_revision
        or snapshot.snapshot_id != plan.plan_id
        or tuple((item.relative_path, item.sha256, item.size) for item in snapshot.entries)
        != tuple((item.relative_path, item.sha256, item.size) for item in detection.entries)
    ):
        raise ValidationError("migration bundle manifests disagree")
    for entry in snapshot.entries:
        file = files[entry.snapshot_path]
        if file.sha256 != entry.sha256 or file.size != entry.size:
            raise ValidationError("migration snapshot bytes disagree")
    expected_plan = _build_plan(
        detection,
        snapshot,
        plan.actor,
        plan.created_at,
        plan.authorization_ref,
        Path(bundle_dir),
        files["snapshot.json"].sha256,
        plan.project_id_mappings,
    )
    if plan != expected_plan:
        raise ValidationError("migration plan semantics disagree")
    return MigrationBundle(Path(bundle_dir), detection, snapshot, plan, _bundle_digest(files))


def load_migration_bundle(path: Path) -> MigrationBundle:
    try:
        bundle_dir = Path(path).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValidationError("migration bundle does not exist") from error
    files = _bundle_inventory(Path(path))
    captured = {relative: item.path.read_bytes() for relative, item in files.items()}
    return _load_migration_bundle_from_bytes(bundle_dir, captured)


_GENERATOR_VERSION = "2.0.0"
_LOWER_HASH = frozenset("0123456789abcdef")
_MIGRATION_JOURNAL = "journal.json"
_ROLLBACK_MANIFEST = "rollback/manifest.json"


def _migration_checkpoint(
    stage: str,
    live_root: Path,
    stage_root: Path,
    bundle: MigrationBundle,
) -> None:
    """Private deterministic hook for staging/activation crash controls."""


def _valid_hash(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in _LOWER_HASH for character in value)
    )


def _require_reviewed_digest(value: object) -> str:
    if not _valid_hash(value):
        raise PlanInvalidatedError("reviewed migration bundle changed")
    return value


def _require_bundle(value: object) -> MigrationBundle:
    if not isinstance(value, MigrationBundle):
        raise ValidationError("invalid migration bundle")
    return load_migration_bundle(value.bundle_dir)


def _child_context(
    parent: TransactionContext,
    step: str,
    identity: str,
) -> TransactionContext:
    material = "{0}\0{1}\0{2}".format(parent.transaction_id, step, identity)
    suffix = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
    return TransactionContext(
        "migration-child-" + suffix,
        parent.actor,
        parent.occurred_at,
    )


def _snapshot_files(bundle: MigrationBundle) -> Dict[str, Path]:
    return {
        entry.relative_path: bundle.bundle_dir.joinpath(
            *PurePosixPath(entry.snapshot_path).parts
        )
        for entry in bundle.snapshot.entries
    }


def _snapshot_entry_map(bundle: MigrationBundle) -> Dict[str, SnapshotEntry]:
    return {entry.relative_path: entry for entry in bundle.snapshot.entries}


def _read_snapshot_text(bundle: MigrationBundle, relative_path: str) -> str:
    path = _snapshot_files(bundle)[relative_path]
    try:
        return path.read_bytes().decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError("legacy record source must be UTF-8 text") from error


def _migration_record_body(
    bundle: MigrationBundle,
    accepted_ids: Tuple[str, ...],
    proposal_paths: Tuple[str, ...],
    projection_paths: Tuple[str, ...],
) -> str:
    snapshot_hash = hashlib.sha256(
        (bundle.bundle_dir / "snapshot.json").read_bytes()
    ).hexdigest()
    return normalize_body(
        "# Migration: {0}\n\n"
        "## Source Snapshot\n"
        "- Source revision: `{1}`\n"
        "- Snapshot manifest SHA-256: `{2}`\n\n"
        "## Reviewed Plan\n"
        "- Plan ID: `{0}`\n"
        "- Bundle SHA-256: `{3}`\n\n"
        "## Applied Changes\n"
        "- Accepted record IDs: {4}\n\n"
        "## Verification\n"
        "- Projection paths: {5}\n\n"
        "## Unresolved Proposals\n"
        "- Proposal paths: {6}\n".format(
            bundle.plan.plan_id,
            bundle.plan.source_revision,
            snapshot_hash,
            bundle.bundle_sha256,
            ", ".join("`{0}`".format(item) for item in accepted_ids) or "none",
            ", ".join("`{0}`".format(item) for item in projection_paths) or "none",
            ", ".join("`{0}`".format(item) for item in proposal_paths) or "none",
        )
    )


def _chronology_record_body(
    bundle: MigrationBundle,
    action: MigrationAction,
    migration_memory_id: str,
) -> str:
    return normalize_body(
        "# Session: Vault migration for {0}\n\n"
        "## User Goal\n"
        "Apply reviewed vault migration plan `{1}`.\n\n"
        "## Work Done\n"
        "Migrated reviewed snapshot `{2}`.\n\n"
        "## Decisions Observed\n"
        "Migration record: `{3}`.\n\n"
        "## Durable Facts Observed\n"
        "Chronology only; canonical facts remain in their accepted record IDs.\n\n"
        "## Commands Verified\n"
        "`apply_migration`\n\n"
        "## Files Changed\n"
        "See migration record `{3}`.\n\n"
        "## Promotion Candidates\n"
        "None.\n\n"
        "## Follow-Ups\n"
        "Run deterministic migration verification.\n".format(
            action.project_id,
            bundle.plan.plan_id,
            bundle.snapshot.snapshot_id,
            migration_memory_id,
        )
    )


def _legacy_record_body(bundle: MigrationBundle, action: MigrationAction) -> str:
    legacy = normalize_body(_read_snapshot_text(bundle, action.source_path))
    return normalize_body(
        legacy
        + "\n## Migration Evidence\n"
        + "- Source path: `{0}`\n".format(action.source_path)
        + "- Source SHA-256: `{0}`\n".format(action.source_sha256)
        + "- Reviewed plan: `{0}`\n".format(bundle.plan.plan_id)
    )


def _record_candidate(
    bundle: MigrationBundle,
    action: MigrationAction,
    body: str,
    observed_at: str,
) -> RecordCandidate:
    if (
        action.memory_id is None
        or action.record_type is None
        or action.owner_scope is None
        or action.target_path is None
    ):
        raise ValidationError("migration record action is incomplete")
    envelope = RecordEnvelope(
        action.memory_id,
        action.record_type,
        2,
        action.owner_scope,
        action.project_id,
        1,
        None,
        bundle.plan.created_at,
        observed_at,
        "migration-snapshot",
        action.source_sha256,
        compute_body_sha256(body),
    )
    if record_relative_path(envelope).as_posix() != action.target_path:
        raise ValidationError("migration record target disagrees with reviewed plan")
    return RecordCandidate(envelope, body)


def _publish_json(path: Path, value: Mapping[str, object], token: str, root: Path) -> None:
    _transactions._publish_exclusive(
        path,
        _transactions._json_bytes(value),
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
        root=root,
    )


def _ensure_focus_file(
    stage_root: Path,
    project_id: str,
    context: TransactionContext,
) -> None:
    target = stage_root / ".agent-memory" / "state" / "focus" / (project_id + ".json")
    if target.exists():
        return
    value = {
        "observed_at": context.occurred_at,
        "project_id": project_id,
        "record_ids": [],
        "revision": 0,
        "schema_version": 2,
    }
    _publish_json(target, value, context.transaction_id + "\0focus-init", stage_root)


def _proposal_document(
    bundle: MigrationBundle,
    action: MigrationAction,
    context: TransactionContext,
) -> Mapping[str, object]:
    return {
        "actor": context.actor,
        "desired": {
            "action_id": action.action_id,
            "classification": (
                action.unresolved_classification.value
                if action.unresolved_classification is not None
                else None
            ),
            "source_path": action.source_path,
            "source_sha256": action.source_sha256,
        },
        "expected_base": {"source_revision": bundle.plan.source_revision},
        "occurred_at": context.occurred_at,
        "operation": "migration-review-proposal",
        "schema_version": 2,
        "status": "proposed",
        "target": action.source_path,
        "transaction_id": action.action_id,
    }


def _stage_projection_paths(bundle: MigrationBundle) -> Tuple[str, ...]:
    return tuple(
        sorted(
            {
                effect
                for action in bundle.plan.actions
                for effect in action.projection_effects
            }
        )
    )


def _build_staging_root(
    stage_root: Path,
    bundle: MigrationBundle,
    context: TransactionContext,
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    projects = tuple(
        sorted(
            {
                action.project_id
                for action in bundle.plan.actions
                if action.project_id is not None
            }
        )
    )
    initialization_project = projects[0] if projects else None
    _transactions.initialize_memory_root(
        stage_root,
        initialization_project,
        _child_context(context, "initialize", bundle.plan.plan_id),
    )
    for project_id in projects:
        _ensure_focus_file(stage_root, project_id, context)

    snapshots = _snapshot_files(bundle)
    for action in bundle.plan.actions:
        if action.kind is MigrationActionKind.PRESERVE and action.source_path in snapshots:
            target = stage_root.joinpath(*PurePosixPath(action.target_path).parts)
            expected = target.read_bytes() if target.exists() else None
            content = snapshots[action.source_path].read_bytes()
            token = hashlib.sha256(
                (context.transaction_id + "\0preserve\0" + action.source_path).encode("utf-8")
            ).hexdigest()
            if expected is None:
                _transactions._publish_exclusive(target, content, token, root=stage_root)
            elif expected != content:
                _transactions._replace_cas(target, expected, content, token, root=stage_root)
        elif action.kind is MigrationActionKind.RAW_SOURCE:
            target = stage_root.joinpath(*PurePosixPath(action.target_path).parts)
            _transactions._publish_exclusive(
                target,
                snapshots[action.source_path].read_bytes(),
                hashlib.sha256(
                    (context.transaction_id + "\0raw\0" + action.source_path).encode("utf-8")
                ).hexdigest(),
                root=stage_root,
            )

    proposal_paths = []
    proposal_kinds = {
        MigrationActionKind.FOCUS_PROPOSAL,
        MigrationActionKind.EMBEDDED_KNOWLEDGE_REVIEW,
        MigrationActionKind.UNRESOLVED_PROPOSAL,
    }
    for action in bundle.plan.actions:
        if action.kind not in proposal_kinds:
            continue
        relative = ".agent-memory/state/proposals/{0}.json".format(action.action_id)
        target = stage_root.joinpath(*PurePosixPath(relative).parts)
        _publish_json(
            target,
            _proposal_document(bundle, action, context),
            context.transaction_id + "\0proposal\0" + action.action_id,
            stage_root,
        )
        proposal_paths.append(relative)

    record_actions = tuple(
        action
        for action in bundle.plan.actions
        if action.kind is MigrationActionKind.RECORD
    )
    migration_action = next(
        action
        for action in record_actions
        if action.source_path == "snapshot.json" and action.record_type == "migration"
    )
    accepted_ids = tuple(
        sorted(action.memory_id for action in record_actions if action.memory_id is not None)
    )
    projections = _stage_projection_paths(bundle)
    catalog_revision = 0
    for action in record_actions:
        if action.source_path != "snapshot.json":
            body = _legacy_record_body(bundle, action)
        elif action.record_type == "migration":
            body = _migration_record_body(
                bundle,
                accepted_ids,
                tuple(sorted(proposal_paths)),
                projections,
            )
        else:
            body = _chronology_record_body(
                bundle,
                action,
                migration_action.memory_id,
            )
        outcome = _transactions._commit_record(
            stage_root,
            _record_candidate(bundle, action, body, context.occurred_at),
            catalog_revision,
            None,
            _child_context(context, "record", action.action_id),
            allow_legacy_migration_session=True,
        )
        catalog_revision = outcome.catalog_revision
        if outcome.status != "accepted":
            if outcome.proposal_path is not None:
                proposal_paths.append(outcome.proposal_path.relative_to(stage_root).as_posix())
            return tuple(sorted(proposal_paths)), ()

    for project_id in projects:
        selected = tuple(
            sorted(
                action.memory_id
                for action in record_actions
                if action.project_id == project_id and action.memory_id is not None
            )
        )
        outcome = _transactions.update_focus(
            stage_root,
            project_id,
            0,
            selected,
            context.occurred_at,
            _child_context(context, "focus", project_id),
        )
        if outcome.status != "accepted":
            if outcome.proposal_path is not None:
                proposal_paths.append(outcome.proposal_path.relative_to(stage_root).as_posix())
            return tuple(sorted(proposal_paths)), ()

    documents = list(_projections.build_root_views(stage_root, _GENERATOR_VERSION))
    for project_id in projects:
        documents.extend(
            _projections.build_project_views(stage_root, project_id, _GENERATOR_VERSION)
        )
    documents = sorted(documents, key=lambda value: value.relative_path)
    for document in documents:
        _projections.publish_projection(
            stage_root,
            document,
            _child_context(context, "stage-projection", document.relative_path),
        )
    actual_projection_paths = tuple(document.relative_path for document in documents)
    if actual_projection_paths != projections:
        raise ValidationError("staged projection inventory disagrees with reviewed plan")
    return tuple(sorted(proposal_paths)), actual_projection_paths


def validate_migration_source(
    root: Path,
    bundle: MigrationBundle,
    gate: AuthorizationGate,
) -> VaultDetection:
    selected_root = require_operation_gate(root, gate, "migration-validate")
    loaded = _require_bundle(bundle)
    detection = _detect_vault_gated(selected_root, Path(root))
    if (
        detection.generation is not VaultGeneration.V1
        or detection.source_revision != loaded.plan.source_revision
    ):
        raise PlanInvalidatedError("migration source revision changed")
    return detection


def _safe_live_path(root: Path, relative_path: str) -> Path:
    relative = _portable_relative(relative_path, "migration endpoint path")
    target = root.joinpath(*PurePosixPath(relative).parts)
    try:
        target.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as error:
        raise ValidationError("migration endpoint escapes root") from error
    return target


def _regular_bytes(path: Path, label: str) -> Optional[bytes]:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    _require_safe(metadata, label)
    if not stat.S_ISREG(metadata.st_mode):
        raise ValidationError("unsafe filesystem entry: {0}".format(label))
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValidationError("cannot read migration endpoint") from error
    if len(raw) != metadata.st_size:
        raise ValidationError("migration endpoint changed during read")
    return raw


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_document(path: Path, label: str) -> Mapping[str, object]:
    raw = _regular_bytes(path, label)
    if raw is None or len(raw) > _JSON_SIZE_LIMIT:
        raise ValidationError("invalid {0}".format(label))
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValidationError("invalid {0}".format(label)) from error
    if not isinstance(value, dict) or _json_bytes(value) != raw:
        raise ValidationError("invalid canonical {0}".format(label))
    return value


def _mkdir_contained(root: Path, directory: Path) -> None:
    root = root.resolve(strict=True)
    try:
        relative = directory.resolve(strict=False).relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise ValidationError("migration directory escapes root") from error
    current = root
    for component in relative.parts:
        current = current / component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            current.mkdir()
            _transactions._fsync_directory(current.parent)
            continue
        _require_safe(metadata, current.relative_to(root).as_posix())
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValidationError("migration directory is occupied")


def _stage_files(stage_root: Path) -> Dict[str, Tuple[Path, str, int]]:
    values = {}
    for path in sorted(stage_root.rglob("*"), key=lambda item: item.relative_to(stage_root).as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(stage_root).as_posix()
        if relative == ".agent-memory-root-write.anchor" or relative.startswith(
            ".agent-memory/transactions/projections/"
        ):
            continue
        raw = path.read_bytes()
        values[relative] = (path, _sha256_bytes(raw), len(raw))
    return values


def _rollback_relative(transaction_id: str, source_path: str) -> str:
    return ".agent-memory/transactions/{0}/rollback/files/{1}".format(
        transaction_id,
        source_path,
    )


def _activation_actions(
    root: Path,
    stage_root: Path,
    bundle: MigrationBundle,
    transaction_id: str,
    projection_paths: Tuple[str, ...],
) -> Tuple[Mapping[str, object], ...]:
    snapshots = _snapshot_entry_map(bundle)
    stage_files = _stage_files(stage_root)
    projection_set = set(projection_paths)
    actions = []

    def before_bytes(relative: str) -> Optional[bytes]:
        raw = _regular_bytes(_safe_live_path(root, relative), relative)
        if raw is None:
            return None
        snapshot = snapshots.get(relative)
        if snapshot is None or _sha256_bytes(raw) != snapshot.sha256 or len(raw) != snapshot.size:
            raise PlanInvalidatedError("migration source revision changed")
        return raw

    for relative, (_, after_hash, _) in sorted(stage_files.items()):
        if relative in projection_set:
            continue
        prior = before_bytes(relative)
        if prior is not None and _sha256_bytes(prior) == after_hash:
            continue
        if prior is None:
            actions.append(
                {
                    "after_sha256": after_hash,
                    "before_sha256": None,
                    "completed": False,
                    "operation": "create",
                    "path": relative,
                    "rollback_path": None,
                }
            )
        else:
            actions.append(
                {
                    "after_sha256": after_hash,
                    "before_sha256": _sha256_bytes(prior),
                    "completed": False,
                    "operation": "replace",
                    "path": relative,
                    "rollback_path": _rollback_relative(transaction_id, relative),
                }
            )

    for relative in projection_paths:
        staged = stage_files.get(relative)
        if staged is None:
            raise ValidationError("staged projection is missing")
        prior = before_bytes(relative)
        actions.append(
            {
                "after_sha256": staged[1],
                "before_sha256": _sha256_bytes(prior) if prior is not None else None,
                "completed": False,
                "operation": "replace" if prior is not None else "create",
                "path": relative,
                "rollback_path": (
                    _rollback_relative(transaction_id, relative)
                    if prior is not None
                    else None
                ),
            }
        )

    mapping_limited_source_kinds = {
        MigrationActionKind.RAW_SOURCE,
        MigrationActionKind.REGENERATE_PROJECTION,
        MigrationActionKind.FOCUS_PROPOSAL,
    }
    mapped_source_project_ids = {
        mapping.source_project_id for mapping in bundle.plan.project_id_mappings
    }

    def is_mapped_project_source(action: MigrationAction) -> bool:
        parts = PurePosixPath(action.source_path).parts
        return (
            len(parts) >= 3
            and parts[0] == "projects"
            and parts[1] in mapped_source_project_ids
        )

    archive_paths = {
        action.source_path
        for action in bundle.plan.actions
        if action.source_path != "snapshot.json"
        and (
            action.kind is MigrationActionKind.RECORD
            or (
                action.kind in mapping_limited_source_kinds
                and is_mapped_project_source(action)
            )
        )
    }
    desired_paths = set(stage_files) | projection_set
    for relative in sorted(archive_paths - desired_paths):
        prior = before_bytes(relative)
        if prior is None:
            raise PlanInvalidatedError("migration source revision changed")
        actions.append(
            {
                "after_sha256": None,
                "before_sha256": _sha256_bytes(prior),
                "completed": False,
                "operation": "archive",
                "path": relative,
                "rollback_path": _rollback_relative(transaction_id, relative),
            }
        )
    return tuple(sorted(actions, key=lambda item: (item["path"], item["operation"])))


def _journal_path(root: Path, transaction_id: str) -> Path:
    validate_identifier(transaction_id, "apply_transaction_id")
    return root / ".agent-memory" / "transactions" / transaction_id / _MIGRATION_JOURNAL


def _result_dict(result: MigrationResult) -> Mapping[str, object]:
    return {
        "apply_authorization_ref": result.apply_authorization_ref,
        "archived_paths": list(result.archived_paths),
        "created_paths": list(result.created_paths),
        "plan_authorization_ref": result.plan_authorization_ref,
        "proposal_paths": list(result.proposal_paths),
        "replaced_paths": list(result.replaced_paths),
        "reviewed_bundle_sha256": result.reviewed_bundle_sha256,
        "rollback_authorization_ref": result.rollback_authorization_ref,
        "source_revision": result.source_revision,
        "status": result.status,
        "transaction_id": result.transaction_id,
    }


def _parse_result(value: object, status: Optional[str] = None) -> MigrationResult:
    keys = {
        "apply_authorization_ref",
        "archived_paths",
        "created_paths",
        "plan_authorization_ref",
        "proposal_paths",
        "replaced_paths",
        "reviewed_bundle_sha256",
        "rollback_authorization_ref",
        "source_revision",
        "status",
        "transaction_id",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ValidationError("invalid migration result")
    actual_status = status if status is not None else value["status"]
    if actual_status not in {"applied", "already-applied", "rolled-back", "proposed"}:
        raise ValidationError("invalid migration result")
    path_fields = ("created_paths", "replaced_paths", "archived_paths", "proposal_paths")
    for field in path_fields:
        values = value[field]
        if not isinstance(values, list) or values != sorted(set(values)):
            raise ValidationError("invalid migration result")
        for item in values:
            _portable_relative(item, "migration result path")
    if not _valid_hash(value["source_revision"]) or not _valid_hash(
        value["reviewed_bundle_sha256"]
    ):
        raise ValidationError("invalid migration result")
    validate_identifier(value["transaction_id"], "migration result transaction")
    for field in (
        "plan_authorization_ref",
        "apply_authorization_ref",
        "rollback_authorization_ref",
    ):
        if value[field] is not None and not isinstance(value[field], str):
            raise ValidationError("invalid migration result")
    return MigrationResult(
        actual_status,
        value["transaction_id"],
        value["source_revision"],
        value["reviewed_bundle_sha256"],
        value["plan_authorization_ref"],
        value["apply_authorization_ref"],
        value["rollback_authorization_ref"],
        tuple(value["created_paths"]),
        tuple(value["replaced_paths"]),
        tuple(value["archived_paths"]),
        tuple(value["proposal_paths"]),
    )


def _journal_document(
    bundle: MigrationBundle,
    context: TransactionContext,
    gate: AuthorizationGate,
    reviewed_digest: str,
    root_guard_sha256: str,
    actions: Tuple[Mapping[str, object], ...],
    proposal_paths: Tuple[str, ...],
    projection_paths: Tuple[str, ...],
    status: str,
    result: Optional[MigrationResult] = None,
) -> Mapping[str, object]:
    return {
        "actions": [dict(item) for item in actions],
        "actor": context.actor,
        "apply_authorization_ref": gate.authorization_ref,
        "apply_transaction_id": context.transaction_id,
        "created_at": context.occurred_at,
        "plan_authorization_ref": bundle.plan.authorization_ref,
        "plan_id": bundle.plan.plan_id,
        "projection_paths": list(projection_paths),
        "proposal_paths": list(proposal_paths),
        "result": _result_dict(result) if result is not None else None,
        "reviewed_bundle_sha256": reviewed_digest,
        "rollback_authorization_ref": (
            result.rollback_authorization_ref if result is not None else None
        ),
        "root_guard_sha256": root_guard_sha256,
        "schema_version": 1,
        "source_revision": bundle.plan.source_revision,
        "status": status,
    }


def _replace_json(
    path: Path,
    expected: Mapping[str, object],
    desired: Mapping[str, object],
    token: str,
    root: Path,
) -> None:
    _transactions._replace_cas(
        path,
        _json_bytes(expected),
        _json_bytes(desired),
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
        root=root,
    )


def _write_rollback_set(
    root: Path,
    journal_dir: Path,
    bundle: MigrationBundle,
    actions: Tuple[Mapping[str, object], ...],
    transaction_id: str,
) -> None:
    snapshots = _snapshot_files(bundle)
    entries = []
    for action in actions:
        rollback_path = action["rollback_path"]
        if rollback_path is None:
            continue
        source_path = action["path"]
        source = snapshots.get(source_path)
        if source is None:
            raise ValidationError("rollback source is absent from reviewed snapshot")
        content = source.read_bytes()
        if _sha256_bytes(content) != action["before_sha256"]:
            raise ValidationError("rollback source hash disagrees with journal")
        target = _safe_live_path(root, rollback_path)
        _transactions._publish_exclusive(
            target,
            content,
            hashlib.sha256(
                (transaction_id + "\0rollback\0" + source_path).encode("utf-8")
            ).hexdigest(),
            root=root,
        )
        entries.append(
            {
                "path": rollback_path,
                "sha256": action["before_sha256"],
                "size": len(content),
                "source_path": source_path,
            }
        )
    manifest = {
        "apply_transaction_id": transaction_id,
        "entries": entries,
        "schema_version": 1,
    }
    _publish_json(
        journal_dir / _ROLLBACK_MANIFEST,
        manifest,
        transaction_id + "\0rollback-manifest",
        root,
    )


def _classify_action(root: Path, action: Mapping[str, object]) -> str:
    raw = _regular_bytes(_safe_live_path(root, action["path"]), action["path"])
    observed = _sha256_bytes(raw) if raw is not None else None
    if observed == action["after_sha256"]:
        return "ran"
    if observed == action["before_sha256"]:
        return "not-run"
    return "ambiguous"


def _find_apply_journal(root: Path, plan_id: str) -> Optional[Tuple[Path, Mapping[str, object]]]:
    transaction_root = root / ".agent-memory" / "transactions"
    try:
        metadata = os.lstat(transaction_root)
    except FileNotFoundError:
        return None
    _require_safe(metadata, ".agent-memory/transactions")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValidationError("invalid migration transaction inventory")
    matches = []
    for child in sorted(transaction_root.iterdir(), key=lambda item: item.name):
        try:
            child_metadata = os.lstat(child)
        except OSError as error:
            raise ValidationError("invalid migration transaction inventory") from error
        if not stat.S_ISDIR(child_metadata.st_mode):
            continue
        _require_safe(child_metadata, child.relative_to(root).as_posix())
        journal = child / _MIGRATION_JOURNAL
        if not journal.exists():
            continue
        document = _canonical_document(journal, "migration journal")
        if document.get("plan_id") == plan_id:
            matches.append((journal, document))
    if len(matches) > 1:
        raise ConflictError("multiple migration journals select the reviewed plan")
    return matches[0] if matches else None


def _validate_journal_action(value: object) -> Mapping[str, object]:
    keys = {
        "after_sha256",
        "before_sha256",
        "completed",
        "operation",
        "path",
        "rollback_path",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ValidationError("invalid migration journal action")
    if value["operation"] not in {"create", "replace", "archive"}:
        raise ValidationError("invalid migration journal action")
    _portable_relative(value["path"], "migration journal path")
    if value["before_sha256"] is not None and not _valid_hash(value["before_sha256"]):
        raise ValidationError("invalid migration journal action")
    if value["after_sha256"] is not None and not _valid_hash(value["after_sha256"]):
        raise ValidationError("invalid migration journal action")
    if type(value["completed"]) is not bool:
        raise ValidationError("invalid migration journal action")
    expected = {
        "create": (None, True, False),
        "replace": (True, True, True),
        "archive": (True, None, True),
    }[value["operation"]]
    before_required, after_required, rollback_required = expected
    if before_required is None:
        before_valid = value["before_sha256"] is None
    else:
        before_valid = _valid_hash(value["before_sha256"])
    if after_required is None:
        after_valid = value["after_sha256"] is None
    else:
        after_valid = _valid_hash(value["after_sha256"])
    if rollback_required:
        if value["rollback_path"] is None:
            rollback_valid = False
        else:
            _portable_relative(value["rollback_path"], "rollback path")
            rollback_valid = True
    else:
        rollback_valid = value["rollback_path"] is None
    if not (before_valid and after_valid and rollback_valid):
        raise ValidationError("invalid migration journal action")
    return value


def _validate_journal(value: Mapping[str, object]) -> Mapping[str, object]:
    keys = {
        "actions",
        "actor",
        "apply_authorization_ref",
        "apply_transaction_id",
        "created_at",
        "plan_authorization_ref",
        "plan_id",
        "projection_paths",
        "proposal_paths",
        "result",
        "reviewed_bundle_sha256",
        "rollback_authorization_ref",
        "root_guard_sha256",
        "schema_version",
        "source_revision",
        "status",
    }
    if set(value) != keys or value["schema_version"] != 1:
        raise ValidationError("invalid migration journal")
    if value["status"] not in {
        "preparing",
        "prepared",
        "applying",
        "applied",
        "rollback-required",
        "rolled-back",
    }:
        raise ValidationError("invalid migration journal")
    for field in ("actor", "apply_transaction_id", "plan_id"):
        validate_identifier(value[field], "migration journal {0}".format(field))
    _validate_timestamp(value["created_at"], "migration journal created_at")
    for field in ("source_revision", "reviewed_bundle_sha256", "root_guard_sha256"):
        if not _valid_hash(value[field]):
            raise ValidationError("invalid migration journal")
    for field in (
        "plan_authorization_ref",
        "apply_authorization_ref",
        "rollback_authorization_ref",
    ):
        if value[field] is not None and not isinstance(value[field], str):
            raise ValidationError("invalid migration journal")
    if not isinstance(value["actions"], list):
        raise ValidationError("invalid migration journal")
    actions = tuple(_validate_journal_action(item) for item in value["actions"])
    if tuple((item["path"], item["operation"]) for item in actions) != tuple(
        sorted((item["path"], item["operation"]) for item in actions)
    ):
        raise ValidationError("invalid migration journal")
    for field in ("projection_paths", "proposal_paths"):
        values = value[field]
        if not isinstance(values, list) or values != sorted(set(values)):
            raise ValidationError("invalid migration journal")
        for item in values:
            _portable_relative(item, "migration journal path")
    if value["result"] is not None:
        _parse_result(value["result"])
    if value["status"] in {"applied", "rolled-back"} and value["result"] is None:
        raise ValidationError("invalid migration journal")
    return value


def _load_apply_journal(path: Path) -> Mapping[str, object]:
    return _validate_journal(_canonical_document(path, "migration journal"))


def index_applied_migration_proposals(
    root: Path,
) -> Mapping[str, Tuple[AppliedMigrationProposalBinding, ...]]:
    """Index exact completed create actions from canonical applied migration journals."""
    selected_root = Path(root).resolve(strict=True)
    transaction_root = selected_root / ".agent-memory" / "transactions"
    try:
        metadata = os.lstat(transaction_root)
    except FileNotFoundError:
        return {}
    _require_safe(metadata, ".agent-memory/transactions")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValidationError("invalid migration transaction inventory")

    indexed: Dict[str, List[AppliedMigrationProposalBinding]] = {}
    try:
        with os.scandir(transaction_root) as stream:
            children = []
            for entry in stream:
                children.append(Path(entry.path))
                if len(children) > _APPLIED_JOURNAL_INVENTORY_LIMIT:
                    raise ValidationError("migration transaction inventory exceeds limit")
    except OSError as error:
        raise ValidationError("invalid migration transaction inventory") from error
    for child in sorted(children, key=lambda item: item.name):
        try:
            child_metadata = os.lstat(child)
        except OSError as error:
            raise ValidationError("invalid migration transaction inventory") from error
        if not stat.S_ISDIR(child_metadata.st_mode):
            continue
        relative_child = child.relative_to(selected_root).as_posix()
        _require_safe(child_metadata, relative_child)
        journal_path = child / _MIGRATION_JOURNAL
        if not journal_path.exists():
            continue
        try:
            journal = _load_apply_journal(journal_path)
        except ValidationError:
            continue
        if (
            journal["status"] != "applied"
            or child.name != journal["apply_transaction_id"]
        ):
            continue
        journal_relative = journal_path.relative_to(selected_root).as_posix()
        journal_sha256 = _sha256_bytes(_json_bytes(journal))
        for proposal_path in journal["proposal_paths"]:
            matches = [
                action
                for action in journal["actions"]
                if action["path"] == proposal_path
                and action["operation"] == "create"
                and action["completed"] is True
                and action["after_sha256"] is not None
            ]
            if len(matches) != 1:
                continue
            binding = AppliedMigrationProposalBinding(
                proposal_path=proposal_path,
                proposal_after_sha256=matches[0]["after_sha256"],
                apply_transaction_id=journal["apply_transaction_id"],
                journal_path=journal_relative,
                journal_sha256=journal_sha256,
                plan_id=journal["plan_id"],
                reviewed_bundle_sha256=journal["reviewed_bundle_sha256"],
                source_revision=journal["source_revision"],
            )
            indexed.setdefault(proposal_path, []).append(binding)
    return {
        path: tuple(
            sorted(
                values,
                key=lambda item: (
                    item.proposal_path,
                    item.journal_path,
                    item.apply_transaction_id,
                ),
            )
        )
        for path, values in sorted(indexed.items())
    }


def _mark_completed(
    root: Path,
    journal_path: Path,
    journal: Mapping[str, object],
    path: str,
) -> Mapping[str, object]:
    desired = dict(journal)
    actions = []
    matched = False
    for action in journal["actions"]:
        item = dict(action)
        if item["path"] == path:
            item["completed"] = True
            matched = True
        actions.append(item)
    if not matched:
        raise ValidationError("migration journal action is absent")
    desired["actions"] = actions
    desired["status"] = "applying"
    _replace_json(
        journal_path,
        journal,
        desired,
        journal["apply_transaction_id"] + "\0complete\0" + path,
        root,
    )
    return desired


def _activate_regular_action(
    root: Path,
    stage_files: Dict[str, Tuple[Path, str, int]],
    action: Mapping[str, object],
    transaction_id: str,
) -> None:
    target = _safe_live_path(root, action["path"])
    operation = action["operation"]
    state = _classify_action(root, action)
    if state != "not-run":
        raise PlanInvalidatedError("migration activation endpoints changed")
    token = hashlib.sha256(
        (transaction_id + "\0activate\0" + action["path"]).encode("utf-8")
    ).hexdigest()
    if operation == "archive":
        target.unlink()
        _transactions._fsync_directory(target.parent)
        return
    staged = stage_files.get(action["path"])
    if staged is None:
        raise ValidationError("staged migration endpoint is absent")
    content = staged[0].read_bytes()
    if _sha256_bytes(content) != action["after_sha256"]:
        raise ValidationError("staged migration endpoint hash changed")
    if operation == "create":
        _transactions._publish_exclusive(target, content, token, root=root)
        return
    prior = _regular_bytes(target, action["path"])
    if prior is None or _sha256_bytes(prior) != action["before_sha256"]:
        raise PlanInvalidatedError("migration activation endpoints changed")
    _transactions._replace_cas(target, prior, content, token, root=root)


def _live_projection_documents(
    root: Path,
    bundle: MigrationBundle,
) -> Dict[str, object]:
    projects = tuple(
        sorted(
            {
                action.project_id
                for action in bundle.plan.actions
                if action.project_id is not None
            }
        )
    )
    documents = list(_projections.build_root_views(root, _GENERATOR_VERSION))
    for project_id in projects:
        documents.extend(_projections.build_project_views(root, project_id, _GENERATOR_VERSION))
    return {item.relative_path: item for item in documents}


def _result_for_actions(
    status: str,
    transaction_id: str,
    bundle: MigrationBundle,
    apply_authorization_ref: Optional[str],
    rollback_authorization_ref: Optional[str],
    actions: Tuple[Mapping[str, object], ...],
    proposal_paths: Tuple[str, ...],
) -> MigrationResult:
    return MigrationResult(
        status,
        transaction_id,
        bundle.plan.source_revision,
        bundle.bundle_sha256,
        bundle.plan.authorization_ref,
        apply_authorization_ref,
        rollback_authorization_ref,
        tuple(sorted(item["path"] for item in actions if item["operation"] == "create")),
        tuple(sorted(item["path"] for item in actions if item["operation"] == "replace")),
        tuple(sorted(item["path"] for item in actions if item["operation"] == "archive")),
        tuple(sorted(proposal_paths)),
    )


def _idempotent_result(
    root: Path,
    journal: Mapping[str, object],
    bundle: MigrationBundle,
    reviewed_digest: str,
) -> MigrationResult:
    if (
        journal["reviewed_bundle_sha256"] != reviewed_digest
        or journal["source_revision"] != bundle.plan.source_revision
        or journal["plan_id"] != bundle.plan.plan_id
    ):
        raise PlanInvalidatedError("reviewed migration bundle changed")
    if journal["status"] != "applied":
        raise ConflictError("migration journal requires rollback before re-apply")
    if any(_classify_action(root, item) != "ran" for item in journal["actions"]):
        raise PlanInvalidatedError("migration apply journal changed")
    result = _parse_result(journal["result"], status="already-applied")
    if result.reviewed_bundle_sha256 != reviewed_digest:
        raise PlanInvalidatedError("reviewed migration bundle changed")
    return result


def _ensure_migration_anchor(root: Path, context: TransactionContext) -> None:
    """Atomically bootstrap the Plan 1 namespace before guarding a legacy root."""
    anchor = root / ".agent-memory-root-write.anchor"
    expected = _transactions._ANCHOR_BYTES
    current = _regular_bytes(anchor, ".agent-memory-root-write.anchor")
    if current is not None:
        if current != expected:
            raise ConflictError("malformed root-write namespace anchor")
        return
    try:
        _transactions._publish_exclusive(
            anchor,
            expected,
            hashlib.sha256(
                (context.transaction_id + "\0migration-anchor").encode("utf-8")
            ).hexdigest(),
            root=root,
        )
    except ConflictError:
        current = _regular_bytes(anchor, ".agent-memory-root-write.anchor")
        if current != expected:
            raise


def _refuse_observed_root_guard(root: Path) -> None:
    canonical = root / _ROOT_GUARD
    if canonical.exists():
        raise LockBusyError("root-write-busy")
    try:
        candidates = tuple(root.glob(".agent-memory-root-write.candidate-*"))
    except OSError as error:
        raise ValidationError("unable to inspect root guard inventory") from error
    if candidates:
        raise LockBusyError("root-write-busy")


def apply_migration(
    root: Path,
    bundle: MigrationBundle,
    reviewed_bundle_sha256: str,
    context: TransactionContext,
    gate: AuthorizationGate,
) -> MigrationResult:
    selected_root = require_operation_gate(root, gate, "migration-apply")
    _validate_context(context)
    reviewed_digest = _require_reviewed_digest(reviewed_bundle_sha256)
    loaded = _require_bundle(bundle)
    if not hmac.compare_digest(loaded.bundle_sha256, reviewed_digest):
        raise PlanInvalidatedError("reviewed migration bundle changed")
    if gate.scope is OperationScope.REAL and (
        not isinstance(loaded.plan.authorization_ref, str)
        or not loaded.plan.authorization_ref.strip()
        or loaded.plan.authorization_ref == gate.authorization_ref
    ):
        raise ValidationError("real migration plan and apply authorizations must be distinct")
    existing = _find_apply_journal(selected_root, loaded.plan.plan_id)
    if existing is not None:
        return _idempotent_result(
            selected_root,
            _load_apply_journal(existing[0]),
            loaded,
            reviewed_digest,
        )
    _refuse_observed_root_guard(selected_root)
    detection = _detect_vault_gated(selected_root, Path(root))
    if (
        detection.generation is not VaultGeneration.V1
        or detection.source_revision != loaded.plan.source_revision
    ):
        raise PlanInvalidatedError("migration source revision changed")

    with tempfile.TemporaryDirectory(
        prefix=".migration-stage-",
        dir=str(loaded.bundle_dir.parent),
    ) as temporary:
        stage_root = Path(temporary).resolve(strict=True)
        if _overlaps(stage_root, selected_root) or _overlaps(stage_root, loaded.bundle_dir):
            raise ValidationError("migration staging directory overlaps protected input")
        proposal_paths, projection_paths = _build_staging_root(stage_root, loaded, context)
        if not projection_paths:
            return MigrationResult(
                "proposed",
                context.transaction_id,
                loaded.plan.source_revision,
                loaded.bundle_sha256,
                loaded.plan.authorization_ref,
                gate.authorization_ref,
                None,
                (),
                (),
                (),
                proposal_paths,
            )
        _migration_checkpoint("after-stage", selected_root, stage_root, loaded)
        stage_files = _stage_files(stage_root)
        _ensure_migration_anchor(selected_root, context)
        with _transactions.root_write_guard(selected_root, context) as guard:
            under_guard = _detect_vault_under_guard(
                selected_root,
                Path(root),
                context,
                guard,
            )
            if (
                under_guard.generation is not VaultGeneration.V1
                or under_guard.source_revision != loaded.plan.source_revision
            ):
                raise PlanInvalidatedError("migration source revision changed")
            reloaded = load_migration_bundle(loaded.bundle_dir)
            if not hmac.compare_digest(reloaded.bundle_sha256, reviewed_digest):
                raise PlanInvalidatedError("reviewed migration bundle changed")
            loaded = reloaded
            actions = _activation_actions(
                selected_root,
                stage_root,
                loaded,
                context.transaction_id,
                projection_paths,
            )
            journal_path = _journal_path(selected_root, context.transaction_id)
            journal_dir = journal_path.parent
            _mkdir_contained(selected_root, journal_dir)
            journal = _journal_document(
                loaded,
                context,
                gate,
                reviewed_digest,
                guard.token,
                actions,
                proposal_paths,
                projection_paths,
                "preparing",
            )
            _publish_json(
                journal_path,
                journal,
                context.transaction_id + "\0migration-journal",
                selected_root,
            )
            _write_rollback_set(
                selected_root,
                journal_dir,
                loaded,
                actions,
                context.transaction_id,
            )
            prepared = dict(journal)
            prepared["status"] = "prepared"
            _replace_json(
                journal_path,
                journal,
                prepared,
                context.transaction_id + "\0prepared",
                selected_root,
            )
            journal = prepared
            _migration_checkpoint("after-prepared", selected_root, stage_root, loaded)

            projection_set = set(projection_paths)
            try:
                for action in actions:
                    if action["path"] in projection_set:
                        continue
                    _migration_checkpoint("before-action", selected_root, stage_root, loaded)
                    _activate_regular_action(
                        selected_root,
                        stage_files,
                        action,
                        context.transaction_id,
                    )
                    _migration_checkpoint("after-endpoint", selected_root, stage_root, loaded)
                    journal = _mark_completed(
                        selected_root,
                        journal_path,
                        journal,
                        action["path"],
                    )
                    _migration_checkpoint("after-completed-marker", selected_root, stage_root, loaded)

                documents = _live_projection_documents(selected_root, loaded)
                if set(documents) != projection_set:
                    raise ValidationError("live projection inventory disagrees with reviewed plan")
                for action in actions:
                    if action["path"] not in projection_set:
                        continue
                    if _classify_action(selected_root, action) != "not-run":
                        raise PlanInvalidatedError("migration activation endpoints changed")
                    document = documents[action["path"]]
                    staged_content = stage_files[action["path"]][0].read_bytes()
                    if document.content.encode("utf-8") != staged_content:
                        raise PlanInvalidatedError("migration projection inputs changed")
                    if document.expected_target_sha256 != action["before_sha256"]:
                        raise PlanInvalidatedError("migration projection target changed")
                    _projections.publish_projection(
                        selected_root,
                        document,
                        context,
                        replace_drift=action["before_sha256"] is not None,
                        guard=guard,
                    )
                    if _classify_action(selected_root, action) != "ran":
                        raise PlanInvalidatedError("migration projection publication changed")
                    journal = _mark_completed(
                        selected_root,
                        journal_path,
                        journal,
                        action["path"],
                    )
            except BaseException:
                failed = dict(journal)
                failed["status"] = "rollback-required"
                try:
                    _replace_json(
                        journal_path,
                        journal,
                        failed,
                        context.transaction_id + "\0rollback-required",
                        selected_root,
                    )
                except BaseException:
                    pass
                raise

            if any(_classify_action(selected_root, item) != "ran" for item in actions):
                raise PlanInvalidatedError("migration activation endpoints changed")
            result = _result_for_actions(
                "applied",
                context.transaction_id,
                loaded,
                gate.authorization_ref,
                None,
                actions,
                proposal_paths,
            )
            applied = dict(journal)
            applied["status"] = "applied"
            applied["result"] = _result_dict(result)
            _replace_json(
                journal_path,
                journal,
                applied,
                context.transaction_id + "\0applied",
                selected_root,
            )
            return result


def _verification_finding(code: str, path: str, message: str) -> Finding:
    return Finding(code, "error", path, message)


def verify_migration(
    root: Path,
    bundle: MigrationBundle,
    gate: AuthorizationGate,
) -> MigrationVerification:
    selected_root = require_operation_gate(root, gate, "migration-verify")
    loaded = _require_bundle(bundle)
    findings = []
    projection_paths = _stage_projection_paths(loaded)
    selected = _find_apply_journal(selected_root, loaded.plan.plan_id)
    if selected is None:
        findings.append(
            _verification_finding(
                "migration-journal-missing",
                ".agent-memory/transactions",
                "accepted migration journal is missing",
            )
        )
        return MigrationVerification(
            False,
            loaded.plan.source_revision,
            loaded.bundle_sha256,
            projection_paths,
            tuple(findings),
        )
    journal_path, _ = selected
    journal = _load_apply_journal(journal_path)
    if (
        journal["status"] != "applied"
        or journal["plan_id"] != loaded.plan.plan_id
        or journal["source_revision"] != loaded.plan.source_revision
        or journal["reviewed_bundle_sha256"] != loaded.bundle_sha256
    ):
        findings.append(
            _verification_finding(
                "migration-journal-mismatch",
                journal_path.relative_to(selected_root).as_posix(),
                "migration journal does not select the reviewed applied bundle",
            )
        )
    for action in journal["actions"]:
        if _classify_action(selected_root, action) != "ran":
            findings.append(
                _verification_finding(
                    "migration-endpoint-mismatch",
                    action["path"],
                    "migration endpoint does not match the journaled applied hash",
                )
            )

    try:
        catalog = load_catalog(selected_root)
    except ValidationError:
        catalog = None
        findings.append(
            _verification_finding(
                "migration-catalog-invalid",
                ".agent-memory/state/catalog.json",
                "accepted-record catalog is invalid after migration",
            )
        )
    if catalog is not None:
        expected_ids = {
            action.memory_id
            for action in loaded.plan.actions
            if action.kind is MigrationActionKind.RECORD and action.memory_id is not None
        }
        observed_ids = {entry.memory_id for entry in catalog.entries}
        for memory_id in sorted(expected_ids - observed_ids):
            findings.append(
                _verification_finding(
                    "migration-record-missing",
                    ".agent-memory/state/catalog.json",
                    "reviewed migration record is not selected: {0}".format(memory_id),
                )
            )

    snapshots = _snapshot_files(loaded)
    for action in loaded.plan.actions:
        if action.kind is MigrationActionKind.PRESERVE:
            preserved = _regular_bytes(
                _safe_live_path(selected_root, action.target_path),
                action.target_path,
            )
            expected = snapshots[action.source_path].read_bytes()
            if preserved != expected:
                findings.append(
                    _verification_finding(
                        "migration-preservation-drift",
                        action.target_path,
                        "preserved migration evidence differs from the reviewed snapshot",
                    )
                )
            continue
        if action.kind is not MigrationActionKind.RAW_SOURCE:
            continue
        raw = _regular_bytes(
            _safe_live_path(selected_root, action.target_path),
            action.target_path,
        )
        expected = snapshots[action.source_path].read_bytes()
        if raw != expected:
            findings.append(
                _verification_finding(
                    "migration-source-copy-mismatch",
                    action.target_path,
                    "raw migration provenance does not match the reviewed snapshot",
                )
            )

    try:
        rebuilt = _live_projection_documents(selected_root, loaded)
    except (ConflictError, ValidationError):
        rebuilt = {}
        findings.append(
            _verification_finding(
                "migration-projection-input-invalid",
                ".agent-memory/state",
                "canonical migration inputs cannot rebuild projections",
            )
        )
    if set(rebuilt) != set(projection_paths):
        findings.append(
            _verification_finding(
                "migration-projection-inventory-mismatch",
                "_index",
                "generated migration projection inventory is incomplete",
            )
        )
    for relative in projection_paths:
        document = rebuilt.get(relative)
        raw = _regular_bytes(_safe_live_path(selected_root, relative), relative)
        if document is None or raw != document.content.encode("utf-8"):
            findings.append(
                _verification_finding(
                    "migration-projection-drift",
                    relative,
                    "generated migration projection differs from canonical inputs",
                )
            )
    ordered = tuple(
        sorted(findings, key=lambda item: (item.severity, item.code, item.path, item.message))
    )
    return MigrationVerification(
        not ordered,
        loaded.plan.source_revision,
        loaded.bundle_sha256,
        projection_paths,
        ordered,
    )


def _rollback_manifest(
    root: Path,
    journal_path: Path,
    journal: Mapping[str, object],
) -> Dict[str, Tuple[Path, str, int]]:
    manifest_path = journal_path.parent / _ROLLBACK_MANIFEST
    manifest = _canonical_document(manifest_path, "migration rollback manifest")
    if set(manifest) != {"apply_transaction_id", "entries", "schema_version"}:
        raise ValidationError("invalid migration rollback manifest")
    if (
        manifest["schema_version"] != 1
        or manifest["apply_transaction_id"] != journal["apply_transaction_id"]
        or not isinstance(manifest["entries"], list)
    ):
        raise ValidationError("invalid migration rollback manifest")
    values = {}
    for entry in manifest["entries"]:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "sha256",
            "size",
            "source_path",
        }:
            raise ValidationError("invalid migration rollback manifest")
        source_path = _portable_relative(entry["source_path"], "rollback source path")
        rollback_path = _portable_relative(entry["path"], "rollback evidence path")
        if not _valid_hash(entry["sha256"]) or type(entry["size"]) is not int or entry["size"] < 0:
            raise ValidationError("invalid migration rollback manifest")
        path = _safe_live_path(root, rollback_path)
        raw = _regular_bytes(path, rollback_path)
        if raw is None or len(raw) != entry["size"] or _sha256_bytes(raw) != entry["sha256"]:
            raise PlanInvalidatedError("migration rollback evidence changed")
        values[source_path] = (path, entry["sha256"], entry["size"])
    expected = {
        action["path"]
        for action in journal["actions"]
        if action["rollback_path"] is not None
    }
    if set(values) != expected:
        raise ValidationError("invalid migration rollback manifest")
    return values


@contextlib.contextmanager
def _rollback_root_guard(
    root: Path,
    apply_transaction_id: str,
    journal: Mapping[str, object],
    context: TransactionContext,
    gate: AuthorizationGate,
) -> Iterator[RootWriteGuard]:
    canonical = root / ".agent-memory-root-write.lock"
    candidate = _transactions._root_candidate(root, apply_transaction_id)
    if canonical.exists() or candidate.exists():
        if not isinstance(gate.authorization_ref, str) or not gate.authorization_ref.strip():
            raise ValidationError("authorization reference is required for root guard recovery")
        expected = journal["root_guard_sha256"] if canonical.exists() else None
        with _transactions.recover_root_write_guard(
            root,
            apply_transaction_id,
            expected,
            context,
            gate.authorization_ref,
        ) as recovery:
            guard = recovery.guard
            yield guard
        return
    with _transactions.root_write_guard(root, context) as guard:
        yield guard


def _rollback_evidence_document(
    journal: Mapping[str, object],
    context: TransactionContext,
    gate: AuthorizationGate,
    states: Mapping[str, str],
    status: str,
    reversed_paths: Tuple[str, ...] = (),
) -> Mapping[str, object]:
    return {
        "actor": context.actor,
        "apply_transaction_id": journal["apply_transaction_id"],
        "occurred_at": context.occurred_at,
        "operation": "migration-rollback",
        "plan_authorization_ref": journal["plan_authorization_ref"],
        "apply_authorization_ref": journal["apply_authorization_ref"],
        "rollback_authorization_ref": gate.authorization_ref,
        "schema_version": 1,
        "states": dict(sorted(states.items())),
        "status": status,
        "reversed_paths": list(reversed_paths),
        "transaction_id": context.transaction_id,
    }


def _reverse_action(
    root: Path,
    action: Mapping[str, object],
    rollback: Dict[str, Tuple[Path, str, int]],
    context: TransactionContext,
) -> None:
    target = _safe_live_path(root, action["path"])
    if action["operation"] == "create":
        raw = _regular_bytes(target, action["path"])
        if raw is None or _sha256_bytes(raw) != action["after_sha256"]:
            raise PlanInvalidatedError("migration rollback endpoints changed")
        target.unlink()
        _transactions._fsync_directory(target.parent)
        return
    evidence_path, evidence_hash, _ = rollback[action["path"]]
    content = evidence_path.read_bytes()
    if _sha256_bytes(content) != evidence_hash:
        raise PlanInvalidatedError("migration rollback evidence changed")
    token = hashlib.sha256(
        (context.transaction_id + "\0reverse\0" + action["path"]).encode("utf-8")
    ).hexdigest()
    if action["operation"] == "archive":
        if target.exists():
            raise PlanInvalidatedError("migration rollback endpoints changed")
        _transactions._publish_exclusive(target, content, token, root=root)
        return
    current = _regular_bytes(target, action["path"])
    if current is None or _sha256_bytes(current) != action["after_sha256"]:
        raise PlanInvalidatedError("migration rollback endpoints changed")
    _transactions._replace_cas(target, current, content, token, root=root)


def rollback_migration(
    root: Path,
    apply_transaction_id: str,
    context: TransactionContext,
    gate: AuthorizationGate,
) -> MigrationResult:
    selected_root = require_operation_gate(root, gate, "migration-rollback")
    validate_identifier(apply_transaction_id, "apply_transaction_id")
    _validate_context(context)
    if apply_transaction_id == context.transaction_id:
        raise ValidationError("rollback context must be distinct")
    journal_path = _journal_path(selected_root, apply_transaction_id)
    journal = _load_apply_journal(journal_path)
    if journal["apply_transaction_id"] != apply_transaction_id:
        raise ValidationError("migration journal transaction identity mismatch")
    if gate.scope is OperationScope.REAL and gate.authorization_ref in {
        journal["plan_authorization_ref"],
        journal["apply_authorization_ref"],
    }:
        raise ValidationError("real rollback authorization must be distinct")
    if journal["status"] == "rolled-back":
        return _parse_result(journal["result"])

    with _rollback_root_guard(
        selected_root,
        apply_transaction_id,
        journal,
        context,
        gate,
    ):
        rollback_evidence_path = (
            selected_root
            / ".agent-memory"
            / "transactions"
            / (context.transaction_id + ".json")
        )
        initial_states = {
            action["path"]: _classify_action(selected_root, action)
            for action in journal["actions"]
        }
        evidence = _rollback_evidence_document(
            journal,
            context,
            gate,
            initial_states,
            "preflight",
        )
        _publish_json(
            rollback_evidence_path,
            evidence,
            context.transaction_id + "\0rollback-evidence",
            selected_root,
        )
        if any(state == "ambiguous" for state in initial_states.values()):
            refused = dict(evidence)
            refused["status"] = "refused"
            _replace_json(
                rollback_evidence_path,
                evidence,
                refused,
                context.transaction_id + "\0rollback-refused",
                selected_root,
            )
            raise PlanInvalidatedError("migration rollback endpoints changed")
        if journal["status"] == "applied" and any(
            state != "ran" for state in initial_states.values()
        ):
            raise PlanInvalidatedError("migration rollback endpoints changed")

        if journal["status"] == "preparing" and not (
            journal_path.parent / _ROLLBACK_MANIFEST
        ).exists():
            rollback = {}
            if any(state == "ran" for state in initial_states.values()):
                raise PlanInvalidatedError("migration rollback evidence changed")
        else:
            rollback = _rollback_manifest(selected_root, journal_path, journal)

        reversed_paths = []
        current_evidence = evidence
        for action in reversed(journal["actions"]):
            if initial_states[action["path"]] != "ran":
                continue
            _reverse_action(selected_root, action, rollback, context)
            reversed_paths.append(action["path"])
            desired_evidence = _rollback_evidence_document(
                journal,
                context,
                gate,
                initial_states,
                "reversing",
                tuple(reversed_paths),
            )
            _replace_json(
                rollback_evidence_path,
                current_evidence,
                desired_evidence,
                context.transaction_id + "\0reversed\0" + action["path"],
                selected_root,
            )
            current_evidence = desired_evidence

        if any(_classify_action(selected_root, item) != "not-run" for item in journal["actions"]):
            raise PlanInvalidatedError("migration rollback endpoints changed")
        if journal["result"] is None:
            applied_result = MigrationResult(
                "applied",
                journal["apply_transaction_id"],
                journal["source_revision"],
                journal["reviewed_bundle_sha256"],
                journal["plan_authorization_ref"],
                journal["apply_authorization_ref"],
                None,
                tuple(
                    sorted(
                        item["path"]
                        for item in journal["actions"]
                        if item["operation"] == "create"
                    )
                ),
                tuple(
                    sorted(
                        item["path"]
                        for item in journal["actions"]
                        if item["operation"] == "replace"
                    )
                ),
                tuple(
                    sorted(
                        item["path"]
                        for item in journal["actions"]
                        if item["operation"] == "archive"
                    )
                ),
                tuple(journal["proposal_paths"]),
            )
        else:
            applied_result = _parse_result(journal["result"])
        result = MigrationResult(
            "rolled-back",
            context.transaction_id,
            applied_result.source_revision,
            applied_result.reviewed_bundle_sha256,
            applied_result.plan_authorization_ref,
            applied_result.apply_authorization_ref,
            gate.authorization_ref,
            applied_result.created_paths,
            applied_result.replaced_paths,
            applied_result.archived_paths,
            applied_result.proposal_paths,
        )
        final_journal = dict(journal)
        final_journal["status"] = "rolled-back"
        final_journal["rollback_authorization_ref"] = gate.authorization_ref
        final_journal["result"] = _result_dict(result)
        _replace_json(
            journal_path,
            journal,
            final_journal,
            context.transaction_id + "\0apply-journal-rolled-back",
            selected_root,
        )
        final_evidence = _rollback_evidence_document(
            journal,
            context,
            gate,
            initial_states,
            "rolled-back",
            tuple(reversed_paths),
        )
        _replace_json(
            rollback_evidence_path,
            current_evidence,
            final_evidence,
            context.transaction_id + "\0rollback-complete",
            selected_root,
        )
        return result
