"""Deterministic generated views over canonical Agent Memory state."""

import ctypes
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

from . import transactions as _transactions
from .errors import AgentMemoryError, ConflictError, ProjectionDriftError, ValidationError
from .models import ProjectionDocument, RecordEnvelope, RootWriteGuard, TransactionContext
from .paths import validate_identifier
from .records import _validate_timestamp, normalize_body, parse_record, record_relative_path
from .session_relationships import parse_session_relationship
from .resolution_outcomes import load_resolution_outcomes


_HASH_HEX = frozenset("0123456789abcdef")
_ROOT_VIEW_PATHS = (
    "_index/current-focus.md",
    "_index/home.md",
    "_index/memory-map.md",
    "_index/stale-or-uncertain.md",
)
_OPERATIONAL_LIMIT = 10000
_OPERATIONAL_BYTE_LIMIT = 1024 * 1024
_TERMINAL_DESCRIPTOR_PREVIEW_LIMIT = 64
_PROJECTION_SNAPSHOT_INVENTORY_LIMIT = 10000
_PROJECTION_SNAPSHOT_BYTE_LIMIT = 1024 * 1024
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True)
class _AcceptedOwner:
    envelope: RecordEnvelope
    body: str
    relative_path: str


@dataclass(frozen=True)
class _OperationalEntry:
    relative_path: str
    operation: str
    status: str
    transaction_id: str
    conflict_code: Optional[str]
    raw_sha256: str
    occurred_at: str
    target_memory_id: Optional[str]
    target_record_type: Optional[str]


@dataclass(frozen=True)
class _StorySessionLink:
    session_id: str
    observed_at: str
    status: str
    role: str


@dataclass(frozen=True)
class _Snapshot:
    catalog_revision: int
    catalog_entries: Mapping[str, Mapping[str, object]]
    records: Mapping[str, _AcceptedOwner]
    focuses: Mapping[str, Mapping[str, object]]
    operational: Tuple[_OperationalEntry, ...]
    canonical_hashes: Tuple[Tuple[str, str], ...]
    focus_inventory: Tuple[str, ...]
    include_operational: bool
    excluded_transaction_id: Optional[str]
    root_observed_at: str


def _projection_snapshot_lstat(path: Path) -> object:
    return Path(path).lstat()


def _projection_snapshot_is_redirect(metadata: object) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def _projection_snapshot_same_identity(first: object, second: object) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _open_projection_snapshot_descriptor(path: Path) -> int:
    if os.name != "nt":
        return os.open(
            os.fspath(path),
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )

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
        0x80000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00000080 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise OSError(ctypes.get_last_error(), "projection snapshot open failed")
    try:
        return msvcrt.open_osfhandle(
            handle,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def _projection_snapshot_relative_path(relative_path: str) -> str:
    if not isinstance(relative_path, str) or not relative_path:
        raise ValidationError("invalid projection snapshot source path")
    portable = PurePosixPath(relative_path)
    windows = PureWindowsPath(relative_path)
    if (
        portable.is_absolute()
        or windows.is_absolute()
        or "\\" in relative_path
        or portable.as_posix() != relative_path
        or any(part in ("", ".", "..") for part in portable.parts)
    ):
        raise ValidationError("invalid projection snapshot source path")
    return portable.as_posix()


def _projection_snapshot_plain_metadata(
    root: Path,
    target: Path,
    expected_kind: str,
    allow_missing: bool = False,
) -> Optional[object]:
    raw_root = Path(os.path.abspath(os.fspath(root)))
    raw_target = Path(os.path.abspath(os.fspath(target)))
    try:
        relative = raw_target.relative_to(raw_root)
    except ValueError as error:
        raise ValidationError("projection snapshot source escapes the memory root") from error

    current = raw_root
    paths = [raw_root]
    for component in relative.parts:
        current = current / component
        paths.append(current)
    leaf = None
    try:
        for index, path in enumerate(paths):
            try:
                metadata = _projection_snapshot_lstat(path)
            except FileNotFoundError:
                if allow_missing:
                    return None
                raise
            if _projection_snapshot_is_redirect(metadata):
                raise ValidationError("projection snapshot reparse path is not supported")
            is_leaf = index == len(paths) - 1
            if not is_leaf and not stat.S_ISDIR(metadata.st_mode):
                raise ValidationError("projection snapshot source parent is not a directory")
            leaf = metadata
        if leaf is None:
            raise ValidationError("projection snapshot source metadata is unavailable")
        if expected_kind == "file" and not stat.S_ISREG(leaf.st_mode):
            raise ValidationError("projection snapshot source is not a regular file")
        if expected_kind == "directory" and not stat.S_ISDIR(leaf.st_mode):
            raise ValidationError("projection snapshot inventory root is not a directory")
        resolved_root = raw_root.resolve(strict=True)
        resolved_target = raw_target.resolve(strict=True)
        resolved_relative = resolved_target.relative_to(resolved_root)
        if os.path.normcase(os.fspath(resolved_relative)) != os.path.normcase(
            os.fspath(relative)
        ):
            raise ValidationError("projection snapshot source changed lexical identity")
    except ValidationError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise ValidationError("unable to inspect projection snapshot source") from error
    return leaf


class _ProjectionSnapshotReader:
    def __init__(self, root: Path):
        self.root = root
        self._cache: Dict[str, bytes] = {}

    def read(self, relative_path: str) -> bytes:
        relative_path = _projection_snapshot_relative_path(relative_path)
        if relative_path in self._cache:
            return self._cache[relative_path]
        target = self.root / Path(*PurePosixPath(relative_path).parts)
        descriptor = None
        primary_failure_active = False
        try:
            before = _projection_snapshot_plain_metadata(
                self.root,
                target,
                "file",
            )
            descriptor = _open_projection_snapshot_descriptor(target)
            after = os.fstat(descriptor)
            if (
                before is None
                or _projection_snapshot_is_redirect(after)
                or not stat.S_ISREG(after.st_mode)
            ):
                raise ValidationError("projection snapshot requires a regular file handle")
            if not _projection_snapshot_same_identity(before, after):
                raise ValidationError("projection snapshot file identity changed before read")
            rechecked = _projection_snapshot_plain_metadata(
                self.root,
                target,
                "file",
            )
            if rechecked is None or not _projection_snapshot_same_identity(after, rechecked):
                raise ValidationError("projection snapshot file identity changed before read")
            if after.st_size > _PROJECTION_SNAPSHOT_BYTE_LIMIT:
                raise ValidationError("projection snapshot input exceeds 1048576 bytes")
            chunks = []
            remaining = _PROJECTION_SNAPSHOT_BYTE_LIMIT + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _PROJECTION_SNAPSHOT_BYTE_LIMIT:
                raise ValidationError("projection snapshot input exceeds 1048576 bytes")
        except BaseException as error:
            primary_failure_active = True
            if isinstance(error, ValidationError):
                raise
            if isinstance(error, (OSError, RuntimeError, ValueError)):
                raise ValidationError("unable to read projection snapshot input") from error
            raise
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as error:
                    if not primary_failure_active:
                        raise ValidationError(
                            "unable to close projection snapshot input"
                        ) from error
        self._cache[relative_path] = raw
        return raw

    def inventory(
        self,
        relative_directory: str,
        label: str,
        allow_missing: bool = False,
    ) -> Tuple[str, ...]:
        relative_directory = _projection_snapshot_relative_path(relative_directory)
        directory = self.root / Path(*PurePosixPath(relative_directory).parts)
        before = _projection_snapshot_plain_metadata(
            self.root,
            directory,
            "directory",
            allow_missing=allow_missing,
        )
        if before is None:
            return ()
        names = []
        try:
            with os.scandir(os.fspath(directory)) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > _PROJECTION_SNAPSHOT_INVENTORY_LIMIT:
                        raise ValidationError(
                            "{0} inventory exceeds 10000 entries".format(label)
                        )
            after = _projection_snapshot_plain_metadata(
                self.root,
                directory,
                "directory",
            )
            if after is None or not _projection_snapshot_same_identity(before, after):
                raise ValidationError("projection snapshot inventory identity changed")
        except ValidationError:
            raise
        except (OSError, RuntimeError, ValueError) as error:
            raise ValidationError("unable to enumerate projection snapshot inventory") from error
        return tuple(sorted(names))


def _projection_checkpoint(stage: str, root: Path, target: Path) -> None:
    """Private deterministic race-injection seam for projection tests."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_hash(value: Optional[str], field: str, allow_none: bool = False) -> None:
    if value is None and allow_none:
        return
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HASH_HEX for character in value)
    ):
        raise ValidationError("invalid {0}".format(field))


def _target_relative_path(relative_path: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise ValidationError("projection target must be a relative path")
    portable = PurePosixPath(relative_path)
    windows = PureWindowsPath(relative_path)
    if (
        portable.is_absolute()
        or windows.is_absolute()
        or "\\" in relative_path
        or any(part in ("", ".", "..") for part in portable.parts)
        or portable.as_posix() != relative_path
    ):
        raise ValidationError("projection target must be a portable relative path")
    parts = portable.parts
    if relative_path in _ROOT_VIEW_PATHS:
        return Path(*parts)
    if len(parts) == 3 and parts[0] == "projects" and parts[2] in (
        "overview.md",
        "current-focus.md",
    ):
        validate_identifier(parts[1], "project_id")
        return Path(*parts)
    if len(parts) == 4 and parts[0] == "projects" and parts[2] == "stories":
        validate_identifier(parts[1], "project_id")
        if not parts[3].endswith(".md"):
            raise ValidationError("story projection target must be Markdown")
        validate_identifier(parts[3][:-3], "memory_id")
        return Path(*parts)
    raise ValidationError("projection target is not an approved generated view")


def _record_path(relative_path: object) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise AgentMemoryError("invalid catalog record path")
    portable = PurePosixPath(relative_path)
    windows = PureWindowsPath(relative_path)
    if (
        portable.is_absolute()
        or windows.is_absolute()
        or "\\" in relative_path
        or portable.as_posix() != relative_path
        or any(part in ("", ".", "..") for part in portable.parts)
        or not portable.parts
        or portable.parts[0] != "_records"
    ):
        raise AgentMemoryError("invalid catalog record path")
    return Path(*portable.parts)


def _read_plain_bytes(path: Path) -> bytes:
    _transactions._assert_plain_file(path)
    return path.read_bytes()


def _read_operational_bytes(path: Path) -> bytes:
    _transactions._assert_plain_file(path)
    if path.lstat().st_size > _OPERATIONAL_BYTE_LIMIT:
        raise ValidationError("operational input exceeds 1048576 bytes")
    with path.open("rb") as stream:
        raw = stream.read(_OPERATIONAL_BYTE_LIMIT + 1)
    if len(raw) > _OPERATIONAL_BYTE_LIMIT:
        raise ValidationError("operational input exceeds 1048576 bytes")
    return raw


def _decode_json(raw: bytes, label: str) -> Mapping[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("malformed {0} JSON".format(label)) from error
    if not isinstance(value, dict):
        raise ValidationError("invalid {0} JSON".format(label))
    return value


def _operational_record_target(
    document: Mapping[str, object],
) -> Tuple[Optional[str], Optional[str]]:
    """Extract only bounded record identity metadata from a commit proposal."""
    if document.get("operation") != "commit-record":
        return None, None
    desired = document.get("desired")
    if not isinstance(desired, dict):
        return None, None
    record_candidate = desired.get("record_candidate")
    if not isinstance(record_candidate, dict):
        return None, None
    envelope = record_candidate.get("envelope")
    if not isinstance(envelope, dict):
        return None, None
    memory_id = envelope.get("memory_id")
    record_type = envelope.get("record_type")
    if not isinstance(memory_id, str) or not isinstance(record_type, str):
        return None, None
    try:
        validate_identifier(memory_id, "memory_id")
    except ValidationError:
        return None, None
    return memory_id, record_type


def _focus_paths(root: Path) -> Tuple[Path, ...]:
    directory = root / ".agent-memory" / "state" / "focus"
    try:
        directory.lstat()
    except FileNotFoundError:
        return ()
    _transactions._assert_plain_path(directory)
    paths = tuple(sorted(directory.glob("*.json"), key=lambda item: item.name))
    for path in paths:
        _transactions._assert_plain_file(path)
    return paths


def _initialization_observation(root: Path) -> Tuple[str, str, str]:
    transaction_directory = root / ".agent-memory" / "transactions"
    candidates = []
    for path in sorted(transaction_directory.glob("*.json"), key=lambda item: item.name):
        raw = _read_operational_bytes(path)
        document = _decode_json(raw, "initialization transaction")
        if document.get("operation") == "initialize" and document.get("status") == "accepted":
            occurred_at = document.get("occurred_at")
            _validate_timestamp(occurred_at, "occurred_at")
            candidates.append(
                (occurred_at, path.relative_to(root).as_posix(), _sha256_bytes(raw))
            )
    if len(candidates) != 1:
        raise AgentMemoryError("memory root must have exactly one accepted initialization")
    return candidates[0]


def _load_operational_entries(
    root: Path,
    excluded_transaction_id: Optional[str],
) -> Tuple[_OperationalEntry, ...]:
    selected = []
    outcomes = load_resolution_outcomes(_ProjectionSnapshotReader(root))
    proposal_directory = root / ".agent-memory" / "state" / "proposals"
    if proposal_directory.exists():
        _transactions._assert_plain_path(proposal_directory)
        proposal_paths = tuple(sorted(proposal_directory.glob("*.json"), key=lambda item: item.name))
    else:
        proposal_paths = ()
    if len(proposal_paths) > _OPERATIONAL_LIMIT:
        raise ValidationError("operational inventory exceeds 10000 entries")
    transaction_directory = root / ".agent-memory" / "transactions"
    _transactions._assert_plain_path(transaction_directory)
    transaction_paths = tuple(
        sorted(
            tuple(transaction_directory.glob("*.json"))
            + tuple(transaction_directory.glob("projections/*/*.json")),
            key=lambda item: item.relative_to(transaction_directory).as_posix(),
        )
    )
    for path, proposal in tuple((path, True) for path in proposal_paths) + tuple(
        (path, False) for path in transaction_paths
    ):
        raw = _read_operational_bytes(path)
        document = _decode_json(raw, "operational")
        if not proposal and document.get("transaction_id") == excluded_transaction_id:
            continue
        if proposal:
            status = outcomes.get(path.relative_to(root).as_posix(), "proposed")
            if status in ("accepted-record", "source-retained"):
                continue
        else:
            status_value = document.get("status")
            if not isinstance(status_value, str):
                raise ValidationError("transaction status is missing")
            if status_value != "in-progress":
                continue
            status = status_value
        operation = document.get("operation")
        transaction_id = document.get("transaction_id")
        occurred_at = document.get("occurred_at")
        conflict_code = document.get("conflict_code")
        if (
            not isinstance(operation, str)
            or not operation
            or not isinstance(transaction_id, str)
            or not transaction_id
            or conflict_code is not None
            and not isinstance(conflict_code, str)
        ):
            raise ValidationError("invalid operational metadata")
        _validate_timestamp(occurred_at, "occurred_at")
        selected.append(
            _OperationalEntry(
                path.relative_to(root).as_posix(),
                operation,
                status,
                transaction_id,
                conflict_code,
                _sha256_bytes(raw),
                occurred_at,
                *_operational_record_target(document),
            )
        )
        if len(selected) > _OPERATIONAL_LIMIT:
            raise ValidationError("operational inventory exceeds 10000 entries")
    return tuple(sorted(selected, key=lambda entry: entry.relative_path))


def _load_snapshot(
    root: Path,
    include_operational: bool,
    excluded_transaction_id: Optional[str] = None,
) -> _Snapshot:
    catalog_path = root / ".agent-memory" / "state" / "catalog.json"
    catalog_raw = _read_plain_bytes(catalog_path)
    catalog = _decode_json(catalog_raw, "catalog")
    revision = catalog.get("revision")
    entries = catalog.get("records")
    if catalog.get("schema_version") != 2 or type(revision) is not int or not isinstance(entries, dict):
        raise AgentMemoryError("invalid catalog")

    canonical_hashes = [(catalog_path.relative_to(root).as_posix(), _sha256_bytes(catalog_raw))]
    root_observed_at, initialization_path, initialization_hash = _initialization_observation(root)
    canonical_hashes.append((initialization_path, initialization_hash))
    accepted_entries: Dict[str, Mapping[str, object]] = {}
    records: Dict[str, _AcceptedOwner] = {}
    for memory_id in sorted(entries):
        validate_identifier(memory_id, "memory_id")
        entry = entries[memory_id]
        if not isinstance(entry, dict):
            raise AgentMemoryError("invalid catalog entry")
        required = (
            "memory_id",
            "revision",
            "relative_path",
            "record_type",
            "owner_scope",
            "project",
        )
        if any(field not in entry for field in required) or entry.get("memory_id") != memory_id:
            raise AgentMemoryError("invalid catalog entry")
        relative = _record_path(entry["relative_path"])
        record_path = root / relative
        raw = _read_plain_bytes(record_path)
        try:
            envelope, body = parse_record(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValidationError) as error:
            raise AgentMemoryError("invalid accepted record") from error
        if (
            envelope.memory_id != memory_id
            or envelope.revision != entry.get("revision")
            or envelope.record_type != entry.get("record_type")
            or envelope.owner_scope != entry.get("owner_scope")
            or envelope.project != entry.get("project")
            or relative.as_posix() != record_relative_path(envelope).as_posix()
        ):
            raise AgentMemoryError("catalog owner does not match accepted record")
        accepted_entries[memory_id] = dict(entry)
        records[memory_id] = _AcceptedOwner(envelope, body, relative.as_posix())
        canonical_hashes.append((relative.as_posix(), _sha256_bytes(raw)))

    focuses: Dict[str, Mapping[str, object]] = {}
    focus_paths = _focus_paths(root)
    focus_inventory = tuple(path.relative_to(root).as_posix() for path in focus_paths)
    for focus_path in focus_paths:
        raw = _read_plain_bytes(focus_path)
        focus = _decode_json(raw, "focus")
        project_id = focus.get("project_id")
        record_ids = focus.get("record_ids")
        focus_revision = focus.get("revision")
        observed_at = focus.get("observed_at")
        if (
            focus.get("schema_version") != 2
            or not isinstance(project_id, str)
            or type(focus_revision) is not int
            or focus_revision < 0
            or not isinstance(record_ids, list)
            or any(not isinstance(record_id, str) or record_id not in records for record_id in record_ids)
            or record_ids != sorted(set(record_ids))
        ):
            raise AgentMemoryError("invalid focus state")
        validate_identifier(project_id, "project_id")
        _validate_timestamp(observed_at, "observed_at")
        if focus_path.name != project_id + ".json":
            raise AgentMemoryError("focus path does not match project")
        focuses[project_id] = dict(focus)
        canonical_hashes.append((focus_path.relative_to(root).as_posix(), _sha256_bytes(raw)))

    operational = (
        _load_operational_entries(root, excluded_transaction_id)
        if include_operational
        else ()
    )
    return _Snapshot(
        revision,
        accepted_entries,
        records,
        focuses,
        operational,
        tuple(sorted(canonical_hashes)),
        focus_inventory,
        include_operational,
        excluded_transaction_id,
        root_observed_at,
    )


def _projection_snapshot_json_paths(
    reader: _ProjectionSnapshotReader,
    relative_directory: str,
    label: str,
    allow_missing: bool = False,
) -> Tuple[str, ...]:
    names = reader.inventory(
        relative_directory,
        label,
        allow_missing=allow_missing,
    )
    return tuple(
        relative_directory + "/" + name
        for name in names
        if name.endswith(".json")
    )


def _projection_snapshot_operational_paths(
    reader: _ProjectionSnapshotReader,
    transaction_paths: Tuple[str, ...],
) -> Tuple[Tuple[str, bool], ...]:
    proposal_paths = _projection_snapshot_json_paths(
        reader,
        ".agent-memory/state/proposals",
        "operational",
        allow_missing=True,
    )
    nested_transaction_paths = []
    projection_root = ".agent-memory/transactions/projections"
    context_names = reader.inventory(
        projection_root,
        "operational",
        allow_missing=True,
    )
    for context_name in context_names:
        context_relative = projection_root + "/" + context_name
        for name in reader.inventory(context_relative, "operational"):
            if name.endswith(".json"):
                nested_transaction_paths.append(context_relative + "/" + name)
                if (
                    len(proposal_paths)
                    + len(transaction_paths)
                    + len(nested_transaction_paths)
                    > _PROJECTION_SNAPSHOT_INVENTORY_LIMIT
                ):
                    raise ValidationError("operational inventory exceeds 10000 entries")
    all_transaction_paths = transaction_paths + tuple(nested_transaction_paths)
    if (
        len(proposal_paths) + len(all_transaction_paths)
        > _PROJECTION_SNAPSHOT_INVENTORY_LIMIT
    ):
        raise ValidationError("operational inventory exceeds 10000 entries")
    return tuple((path, True) for path in proposal_paths) + tuple(
        (path, False) for path in all_transaction_paths
    )


def _load_projection_snapshot_once(
    root: Path,
    reader: _ProjectionSnapshotReader,
    include_operational: bool,
) -> _Snapshot:
    catalog_relative = ".agent-memory/state/catalog.json"
    catalog_raw = reader.read(catalog_relative)
    catalog = _decode_json(catalog_raw, "catalog")
    revision = catalog.get("revision")
    entries = catalog.get("records")
    if catalog.get("schema_version") != 2 or type(revision) is not int or not isinstance(entries, dict):
        raise AgentMemoryError("invalid catalog")
    if len(entries) > _PROJECTION_SNAPSHOT_INVENTORY_LIMIT:
        raise ValidationError("catalog inventory exceeds 10000 entries")

    transaction_paths = _projection_snapshot_json_paths(
        reader,
        ".agent-memory/transactions",
        "initialization",
    )
    if len(transaction_paths) > _PROJECTION_SNAPSHOT_INVENTORY_LIMIT:
        raise ValidationError("initialization inventory exceeds 10000 entries")
    initialization_candidates = []
    for relative_path in transaction_paths:
        raw = reader.read(relative_path)
        document = _decode_json(raw, "initialization transaction")
        if document.get("operation") == "initialize" and document.get("status") == "accepted":
            occurred_at = document.get("occurred_at")
            _validate_timestamp(occurred_at, "occurred_at")
            initialization_candidates.append(
                (occurred_at, relative_path, _sha256_bytes(raw))
            )
    if len(initialization_candidates) != 1:
        raise AgentMemoryError("memory root must have exactly one accepted initialization")
    root_observed_at, initialization_path, initialization_hash = initialization_candidates[0]

    canonical_hashes = [(catalog_relative, _sha256_bytes(catalog_raw))]
    canonical_hashes.append((initialization_path, initialization_hash))
    accepted_entries: Dict[str, Mapping[str, object]] = {}
    records: Dict[str, _AcceptedOwner] = {}
    for memory_id in sorted(entries):
        validate_identifier(memory_id, "memory_id")
        entry = entries[memory_id]
        if not isinstance(entry, dict):
            raise AgentMemoryError("invalid catalog entry")
        required = (
            "memory_id",
            "revision",
            "relative_path",
            "record_type",
            "owner_scope",
            "project",
        )
        if any(field not in entry for field in required) or entry.get("memory_id") != memory_id:
            raise AgentMemoryError("invalid catalog entry")
        relative = _record_path(entry["relative_path"])
        relative_path = relative.as_posix()
        raw = reader.read(relative_path)
        try:
            envelope, body = parse_record(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValidationError) as error:
            raise AgentMemoryError("invalid accepted record") from error
        if (
            envelope.memory_id != memory_id
            or envelope.revision != entry.get("revision")
            or envelope.record_type != entry.get("record_type")
            or envelope.owner_scope != entry.get("owner_scope")
            or envelope.project != entry.get("project")
            or relative_path != record_relative_path(envelope).as_posix()
        ):
            raise AgentMemoryError("catalog owner does not match accepted record")
        accepted_entries[memory_id] = dict(entry)
        records[memory_id] = _AcceptedOwner(envelope, body, relative_path)
        canonical_hashes.append((relative_path, _sha256_bytes(raw)))

    focus_paths = _projection_snapshot_json_paths(
        reader,
        ".agent-memory/state/focus",
        "focus",
        allow_missing=True,
    )
    if len(focus_paths) > _PROJECTION_SNAPSHOT_INVENTORY_LIMIT:
        raise ValidationError("focus inventory exceeds 10000 entries")
    focuses: Dict[str, Mapping[str, object]] = {}
    for relative_path in focus_paths:
        raw = reader.read(relative_path)
        focus = _decode_json(raw, "focus")
        project_id = focus.get("project_id")
        record_ids = focus.get("record_ids")
        focus_revision = focus.get("revision")
        observed_at = focus.get("observed_at")
        if (
            focus.get("schema_version") != 2
            or not isinstance(project_id, str)
            or type(focus_revision) is not int
            or focus_revision < 0
            or not isinstance(record_ids, list)
            or any(not isinstance(record_id, str) or record_id not in records for record_id in record_ids)
            or record_ids != sorted(set(record_ids))
        ):
            raise AgentMemoryError("invalid focus state")
        validate_identifier(project_id, "project_id")
        _validate_timestamp(observed_at, "observed_at")
        if PurePosixPath(relative_path).name != project_id + ".json":
            raise AgentMemoryError("focus path does not match project")
        focuses[project_id] = dict(focus)
        canonical_hashes.append((relative_path, _sha256_bytes(raw)))

    operational_entries = []
    if include_operational:
        outcomes = load_resolution_outcomes(reader)
        for relative_path, proposal in _projection_snapshot_operational_paths(
            reader,
            transaction_paths,
        ):
            raw = reader.read(relative_path)
            document = _decode_json(raw, "operational")
            if proposal:
                status = outcomes.get(relative_path, "proposed")
                if status in ("accepted-record", "source-retained"):
                    continue
            else:
                status_value = document.get("status")
                if not isinstance(status_value, str):
                    raise ValidationError("transaction status is missing")
                if status_value != "in-progress":
                    continue
                status = status_value
            operation = document.get("operation")
            transaction_id = document.get("transaction_id")
            occurred_at = document.get("occurred_at")
            conflict_code = document.get("conflict_code")
            if (
                not isinstance(operation, str)
                or not operation
                or not isinstance(transaction_id, str)
                or not transaction_id
                or conflict_code is not None
                and not isinstance(conflict_code, str)
            ):
                raise ValidationError("invalid operational metadata")
            _validate_timestamp(occurred_at, "occurred_at")
            operational_entries.append(
                _OperationalEntry(
                    relative_path,
                    operation,
                    status,
                    transaction_id,
                    conflict_code,
                    _sha256_bytes(raw),
                    occurred_at,
                    *_operational_record_target(document),
                )
            )

    return _Snapshot(
        revision,
        accepted_entries,
        records,
        focuses,
        tuple(sorted(operational_entries, key=lambda entry: entry.relative_path)),
        tuple(sorted(canonical_hashes)),
        tuple(focus_paths),
        include_operational,
        None,
        root_observed_at,
    )


def _recheck_snapshot(root: Path, snapshot: _Snapshot) -> None:
    if tuple(path.relative_to(root).as_posix() for path in _focus_paths(root)) != snapshot.focus_inventory:
        raise ConflictError("canonical focus inventory changed during projection build")
    for relative_path, expected_hash in snapshot.canonical_hashes:
        path = root / Path(*PurePosixPath(relative_path).parts)
        try:
            current = _read_plain_bytes(path)
        except FileNotFoundError as error:
            raise ConflictError("canonical input disappeared during projection build") from error
        if _sha256_bytes(current) != expected_hash:
            raise ConflictError("canonical input changed during projection build")
    if snapshot.include_operational:
        current = _load_operational_entries(root, snapshot.excluded_transaction_id)
        if current != snapshot.operational:
            raise ConflictError("operational input changed during projection build")


def _timestamp_key(value: str) -> Tuple[datetime, str]:
    _validate_timestamp(value, "observed_at")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    return parsed, value


def _latest_timestamp(values: Iterable[str]) -> str:
    timestamps = tuple(values)
    if not timestamps:
        raise AgentMemoryError("projection input has no observed timestamp")
    return max(timestamps, key=_timestamp_key)


def _summary(owner: _AcceptedOwner) -> str:
    lines = [line.strip() for line in owner.body.splitlines() if line.strip()]
    for line in lines:
        if not line.startswith("#"):
            return line
    if lines:
        return lines[0].lstrip("# ")
    return "(empty accepted body)"


def _entry_input(snapshot: _Snapshot, memory_id: str) -> Mapping[str, object]:
    entry = snapshot.catalog_entries[memory_id]
    owner = snapshot.records[memory_id]
    return {
        "body_sha256": owner.envelope.body_sha256,
        "memory_id": memory_id,
        "observed_at": owner.envelope.observed_at,
        "owner_scope": entry["owner_scope"],
        "project": entry["project"],
        "record_type": entry["record_type"],
        "relative_path": entry["relative_path"],
        "revision": entry["revision"],
    }


def _render_document(
    relative_path: str,
    body: str,
    source_input: Mapping[str, object],
    timestamps: Iterable[str],
    generator_version: str,
    expected_target_sha256: Optional[str],
) -> ProjectionDocument:
    validate_identifier(generator_version, "generator_version")
    normalized_body = normalize_body(body)
    source_revision = _sha256_bytes(_transactions._json_bytes(source_input))
    observed_at = _latest_timestamp(timestamps)
    body_sha256 = _sha256_bytes(normalized_body.encode("utf-8"))
    content = (
        "---\n"
        "generated: true\n"
        "projection_version: 2\n"
        "source_revision: {0}\n"
        "observed_at: {1}\n"
        "generator_version: {2}\n"
        "projection_body_sha256: {3}\n"
        "---\n{4}"
    ).format(
        source_revision,
        observed_at,
        generator_version,
        body_sha256,
        normalized_body,
    )
    return ProjectionDocument(
        relative_path,
        content,
        source_revision,
        observed_at,
        expected_target_sha256,
    )


def _target_hash(root: Path, relative_path: str) -> Optional[str]:
    relative = _target_relative_path(relative_path)
    target = root / relative
    if not target.exists():
        return None
    return _sha256_bytes(_read_plain_bytes(target))


def _project_target_hashes(root: Path, project_id: str) -> Mapping[str, Optional[str]]:
    """Capture every existing project-view target before canonical input reads."""
    relative_paths = [
        "projects/{0}/current-focus.md".format(project_id),
        "projects/{0}/overview.md".format(project_id),
    ]
    story_directory = root / "projects" / project_id / "stories"
    if story_directory.exists():
        _transactions._assert_plain_path(story_directory)
        for path in sorted(story_directory.glob("*.md"), key=lambda item: item.name):
            relative_path = path.relative_to(root).as_posix()
            _target_relative_path(relative_path)
            relative_paths.append(relative_path)
    return {relative_path: _target_hash(root, relative_path) for relative_path in relative_paths}


def _project_focus_document(
    snapshot: _Snapshot,
    project_id: str,
    generator_version: str,
    expected_hash: Optional[str],
) -> ProjectionDocument:
    focus = snapshot.focuses.get(project_id)
    if focus is None:
        raise ValidationError("project focus does not exist")
    selected_ids = tuple(focus["record_ids"])
    lines = ["# Current focus: " + project_id, ""]
    if selected_ids:
        for memory_id in selected_ids:
            owner = snapshot.records[memory_id]
            lines.append(
                "- `{0}` ({1}): {2}".format(
                    memory_id,
                    owner.envelope.record_type,
                    _summary(owner),
                )
            )
    else:
        lines.append("- No accepted records selected.")
    inputs = {
        "focus": dict(focus),
        "records": [_entry_input(snapshot, memory_id) for memory_id in selected_ids],
        "view": "project-current-focus",
    }
    timestamps = [focus["observed_at"]]
    timestamps.extend(snapshot.records[memory_id].envelope.observed_at for memory_id in selected_ids)
    return _render_document(
        "projects/{0}/current-focus.md".format(project_id),
        "\n".join(lines),
        inputs,
        timestamps,
        generator_version,
        expected_hash,
    )


def _global_focus_document(
    snapshot: _Snapshot,
    generator_version: str,
    expected_hash: Optional[str],
) -> ProjectionDocument:
    lines = ["# Current focus", ""]
    focus_inputs = []
    record_inputs = []
    timestamps = []
    for project_id in sorted(snapshot.focuses):
        focus = snapshot.focuses[project_id]
        focus_inputs.append(dict(focus))
        timestamps.append(focus["observed_at"])
        lines.extend(("## " + project_id, ""))
        selected_ids = tuple(focus["record_ids"])
        if not selected_ids:
            lines.append("- No accepted records selected.")
        for memory_id in selected_ids:
            owner = snapshot.records[memory_id]
            lines.append("- `{0}`: {1}".format(memory_id, _summary(owner)))
            record_inputs.append(_entry_input(snapshot, memory_id))
            timestamps.append(owner.envelope.observed_at)
        lines.append("")
    inputs = {
        "focus": focus_inputs,
        "records": record_inputs,
        "view": "global-current-focus",
    }
    if not timestamps:
        inputs["root_observed_at"] = snapshot.root_observed_at
        timestamps.append(snapshot.root_observed_at)
    return _render_document(
        "_index/current-focus.md",
        "\n".join(lines),
        inputs,
        timestamps,
        generator_version,
        expected_hash,
    )


def _home_document(
    snapshot: _Snapshot,
    generator_version: str,
    expected_hash: Optional[str],
) -> ProjectionDocument:
    lines = ["# Agent Memory Home", "", "## Projects", ""]
    timestamps = []
    for project_id in sorted(snapshot.focuses):
        focus = snapshot.focuses[project_id]
        lines.append("- `{0}` — focus revision {1}".format(project_id, focus["revision"]))
        timestamps.append(focus["observed_at"])
    accepted_ids = tuple(sorted(snapshot.records))
    lines.extend(("", "## Accepted owners", ""))
    for memory_id in accepted_ids:
        owner = snapshot.records[memory_id]
        lines.append(
            "- `{0}` ({1}): {2}".format(
                memory_id,
                owner.envelope.project or "global",
                _summary(owner),
            )
        )
        timestamps.append(snapshot.records[memory_id].envelope.observed_at)
    inputs = {
        "focus": [dict(snapshot.focuses[project_id]) for project_id in sorted(snapshot.focuses)],
        "records": [_entry_input(snapshot, memory_id) for memory_id in accepted_ids],
        "view": "home",
    }
    if not timestamps:
        inputs["root_observed_at"] = snapshot.root_observed_at
        timestamps.append(snapshot.root_observed_at)
    return _render_document(
        "_index/home.md",
        "\n".join(lines),
        inputs,
        timestamps,
        generator_version,
        expected_hash,
    )


def _memory_map_document(
    snapshot: _Snapshot,
    generator_version: str,
    expected_hash: Optional[str],
) -> ProjectionDocument:
    lines = ["# Memory map", ""]
    timestamps = []
    for memory_id in sorted(snapshot.records):
        owner = snapshot.records[memory_id]
        lines.append(
            "- `{0}` — {1}; owner `{2}`; project `{3}`; `{4}`".format(
                memory_id,
                owner.envelope.record_type,
                owner.envelope.owner_scope,
                owner.envelope.project or "global",
                owner.relative_path,
            )
        )
        timestamps.append(owner.envelope.observed_at)
    inputs = {
        "catalog_revision": snapshot.catalog_revision,
        "records": [_entry_input(snapshot, memory_id) for memory_id in sorted(snapshot.records)],
        "view": "memory-map",
    }
    if not timestamps:
        inputs["root_observed_at"] = snapshot.root_observed_at
        timestamps.append(snapshot.root_observed_at)
    return _render_document(
        "_index/memory-map.md",
        "\n".join(lines),
        inputs,
        timestamps,
        generator_version,
        expected_hash,
    )


def _stale_document(
    snapshot: _Snapshot,
    generator_version: str,
    expected_hash: Optional[str],
) -> ProjectionDocument:
    lines = ["# Stale or uncertain", ""]
    timestamps = [focus["observed_at"] for focus in snapshot.focuses.values()]
    operational_input = []
    for entry in snapshot.operational:
        metadata = {
            "conflict_code": entry.conflict_code,
            "operation": entry.operation,
            "path": entry.relative_path,
            "raw_sha256": entry.raw_sha256,
            "status": entry.status,
            "transaction_id": entry.transaction_id,
        }
        operational_input.append(metadata)
        timestamps.append(entry.occurred_at)
        lines.append(
            "- `{path}` — operation={operation}; status={status}; transaction_id={transaction_id}; "
            "conflict_code={conflict_code}; sha256={raw_sha256}".format(**metadata)
        )
    legacy_sessions = _legacy_unbound_sessions(snapshot)
    for memory_id in legacy_sessions:
        owner = snapshot.records[memory_id]
        timestamps.append(owner.envelope.observed_at)
        lines.append(
            "- `{0}` — code=legacy-session-unbound; project={1}".format(
                memory_id,
                owner.envelope.project,
            )
        )
    if not operational_input and not legacy_sessions:
        lines.append("- No proposals or incomplete transaction intents.")
    inputs = {
        "focus_revisions": [
            {
                "observed_at": snapshot.focuses[project_id]["observed_at"],
                "project_id": project_id,
                "revision": snapshot.focuses[project_id]["revision"],
            }
            for project_id in sorted(snapshot.focuses)
        ],
        "legacy_session_unbound": [
            _entry_input(snapshot, memory_id) for memory_id in legacy_sessions
        ],
        "operational": operational_input,
        "view": "stale-or-uncertain",
    }
    if not timestamps:
        inputs["root_observed_at"] = snapshot.root_observed_at
        timestamps.append(snapshot.root_observed_at)
    return _render_document(
        "_index/stale-or-uncertain.md",
        "\n".join(lines),
        inputs,
        timestamps,
        generator_version,
        expected_hash,
    )


def _legacy_unbound_sessions(snapshot: _Snapshot) -> Tuple[str, ...]:
    legacy = []
    for memory_id in sorted(snapshot.records):
        owner = snapshot.records[memory_id]
        if owner.envelope.record_type != "session":
            continue
        try:
            parse_session_relationship(owner.body)
        except ValidationError as error:
            if str(error) != "session-relationship-required":
                raise AgentMemoryError("invalid accepted session relationship") from error
            legacy.append(memory_id)
    return tuple(legacy)


def _overview_document(
    snapshot: _Snapshot,
    project_id: str,
    generator_version: str,
    expected_hash: Optional[str],
) -> ProjectionDocument:
    focus = snapshot.focuses.get(project_id)
    if focus is None:
        raise ValidationError("project focus does not exist")
    project_ids = tuple(
        memory_id
        for memory_id in sorted(snapshot.records)
        if snapshot.records[memory_id].envelope.project == project_id
    )
    lines = ["# Project overview: " + project_id, "", "## Accepted owners", ""]
    for memory_id in project_ids:
        lines.append("- `{0}`: {1}".format(memory_id, _summary(snapshot.records[memory_id])))
    inputs = {
        "focus": dict(focus),
        "records": [_entry_input(snapshot, memory_id) for memory_id in project_ids],
        "view": "project-overview",
    }
    timestamps = [focus["observed_at"]]
    timestamps.extend(snapshot.records[memory_id].envelope.observed_at for memory_id in project_ids)
    return _render_document(
        "projects/{0}/overview.md".format(project_id),
        "\n".join(lines),
        inputs,
        timestamps,
        generator_version,
        expected_hash,
    )


def _story_document(
    snapshot: _Snapshot,
    project_id: str,
    memory_id: str,
    generator_version: str,
    expected_hash: Optional[str],
) -> ProjectionDocument:
    owner = snapshot.records[memory_id]
    if owner.envelope.project != project_id or owner.envelope.record_type != "story":
        raise ValidationError("story projection does not identify an accepted project story")
    links = _story_session_links(snapshot, project_id, memory_id)
    pending = _story_pending_updates(snapshot, memory_id)
    lines = [
        "# Story: " + memory_id,
        "",
        "- Durable owner: `" + memory_id + "`",
        "- Revision: " + str(owner.envelope.revision),
        "- Canonical record: `" + owner.relative_path + "`",
        "",
        "## Summary",
        "",
        _summary(owner),
        "",
        "## Session timeline",
        "",
    ]
    if links:
        lines.append("- Time range: `{0} to {1}`".format(links[0].observed_at, links[-1].observed_at))
        for link in links:
            lines.append(
                "- `{0}` ({1}, {2}) — observed_at={3}".format(
                    link.session_id,
                    link.status,
                    link.role,
                    link.observed_at,
                )
            )
    else:
        lines.append("- No accepted Sessions explicitly link this Story.")
    if pending:
        lines.extend(("", "## Pending Story updates", ""))
        for entry in pending:
            lines.append(
                "- `{0}` ({1}) — conflict_code={2}".format(
                    entry.transaction_id,
                    entry.status,
                    entry.conflict_code,
                )
            )
    body = "\n".join(lines)
    inputs = {
        "pending_story_updates": [_operational_input(entry) for entry in pending],
        "record": _entry_input(snapshot, memory_id),
        "sessions": [
            {
                "record": _entry_input(snapshot, link.session_id),
                "role": link.role,
                "status": link.status,
            }
            for link in links
        ],
        "view": "project-story",
    }
    timestamps = [owner.envelope.observed_at]
    timestamps.extend(link.observed_at for link in links)
    timestamps.extend(entry.occurred_at for entry in pending)
    return _render_document(
        "projects/{0}/stories/{1}.md".format(project_id, memory_id),
        body,
        inputs,
        timestamps,
        generator_version,
        expected_hash,
    )


def _story_session_links(
    snapshot: _Snapshot,
    project_id: str,
    story_id: str,
) -> Tuple[_StorySessionLink, ...]:
    links = []
    for session_id in sorted(snapshot.records):
        owner = snapshot.records[session_id]
        if owner.envelope.record_type != "session" or owner.envelope.project != project_id:
            continue
        try:
            relationship = parse_session_relationship(owner.body)
        except ValidationError as error:
            if str(error) == "session-relationship-required":
                continue
            raise AgentMemoryError("invalid accepted session relationship") from error
        if relationship.primary_story_id == story_id:
            role = "primary"
        elif story_id in relationship.related_story_ids:
            role = "related"
        else:
            continue
        links.append(
            _StorySessionLink(
                session_id,
                owner.envelope.observed_at,
                relationship.session_status,
                role,
            )
        )
    return tuple(sorted(links, key=lambda item: (_timestamp_key(item.observed_at), item.session_id)))


def _story_pending_updates(
    snapshot: _Snapshot,
    story_id: str,
) -> Tuple[_OperationalEntry, ...]:
    return tuple(
        entry
        for entry in snapshot.operational
        if entry.target_memory_id == story_id and entry.target_record_type == "story"
    )


def _operational_input(entry: _OperationalEntry) -> Mapping[str, object]:
    return {
        "conflict_code": entry.conflict_code,
        "occurred_at": entry.occurred_at,
        "operation": entry.operation,
        "path": entry.relative_path,
        "raw_sha256": entry.raw_sha256,
        "status": entry.status,
        "transaction_id": entry.transaction_id,
    }


def _build_root_views(
    root: Path,
    generator_version: str,
    excluded_transaction_id: Optional[str] = None,
) -> Tuple[ProjectionDocument, ...]:
    root = _transactions._prepare_root(root)
    validate_identifier(generator_version, "generator_version")
    target_hashes = {path: _target_hash(root, path) for path in _ROOT_VIEW_PATHS}
    snapshot = _load_snapshot(root, True, excluded_transaction_id)
    documents = (
        _global_focus_document(snapshot, generator_version, target_hashes["_index/current-focus.md"]),
        _home_document(snapshot, generator_version, target_hashes["_index/home.md"]),
        _memory_map_document(snapshot, generator_version, target_hashes["_index/memory-map.md"]),
        _stale_document(snapshot, generator_version, target_hashes["_index/stale-or-uncertain.md"]),
    )
    _recheck_snapshot(root, snapshot)
    return tuple(sorted(documents, key=lambda document: document.relative_path))


def _build_project_views(
    root: Path,
    project_id: str,
    generator_version: str,
) -> Tuple[ProjectionDocument, ...]:
    root = _transactions._prepare_root(root)
    validate_identifier(project_id, "project_id")
    validate_identifier(generator_version, "generator_version")
    target_hashes = _project_target_hashes(root, project_id)
    snapshot = _load_snapshot(root, True)
    story_ids = tuple(
        memory_id
        for memory_id in sorted(snapshot.records)
        if snapshot.records[memory_id].envelope.project == project_id
        and snapshot.records[memory_id].envelope.record_type == "story"
    )
    documents: List[ProjectionDocument] = [
        _project_focus_document(
            snapshot,
            project_id,
            generator_version,
            target_hashes["projects/{0}/current-focus.md".format(project_id)],
        ),
        _overview_document(
            snapshot,
            project_id,
            generator_version,
            target_hashes["projects/{0}/overview.md".format(project_id)],
        ),
    ]
    documents.extend(
        _story_document(
            snapshot,
            project_id,
            memory_id,
            generator_version,
            target_hashes.get("projects/{0}/stories/{1}.md".format(project_id, memory_id)),
        )
        for memory_id in story_ids
    )
    _recheck_snapshot(root, snapshot)
    return tuple(sorted(documents, key=lambda document: document.relative_path))


def build_project_focus(root: Path, project_id: str, generator_version: str) -> ProjectionDocument:
    root = _transactions._prepare_root(root)
    validate_identifier(project_id, "project_id")
    validate_identifier(generator_version, "generator_version")
    relative_path = "projects/{0}/current-focus.md".format(project_id)
    expected_hash = _target_hash(root, relative_path)
    snapshot = _load_snapshot(root, False)
    document = _project_focus_document(snapshot, project_id, generator_version, expected_hash)
    _recheck_snapshot(root, snapshot)
    return document


def build_global_focus(root: Path, generator_version: str) -> ProjectionDocument:
    root = _transactions._prepare_root(root)
    validate_identifier(generator_version, "generator_version")
    expected_hash = _target_hash(root, "_index/current-focus.md")
    snapshot = _load_snapshot(root, False)
    document = _global_focus_document(snapshot, generator_version, expected_hash)
    _recheck_snapshot(root, snapshot)
    return document


def build_root_views(root: Path, generator_version: str) -> Tuple[ProjectionDocument, ...]:
    return _build_root_views(root, generator_version)


def build_project_views(
    root: Path,
    project_id: str,
    generator_version: str,
) -> Tuple[ProjectionDocument, ...]:
    return _build_project_views(root, project_id, generator_version)


def build_projection_from_observed_target(
    root: Path,
    relative_path: str,
    generator_version: str,
    observed_target_sha256: str,
) -> ProjectionDocument:
    """Render one doctor projection from a cached, bounded source snapshot."""
    relative = _target_relative_path(relative_path)
    canonical_relative_path = relative.as_posix()
    validate_identifier(generator_version, "generator_version")
    _validate_hash(observed_target_sha256, "observed_target_sha256")
    root = _transactions._prepare_root(root)
    reader = _ProjectionSnapshotReader(root)
    parts = PurePosixPath(canonical_relative_path).parts
    include_operational = (
        canonical_relative_path == "_index/stale-or-uncertain.md"
        or len(parts) == 4
        and parts[0] == "projects"
        and parts[2] == "stories"
    )
    snapshot = _load_projection_snapshot_once(
        root,
        reader,
        include_operational,
    )
    if canonical_relative_path == "_index/current-focus.md":
        return _global_focus_document(
            snapshot,
            generator_version,
            observed_target_sha256,
        )
    if canonical_relative_path == "_index/home.md":
        return _home_document(snapshot, generator_version, observed_target_sha256)
    if canonical_relative_path == "_index/memory-map.md":
        return _memory_map_document(
            snapshot,
            generator_version,
            observed_target_sha256,
        )
    if canonical_relative_path == "_index/stale-or-uncertain.md":
        return _stale_document(snapshot, generator_version, observed_target_sha256)
    if parts[2] == "current-focus.md":
        return _project_focus_document(
            snapshot,
            parts[1],
            generator_version,
            observed_target_sha256,
        )
    if parts[2] == "overview.md":
        return _overview_document(
            snapshot,
            parts[1],
            generator_version,
            observed_target_sha256,
        )
    return _story_document(
        snapshot,
        parts[1],
        parts[3][:-3],
        generator_version,
        observed_target_sha256,
    )


def _parse_projection(content: str) -> Tuple[Mapping[str, str], str]:
    if not isinstance(content, str):
        raise ValidationError("projection content must be text")
    lines = content.splitlines(keepends=True)
    if len(lines) < 9 or lines[0] != "---\n":
        raise ValidationError("invalid projection frontmatter")
    try:
        closing_index = lines.index("---\n", 1)
    except ValueError as error:
        raise ValidationError("invalid projection frontmatter") from error
    fields: Dict[str, str] = {}
    for line in lines[1:closing_index]:
        if not line.endswith("\n") or ": " not in line:
            raise ValidationError("invalid projection frontmatter")
        name, value = line[:-1].split(": ", 1)
        if name in fields or not value:
            raise ValidationError("invalid projection frontmatter")
        fields[name] = value
    required = {
        "generated",
        "projection_version",
        "source_revision",
        "observed_at",
        "generator_version",
        "projection_body_sha256",
    }
    if set(fields) != required or fields["generated"] != "true" or fields["projection_version"] != "2":
        raise ValidationError("invalid projection frontmatter")
    _validate_hash(fields["source_revision"], "source_revision")
    _validate_hash(fields["projection_body_sha256"], "projection_body_sha256")
    _validate_timestamp(fields["observed_at"], "observed_at")
    validate_identifier(fields["generator_version"], "generator_version")
    return fields, "".join(lines[closing_index + 1 :])


def _projection_is_intact(content: bytes) -> bool:
    try:
        text = content.decode("utf-8")
        fields, body = _parse_projection(text)
        normalized_body = normalize_body(body)
    except (UnicodeDecodeError, ValidationError):
        return False
    return _sha256_bytes(normalized_body.encode("utf-8")) == fields["projection_body_sha256"]


def _current_document_for_publish(
    root: Path,
    relative_path: str,
    generator_version: str,
    excluded_transaction_id: str,
) -> ProjectionDocument:
    expected_hash = _target_hash(root, relative_path)
    parts = PurePosixPath(relative_path).parts
    include_operational = (
        relative_path == "_index/stale-or-uncertain.md"
        or len(parts) == 4
        and parts[0] == "projects"
        and parts[2] == "stories"
    )
    snapshot = _load_snapshot(
        root,
        include_operational,
        excluded_transaction_id if include_operational else None,
    )
    if relative_path == "_index/current-focus.md":
        document = _global_focus_document(snapshot, generator_version, expected_hash)
    elif relative_path == "_index/home.md":
        document = _home_document(snapshot, generator_version, expected_hash)
    elif relative_path == "_index/memory-map.md":
        document = _memory_map_document(snapshot, generator_version, expected_hash)
    elif relative_path == "_index/stale-or-uncertain.md":
        document = _stale_document(snapshot, generator_version, expected_hash)
    elif parts[2] == "current-focus.md":
        document = _project_focus_document(
            snapshot,
            parts[1],
            generator_version,
            expected_hash,
        )
    elif parts[2] == "overview.md":
        document = _overview_document(
            snapshot,
            parts[1],
            generator_version,
            expected_hash,
        )
    else:
        document = _story_document(
            snapshot,
            parts[1],
            parts[3][:-3],
            generator_version,
            expected_hash,
        )
    _recheck_snapshot(root, snapshot)
    return document


def _verify_document_matches_canonical(
    root: Path,
    document: ProjectionDocument,
    generator_version: str,
    transaction_id: str,
) -> None:
    rebuilt = _current_document_for_publish(
        root,
        document.relative_path,
        generator_version,
        transaction_id,
    )
    if (
        rebuilt.source_revision != document.source_revision
        or rebuilt.observed_at != document.observed_at
        or rebuilt.content != document.content
    ):
        raise ConflictError("projection inputs or deterministic bytes changed")


def _projection_lock_name(relative_path: str) -> str:
    return "projection--" + _sha256_bytes(relative_path.encode("utf-8"))


def _backup_drift(root: Path, content: bytes, transaction_id: str) -> Path:
    content_hash = _sha256_bytes(content)
    backup = root / ".agent-memory" / "transactions" / "projection-drift" / (content_hash + ".md")
    if backup.exists():
        if _read_plain_bytes(backup) != content:
            raise ConflictError("projection drift backup hash collision")
        return backup
    _transactions._publish_exclusive(
        backup,
        content,
        _sha256_bytes((transaction_id + "\0projection-drift\0" + content_hash).encode("utf-8")),
        root=root,
    )
    return backup


def _namespace_description(root: Path, path: Path) -> Mapping[str, object]:
    relative_path = path.relative_to(root).as_posix()
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"kind": "absent", "path": relative_path}
    attributes = getattr(metadata, "st_file_attributes", 0)
    if stat.S_ISLNK(metadata.st_mode) or attributes & getattr(
        stat,
        "FILE_ATTRIBUTE_REPARSE_POINT",
        0x400,
    ):
        kind = "reparse"
    elif stat.S_ISREG(metadata.st_mode):
        kind = "regular"
    elif stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
    else:
        kind = "special"
    return {
        "file_type": stat.S_IFMT(metadata.st_mode),
        "kind": kind,
        "path": relative_path,
    }


def _terminal_operation_fields(
    transaction_id: str,
    relative_target: str,
    published: bytes,
    prior: Optional[bytes],
) -> Mapping[str, object]:
    return {
        "prior_sha256": _sha256_bytes(prior) if prior is not None else None,
        "projection_evidence": {
            "context_sha256": _sha256_bytes(transaction_id.encode("utf-8")),
            "target_path_sha256": _sha256_bytes(relative_target.encode("utf-8")),
        },
        "published_sha256": _sha256_bytes(published),
        "schema_version": 2,
        "status": "terminal",
        "target": relative_target,
        "transaction_id": transaction_id,
    }


def _rollback_projection_once(
    root: Path,
    target: Path,
    published: bytes,
    prior: Optional[bytes],
    transaction_id: str,
) -> Tuple[str, ...]:
    relative_target = target.relative_to(root).as_posix()
    context_hash = _sha256_bytes(transaction_id.encode("utf-8"))
    target_hash = _sha256_bytes(relative_target.encode("utf-8"))
    recovery_directory = (
        root
        / ".agent-memory"
        / "transactions"
        / "projection-recovery"
        / context_hash
        / target_hash
    )
    _transactions._assert_checked_parent(
        root,
        recovery_directory / "placeholder",
        allow_missing=True,
    )
    recovery_directory.mkdir(parents=True, exist_ok=True)
    _transactions._assert_plain_path(recovery_directory)
    quarantine = recovery_directory / "displaced.bin"
    evidence_paths = []

    def preserve(path: Path, content: bytes, label: str) -> None:
        if path.exists():
            if _read_plain_bytes(path) != content:
                raise ConflictError("projection recovery evidence is occupied")
        else:
            _transactions._publish_exclusive(
                path,
                content,
                _sha256_bytes((transaction_id + "\0" + label).encode("utf-8")),
                root=root,
            )
        evidence_paths.append(path.relative_to(root).as_posix())

    prior_path = None
    if prior is not None:
        prior_path = recovery_directory / (
            "prior-" + _sha256_bytes(prior) + ".bin"
        )
        preserve(prior_path, prior, "projection-rollback-prior")
    intent = {
        "displaced_path": quarantine.relative_to(root).as_posix(),
        "prior_path": prior_path.relative_to(root).as_posix() if prior_path else None,
        "prior_sha256": _sha256_bytes(prior) if prior is not None else None,
        "published_sha256": _sha256_bytes(published),
        "schema_version": 2,
        "status": "in-progress",
        "target": relative_target,
        "transaction_id": transaction_id,
    }
    preserve(
        recovery_directory / "intent.json",
        _transactions._json_bytes(intent),
        "projection-rollback-intent",
    )
    if not target.exists() or _read_plain_bytes(target) != published:
        raise ConflictError("projection rollback target changed")
    _transactions._cas_checkpoint("before-projection-quarantine", target)
    try:
        _transactions._move_no_replace(root, target, quarantine)
    except (AgentMemoryError, ConflictError) as move_error:
        endpoint_hashes = {}
        for label, path in (("quarantine", quarantine), ("target", target)):
            if not path.exists():
                endpoint_hashes[label] = None
                continue
            endpoint_bytes = _read_plain_bytes(path)
            endpoint_hash = _sha256_bytes(endpoint_bytes)
            endpoint_hashes[label] = endpoint_hash
            preserve(
                recovery_directory / (label + "-" + endpoint_hash + ".bin"),
                endpoint_bytes,
                "projection-rollback-move-failure-" + label + "-" + endpoint_hash,
            )
        failure = {
            **_terminal_operation_fields(
                transaction_id,
                relative_target,
                published,
                prior,
            ),
            "endpoint_hashes": endpoint_hashes,
            "evidence_paths": sorted(set(evidence_paths)),
            "outcome": "quarantine-failed-closed",
        }
        failure_bytes = _transactions._json_bytes(failure)
        preserve(
            recovery_directory / ("terminal-" + _sha256_bytes(failure_bytes) + ".json"),
            failure_bytes,
            "projection-rollback-move-failure-terminal",
        )
        error = ConflictError("projection rollback quarantine failed closed")
        error.evidence_paths = tuple(sorted(set(evidence_paths)))
        raise error from move_error
    _transactions._cas_checkpoint("after-projection-quarantine", target)

    displaced_entry = _namespace_description(root, quarantine)
    if displaced_entry["kind"] != "regular":
        if _namespace_description(root, target)["kind"] == "absent":
            try:
                _transactions._move_no_replace(root, quarantine, target)
            except (AgentMemoryError, ConflictError):
                pass
        observed_entry = _namespace_description(root, target)
        retained_entry = (
            observed_entry
            if observed_entry["kind"] != "absent"
            else _namespace_description(root, quarantine)
        )
        if retained_entry["kind"] != "absent":
            evidence_paths.append(str(retained_entry["path"]))
        terminal = {
            **_terminal_operation_fields(
                transaction_id,
                relative_target,
                published,
                prior,
            ),
            "displaced": displaced_entry,
            "evidence_paths": sorted(set(evidence_paths)),
            "observed": observed_entry,
            "outcome": "conflict-preserved",
        }
        terminal_bytes = _transactions._json_bytes(terminal)
        preserve(
            recovery_directory / ("terminal-" + _sha256_bytes(terminal_bytes) + ".json"),
            terminal_bytes,
            "projection-rollback-nonregular-terminal-" + _sha256_bytes(terminal_bytes),
        )
        error = ConflictError("projection rollback retained non-regular namespace entry")
        error.evidence_paths = tuple(sorted(set(evidence_paths)))
        raise error

    displaced = _read_plain_bytes(quarantine)
    displaced_hash = _sha256_bytes(displaced)
    if displaced != published:
        unexpected_path = recovery_directory / ("unexpected-" + displaced_hash + ".bin")
        preserve(unexpected_path, displaced, "projection-rollback-unexpected-" + displaced_hash)

    restored = False
    target_entry = _namespace_description(root, target)
    if target_entry["kind"] == "absent":
        if displaced != published:
            restore_bytes = displaced
        else:
            restore_bytes = prior
        if restore_bytes is not None:
            try:
                _transactions._publish_exclusive(
                    target,
                    restore_bytes,
                    _sha256_bytes(
                        (
                            transaction_id
                            + "\0projection-rollback-restore\0"
                            + _sha256_bytes(restore_bytes)
                        ).encode("utf-8")
                    ),
                    root=root,
                )
                restored = True
            except ConflictError:
                restored = False
        else:
            restored = True

    observed_entry = _namespace_description(root, target)
    observed = (
        _read_plain_bytes(target)
        if observed_entry["kind"] == "regular"
        else None
    )
    if observed is not None:
        observed_hash = _sha256_bytes(observed)
        observed_path = recovery_directory / ("observed-" + observed_hash + ".bin")
        preserve(observed_path, observed, "projection-rollback-observed-" + observed_hash)
    else:
        observed_hash = None
        if observed_entry["kind"] != "absent":
            evidence_paths.append(str(observed_entry["path"]))
    expected_terminal = (
        displaced == published
        and restored
        and observed == prior
        and (
            observed_entry["kind"] == "regular"
            if prior is not None
            else observed_entry["kind"] == "absent"
        )
    )
    terminal = {
        **_terminal_operation_fields(
            transaction_id,
            relative_target,
            published,
            prior,
        ),
        "displaced": displaced_entry,
        "displaced_path": quarantine.relative_to(root).as_posix(),
        "displaced_sha256": displaced_hash,
        "evidence_paths": sorted(set(evidence_paths)),
        "observed_sha256": observed_hash,
        "observed": observed_entry,
        "outcome": "restored" if expected_terminal else "conflict-preserved",
    }
    terminal_bytes = _transactions._json_bytes(terminal)
    terminal_path = recovery_directory / (
        "terminal-" + _sha256_bytes(terminal_bytes) + ".json"
    )
    preserve(
        terminal_path,
        terminal_bytes,
        "projection-rollback-terminal-" + _sha256_bytes(terminal_bytes),
    )
    if not expected_terminal:
        error = ConflictError("projection rollback retained conflicting namespace bytes")
        error.evidence_paths = tuple(sorted(set(evidence_paths)))
        raise error
    return tuple(sorted(set(evidence_paths)))


def _is_safe_relative_evidence_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    portable = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return (
        not portable.is_absolute()
        and not windows.is_absolute()
        and portable.as_posix() == value
        and all(part not in ("", ".", "..") for part in portable.parts)
    )


def _terminal_hash_is_exact(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HASH_HEX for character in value)
    )


def _terminal_recovery_relative(transaction_id: str, relative_target: str) -> str:
    return ".agent-memory/transactions/projection-recovery/{0}/{1}".format(
        _sha256_bytes(transaction_id.encode("utf-8")),
        _sha256_bytes(relative_target.encode("utf-8")),
    )


def _terminal_namespace_description_is_exact(
    value: object,
    expected_path: str,
    allowed_kinds: Iterable[str],
) -> bool:
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    if (
        not isinstance(kind, str)
        or kind not in frozenset(allowed_kinds)
        or value.get("path") != expected_path
    ):
        return False
    if kind in ("absent", "unclassifiable"):
        return set(value) == {"kind", "path"}
    if set(value) != {"file_type", "kind", "path"}:
        return False
    file_type = value.get("file_type")
    if not isinstance(file_type, int) or isinstance(file_type, bool):
        return False
    if kind == "regular":
        return file_type == stat.S_IFREG
    if kind == "directory":
        return file_type == stat.S_IFDIR
    if kind == "special":
        return file_type not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK)
    return kind == "reparse"


def _terminal_evidence_paths(
    value: object,
    relative_target: str,
    recovery_relative: str,
) -> Optional[frozenset]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > _OPERATIONAL_LIMIT
        or any(not isinstance(item, str) for item in value)
        or value != sorted(set(value))
        or any(not _is_safe_relative_evidence_path(item) for item in value)
    ):
        return None
    if any(
        item != relative_target
        and item != recovery_relative
        and not item.startswith(recovery_relative + "/")
        for item in value
    ):
        return None
    intent = recovery_relative + "/intent.json"
    if intent not in value:
        return None
    return frozenset(value)


def _terminal_invalid_description_is_exact(
    value: object,
    recovery_relative: str,
) -> bool:
    if not isinstance(value, dict):
        return False
    path = value.get("path")
    if not _is_safe_relative_evidence_path(path):
        return False
    if path == recovery_relative:
        return value == {"kind": "unclassifiable", "path": recovery_relative}
    portable = PurePosixPath(path)
    if (
        portable.parent.as_posix() != recovery_relative
        or not portable.name.startswith("terminal-")
        or not portable.name.endswith(".json")
    ):
        return False
    kind = value.get("kind")
    if kind != "regular":
        return _terminal_namespace_description_is_exact(
            value,
            path,
            ("absent", "directory", "reparse", "special", "unclassifiable"),
        )
    base_keys = {"file_type", "kind", "path"}
    if not _terminal_namespace_description_is_exact(
        {key: value[key] for key in base_keys if key in value},
        path,
        ("regular",),
    ):
        return False
    keys = set(value)
    if keys == base_keys:
        return True
    if keys == base_keys.union({"raw_sha256"}):
        return _terminal_hash_is_exact(value.get("raw_sha256"))
    if keys == base_keys.union({"size"}):
        size = value.get("size")
        return (
            isinstance(size, int)
            and not isinstance(size, bool)
            and size > _OPERATIONAL_BYTE_LIMIT
        )
    return False


def _terminal_inventory_value_is_exact(value: object) -> bool:
    if value == {
        "count_at_least": _OPERATIONAL_LIMIT + 1,
        "limit": _OPERATIONAL_LIMIT,
    }:
        return True
    if not isinstance(value, dict) or set(value) != {
        "count",
        "invalid_count",
        "inventory_sha256",
        "limit",
        "listed_invalid_count",
        "valid_count",
    }:
        return False
    count = value.get("count")
    invalid_count = value.get("invalid_count")
    listed_count = value.get("listed_invalid_count")
    valid_count = value.get("valid_count")
    counts = (count, invalid_count, listed_count, valid_count)
    if any(not isinstance(item, int) or isinstance(item, bool) for item in counts):
        return False
    return (
        0 < count <= _OPERATIONAL_LIMIT
        and invalid_count >= 0
        and valid_count >= 0
        and count == invalid_count + valid_count
        and 0 <= listed_count <= min(invalid_count, _TERMINAL_DESCRIPTOR_PREVIEW_LIMIT)
        and value.get("limit") == _OPERATIONAL_LIMIT
        and _terminal_hash_is_exact(value.get("inventory_sha256"))
    )


def _terminal_base_evidence(
    recovery_relative: str,
    prior: Optional[bytes],
) -> frozenset:
    paths = {recovery_relative + "/intent.json"}
    if prior is not None:
        paths.add(recovery_relative + "/prior-" + _sha256_bytes(prior) + ".bin")
    return frozenset(paths)


def _terminal_unexpected_evidence(
    recovery_relative: str,
    prior: Optional[bytes],
    endpoints: Mapping[str, object],
    invalid: Iterable[Mapping[str, object]],
) -> frozenset:
    paths = set(_terminal_base_evidence(recovery_relative, prior))
    for label in ("quarantine", "target"):
        description = endpoints.get(label)
        if not isinstance(description, dict):
            continue
        kind = description.get("kind")
        path = description.get("path")
        if (
            isinstance(kind, str)
            and kind not in ("absent", "unclassifiable")
            and isinstance(path, str)
        ):
            paths.add(path)
    for description in invalid:
        if isinstance(description, dict) and isinstance(description.get("path"), str):
            paths.add(str(description["path"]))
    return frozenset(paths)


def _terminal_byte_fields_are_exact(
    value: Mapping[str, object],
    outcome: str,
    relative_target: str,
    recovery_relative: str,
    published: bytes,
    prior: Optional[bytes],
    evidence: frozenset,
) -> bool:
    quarantine = recovery_relative + "/displaced.bin"
    if not _terminal_namespace_description_is_exact(
        value.get("displaced"),
        quarantine,
        ("regular",),
    ) or value.get("displaced_path") != quarantine:
        return False
    displaced_hash = value.get("displaced_sha256")
    if not _terminal_hash_is_exact(displaced_hash):
        return False
    observed = value.get("observed")
    if not _terminal_namespace_description_is_exact(
        observed,
        relative_target,
        ("absent", "directory", "regular", "reparse", "special"),
    ):
        return False
    observed_hash = value.get("observed_sha256")
    if observed["kind"] == "regular":
        if not _terminal_hash_is_exact(observed_hash):
            return False
    elif observed_hash is not None:
        return False
    required = set(_terminal_base_evidence(recovery_relative, prior))
    if displaced_hash != _sha256_bytes(published):
        required.add(recovery_relative + "/unexpected-" + displaced_hash + ".bin")
    if isinstance(observed_hash, str):
        required.add(recovery_relative + "/observed-" + observed_hash + ".bin")
    elif observed["kind"] != "absent":
        required.add(relative_target)
    if evidence != frozenset(required):
        return False
    if outcome == "conflict-preserved":
        return True
    if displaced_hash != _sha256_bytes(published):
        return False
    if prior is None:
        return observed["kind"] == "absent" and observed_hash is None
    return observed["kind"] == "regular" and observed_hash == _sha256_bytes(prior)


def _terminal_namespace_fields_are_exact(
    value: Mapping[str, object],
    relative_target: str,
    recovery_relative: str,
    prior: Optional[bytes],
    evidence: frozenset,
) -> bool:
    quarantine = recovery_relative + "/displaced.bin"
    displaced = value.get("displaced")
    observed = value.get("observed")
    if not _terminal_namespace_description_is_exact(
        displaced,
        quarantine,
        ("absent", "directory", "reparse", "special"),
    ) or not _terminal_namespace_description_is_exact(
        observed,
        relative_target,
        ("absent", "directory", "regular", "reparse", "special"),
    ):
        return False
    required = set(_terminal_base_evidence(recovery_relative, prior))
    if observed["kind"] != "absent":
        required.add(relative_target)
        return evidence == frozenset(required)
    return evidence in (
        frozenset(required),
        frozenset(required.union({quarantine})),
    )


def _terminal_quarantine_fields_are_exact(
    value: Mapping[str, object],
    recovery_relative: str,
    prior: Optional[bytes],
    evidence: frozenset,
) -> bool:
    endpoint_hashes = value.get("endpoint_hashes")
    if not isinstance(endpoint_hashes, dict) or set(endpoint_hashes) != {
        "quarantine",
        "target",
    }:
        return False
    required = set(_terminal_base_evidence(recovery_relative, prior))
    for label in ("quarantine", "target"):
        endpoint_hash = endpoint_hashes[label]
        if endpoint_hash is not None and not _terminal_hash_is_exact(endpoint_hash):
            return False
        if isinstance(endpoint_hash, str):
            required.add(
                recovery_relative + "/" + label + "-" + endpoint_hash + ".bin"
            )
    return evidence == frozenset(required)


def _terminal_unexpected_fields_are_exact(
    value: Mapping[str, object],
    relative_target: str,
    recovery_relative: str,
    prior: Optional[bytes],
    evidence: frozenset,
) -> bool:
    error_type = value.get("error_type")
    if not isinstance(error_type, str) or not error_type:
        return False
    endpoints = value.get("endpoints")
    if not isinstance(endpoints, dict) or set(endpoints) != {"quarantine", "target"}:
        return False
    quarantine = recovery_relative + "/displaced.bin"
    endpoint_kinds = (
        "absent",
        "directory",
        "regular",
        "reparse",
        "special",
        "unclassifiable",
    )
    if not _terminal_namespace_description_is_exact(
        endpoints["quarantine"],
        quarantine,
        endpoint_kinds,
    ) or not _terminal_namespace_description_is_exact(
        endpoints["target"],
        relative_target,
        endpoint_kinds,
    ):
        return False
    invalid = value.get("invalid_terminals")
    if not isinstance(invalid, list) or len(invalid) > _TERMINAL_DESCRIPTOR_PREVIEW_LIMIT:
        return False
    if any(
        not _terminal_invalid_description_is_exact(item, recovery_relative)
        for item in invalid
    ):
        return False
    invalid_paths = [str(item["path"]) for item in invalid]
    if invalid_paths != sorted(set(invalid_paths)) or any(
        path not in evidence for path in invalid_paths
    ):
        return False
    inventory = value.get("terminal_inventory")
    if inventory is None:
        pass
    elif not _terminal_inventory_value_is_exact(inventory):
        return False
    elif "count_at_least" in inventory:
        if invalid:
            return False
    elif inventory.get("listed_invalid_count") != len(invalid):
        return False
    return evidence == _terminal_unexpected_evidence(
        recovery_relative,
        prior,
        endpoints,
        invalid,
    )


def _terminal_manifest_is_exact(
    value: Mapping[str, object],
    transaction_id: str,
    relative_target: str,
    published: bytes,
    prior: Optional[bytes],
) -> bool:
    if not isinstance(value, dict):
        return False
    common = _terminal_operation_fields(
        transaction_id,
        relative_target,
        published,
        prior,
    )
    if not set(common).issubset(value) or any(
        value[key] != expected for key, expected in common.items()
    ):
        return False
    outcome = value.get("outcome")
    recovery_relative = _terminal_recovery_relative(transaction_id, relative_target)
    evidence = _terminal_evidence_paths(
        value.get("evidence_paths"),
        relative_target,
        recovery_relative,
    )
    if evidence is None:
        return False
    base_keys = frozenset(common).union({"evidence_paths", "outcome"})
    byte_keys = base_keys.union(
        {"displaced", "displaced_path", "displaced_sha256", "observed", "observed_sha256"}
    )
    namespace_keys = base_keys.union({"displaced", "observed"})
    quarantine_keys = base_keys.union({"endpoint_hashes"})
    unexpected_keys = base_keys.union(
        {"endpoints", "error_type", "invalid_terminals"}
    )

    if outcome == "restored":
        return set(value) == byte_keys and _terminal_byte_fields_are_exact(
            value,
            outcome,
            relative_target,
            recovery_relative,
            published,
            prior,
            evidence,
        )
    if outcome == "conflict-preserved" and set(value) == byte_keys:
        return _terminal_byte_fields_are_exact(
            value,
            outcome,
            relative_target,
            recovery_relative,
            published,
            prior,
            evidence,
        )
    if outcome == "conflict-preserved" and set(value) == namespace_keys:
        return _terminal_namespace_fields_are_exact(
            value,
            relative_target,
            recovery_relative,
            prior,
            evidence,
        )
    if outcome == "quarantine-failed-closed":
        return set(value) == quarantine_keys and _terminal_quarantine_fields_are_exact(
            value,
            recovery_relative,
            prior,
            evidence,
        )
    if outcome != "unexpected-exception":
        return False
    inventory = value.get("terminal_inventory")
    expected_keys = (
        unexpected_keys.union({"terminal_inventory"})
        if inventory is not None
        else unexpected_keys
    )
    return set(value) == expected_keys and _terminal_unexpected_fields_are_exact(
        value,
        relative_target,
        recovery_relative,
        prior,
        evidence,
    )


def _terminal_entry(
    root: Path,
    path: Path,
) -> Tuple[Mapping[str, object], Optional[bytes]]:
    try:
        description = dict(_namespace_description(root, path))
    except Exception:
        return (
            {
                "kind": "unclassifiable",
                "path": path.relative_to(root).as_posix(),
            },
            None,
        )
    if description["kind"] != "regular":
        return description, None
    try:
        size = path.lstat().st_size
    except Exception:
        return description, None
    if size > _OPERATIONAL_BYTE_LIMIT:
        description["size"] = size
        return description, None
    try:
        raw = _read_operational_bytes(path)
    except Exception:
        try:
            return dict(_namespace_description(root, path)), None
        except Exception:
            return description, None
    description["raw_sha256"] = _sha256_bytes(raw)
    return description, raw


def _terminal_inventory(
    root: Path,
    recovery_directory: Path,
    transaction_id: str,
    relative_target: str,
    published: bytes,
    prior: Optional[bytes],
) -> Tuple[
    Tuple[Tuple[Path, Mapping[str, object]], ...],
    Tuple[Mapping[str, object], ...],
    Optional[Mapping[str, int]],
]:
    candidates = []
    try:
        children = recovery_directory.iterdir()
        for child in children:
            if not child.name.startswith("terminal-") or not child.name.endswith(".json"):
                continue
            candidates.append(child)
            if len(candidates) > _OPERATIONAL_LIMIT:
                return (
                    (),
                    (),
                    {
                        "count_at_least": _OPERATIONAL_LIMIT + 1,
                        "limit": _OPERATIONAL_LIMIT,
                    },
                )
    except Exception:
        return (
            (),
            (
                {
                    "kind": "unclassifiable",
                    "path": recovery_directory.relative_to(root).as_posix(),
                },
            ),
            None,
        )
    valid = []
    invalid = []
    for path in sorted(candidates, key=lambda item: item.name):
        description, raw = _terminal_entry(root, path)
        if raw is None:
            invalid.append(description)
            continue
        expected_name = "terminal-" + _sha256_bytes(raw) + ".json"
        if path.name != expected_name:
            invalid.append(description)
            continue
        try:
            value = _decode_json(raw, "projection rollback terminal")
        except ValidationError:
            invalid.append(description)
            continue
        if not _terminal_manifest_is_exact(
            value,
            transaction_id,
            relative_target,
            published,
            prior,
        ):
            invalid.append(description)
            continue
        valid.append((path, value))
    return tuple(valid), tuple(invalid), None


def _compact_terminal_inventory(
    valid: Iterable[Tuple[Path, Mapping[str, object]]],
    invalid: Iterable[Mapping[str, object]],
    excluded_path: Optional[Path] = None,
    listed_invalid_count: Optional[int] = None,
) -> Mapping[str, object]:
    valid_list = [entry for entry in valid if entry[0] != excluded_path]
    invalid_list = list(invalid)
    entries = []
    for path, _ in valid_list:
        name = path.name
        raw_hash = name[len("terminal-") : -len(".json")]
        entries.append(
            (
                name,
                0,
                {
                    "classification": "valid",
                    "name": name,
                    "raw_sha256": raw_hash,
                },
            )
        )
    for description in invalid_list:
        path = str(description["path"])
        entries.append(
            (
                PurePosixPath(path).name,
                1,
                {
                    "classification": "invalid",
                    "description": description,
                },
            )
        )
    digest = hashlib.sha256()
    digest.update(b"projection-terminal-inventory-v1\n")
    for _, _, entry in sorted(entries, key=lambda item: (item[0], item[1])):
        digest.update(_transactions._json_bytes(entry))
    if listed_invalid_count is None:
        listed_invalid_count = min(
            len(invalid_list),
            _TERMINAL_DESCRIPTOR_PREVIEW_LIMIT,
        )
    return {
        "count": len(valid_list) + len(invalid_list),
        "invalid_count": len(invalid_list),
        "inventory_sha256": digest.hexdigest(),
        "limit": _OPERATIONAL_LIMIT,
        "listed_invalid_count": listed_invalid_count,
        "valid_count": len(valid_list),
    }


def _matching_terminal_replay(
    valid: Iterable[Tuple[Path, Mapping[str, object]]],
    invalid: Iterable[Mapping[str, object]],
    inventory: Optional[Mapping[str, int]],
) -> Optional[Tuple[Path, Mapping[str, object]]]:
    valid_list = list(valid)
    invalid_list = list(invalid)
    if inventory is not None:
        candidates = [
            (path, manifest)
            for path, manifest in valid_list
            if manifest.get("terminal_inventory") == inventory
            and manifest.get("invalid_terminals", []) == invalid_list
        ]
        return candidates[0] if len(candidates) == 1 else None
    if len(valid_list) == 1:
        path, manifest = valid_list[0]
        if (
            manifest.get("terminal_inventory") is None
            and manifest.get("invalid_terminals", []) == invalid_list
        ):
            return path, manifest
    compact_candidates = []
    expected_count = len(valid_list) - 1 + len(invalid_list)
    for path, manifest in valid_list:
        manifest_inventory = manifest.get("terminal_inventory")
        if not isinstance(manifest_inventory, dict) or "count" not in manifest_inventory:
            continue
        listed_count = manifest_inventory.get("listed_invalid_count")
        if (
            manifest_inventory.get("count") != expected_count
            or manifest_inventory.get("invalid_count") != len(invalid_list)
            or manifest_inventory.get("valid_count") != len(valid_list) - 1
            or not isinstance(listed_count, int)
            or isinstance(listed_count, bool)
            or manifest.get("invalid_terminals") != invalid_list[:listed_count]
        ):
            continue
        compact_candidates.append((path, manifest))
    if len(compact_candidates) != 1:
        return None
    path, manifest = compact_candidates[0]
    listed_count = manifest["terminal_inventory"]["listed_invalid_count"]
    expected_inventory = _compact_terminal_inventory(
        valid_list,
        invalid_list,
        excluded_path=path,
        listed_invalid_count=listed_count,
    )
    if manifest["terminal_inventory"] == expected_inventory:
        return path, manifest
    return None


def _rollback_terminal_error(
    message: str,
    cause: Exception,
    evidence_paths: Iterable[str],
) -> ConflictError:
    error = ConflictError(message)
    error.evidence_paths = tuple(sorted(set(evidence_paths)))
    error.__cause__ = cause
    return error


def _rollback_projection(
    root: Path,
    target: Path,
    published: bytes,
    prior: Optional[bytes],
    transaction_id: str,
) -> Tuple[str, ...]:
    try:
        return _rollback_projection_once(
            root,
            target,
            published,
            prior,
            transaction_id,
        )
    except Exception as rollback_error:
        relative_target = target.relative_to(root).as_posix()
        recovery_directory = (
            root
            / ".agent-memory"
            / "transactions"
            / "projection-recovery"
            / _sha256_bytes(transaction_id.encode("utf-8"))
            / _sha256_bytes(relative_target.encode("utf-8"))
        )
        intent_path = recovery_directory / "intent.json"
        if not intent_path.exists():
            raise

        valid, invalid, inventory = _terminal_inventory(
            root,
            recovery_directory,
            transaction_id,
            relative_target,
            published,
            prior,
        )
        replay = _matching_terminal_replay(valid, invalid, inventory)
        if replay is not None:
            replay_path, replay_manifest = replay
            replay_evidence = list(replay_manifest["evidence_paths"])
            replay_evidence.append(replay_path.relative_to(root).as_posix())
            raise _rollback_terminal_error(
                "projection rollback replayed exact terminal evidence",
                rollback_error,
                replay_evidence,
            )

        endpoints = {}
        for label, path in (
            ("quarantine", recovery_directory / "displaced.bin"),
            ("target", target),
        ):
            try:
                description = _namespace_description(root, path)
            except Exception:
                description = {
                    "kind": "unclassifiable",
                    "path": path.relative_to(root).as_posix(),
                }
            endpoints[label] = description
        recovery_relative = recovery_directory.relative_to(root).as_posix()

        def terminal_manifest(
            valid_entries: Iterable[Tuple[Path, Mapping[str, object]]],
            invalid_entries: Iterable[Mapping[str, object]],
            terminal_inventory: Optional[Mapping[str, int]],
        ) -> Tuple[bytes, Path, List[str]]:
            valid_list = list(valid_entries)
            invalid_list = list(invalid_entries)
            if terminal_inventory is not None:
                listed_invalid = []
                recorded_inventory = terminal_inventory
            elif valid_list or len(invalid_list) > _TERMINAL_DESCRIPTOR_PREVIEW_LIMIT:
                listed_invalid = invalid_list[:_TERMINAL_DESCRIPTOR_PREVIEW_LIMIT]
                recorded_inventory = _compact_terminal_inventory(
                    valid_list,
                    invalid_list,
                    listed_invalid_count=len(listed_invalid),
                )
            else:
                listed_invalid = list(invalid_list)
                recorded_inventory = None
            while True:
                evidence_paths = sorted(
                    _terminal_unexpected_evidence(
                        recovery_relative,
                        prior,
                        endpoints,
                        listed_invalid,
                    )
                )
                value = {
                    **_terminal_operation_fields(
                        transaction_id,
                        relative_target,
                        published,
                        prior,
                    ),
                    "endpoints": endpoints,
                    "error_type": type(rollback_error).__name__,
                    "evidence_paths": evidence_paths,
                    "invalid_terminals": list(listed_invalid),
                    "outcome": "unexpected-exception",
                }
                if recorded_inventory is not None:
                    value["terminal_inventory"] = recorded_inventory
                raw = _transactions._json_bytes(value)
                if len(raw) <= _OPERATIONAL_BYTE_LIMIT:
                    path = recovery_directory / (
                        "terminal-" + _sha256_bytes(raw) + ".json"
                    )
                    return raw, path, evidence_paths
                if not listed_invalid:
                    raise _rollback_terminal_error(
                        "projection rollback terminal exceeded byte limit",
                        rollback_error,
                        evidence_paths,
                    )
                if recorded_inventory is None:
                    recorded_inventory = _compact_terminal_inventory(
                        valid_list,
                        invalid_list,
                    )
                listed_invalid = listed_invalid[: len(listed_invalid) // 2]
                recorded_inventory = dict(recorded_inventory)
                recorded_inventory["listed_invalid_count"] = len(listed_invalid)

        def replay_exact_terminal(path: Path, raw: bytes, evidence_paths: List[str]) -> None:
            try:
                existing = _read_operational_bytes(path)
            except (AgentMemoryError, OSError):
                return
            if existing == raw:
                replay_evidence = list(evidence_paths)
                replay_evidence.append(path.relative_to(root).as_posix())
                raise _rollback_terminal_error(
                    "projection rollback replayed exact terminal evidence",
                    rollback_error,
                    replay_evidence,
                )

        terminal_bytes, terminal_path, evidence_paths = terminal_manifest(
            valid,
            invalid,
            inventory,
        )
        replay_exact_terminal(terminal_path, terminal_bytes, evidence_paths)
        try:
            _transactions._publish_exclusive(
                terminal_path,
                terminal_bytes,
                _sha256_bytes(
                    (transaction_id + "\0projection-rollback-fallback-terminal").encode("utf-8")
                ),
                root=root,
            )
        except ConflictError:
            valid, invalid, inventory = _terminal_inventory(
                root,
                recovery_directory,
                transaction_id,
                relative_target,
                published,
                prior,
            )
            replay = _matching_terminal_replay(valid, invalid, inventory)
            if replay is not None:
                replay_path, replay_manifest = replay
                replay_evidence = list(replay_manifest["evidence_paths"])
                replay_evidence.append(replay_path.relative_to(root).as_posix())
                raise _rollback_terminal_error(
                    "projection rollback replayed exact terminal evidence",
                    rollback_error,
                    replay_evidence,
                )
            terminal_bytes, terminal_path, evidence_paths = terminal_manifest(
                valid,
                invalid,
                inventory,
            )
            replay_exact_terminal(terminal_path, terminal_bytes, evidence_paths)
            try:
                _transactions._publish_exclusive(
                    terminal_path,
                    terminal_bytes,
                    _sha256_bytes(
                        (
                            transaction_id
                            + "\0projection-rollback-reclassified-terminal"
                        ).encode("utf-8")
                    ),
                    root=root,
                )
            except ConflictError as second_publication_error:
                conflict_evidence = list(evidence_paths)
                conflict_evidence.append(terminal_path.relative_to(root).as_posix())
                raise _rollback_terminal_error(
                    "projection rollback terminal publication conflicted",
                    second_publication_error,
                    conflict_evidence,
                )
        terminal_evidence = list(evidence_paths)
        terminal_evidence.append(terminal_path.relative_to(root).as_posix())
        raise _rollback_terminal_error(
            "projection rollback failed with terminal evidence",
            rollback_error,
            terminal_evidence,
        )


def _projection_transaction_path(
    root: Path,
    transaction_id: str,
    relative_target: str,
) -> Tuple[Path, str, str]:
    context_hash = _sha256_bytes(transaction_id.encode("utf-8"))
    target_hash = _sha256_bytes(relative_target.encode("utf-8"))
    return (
        root
        / ".agent-memory"
        / "transactions"
        / "projections"
        / context_hash
        / (target_hash + ".json"),
        context_hash,
        target_hash,
    )


def _bind_unguarded_projection_context(
    root: Path,
    transaction_path: Path,
    context_hash: str,
    target_hash: str,
    relative_target: str,
    transaction_id: str,
) -> None:
    context_directory = transaction_path.parent
    if context_directory.exists():
        _transactions._assert_plain_path(context_directory)
        for child in context_directory.glob("*.json"):
            _transactions._assert_plain_file(child)
            child_hash = child.stem
            _validate_hash(child_hash, "projection transaction target path hash")
            if child_hash != target_hash:
                raise ConflictError("unguarded projection context is bound to another target")
    claim = {
        "context_sha256": context_hash,
        "schema_version": 2,
        "target": relative_target,
        "target_path_sha256": target_hash,
        "transaction_id": transaction_id,
    }
    claim_bytes = _transactions._json_bytes(claim)
    claim_path = context_directory / "unguarded-target.claim"
    if claim_path.exists():
        if _read_operational_bytes(claim_path) != claim_bytes:
            raise ConflictError("unguarded projection context claim is occupied")
        return
    try:
        _transactions._publish_exclusive(
            claim_path,
            claim_bytes,
            _sha256_bytes((transaction_id + "\0unguarded-projection-claim").encode("utf-8")),
            root=root,
        )
    except ConflictError:
        if _read_operational_bytes(claim_path) != claim_bytes:
            raise ConflictError("unguarded projection context claim is occupied")


def _accepted_projection_replay(
    root: Path,
    target: Path,
    transaction_path: Path,
    intent: Mapping[str, object],
) -> Optional[Path]:
    if not transaction_path.exists():
        return None
    raw = _read_operational_bytes(transaction_path)
    evidence = _decode_json(raw, "projection transaction")
    expected = dict(intent)
    expected["status"] = "accepted"
    if evidence != expected:
        raise ConflictError("projection transaction evidence is occupied")
    if not target.exists() or _sha256_bytes(_read_plain_bytes(target)) != intent["desired"]["target_sha256"]:
        raise ConflictError("accepted projection replay target changed")
    return target


def publish_projection(
    root: Path,
    document: ProjectionDocument,
    context: TransactionContext,
    replace_drift: bool = False,
    guard: Optional[RootWriteGuard] = None,
) -> Path:
    _transactions._validate_context(context)
    if not isinstance(document, ProjectionDocument):
        raise ValidationError("invalid projection document")
    relative = _target_relative_path(document.relative_path)
    if not isinstance(replace_drift, bool):
        raise ValidationError("replace_drift must be boolean")
    _validate_hash(document.source_revision, "source_revision")
    _validate_hash(document.expected_target_sha256, "expected_target_sha256", allow_none=True)
    fields, body = _parse_projection(document.content)
    if (
        fields["source_revision"] != document.source_revision
        or fields["observed_at"] != document.observed_at
        or _sha256_bytes(normalize_body(body).encode("utf-8"))
        != fields["projection_body_sha256"]
    ):
        raise ValidationError("projection document fields disagree")
    generator_version = fields["generator_version"]
    root = _transactions._prepare_root(root)
    if guard is not None:
        _transactions._require_guard(root, context, guard)
    target = root / relative
    transaction_path, context_hash, target_path_hash = _projection_transaction_path(
        root,
        context.transaction_id,
        document.relative_path,
    )
    content_bytes = document.content.encode("utf-8")
    content_hash = _sha256_bytes(content_bytes)
    intent = {
        "actor": context.actor,
        "desired": {
            "content_sha256": content_hash,
            "source_revision": document.source_revision,
            "target_sha256": content_hash,
        },
        "expected_base": {
            "source_revision": document.source_revision,
            "target_sha256": document.expected_target_sha256,
        },
        "occurred_at": context.occurred_at,
        "operation": "publish_projection",
        "projection_evidence": {
            "context_sha256": context_hash,
            "target_path_sha256": target_path_hash,
        },
        "schema_version": 2,
        "status": "in-progress",
        "target": document.relative_path,
        "transaction_id": context.transaction_id,
    }
    intent_bytes = _transactions._json_bytes(intent)
    if guard is None:
        if not transaction_path.exists():
            _verify_document_matches_canonical(
                root,
                document,
                generator_version,
                context.transaction_id,
            )
        _bind_unguarded_projection_context(
            root,
            transaction_path,
            context_hash,
            target_path_hash,
            document.relative_path,
            context.transaction_id,
        )
    if transaction_path.exists():
        with _transactions._with_guard(root, context, guard):
            replay = _accepted_projection_replay(
                root,
                target,
                transaction_path,
                intent,
            )
            if replay is not None:
                return replay
    _transactions._publish_exclusive(
        transaction_path,
        intent_bytes,
        _sha256_bytes((context.transaction_id + "\0projection-intent").encode("utf-8")),
        root=root,
    )

    with _transactions._with_guard(root, context, guard):
        _verify_document_matches_canonical(
            root,
            document,
            generator_version,
            context.transaction_id,
        )
        _projection_checkpoint("after-input-recheck", root, target)
        with _transactions._narrow_lock(
            root,
            _projection_lock_name(document.relative_path),
            context,
            Path(".agent-memory/state/locks"),
        ):
            prior: Optional[bytes]
            if document.expected_target_sha256 is None:
                if target.exists():
                    raise ConflictError("projection target appeared after build")
                prior = None
            else:
                if not target.exists():
                    raise ConflictError("projection target disappeared after build")
                prior = _read_plain_bytes(target)
                target_matches = _sha256_bytes(prior) == document.expected_target_sha256
                if not target_matches:
                    raise ConflictError("projection target changed after build")
                target_is_intact = _projection_is_intact(prior)
                if not target_is_intact:
                    if not replace_drift:
                        raise ProjectionDriftError("projection body has manual drift")
                    _backup_drift(root, prior, context.transaction_id)

            publication_token = _sha256_bytes(
                (
                    context.transaction_id
                    + "\0"
                    + (document.expected_target_sha256 or "absent")
                    + "\0"
                    + content_hash
                ).encode("utf-8")
            )
            if prior is None:
                _transactions._publish_exclusive(
                    target,
                    content_bytes,
                    publication_token,
                    root=root,
                )
            else:
                _transactions._replace_cas(
                    target,
                    prior,
                    content_bytes,
                    publication_token,
                    root=root,
                )
            _projection_checkpoint("after-target-replace", root, target)

            if document.relative_path == "_index/stale-or-uncertain.md":
                try:
                    _verify_document_matches_canonical(
                        root,
                        document,
                        generator_version,
                        context.transaction_id,
                    )
                except ConflictError as input_error:
                    _projection_checkpoint("before-rollback-cas", root, target)
                    try:
                        _rollback_projection(
                            root,
                            target,
                            content_bytes,
                            prior,
                            context.transaction_id,
                        )
                    except ConflictError as rollback_error:
                        observed_entry = _namespace_description(root, target)
                        observed_hash = (
                            _sha256_bytes(_read_plain_bytes(target))
                            if observed_entry["kind"] == "regular"
                            else None
                        )
                        recovery = {
                            "evidence_paths": list(
                                getattr(rollback_error, "evidence_paths", ())
                            ),
                            "failure_code": "rollback-target-drift",
                            "observed_sha256": observed_hash,
                            "observed": observed_entry,
                            "prior_sha256": _sha256_bytes(prior) if prior is not None else None,
                            "published_sha256": content_hash,
                            "target": document.relative_path,
                        }
                        recovery_intent = dict(intent)
                        recovery_intent["projection_recovery"] = recovery
                        _transactions._finalize_transaction(
                            transaction_path,
                            intent_bytes,
                            _transactions._json_bytes(recovery_intent),
                            context.transaction_id,
                        )
                        raise ConflictError("projection rollback CAS failed") from rollback_error
                    raise ConflictError("projection operational inputs changed; publication rolled back") from input_error

            final = dict(intent)
            final["status"] = "accepted"
            _transactions._finalize_transaction(
                transaction_path,
                intent_bytes,
                _transactions._json_bytes(final),
                context.transaction_id,
            )
            return target
