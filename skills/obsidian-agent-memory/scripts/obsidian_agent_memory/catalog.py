"""Trusted, bounded reads of the canonical accepted-record catalog."""

import hmac
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Mapping, Tuple

from .adapters import (
    _contained_raw_path,
    _plain_contained_metadata,
    _raw_absolute,
    _read_plain_contained_utf8,
    _resolve_inside_safely,
    _validate_portable_components,
)
from .errors import ValidationError
from .models import (
    AcceptedRecord,
    CatalogEntry,
    CatalogSnapshot,
    ReadAdapter,
    RecordEnvelope,
)
from .paths import validate_identifier
from .records import (
    compute_body_sha256,
    normalize_body,
    parse_record,
    record_relative_path,
)


_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_CATALOG_ENTRIES = 10000
_CATALOG_KEYS = frozenset(("records", "revision", "schema_version"))
_ENTRY_KEYS = frozenset(
    (
        "memory_id",
        "owner_scope",
        "project",
        "record_type",
        "relative_path",
        "revision",
    )
)
_VALIDATION_TIMESTAMP = "2000-01-01T00:00:00Z"


def _reject_duplicate_keys(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValidationError("JSON document contains duplicate keys")
        document[key] = value
    return document


def _parse_json_document(text: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ValidationError:
        raise
    except (TypeError, ValueError) as error:
        raise ValidationError("invalid catalog JSON") from error


def _operational_path(root: Path, *parts: str) -> Path:
    raw_root = _raw_absolute(root)
    target = raw_root.joinpath(".agent-memory", *parts)
    return _contained_raw_path(raw_root, target)


def _selected_record_path(root: Path, relative_path: str) -> Tuple[Path, str]:
    normalized = _validate_selected_record_relative_path(relative_path)
    pure_path = PurePosixPath(normalized)
    raw_root = _raw_absolute(root)
    records_root = raw_root / "_records"
    target = raw_root.joinpath(*pure_path.parts)
    raw_target = _contained_raw_path(raw_root, target)
    _plain_contained_metadata(raw_root, raw_target, allow_missing=True)
    _resolve_inside_safely(records_root, *pure_path.parts[1:])
    return raw_target, normalized


def _validate_selected_record_relative_path(relative_path: str) -> str:
    if not isinstance(relative_path, str) or not relative_path or "\\" in relative_path:
        raise ValidationError("invalid catalog record path")
    pure_path = PurePosixPath(relative_path)
    if (
        pure_path.is_absolute()
        or PureWindowsPath(relative_path).is_absolute()
        or pure_path.as_posix() != relative_path
        or len(pure_path.parts) < 2
        or pure_path.parts[0] != "_records"
        or any(part in (".", "..") for part in pure_path.parts)
    ):
        raise ValidationError("invalid catalog record path")
    _validate_portable_components(pure_path.parts[1:])
    return pure_path.as_posix()


def _entry_validation_envelope(entry: Mapping[str, object]) -> RecordEnvelope:
    return RecordEnvelope(
        memory_id=entry["memory_id"],
        record_type=entry["record_type"],
        schema_version=2,
        owner_scope=entry["owner_scope"],
        project=entry["project"],
        revision=entry["revision"],
        supersedes=None,
        created_at=_VALIDATION_TIMESTAMP,
        observed_at=_VALIDATION_TIMESTAMP,
        source="catalog",
        source_revision="schema-2",
        body_sha256="0" * 64,
    )


def _catalog_entry(root: Path, catalog_id: object, value: object) -> CatalogEntry:
    if not isinstance(catalog_id, str):
        raise ValidationError("invalid catalog memory ID")
    memory_id = validate_identifier(catalog_id, "catalog memory_id")
    if not isinstance(value, dict) or set(value) != _ENTRY_KEYS:
        raise ValidationError("invalid catalog entry shape")
    if value["memory_id"] != memory_id:
        raise ValidationError("catalog entry memory ID mismatch")
    validate_identifier(value["memory_id"], "catalog memory_id")
    revision = value["revision"]
    if type(revision) is not int or revision <= 0:
        raise ValidationError("invalid catalog record revision")
    for field in ("record_type", "owner_scope"):
        validate_identifier(value[field], "catalog {0}".format(field))
    project = value["project"]
    if project is not None:
        validate_identifier(project, "catalog project")

    normalized_path = _validate_selected_record_relative_path(value["relative_path"])
    expected_path = record_relative_path(_entry_validation_envelope(value)).as_posix()
    if normalized_path != expected_path:
        raise ValidationError("catalog entry selects a noncanonical record path")
    return CatalogEntry(
        memory_id,
        revision,
        normalized_path,
        value["record_type"],
        value["owner_scope"],
        project,
    )


def _parse_catalog_bytes(root: Path, raw: bytes) -> CatalogSnapshot:
    """Validate already captured catalog bytes without reading selected records."""
    if not isinstance(raw, bytes) or len(raw) > _MAX_DOCUMENT_BYTES:
        raise ValidationError("invalid catalog bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError("invalid catalog UTF-8") from error
    document = _parse_json_document(text)
    if not isinstance(document, dict) or set(document) != _CATALOG_KEYS:
        raise ValidationError("invalid catalog shape")
    if type(document["schema_version"]) is not int or document["schema_version"] != 2:
        raise ValidationError("unsupported catalog schema")
    revision = document["revision"]
    records = document["records"]
    if type(revision) is not int or revision < 0 or not isinstance(records, dict):
        raise ValidationError("invalid catalog state")
    if len(records) > _MAX_CATALOG_ENTRIES:
        raise ValidationError("catalog contains more than 10000 entries")
    entries = tuple(
        _catalog_entry(root, memory_id, records[memory_id])
        for memory_id in sorted(records)
    )
    return CatalogSnapshot(revision, entries)


def load_catalog(root: Path) -> CatalogSnapshot:
    """Load and strictly validate the one canonical catalog document."""
    catalog_path = _operational_path(root, "state", "catalog.json")
    text = _read_plain_contained_utf8(root, catalog_path, _MAX_DOCUMENT_BYTES, "catalog")
    return _parse_catalog_bytes(root, text.encode("utf-8"))


def _accepted_record_from_text(
    entry: CatalogEntry,
    catalog_revision: int,
    text: str,
) -> AcceptedRecord:
    if not isinstance(text, str):
        raise ValidationError("accepted record adapter returned non-text")
    try:
        raw = text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValidationError("accepted record is not valid UTF-8") from error
    if len(raw) > _MAX_DOCUMENT_BYTES:
        raise ValidationError("accepted record exceeds the size limit")

    envelope, body = parse_record(text)
    expected_path = record_relative_path(envelope).as_posix()
    if entry.relative_path != expected_path:
        raise ValidationError("accepted record path mismatch")
    if (
        entry.memory_id != envelope.memory_id
        or entry.revision != envelope.revision
        or entry.record_type != envelope.record_type
        or entry.owner_scope != envelope.owner_scope
        or entry.project != envelope.project
    ):
        raise ValidationError("accepted record identity mismatch")
    recomputed_hash = compute_body_sha256(normalize_body(body))
    if not hmac.compare_digest(envelope.body_sha256, recomputed_hash):
        raise ValidationError("accepted record body hash mismatch")
    return AcceptedRecord(envelope, body, entry.relative_path, catalog_revision)


def _parse_accepted_record_bytes(
    entry: CatalogEntry,
    catalog_revision: int,
    raw: bytes,
) -> AcceptedRecord:
    if not isinstance(raw, bytes) or len(raw) > _MAX_DOCUMENT_BYTES:
        raise ValidationError("invalid accepted record bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError("accepted record is not valid UTF-8") from error
    return _accepted_record_from_text(entry, catalog_revision, text)


def read_accepted_record(root: Path, memory_id: str) -> AcceptedRecord:
    """Read exactly the immutable record selected by the canonical catalog."""
    selected_id = validate_identifier(memory_id, "memory_id")
    snapshot = load_catalog(root)
    selected = next(
        (entry for entry in snapshot.entries if entry.memory_id == selected_id), None
    )
    if selected is None:
        raise ValidationError("accepted record is not present in the catalog")
    record_path, normalized_path = _selected_record_path(root, selected.relative_path)
    if normalized_path != selected.relative_path:
        raise ValidationError("accepted record path mismatch")
    text = _read_plain_contained_utf8(
        root, record_path, _MAX_DOCUMENT_BYTES, "accepted record"
    )
    return _accepted_record_from_text(selected, snapshot.revision, text)


def search_accepted_records(
    root: Path,
    adapter: ReadAdapter,
    query: str,
    limit: int = 20,
) -> Tuple[AcceptedRecord, ...]:
    """Search only catalog-selected immutable records in deterministic order."""
    if not isinstance(query, str) or not query.strip():
        raise ValidationError("query must be non-empty text")
    if type(limit) is not int or limit <= 0:
        raise ValidationError("limit must be a positive integer")
    normalized_query = query.strip().casefold()
    snapshot = load_catalog(root)
    matches = []
    for entry in snapshot.entries:
        record_path, normalized_path = _selected_record_path(root, entry.relative_path)
        if normalized_path != entry.relative_path:
            raise ValidationError("accepted record path mismatch")
        _plain_contained_metadata(root, record_path, expected_kind="file")
        text = adapter.read(entry.relative_path)
        accepted = _accepted_record_from_text(entry, snapshot.revision, text)
        if normalized_query in text.casefold():
            matches.append(accepted)
            if len(matches) == limit:
                break
    return tuple(matches)
