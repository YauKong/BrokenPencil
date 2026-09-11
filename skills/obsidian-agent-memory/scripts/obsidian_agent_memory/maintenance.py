"""Deterministic, bounded, read-only maintenance audits."""

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import List, Literal, Mapping, Optional, Sequence, Tuple

from .artifact_schemas import parse_proposal_artifact
from .catalog import load_catalog, read_accepted_record
from .errors import AgentMemoryError, PlanInvalidatedError, ValidationError
from .models import AcceptedRecord, CatalogSnapshot, Finding, TransactionContext
from .operation_scope import AuthorizationGate, require_operation_gate
from .paths import validate_identifier
from .projections import build_project_views, build_root_views
from .records import parse_record
from .transactions import recover_root_write_guard
from .validation import doctor_memory_root


_MAX_FILES = 10000
_MAX_DIRECTORIES = 10000
_MAX_FILE_BYTES = 1024 * 1024
_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_TEXT_SUFFIXES = frozenset((".json", ".md", ".txt", ".yaml", ".yml"))
_COUNT_KEYS = (
    "accepted-records",
    "findings-error",
    "findings-total",
    "findings-warning",
    "locks",
    "migration-artifacts",
    "projections",
    "proposals",
    "sources",
    "transactions",
)
_ROOT_PROJECTIONS = frozenset(
    (
        "_index/current-focus.md",
        "_index/home.md",
        "_index/memory-map.md",
        "_index/stale-or-uncertain.md",
    )
)
_SECRET_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\b"
    r"\s*[:=]\s*[\"']?([a-z0-9][a-z0-9._/+-]{7,})"
)
_RAW_CHAT_PATTERN = re.compile(
    r"(?im)^(?:user|human|assistant|chatgpt|system)\s*:\s*\S"
)
_WIKILINK_PATTERN = re.compile(r"\[\[([^\[\]\n]+)\]\]")
_HISTORY_PATTERN = re.compile(
    r"(?im)^#{1,6}\s+(?:history|historical|completed|previous|archive(?:d)?)\s*$"
)


@dataclass(frozen=True)
class MaintenanceAudit:
    schema_version: int
    source_revision: str
    authorization_ref: Optional[str]
    findings: Tuple[Finding, ...]
    counts: Tuple[Tuple[str, int], ...]


class CleanupDisposition(str, Enum):
    MERGE = "merge"
    SUPERSEDE = "supersede"
    ARCHIVE = "archive"
    REGENERATE = "regenerate"
    DELETE = "delete"
    REVIEW = "review"


@dataclass(frozen=True)
class CleanupAction:
    action_id: str
    finding_code: str
    disposition: CleanupDisposition
    source_paths: Tuple[str, ...]
    expected_hashes: Tuple[Tuple[str, str], ...]
    target_owner: Optional[str]
    reason: str
    requires_explicit_approval: bool


@dataclass(frozen=True)
class CleanupPlan:
    plan_id: str
    source_revision: str
    actor: str
    created_at: str
    authorization_ref: Optional[str]
    actions: Tuple[CleanupAction, ...]
    blocked_actions: Tuple[CleanupAction, ...]


@dataclass(frozen=True)
class GuardRecoveryResult:
    status: Literal["recovered"]
    target_transaction_id: str
    recovery_transaction_id: str
    recovered_kind: Literal["canonical-lock", "candidate-only"]
    evidence_path: str
    recovered_artifact_sha256: str


DEFAULT_DISPOSITIONS = {
    "duplicate-durable-owner": CleanupDisposition.MERGE,
    "stale-current-record": CleanupDisposition.SUPERSEDE,
    "fragmented-story": CleanupDisposition.MERGE,
    "current-focus-history": CleanupDisposition.REGENERATE,
    "obsolete-schema-path": CleanupDisposition.ARCHIVE,
    "raw-chat-pattern": CleanupDisposition.REVIEW,
    "broken-wikilink": CleanupDisposition.REVIEW,
    "unresolved-proposal": CleanupDisposition.REVIEW,
    "secret-pattern": CleanupDisposition.REVIEW,
    "orphaned-migration-artifact": CleanupDisposition.REVIEW,
    "projection-drift": CleanupDisposition.REGENERATE,
    "stale-lock-review": CleanupDisposition.REVIEW,
    "root-write-recovery-incomplete": CleanupDisposition.REVIEW,
    "embedded-knowledge-decision": CleanupDisposition.REVIEW,
}
_BLOCKED_FINDING_CODES = frozenset(
    (
        "embedded-knowledge-decision",
        "orphaned-migration-artifact",
        "raw-chat-pattern",
        "root-write-recovery-incomplete",
        "stale-lock-review",
        "unresolved-proposal",
    )
)


@dataclass(frozen=True)
class _AuditFile:
    relative_path: str
    raw: bytes
    sha256: str


@dataclass(frozen=True)
class _Inventory:
    files: Tuple[_AuditFile, ...]
    directories: Tuple[str, ...]


def _is_reparse(metadata) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_FLAG)


def _inventory_vault(root: Path) -> _Inventory:
    files = []
    directories = []
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(str(directory)) as stream:
                children = sorted(stream, key=lambda item: item.name)
        except OSError as error:
            raise ValidationError("unable to inventory memory root") from error
        for child in children:
            relative = child.name if not prefix else prefix + "/" + child.name
            try:
                metadata = os.lstat(child.path)
            except OSError as error:
                raise ValidationError("unable to inventory memory root") from error
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                raise ValidationError("audit inventory contains a reparse point")
            if stat.S_ISDIR(metadata.st_mode):
                if relative == ".git" or relative.startswith(".git/"):
                    continue
                directories.append(relative)
                if len(directories) > _MAX_DIRECTORIES:
                    raise ValidationError("audit directory inventory exceeds the limit")
                pending.append((Path(child.path), relative))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValidationError("audit inventory contains a non-regular file")
            if len(files) >= _MAX_FILES:
                raise ValidationError("audit file inventory exceeds the limit")
            if metadata.st_size > _MAX_FILE_BYTES:
                raise ValidationError("audit file exceeds the size limit")
            try:
                with open(child.path, "rb") as handle:
                    opened = os.fstat(handle.fileno())
                    if not stat.S_ISREG(opened.st_mode) or _is_reparse(opened):
                        raise ValidationError("audit inventory contains a non-regular file")
                    raw = handle.read(_MAX_FILE_BYTES + 1)
            except ValidationError:
                raise
            except OSError as error:
                raise ValidationError("unable to read audit inventory") from error
            if len(raw) > _MAX_FILE_BYTES or len(raw) != opened.st_size:
                raise ValidationError("audit file exceeds or changed within the size limit")
            files.append(
                _AuditFile(relative, raw, hashlib.sha256(raw).hexdigest())
            )
    return _Inventory(
        tuple(sorted(files, key=lambda item: item.relative_path)),
        tuple(sorted(directories)),
    )


def _source_revision(files: Sequence[_AuditFile]) -> str:
    document = [
        {"path": item.relative_path, "sha256": item.sha256, "size": len(item.raw)}
        for item in files
    ]
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _decode_text(item: _AuditFile) -> Optional[str]:
    suffix = PurePosixPath(item.relative_path).suffix.lower()
    if suffix not in _TEXT_SUFFIXES:
        return None
    try:
        return item.raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _json_document(item: _AuditFile) -> Optional[object]:
    try:
        return json.loads(
            item.raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, ValueError):
        return None


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _catalog_records(root: Path) -> Tuple[Optional[CatalogSnapshot], Tuple[AcceptedRecord, ...]]:
    try:
        catalog = load_catalog(root)
    except AgentMemoryError:
        return None, ()
    records = []
    for entry in catalog.entries:
        try:
            records.append(read_accepted_record(root, entry.memory_id))
        except AgentMemoryError:
            continue
    return catalog, tuple(records)


def _projection_allowlist(
    catalog: Optional[CatalogSnapshot], files: Sequence[_AuditFile]
) -> Tuple[str, ...]:
    if catalog is None:
        return ()
    projects = {
        entry.project for entry in catalog.entries if entry.project is not None
    }
    prefix = ".agent-memory/state/focus/"
    for item in files:
        if item.relative_path.startswith(prefix) and item.relative_path.endswith(".json"):
            project = PurePosixPath(item.relative_path).stem
            if project:
                projects.add(project)
    paths = set(_ROOT_PROJECTIONS)
    for project in projects:
        paths.add("projects/{0}/current-focus.md".format(project))
        paths.add("projects/{0}/overview.md".format(project))
    paths.update(
        "projects/{0}/stories/{1}.md".format(entry.project, entry.memory_id)
        for entry in catalog.entries
        if entry.project is not None and entry.record_type == "story"
    )
    return tuple(sorted(paths))


def _canonical_proposal(item: _AuditFile) -> bool:
    try:
        parse_proposal_artifact(item.relative_path, item.raw)
    except ValidationError:
        return False
    return True


def _canonical_transaction(item: _AuditFile) -> bool:
    path = PurePosixPath(item.relative_path)
    if (
        len(path.parts) != 3
        or path.parts[:2] != (".agent-memory", "transactions")
        or path.suffix != ".json"
    ):
        return False
    document = _json_document(item)
    return bool(
        isinstance(document, dict)
        and document.get("schema_version") == 2
        and document.get("transaction_id") == path.stem
        and document.get("operation")
        in ("commit-record", "initialize", "knowledge-promotion", "update_focus")
        and document.get("status") in ("accepted", "in-progress", "proposed", "rolled-back")
    )


def _lock_paths(files: Sequence[_AuditFile]) -> Tuple[str, ...]:
    values = set()
    for item in files:
        relative = item.relative_path
        if relative.startswith(".agent-memory/state/locks/"):
            values.add(relative)
        elif relative in (
            ".agent-memory-root-write.lock",
            ".agent-memory-root-write.anchor.candidate",
        ):
            values.add(relative)
        elif relative.startswith(".agent-memory-root-write.candidate-"):
            values.add(relative)
    return tuple(sorted(values))


def _migration_artifact_paths(
    files: Sequence[_AuditFile], records: Sequence[AcceptedRecord]
) -> Tuple[str, ...]:
    paths = {
        record.relative_path
        for record in records
        if record.envelope.record_type == "migration"
    }
    for item in files:
        parts = PurePosixPath(item.relative_path).parts
        if len(parts) >= 4 and parts[:2] == (".agent-memory", "transactions"):
            if "rollback" in parts[3:] or "archive" in parts[3:]:
                paths.add(item.relative_path)
            elif parts[-1] in ("migration-journal.json", "journal.json"):
                document = _json_document(item)
                operation = document.get("operation") if isinstance(document, dict) else None
                if isinstance(operation, str) and operation.startswith("migration-"):
                    paths.add(item.relative_path)
                elif (
                    isinstance(document, dict)
                    and document.get("schema_version") == 1
                    and document.get("apply_transaction_id") == parts[2]
                    and isinstance(document.get("source_revision"), str)
                    and isinstance(document.get("reviewed_bundle_sha256"), str)
                ):
                    paths.add(item.relative_path)
    return tuple(sorted(paths))


def _finding(code: str, severity: str, path: str, message: str) -> Finding:
    return Finding(code=code, severity=severity, path=path, message=message)


def _record_findings(
    files: Sequence[_AuditFile],
    catalog: Optional[CatalogSnapshot],
    records: Sequence[AcceptedRecord],
) -> List[Finding]:
    findings = []
    by_provenance = {}
    for record in records:
        key = (record.envelope.source, record.envelope.source_revision)
        by_provenance.setdefault(key, []).append(record)
    for grouped in by_provenance.values():
        owners = {record.envelope.memory_id for record in grouped}
        if len(owners) > 1:
            selected = sorted(grouped, key=lambda item: item.relative_path)[1]
            findings.append(
                _finding(
                    "duplicate-durable-owner",
                    "error",
                    selected.relative_path,
                    "matching durable provenance is selected by different current owners",
                )
            )

    if catalog is not None:
        current_ids = {entry.memory_id for entry in catalog.entries}
        current_revisions = {entry.memory_id: entry.revision for entry in catalog.entries}
        for item in files:
            relative = item.relative_path
            if relative.startswith(".agent-memory/state/focus/") and relative.endswith(".json"):
                document = _json_document(item)
                record_ids = document.get("record_ids") if isinstance(document, dict) else None
                if isinstance(record_ids, list) and any(
                    isinstance(value, str) and value not in current_ids for value in record_ids
                ):
                    findings.append(
                        _finding(
                            "stale-current-record",
                            "error",
                            relative,
                            "canonical focus references a missing or superseded record revision",
                        )
                    )
        for item in files:
            if not item.relative_path.startswith("_records/") or not item.relative_path.endswith(".md"):
                continue
            text = _decode_text(item)
            if text is None:
                continue
            try:
                envelope, _ = parse_record(text)
            except AgentMemoryError:
                continue
            selected_revision = current_revisions.get(envelope.memory_id)
            if selected_revision is not None and envelope.revision > selected_revision:
                findings.append(
                    _finding(
                        "stale-current-record",
                        "error",
                        ".agent-memory/state/catalog.json",
                        "canonical catalog references a superseded record revision",
                    )
                )
                break

    for record in records:
        if record.envelope.record_type != "story":
            continue
        lines = [line.strip() for line in record.body.splitlines() if line.strip()]
        normalized_length = len(" ".join(lines))
        link_or_heading_only = bool(lines) and all(
            line.startswith("#")
            or re.fullmatch(r"(?:[-*+]\s+)?\[\[[^\]]+\]\]", line) is not None
            for line in lines
        )
        if normalized_length < 80 and link_or_heading_only:
            findings.append(
                _finding(
                    "fragmented-story",
                    "warning",
                    record.relative_path,
                    "current story is a short heading-and-link fragment requiring owner review",
                )
            )
    return findings


def _legacy_duplicate_findings(files: Sequence[_AuditFile]) -> List[Finding]:
    candidates = {}
    for item in files:
        relative = item.relative_path
        if not relative.endswith(".md") or not (
            relative.startswith("preferences/")
            or "/sessions/" in relative
            or "/stories/" in relative
        ):
            continue
        text = _decode_text(item)
        if text is None or text.startswith("---\ngenerated: true\n"):
            continue
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.startswith("#") and not line.lower().startswith("source:")
        ]
        body = " ".join(lines).casefold()
        source_lines = [
            line.split(":", 1)[1].strip().casefold()
            for line in text.splitlines()
            if line.lower().startswith("source:") and ":" in line
        ]
        if body and source_lines:
            candidates.setdefault((source_lines[0], body), []).append(relative)
    findings = []
    for paths in candidates.values():
        if len(paths) > 1:
            findings.append(
                _finding(
                    "duplicate-durable-owner",
                    "warning",
                    sorted(paths)[1],
                    "similar legacy bodies require provenance review before assigning one owner",
                )
            )
    return findings


def _projection_findings(
    root: Path,
    files_by_path: Mapping[str, _AuditFile],
    allowlist: Sequence[str],
    catalog: Optional[CatalogSnapshot],
) -> List[Finding]:
    if catalog is None:
        return []
    findings = []
    expected_cache = {}
    projects = sorted(
        {entry.project for entry in catalog.entries if entry.project is not None}
    )
    for relative in allowlist:
        item = files_by_path.get(relative)
        if item is None:
            continue
        text = _decode_text(item)
        matched = None if text is None else re.search(
            r"(?m)^generator_version: ([a-z0-9][a-z0-9._-]{0,127})$", text
        )
        if matched is None:
            findings.append(
                _finding(
                    "projection-drift",
                    "warning",
                    relative,
                    "generated projection differs from deterministic canonical output",
                )
            )
            continue
        generator = matched.group(1)
        if generator not in expected_cache:
            try:
                documents = list(build_root_views(root, generator))
                for project in projects:
                    documents.extend(build_project_views(root, project, generator))
                expected_cache[generator] = {
                    document.relative_path: document.content.encode("utf-8")
                    for document in documents
                }
            except AgentMemoryError:
                expected_cache[generator] = {}
        if expected_cache[generator].get(relative) != item.raw:
            findings.append(
                _finding(
                    "projection-drift",
                    "warning",
                    relative,
                    "generated projection differs from deterministic canonical output",
                )
            )
    return findings


def _content_findings(
    files: Sequence[_AuditFile], allowlist: Sequence[str]
) -> List[Finding]:
    findings = []
    allowlist_set = set(allowlist)
    markdown_paths = {
        item.relative_path[:-3]
        for item in files
        if item.relative_path.endswith(".md")
    }
    markdown_stems = {PurePosixPath(path).name for path in markdown_paths}
    for item in files:
        relative = item.relative_path
        text = _decode_text(item)
        if text is None:
            continue
        if relative.endswith("current-focus.md") and not text.startswith("---\ngenerated: true\n"):
            if _HISTORY_PATTERN.search(text):
                findings.append(
                    _finding(
                        "current-focus-history",
                        "warning",
                        relative,
                        "current-focus page contains historical material and must be regenerated",
                    )
                )
        obsolete = (
            relative.startswith("preferences/")
            or relative.startswith("skills/")
            or "/sessions/" in relative
            or (relative.startswith("projects/") and "/decisions/" in relative)
            or (
                (
                    relative.startswith("_index/")
                    or (relative.startswith("projects/") and "/stories/" in relative)
                )
                and relative not in allowlist_set
            )
        )
        if obsolete and relative.endswith(".md"):
            findings.append(
                _finding(
                    "obsolete-schema-path",
                    "warning",
                    relative,
                    "legacy mutable path is outside the Schema-2 canonical record layout",
                )
            )
        if PurePosixPath(relative).suffix.lower() in (".md", ".txt"):
            if _RAW_CHAT_PATTERN.search(text):
                findings.append(
                    _finding(
                        "raw-chat-pattern",
                        "warning",
                        relative,
                        "role-prefixed raw chat requires provenance-preserving review",
                    )
                )
            for matched in _WIKILINK_PATTERN.finditer(text):
                target = matched.group(1).split("|", 1)[0].split("#", 1)[0].strip()
                if not target or "://" in target:
                    continue
                normalized = target.replace("\\", "/").lstrip("/")
                if normalized.endswith(".md"):
                    normalized = normalized[:-3]
                if normalized not in markdown_paths and PurePosixPath(normalized).name not in markdown_stems:
                    findings.append(
                        _finding(
                            "broken-wikilink",
                            "warning",
                            relative,
                            "wikilink target does not resolve within the audited vault",
                        )
                    )
                    break
        for line_number, line in enumerate(text.splitlines(), start=1):
            if _SECRET_PATTERN.search(line):
                findings.append(
                    _finding(
                        "secret-pattern",
                        "error",
                        "{0}:{1}".format(relative, line_number),
                        "credential-shaped text requires manual secret review",
                    )
                )
        if relative.startswith("knowledge/") and relative.endswith(".md"):
            findings.append(
                _finding(
                    "embedded-knowledge-decision",
                    "warning",
                    relative,
                    "embedded Knowledge Base material requires an explicit promotion decision",
                )
            )
    return findings


def _operational_findings(
    files: Sequence[_AuditFile],
    proposals: Sequence[_AuditFile],
    transactions: Sequence[_AuditFile],
    lock_paths: Sequence[str],
    migration_artifacts: Sequence[str],
    records: Sequence[AcceptedRecord],
    doctor_findings: Sequence[Finding],
) -> List[Finding]:
    findings = []
    findings.extend(
        _finding(
            "unresolved-proposal",
            "warning",
            item.relative_path,
            "canonical proposal remains unresolved and requires explicit review",
        )
        for item in proposals
    )
    accepted_migrations = {
        record.envelope.memory_id
        for record in records
        if record.envelope.record_type == "migration"
    }
    if migration_artifacts and not accepted_migrations:
        findings.append(
            _finding(
                "orphaned-migration-artifact",
                "warning",
                sorted(migration_artifacts)[0],
                "migration rollback or archive evidence has no accepted migration owner",
            )
        )
    for item in files:
        path = PurePosixPath(item.relative_path)
        if (
            len(path.parts) == 3
            and path.parts[:2] == (".agent-memory", "transactions")
            and path.suffix == ".json"
            and item not in transactions
        ):
            findings.append(
                _finding(
                    "orphaned-migration-artifact",
                    "warning",
                    item.relative_path,
                    "noncanonical or incomplete operation journal requires explicit review",
                )
            )
    findings.extend(
        _finding(
            "stale-lock-review",
            "warning",
            path,
            "owner/process verification is required before recovery; the audit never clears locks",
        )
        for path in lock_paths
    )
    for item in doctor_findings:
        if item.code in ("proposal-invalid", "proposal-unbound"):
            findings.append(item)
        elif item.code == "root-write-recovery-incomplete":
            findings.append(
                _finding(
                    "root-write-recovery-incomplete",
                    "error",
                    item.path,
                    "root-write recovery evidence is incomplete and requires explicit review",
                )
            )
        elif item.code in (
            "root-write-active",
            "root-write-stale",
            "root-write-candidate",
            "root-write-malformed",
            "root-write-anchor-candidate-active",
            "root-write-anchor-candidate-stale",
            "root-write-anchor-candidate-malformed",
        ) and item.path not in lock_paths:
            findings.append(
                _finding(
                    "stale-lock-review",
                    "warning",
                    item.path,
                    "owner/process verification is required before recovery; the audit never clears locks",
                )
            )
    return findings


def _audit_gated(root: Path, authorization_ref: Optional[str]) -> MaintenanceAudit:
    inventory = _inventory_vault(root)
    files = inventory.files
    files_by_path = {item.relative_path: item for item in files}
    catalog, records = _catalog_records(root)
    allowlist = _projection_allowlist(catalog, files)
    try:
        doctor_findings = doctor_memory_root(root)
    except AgentMemoryError:
        doctor_findings = ()
    invalid_proposals = {
        item.path
        for item in doctor_findings
        if item.code in ("proposal-invalid", "proposal-unbound")
    }
    invalid_transactions = {
        item.path for item in doctor_findings if item.code == "transaction-invalid"
    }
    proposals = tuple(
        item
        for item in files
        if _canonical_proposal(item) and item.relative_path not in invalid_proposals
    )
    transactions = tuple(
        item
        for item in files
        if _canonical_transaction(item) and item.relative_path not in invalid_transactions
    )
    lock_paths = _lock_paths(files)
    migration_artifacts = _migration_artifact_paths(files, records)

    findings = []
    findings.extend(_record_findings(files, catalog, records))
    findings.extend(_legacy_duplicate_findings(files))
    findings.extend(_projection_findings(root, files_by_path, allowlist, catalog))
    findings.extend(_content_findings(files, allowlist))
    findings.extend(
        _operational_findings(
            files,
            proposals,
            transactions,
            lock_paths,
            migration_artifacts,
            records,
            doctor_findings,
        )
    )
    unique = {
        (item.severity, item.code, item.path, item.message): item for item in findings
    }
    sorted_findings = tuple(
        unique[key]
        for key in sorted(unique)
    )
    errors = sum(item.severity == "error" for item in sorted_findings)
    warnings = sum(item.severity == "warning" for item in sorted_findings)
    counts = {
        "accepted-records": len(records),
        "findings-error": errors,
        "findings-total": errors + warnings,
        "findings-warning": warnings,
        "locks": len(lock_paths),
        "migration-artifacts": len(migration_artifacts),
        "projections": sum(path in files_by_path for path in allowlist),
        "proposals": len(proposals),
        "sources": sum(item.relative_path.startswith("_sources/") for item in files),
        "transactions": len(transactions),
    }
    return MaintenanceAudit(
        schema_version=1,
        source_revision=_source_revision(files),
        authorization_ref=authorization_ref,
        findings=sorted_findings,
        counts=tuple((key, counts[key]) for key in _COUNT_KEYS),
    )


def audit_vault(root: Path, gate: AuthorizationGate) -> MaintenanceAudit:
    """Return a deterministic audit without mutating the authorized vault."""
    selected_root = require_operation_gate(root, gate, "maintenance-audit")
    return _audit_gated(selected_root, gate.authorization_ref)


def _cleanup_source_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise ValidationError("cleanup finding path must be relative")
    matched = re.fullmatch(r"(.+):([1-9][0-9]*)", path)
    relative = matched.group(1) if matched is not None else path
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or pure.as_posix() != relative
        or any(part in ("", ".", "..") for part in pure.parts)
    ):
        raise ValidationError("cleanup finding path must be relative")
    return relative


def _expected_cleanup_hashes(
    inventory: _Inventory, relative: str
) -> Tuple[Tuple[str, str], ...]:
    exact = tuple(
        (item.relative_path, item.sha256)
        for item in inventory.files
        if item.relative_path == relative
    )
    if exact:
        return exact
    prefix = relative.rstrip("/") + "/"
    descendants = tuple(
        (item.relative_path, item.sha256)
        for item in inventory.files
        if item.relative_path.startswith(prefix)
    )
    if descendants:
        return descendants
    raise PlanInvalidatedError("cleanup finding source is missing")


def _cleanup_action_id(
    finding_code: str,
    disposition: CleanupDisposition,
    source_paths: Tuple[str, ...],
    expected_hashes: Tuple[Tuple[str, str], ...],
) -> str:
    value = {
        "disposition": disposition.value,
        "expected_hashes": [list(item) for item in expected_hashes],
        "finding_code": finding_code,
        "source_paths": list(source_paths),
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _cleanup_action_sort_key(action: CleanupAction):
    return (
        action.disposition.value,
        action.finding_code,
        action.source_paths,
        action.action_id,
    )


def _blocked_cleanup_action(finding: Finding, source_paths: Sequence[str]) -> bool:
    if finding.code in _BLOCKED_FINDING_CODES:
        return True
    for relative in source_paths:
        if (
            relative.startswith("_sources/")
            or relative.startswith("knowledge/")
            or relative.startswith(".agent-memory/state/proposals/")
            or relative.startswith(".agent-memory/state/locks/")
            or relative.startswith(".agent-memory-root-write.")
            or "/rollback/" in relative
            or "/archive/" in relative
        ):
            return True
    return False


def _validate_cleanup_context(context: TransactionContext) -> None:
    if not isinstance(context, TransactionContext):
        raise ValidationError("invalid cleanup transaction context")
    validate_identifier(context.transaction_id, "cleanup transaction_id")
    validate_identifier(context.actor, "cleanup actor")
    if not isinstance(context.occurred_at, str) or not context.occurred_at:
        raise ValidationError("invalid cleanup occurred_at")


def build_cleanup_plan(
    root: Path,
    audit: MaintenanceAudit,
    context: TransactionContext,
    gate: AuthorizationGate,
) -> CleanupPlan:
    """Build deterministic approval-required actions; never execute them."""
    selected_root = require_operation_gate(root, gate, "maintenance-plan")
    if not isinstance(audit, MaintenanceAudit):
        raise ValidationError("invalid maintenance audit")
    _validate_cleanup_context(context)
    inventory = _inventory_vault(selected_root)
    if _source_revision(inventory.files) != audit.source_revision:
        raise PlanInvalidatedError("cleanup source revision changed")

    actions = []
    blocked_actions = []
    for finding in audit.findings:
        disposition = DEFAULT_DISPOSITIONS.get(finding.code)
        if disposition is None:
            raise ValidationError("unsupported cleanup finding code")
        relative = _cleanup_source_path(finding.path)
        source_paths = (relative,)
        expected_hashes = _expected_cleanup_hashes(inventory, relative)
        blocked = _blocked_cleanup_action(finding, source_paths)
        if blocked:
            disposition = CleanupDisposition.REVIEW
        action = CleanupAction(
            action_id=_cleanup_action_id(
                finding.code,
                disposition,
                source_paths,
                expected_hashes,
            ),
            finding_code=finding.code,
            disposition=disposition,
            source_paths=source_paths,
            expected_hashes=expected_hashes,
            target_owner=None,
            reason=finding.message,
            requires_explicit_approval=True,
        )
        (blocked_actions if blocked else actions).append(action)
    ordered_actions = tuple(sorted(actions, key=_cleanup_action_sort_key))
    ordered_blocked = tuple(sorted(blocked_actions, key=_cleanup_action_sort_key))
    plan_value = {
        "actions": [item.action_id for item in ordered_actions],
        "actor": context.actor,
        "authorization_ref": gate.authorization_ref,
        "blocked_actions": [item.action_id for item in ordered_blocked],
        "created_at": context.occurred_at,
        "source_revision": audit.source_revision,
    }
    plan_id = hashlib.sha256(
        json.dumps(plan_value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return CleanupPlan(
        plan_id=plan_id,
        source_revision=audit.source_revision,
        actor=context.actor,
        created_at=context.occurred_at,
        authorization_ref=gate.authorization_ref,
        actions=ordered_actions,
        blocked_actions=ordered_blocked,
    )


def validate_cleanup_source(
    root: Path,
    plan: CleanupPlan,
    gate: AuthorizationGate,
) -> MaintenanceAudit:
    """Re-audit after gate validation and reject any cleanup source drift."""
    selected_root = require_operation_gate(root, gate, "maintenance-validate")
    if not isinstance(plan, CleanupPlan):
        raise ValidationError("invalid cleanup plan")
    audit = _audit_gated(selected_root, gate.authorization_ref)
    if audit.source_revision != plan.source_revision:
        raise PlanInvalidatedError("cleanup source revision changed")
    return audit


def recover_stale_root_guard(
    root: Path,
    target_transaction_id: str,
    expected_lock_sha256: Optional[str],
    context: TransactionContext,
    gate: AuthorizationGate,
) -> GuardRecoveryResult:
    """Recover one reviewed dead root guard without performing cleanup work."""
    selected_root = require_operation_gate(
        root, gate, "maintenance-recover-root-guard"
    )
    authorization_ref = gate.authorization_ref
    if not isinstance(authorization_ref, str) or not authorization_ref.strip():
        raise ValidationError("authorization reference is required")
    with recover_root_write_guard(
        selected_root,
        target_transaction_id,
        expected_lock_sha256,
        context,
        authorization_ref,
    ) as recovery:
        try:
            evidence_path = recovery.evidence_path.relative_to(selected_root).as_posix()
        except ValueError as error:
            raise ValidationError("recovery evidence escaped the memory root") from error
        result = GuardRecoveryResult(
            status="recovered",
            target_transaction_id=target_transaction_id,
            recovery_transaction_id=context.transaction_id,
            recovered_kind=recovery.recovered_kind,
            evidence_path=evidence_path,
            recovered_artifact_sha256=recovery.recovered_artifact_sha256,
        )
    return result
