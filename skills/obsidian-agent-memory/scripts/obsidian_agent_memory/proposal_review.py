"""Deterministic, content-redacted post-migration proposal review primitives."""

import dataclasses
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Mapping, Optional, Tuple

from .artifact_schemas import MigrationReviewProposal, parse_proposal_artifact
from .catalog import _parse_accepted_record_bytes, _parse_catalog_bytes
from .errors import ConflictError, PlanInvalidatedError, ValidationError
from .migration import (
    MigrationAction,
    MigrationBundle,
    SourceCategory,
    _json_bytes,
    _load_migration_bundle_from_bytes,
    _validate_journal,
    derive_legacy_owner_candidate,
)
from .manifest import _portable_path_is_safe
from .operation_scope import AuthorizationGate, require_operation_gate
from .paths import validate_identifier
from .runtime_identity import CodeIdentityProof, observe_runtime_identity


_MAX_OWNER_SOURCE_BYTES = 8 * 1024 * 1024
_MAX_REPORT_BYTES = 64 * 1024 * 1024
_MAX_REVIEW_ITEMS = 10_000
_MAX_EVIDENCE_GROUPS = 100_000
_MAX_EVIDENCE_OCCURRENCES = 1_000_000
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MIGRATION_ID = re.compile(r"migr-[0-9a-f]{24}\Z")
_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_ATX_HEADING = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+|$)")
_THEMATIC = re.compile(
    r"^ {0,3}(?:(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$"
)
_TABLE_CELL = re.compile(r":?-{3,}:?\Z")
_LIST_ITEM = re.compile(r"^ {0,3}(?:[-+*]|[0-9]{1,9}[.)])[ \t]+")
_INLINE_CODE = re.compile(r"^(`+)(?!`)(?:.|\n)*?(?<!`)\1$")
_MARKDOWN_LINK = re.compile(r"^\[[^\]\r\n]+\]\([^\r\n]+\)$")
_WIKILINK = re.compile(r"^!?\[\[[^\[\]\r\n]+\]\]$")
_SCHEME_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:\S+$")


@dataclass(frozen=True)
class FactBlock:
    normalized_utf8: bytes
    start_line: int
    end_line: int


@dataclass(frozen=True)
class FactOccurrenceInput:
    source_path: str
    source_sha256: str
    source_category: str
    candidate_owner: Mapping[str, object]
    block: FactBlock


@dataclass(frozen=True)
class EvidenceOccurrence:
    candidate_owner: Mapping[str, object]
    end_line: int
    source_category: str
    source_path: str
    source_sha256: str
    start_line: int


@dataclass(frozen=True)
class ConflictEvidence:
    evidence_id: str
    fact_sha256: str
    occurrences: Tuple[EvidenceOccurrence, ...]


@dataclass(frozen=True)
class ReviewItemInput:
    artifact: MigrationReviewProposal
    source_category: str
    snapshot_path: str
    snapshot_sha256: str
    snapshot_raw: bytes
    candidate_owner: Optional[Mapping[str, object]]
    live_source_state: str


@dataclass(frozen=True)
class ProposalReviewItem:
    candidate_owner: Optional[Mapping[str, object]]
    decision_code: str
    evidence_ids: Tuple[str, ...]
    live_source_state: str
    prior_classification: str
    proposal_id: str
    proposal_path: str
    proposal_sha256: str
    proposal_size: int
    refined_status: str
    snapshot_path: str
    snapshot_sha256: str
    source_path: str
    source_sha256: str


@dataclass(frozen=True)
class ProposalReviewModel:
    evidence: Tuple[ConflictEvidence, ...]
    items: Tuple[ProposalReviewItem, ...]
    prior_classification_counts: Mapping[str, int]
    refined_status_counts: Mapping[str, int]
    total: int


@dataclass(frozen=True)
class ProposalReviewArtifact:
    document: Mapping[str, object]
    raw: bytes
    review_id: str
    report_sha256: str

    @property
    def canonical_bytes(self) -> bytes:
        return self.raw

    @property
    def total(self) -> int:
        return self.document["summary"]["total"]

    @property
    def prior_classification_counts(self):
        return tuple(sorted(self.document["summary"]["prior_classification_counts"].items()))

    @property
    def refined_status_counts(self):
        return tuple(sorted(self.document["summary"]["refined_status_counts"].items()))


@dataclass(frozen=True)
class ProposalReviewContext:
    actor: str
    observed_at: str
    fixture_code_revision: Optional[str] = None


@dataclass(frozen=True)
class _CapturedNode:
    logical_path: str
    node_type: str
    st_dev: Optional[int]
    st_ino: Optional[int]
    st_size: Optional[int]
    st_mtime_ns: Optional[int]


@dataclass(frozen=True)
class _CapturedPath:
    logical_path: str
    node_type: str
    st_dev: Optional[int]
    st_ino: Optional[int]
    st_size: int
    st_mtime_ns: Optional[int]
    sha256: str
    raw: bytes


@dataclass(frozen=True)
class _CapturedPathState:
    logical_path: str
    state: str
    captured: Optional[_CapturedPath]


@dataclass(frozen=True)
class _ReviewInputSnapshot:
    root: Path
    bundle_dir: Path
    reviewed_bundle_sha256: str
    bundle_inventory: Tuple[_CapturedPath, ...]
    transaction_membership: Tuple[_CapturedNode, ...]
    candidate_journals: Tuple[_CapturedPath, ...]
    selected_journal: _CapturedPath
    immutable_journal_evidence: Tuple[_CapturedPath, ...]
    proposal_membership: Tuple[_CapturedNode, ...]
    selected_proposals: Tuple[_CapturedPath, ...]
    catalog: _CapturedPath
    selected_records: Tuple[_CapturedPath, ...]
    live_sources: Tuple[_CapturedPathState, ...]
    migration_bundle: MigrationBundle
    journal_document: Mapping[str, object]
    proposal_artifacts: Tuple[MigrationReviewProposal, ...]
    catalog_revision: int
    code_identity_proof: Optional[CodeIdentityProof] = None


_PRIOR_CLASSIFICATIONS = (
    "ambiguous-owner",
    "embedded-knowledge-external",
    "legacy-focus-input",
    "legacy-project-id-mapping-required",
    "unknown-format",
)
_REFINED_STATUSES = (
    "focus-history-review",
    "knowledge-routing-review",
    "manual-format-review",
    "manual-owner-review",
    "manual-parse-review",
    "path-owner-candidate",
    "project-id-routing-review",
)
_FIXED_STATUS = {
    "unknown-format": ("manual-format-review", "choose-source-format"),
    "embedded-knowledge-external": (
        "knowledge-routing-review",
        "choose-knowledge-destination",
    ),
    "legacy-focus-input": (
        "focus-history-review",
        "extract-or-dismiss-focus-history",
    ),
    "legacy-project-id-mapping-required": (
        "project-id-routing-review",
        "supply-project-id-mapping",
    ),
}
_LIVE_SOURCE_STATES = frozenset(
    (
        "unchanged",
        "journaled-replaced",
        "journaled-archived",
        "drifted",
        "missing-unexplained",
    )
)


class FactParseCode(str, Enum):
    INVALID_UTF8 = "invalid-utf8"
    UNCLOSED_FRONTMATTER = "unclosed-frontmatter"
    UNCLOSED_FENCE = "unclosed-fence"
    UNCLOSED_COMMENT = "unclosed-comment"
    RESOURCE_LIMIT = "resource-limit"


class FactParseError(ValidationError):
    def __init__(self, code: FactParseCode):
        super().__init__(code.value)
        self.code = code


def candidate_owner_for_action(
    bundle: MigrationBundle,
    action: MigrationAction,
) -> Optional[Mapping[str, object]]:
    entries = {
        entry.relative_path: entry
        for entry in bundle.detection.entries
    }
    entry = entries.get(action.source_path)
    if entry is None or action not in bundle.plan.actions:
        return None
    expected_action_id = "action-" + hashlib.sha256(
        (entry.relative_path + "\0" + entry.sha256).encode("utf-8")
    ).hexdigest()[:20]
    if action.source_sha256 != entry.sha256 or action.action_id != expected_action_id:
        return None
    try:
        candidate = derive_legacy_owner_candidate(
            entry, bundle.plan.project_id_mappings
        )
    except ValidationError:
        return None
    if candidate is None:
        return None
    return {
        "candidate_memory_id": candidate.candidate_memory_id,
        "owner_scope": candidate.owner_scope,
        "project_id": candidate.project_id,
        "record_type": candidate.record_type,
    }


def _owner_identity(owner):
    return (
        owner["candidate_memory_id"],
        owner["owner_scope"],
        owner["project_id"],
        owner["record_type"],
    )


def group_conflict_evidence(
    bundle_sha256: str,
    source_revision: str,
    occurrences: Tuple[FactOccurrenceInput, ...],
) -> Tuple[ConflictEvidence, ...]:
    buckets = {}
    for occurrence in occurrences:
        fact_sha256 = hashlib.sha256(
            b"agent-memory-proposal-fact-v1"
            + b"\0"
            + bundle_sha256.encode("utf-8")
            + b"\0"
            + source_revision.encode("utf-8")
            + b"\0"
            + occurrence.block.normalized_utf8
        ).hexdigest()
        by_bytes = buckets.setdefault(fact_sha256, {})
        by_bytes.setdefault(occurrence.block.normalized_utf8, []).append(occurrence)

    evidence = []
    used_ids = set()
    for fact_sha256, by_bytes in sorted(buckets.items()):
        for _, values in sorted(by_bytes.items(), key=lambda item: item[0]):
            if len({_owner_identity(item.candidate_owner) for item in values}) < 2:
                continue
            evidence_id = "evidence-" + fact_sha256
            if evidence_id in used_ids:
                raise ValidationError("proposal fact digest collision")
            used_ids.add(evidence_id)
            evidence.append(
                ConflictEvidence(
                    evidence_id,
                    fact_sha256,
                    tuple(
                        EvidenceOccurrence(
                            candidate_owner=item.candidate_owner,
                            end_line=item.block.end_line,
                            source_category=item.source_category,
                            source_path=item.source_path,
                            source_sha256=item.source_sha256,
                            start_line=item.block.start_line,
                        )
                        for item in sorted(
                            values,
                            key=lambda value: (
                                value.source_path,
                                value.block.start_line,
                                value.block.end_line,
                                value.candidate_owner["candidate_memory_id"],
                            ),
                        )
                    ),
                )
            )
    return tuple(sorted(evidence, key=lambda item: item.evidence_id))


def build_conflict_evidence(
    bundle: MigrationBundle,
    actions: Optional[Tuple[MigrationAction, ...]] = None,
) -> Tuple[ConflictEvidence, ...]:
    selected_actions = bundle.plan.actions if actions is None else actions
    entries = {entry.relative_path: entry for entry in bundle.detection.entries}
    snapshots = {entry.relative_path: entry for entry in bundle.snapshot.entries}
    inputs = []
    for action in selected_actions:
        if (
            action.unresolved_classification is None
            or action.unresolved_classification.value != "ambiguous-owner"
        ):
            continue
        owner = candidate_owner_for_action(bundle, action)
        entry = entries.get(action.source_path)
        snapshot = snapshots.get(action.source_path)
        if owner is None or entry is None or snapshot is None:
            continue
        if snapshot.sha256 != action.source_sha256 or entry.sha256 != action.source_sha256:
            continue
        raw = (bundle.bundle_dir / snapshot.snapshot_path).read_bytes()
        if len(raw) != snapshot.size or hashlib.sha256(raw).hexdigest() != snapshot.sha256:
            raise ValidationError("proposal snapshot changed")
        try:
            blocks = extract_fact_blocks(raw)
        except FactParseError:
            continue
        inputs.extend(
            FactOccurrenceInput(
                source_path=action.source_path,
                source_sha256=action.source_sha256,
                source_category=entry.category.value,
                candidate_owner=owner,
                block=block,
            )
            for block in blocks
        )
    return group_conflict_evidence(
        bundle.bundle_sha256,
        bundle.plan.source_revision,
        tuple(inputs),
    )


def review_inputs_for_bundle(
    bundle: MigrationBundle,
    artifacts: Tuple[MigrationReviewProposal, ...],
) -> Tuple[ReviewItemInput, ...]:
    actions = {action.action_id: action for action in bundle.plan.actions}
    entries = {entry.relative_path: entry for entry in bundle.detection.entries}
    snapshots = {entry.relative_path: entry for entry in bundle.snapshot.entries}
    inputs = []
    for artifact in artifacts:
        action = actions.get(artifact.proposal_id)
        entry = entries.get(artifact.source_path)
        snapshot = snapshots.get(artifact.source_path)
        candidate_owner = None
        if (
            action is not None
            and entry is not None
            and snapshot is not None
            and action.source_path == artifact.source_path
            and action.source_sha256 == artifact.source_sha256
            and snapshot.sha256 == artifact.source_sha256
            and entry.sha256 == artifact.source_sha256
        ):
            candidate_owner = candidate_owner_for_action(bundle, action)
        if snapshot is None:
            snapshot_path = "snapshot/files/" + artifact.source_path
            snapshot_sha256 = artifact.source_sha256
            snapshot_raw = b""
        else:
            snapshot_path = snapshot.snapshot_path
            snapshot_sha256 = snapshot.sha256
            snapshot_raw = (bundle.bundle_dir / snapshot.snapshot_path).read_bytes()
            if (
                len(snapshot_raw) != snapshot.size
                or hashlib.sha256(snapshot_raw).hexdigest() != snapshot.sha256
            ):
                raise ValidationError("proposal snapshot changed")
        inputs.append(
            ReviewItemInput(
                artifact=artifact,
                source_category="unknown" if entry is None else entry.category.value,
                snapshot_path=snapshot_path,
                snapshot_sha256=snapshot_sha256,
                snapshot_raw=snapshot_raw,
                candidate_owner=candidate_owner,
                live_source_state="unchanged",
            )
        )
    return tuple(inputs)


def _metadata_value(metadata, field):
    value = getattr(metadata, field, None)
    return None if value in (None, 0) else value


def _captured_node(path: Path, logical_path: str) -> _CapturedNode:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValidationError("proposal review input cannot be inventoried") from error
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & _REPARSE_FLAG:
        raise ValidationError("unsafe proposal review input")
    if stat.S_ISREG(metadata.st_mode):
        node_type = "file"
    elif stat.S_ISDIR(metadata.st_mode):
        node_type = "directory"
    else:
        raise ValidationError("unsafe proposal review input")
    return _CapturedNode(
        logical_path,
        node_type,
        _metadata_value(metadata, "st_dev"),
        _metadata_value(metadata, "st_ino"),
        metadata.st_size,
        _metadata_value(metadata, "st_mtime_ns"),
    )


def _capture_regular(path: Path, logical_path: str, maximum=_MAX_REPORT_BYTES) -> _CapturedPath:
    node = _captured_node(path, logical_path)
    if node.node_type != "file" or node.st_size is None or node.st_size > maximum:
        raise ValidationError("invalid proposal review input file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            raw = handle.read(maximum + 1)
            after_open = os.fstat(handle.fileno())
        after_path = _captured_node(path, logical_path)
    except OSError as error:
        raise ValidationError("proposal review input cannot be read") from error
    opened_identity = (
        _metadata_value(opened, "st_dev"),
        _metadata_value(opened, "st_ino"),
        opened.st_size,
        _metadata_value(opened, "st_mtime_ns"),
    )
    if (
        len(raw) > maximum
        or node.node_type != "file"
        or after_path.node_type != "file"
        or (node.st_dev, node.st_ino, node.st_size, node.st_mtime_ns) != opened_identity
        or opened_identity
        != (
            _metadata_value(after_open, "st_dev"),
            _metadata_value(after_open, "st_ino"),
            after_open.st_size,
            _metadata_value(after_open, "st_mtime_ns"),
        )
        or (node.st_dev, node.st_ino, node.st_size, node.st_mtime_ns)
        != (after_path.st_dev, after_path.st_ino, after_path.st_size, after_path.st_mtime_ns)
    ):
        raise ValidationError("proposal review input changed during capture")
    return _CapturedPath(
        logical_path,
        "file",
        node.st_dev,
        node.st_ino,
        len(raw),
        node.st_mtime_ns,
        hashlib.sha256(raw).hexdigest(),
        raw,
    )


def _enumerate_directory(path: Path, prefix="") -> Tuple[_CapturedNode, ...]:
    before = _captured_node(path, prefix or ".")
    if before.node_type != "directory":
        raise ValidationError("invalid proposal review input directory")
    try:
        children = sorted(path.iterdir(), key=lambda item: item.name)
    except OSError as error:
        raise ValidationError("proposal review input cannot be enumerated") from error
    nodes = tuple(
        _captured_node(child, child.name if not prefix else prefix + "/" + child.name)
        for child in children
    )
    after = _captured_node(path, prefix or ".")
    if before != after:
        raise ValidationError("proposal review directory changed during capture")
    return nodes


def _capture_tree(root: Path) -> Tuple[_CapturedPath, ...]:
    files = []
    stack = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        nodes = _enumerate_directory(directory, prefix)
        for node in reversed(nodes):
            child = root.joinpath(*PurePosixPath(node.logical_path).parts)
            if node.node_type == "directory":
                stack.append((child, node.logical_path))
            else:
                files.append(_capture_regular(child, node.logical_path))
    return tuple(sorted(files, key=lambda item: item.logical_path))


def _capture_optional_source(root: Path, relative_path: str) -> _CapturedPathState:
    _portable_relative(relative_path, "live source path")
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    try:
        path.lstat()
    except FileNotFoundError:
        return _CapturedPathState(relative_path, "missing", None)
    return _CapturedPathState(relative_path, "present", _capture_regular(path, relative_path))


def _parse_canonical_journal(captured: _CapturedPath):
    try:
        value = json.loads(
            captured.raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_report_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("invalid migration journal") from error
    if _json_bytes(value) != captured.raw:
        raise ValidationError("invalid canonical migration journal")
    return _validate_journal(value)


def _capture_review_inputs(
    root: Path,
    bundle_dir: Path,
    reviewed_bundle_sha256: str,
) -> _ReviewInputSnapshot:
    selected_root = Path(root).resolve(strict=True)
    selected_bundle = Path(bundle_dir).resolve(strict=True)
    _digest(reviewed_bundle_sha256, "reviewed bundle digest")
    bundle_inventory = _capture_tree(selected_bundle)
    bundle_bytes = {item.logical_path: item.raw for item in bundle_inventory}
    bundle = _load_migration_bundle_from_bytes(selected_bundle, bundle_bytes)
    if bundle.bundle_sha256 != reviewed_bundle_sha256:
        raise ValidationError("reviewed migration bundle changed")

    transaction_root = selected_root / ".agent-memory" / "transactions"
    transaction_membership = _enumerate_directory(
        transaction_root, ".agent-memory/transactions"
    )
    journals = []
    journal_documents = []
    for node in transaction_membership:
        if node.node_type != "directory":
            continue
        journal_path = selected_root.joinpath(*PurePosixPath(node.logical_path).parts) / "journal.json"
        if not journal_path.exists():
            continue
        captured = _capture_regular(journal_path, node.logical_path + "/journal.json")
        journals.append(captured)
        journal_documents.append((captured, _parse_canonical_journal(captured)))
    matches = [
        pair for pair in journal_documents
        if pair[1]["status"] == "applied"
        and pair[1]["plan_id"] == bundle.plan.plan_id
        and pair[1]["source_revision"] == bundle.plan.source_revision
        and pair[1]["reviewed_bundle_sha256"] == bundle.bundle_sha256
    ]
    if len(matches) != 1:
        raise ValidationError("proposal review requires one applied migration journal")
    selected_journal, journal = matches[0]
    if PurePosixPath(selected_journal.logical_path).parent.name != journal["apply_transaction_id"]:
        raise ValidationError("migration journal transaction identity mismatch")

    proposal_root = selected_root / ".agent-memory" / "state" / "proposals"
    proposal_membership = _enumerate_directory(
        proposal_root, ".agent-memory/state/proposals"
    )
    all_proposals = []
    selected_by_path = {}
    for node in proposal_membership:
        if node.node_type != "file":
            raise ValidationError("invalid proposal directory member")
        path = selected_root.joinpath(*PurePosixPath(node.logical_path).parts)
        captured = _capture_regular(path, node.logical_path)
        artifact = parse_proposal_artifact(node.logical_path, captured.raw)
        all_proposals.append((captured, artifact))
        if isinstance(artifact, MigrationReviewProposal) and artifact.source_revision == bundle.plan.source_revision:
            selected_by_path[node.logical_path] = (captured, artifact)
    if set(selected_by_path) != set(journal["proposal_paths"]):
        raise ValidationError("migration proposal set disagrees with journal")
    actions = {action.action_id: action for action in bundle.plan.actions}
    journal_actions = {action["path"]: action for action in journal["actions"]}
    selected_proposals = []
    artifacts = []
    for relative in journal["proposal_paths"]:
        captured, artifact = selected_by_path[relative]
        action = actions.get(artifact.proposal_id)
        journal_action = journal_actions.get(relative)
        if (
            action is None
            or action.unresolved_classification is None
            or artifact.classification.value != action.unresolved_classification.value
            or artifact.source_path != action.source_path
            or artifact.source_sha256 != action.source_sha256
            or journal_action is None
            or journal_action["operation"] != "create"
            or journal_action["completed"] is not True
            or journal_action["after_sha256"] != captured.sha256
        ):
            raise ValidationError("migration proposal binding mismatch")
        selected_proposals.append(captured)
        artifacts.append(artifact)

    catalog_path = selected_root / ".agent-memory" / "state" / "catalog.json"
    catalog = _capture_regular(catalog_path, ".agent-memory/state/catalog.json")
    catalog_snapshot = _parse_catalog_bytes(selected_root, catalog.raw)
    selected_records = []
    for entry in catalog_snapshot.entries:
        path = selected_root.joinpath(*PurePosixPath(entry.relative_path).parts)
        captured = _capture_regular(path, entry.relative_path)
        _parse_accepted_record_bytes(entry, catalog_snapshot.revision, captured.raw)
        selected_records.append(captured)

    live_sources = tuple(
        _capture_optional_source(selected_root, action.source_path)
        for action in bundle.plan.actions
        if action.unresolved_classification is not None
    )
    immutable = []
    for action in journal["actions"]:
        if action["completed"] and action["operation"] in ("replace", "archive"):
            rollback_path = action["rollback_path"]
            captured = _capture_regular(
                selected_root.joinpath(*PurePosixPath(rollback_path).parts),
                rollback_path,
            )
            if captured.sha256 != action["before_sha256"]:
                raise ValidationError("migration rollback evidence mismatch")
            immutable.append(captured)

    return _ReviewInputSnapshot(
        selected_root,
        selected_bundle,
        reviewed_bundle_sha256,
        bundle_inventory,
        transaction_membership,
        tuple(journals),
        selected_journal,
        tuple(sorted(immutable, key=lambda item: item.logical_path)),
        proposal_membership,
        tuple(selected_proposals),
        catalog,
        tuple(selected_records),
        live_sources,
        bundle,
        journal,
        tuple(artifacts),
        catalog_snapshot.revision,
    )


def _live_state(snapshot: _ReviewInputSnapshot, action: MigrationAction, state: _CapturedPathState) -> str:
    journal_action = next(
        (item for item in snapshot.journal_document["actions"] if item["path"] == action.source_path),
        None,
    )
    current_hash = None if state.captured is None else state.captured.sha256
    if journal_action is not None and journal_action["completed"]:
        if journal_action["operation"] == "replace" and current_hash == journal_action["after_sha256"]:
            return "journaled-replaced"
        if journal_action["operation"] == "archive" and state.state == "missing":
            return "journaled-archived"
    if state.state == "missing":
        return "missing-unexplained"
    return "unchanged" if current_hash == action.source_sha256 else "drifted"


def _build_captured_proposal_review(
    snapshot: _ReviewInputSnapshot,
    code_identity: Mapping[str, object],
    run_context: Mapping[str, object],
) -> ProposalReviewArtifact:
    bundle = snapshot.migration_bundle
    actions = {action.action_id: action for action in bundle.plan.actions}
    entries = {entry.relative_path: entry for entry in bundle.detection.entries}
    snapshots = {entry.relative_path: entry for entry in bundle.snapshot.entries}
    captured_bundle = {item.logical_path: item for item in snapshot.bundle_inventory}
    live = {item.logical_path: item for item in snapshot.live_sources}
    inputs = []
    for artifact in snapshot.proposal_artifacts:
        action = actions[artifact.proposal_id]
        entry = entries[action.source_path]
        frozen = snapshots[action.source_path]
        raw = captured_bundle[frozen.snapshot_path].raw
        inputs.append(
            ReviewItemInput(
                artifact,
                entry.category.value,
                frozen.snapshot_path,
                frozen.sha256,
                raw,
                candidate_owner_for_action(bundle, action),
                _live_state(snapshot, action, live[action.source_path]),
            )
        )
    model = build_review_model(bundle.bundle_sha256, bundle.plan.source_revision, tuple(inputs))
    return build_proposal_review_artifact(
        model=model,
        code_identity=code_identity,
        apply_journal={
            "path": snapshot.selected_journal.logical_path,
            "sha256": snapshot.selected_journal.sha256,
            "transaction_id": snapshot.journal_document["apply_transaction_id"],
        },
        bundle={
            "plan_id": bundle.plan.plan_id,
            "sha256": bundle.bundle_sha256,
            "source_revision": bundle.plan.source_revision,
        },
        catalog={"revision": snapshot.catalog_revision, "sha256": snapshot.catalog.sha256},
        run_context=run_context,
    )


def _bind_captured_proposal_review(
    artifact: ProposalReviewArtifact,
    root: Path,
    bundle_dir: Path,
    reviewed_bundle_sha256: str,
    code_identity: Mapping[str, object],
    run_context: Mapping[str, object],
) -> ProposalReviewArtifact:
    captured = _capture_review_inputs(root, bundle_dir, reviewed_bundle_sha256)
    expected = _build_captured_proposal_review(captured, code_identity, run_context)
    if artifact.raw != expected.raw:
        raise ValidationError("proposal review does not bind captured inputs")
    return expected


def _observe_expected_identity(
    expected: CodeIdentityProof,
    scope,
    fixture_code_revision,
    observer,
) -> CodeIdentityProof:
    observed = observer(scope, fixture_code_revision)
    if observed != expected:
        raise ConflictError("proposal review runtime identity changed")
    return observed


def _proposal_review_consistency_checkpoint(
    snapshot: _ReviewInputSnapshot,
    artifact: ProposalReviewArtifact,
) -> None:
    """Narrow test seam between cached construction and observation-only pass two."""


def build_proposal_review(
    root: Path,
    bundle_path: Path,
    reviewed_bundle_sha256: str,
    context: ProposalReviewContext,
    gate: AuthorizationGate,
    code_identity_proof: CodeIdentityProof,
) -> ProposalReviewArtifact:
    if not isinstance(context, ProposalReviewContext):
        raise ValidationError("invalid proposal review context")
    if not isinstance(gate, AuthorizationGate):
        raise ValidationError("invalid proposal review authorization gate")
    if not isinstance(code_identity_proof, CodeIdentityProof):
        raise ValidationError("invalid runtime identity proof")
    run_context = {
        "actor": context.actor,
        "authorization_ref": gate.authorization_ref,
        "observed_at": context.observed_at,
        "scope": gate.scope.value,
    }
    require_operation_gate(root, gate, "review-proposals")
    _observe_expected_identity(
        code_identity_proof,
        gate.scope,
        context.fixture_code_revision,
        observe_runtime_identity,
    )
    try:
        captured = _capture_review_inputs(root, bundle_path, reviewed_bundle_sha256)
    except (ValidationError, OSError) as error:
        raise PlanInvalidatedError("proposal review inputs are invalid") from error
    captured = dataclasses.replace(captured, code_identity_proof=code_identity_proof)
    artifact = _build_captured_proposal_review(
        captured, code_identity_proof.identity.document, run_context
    )
    _proposal_review_consistency_checkpoint(captured, artifact)
    try:
        second = _capture_review_inputs(root, bundle_path, reviewed_bundle_sha256)
        second = dataclasses.replace(second, code_identity_proof=code_identity_proof)
        _observe_expected_identity(
            code_identity_proof,
            gate.scope,
            context.fixture_code_revision,
            observe_runtime_identity,
        )
    except ConflictError:
        raise
    except (ValidationError, OSError) as error:
        raise ConflictError("proposal review inputs changed between passes") from error
    if second != captured:
        raise ConflictError("proposal review inputs changed between passes")
    return artifact


def bind_proposal_review(
    root: Path,
    bundle_path: Path,
    reviewed_bundle_sha256: str,
    context: ProposalReviewContext,
    gate: AuthorizationGate,
    code_identity_proof: CodeIdentityProof,
    report: ProposalReviewArtifact,
) -> ProposalReviewArtifact:
    expected = build_proposal_review(
        root,
        bundle_path,
        reviewed_bundle_sha256,
        context,
        gate,
        code_identity_proof,
    )
    if report.raw != expected.raw:
        raise ValidationError("proposal review does not bind captured inputs")
    return expected


def build_review_model(
    bundle_sha256: str,
    source_revision: str,
    inputs: Tuple[ReviewItemInput, ...],
) -> ProposalReviewModel:
    identities = [
        (item.artifact.relative_path, item.artifact.proposal_id) for item in inputs
    ]
    if len(identities) != len(set(identities)):
        raise ValidationError("duplicate proposal review item")

    parse_failures = set()
    occurrence_inputs = []
    for item in inputs:
        if item.live_source_state not in _LIVE_SOURCE_STATES:
            raise ValidationError("invalid live source state")
        if (
            item.artifact.classification.value != "ambiguous-owner"
            or item.candidate_owner is None
        ):
            continue
        try:
            blocks = extract_fact_blocks(item.snapshot_raw)
        except FactParseError:
            parse_failures.add(item.artifact.proposal_id)
            continue
        occurrence_inputs.extend(
            FactOccurrenceInput(
                source_path=item.artifact.source_path,
                source_sha256=item.artifact.source_sha256,
                source_category=item.source_category,
                candidate_owner=item.candidate_owner,
                block=block,
            )
            for block in blocks
        )

    evidence = group_conflict_evidence(
        bundle_sha256,
        source_revision,
        tuple(occurrence_inputs),
    )
    evidence_by_source = {}
    for group in evidence:
        for occurrence in group.occurrences:
            key = (
                occurrence.source_path,
                occurrence.source_sha256,
                occurrence.candidate_owner["candidate_memory_id"],
            )
            evidence_by_source.setdefault(key, set()).add(group.evidence_id)

    items = []
    for item in inputs:
        artifact = item.artifact
        classification = artifact.classification.value
        evidence_ids = ()
        if classification == "ambiguous-owner":
            if item.candidate_owner is None:
                refined_status = "manual-parse-review"
                decision_code = "candidate-owner-unavailable"
            elif artifact.proposal_id in parse_failures:
                refined_status = "manual-parse-review"
                decision_code = "inspect-unparseable-source"
            else:
                key = (
                    artifact.source_path,
                    artifact.source_sha256,
                    item.candidate_owner["candidate_memory_id"],
                )
                evidence_ids = tuple(sorted(evidence_by_source.get(key, ())))
                if evidence_ids:
                    refined_status = "manual-owner-review"
                    decision_code = "choose-fact-owner"
                else:
                    refined_status = "path-owner-candidate"
                    decision_code = "review-path-owner"
        else:
            try:
                refined_status, decision_code = _FIXED_STATUS[classification]
            except KeyError as error:
                raise ValidationError("invalid proposal review classification") from error
        items.append(
            ProposalReviewItem(
                candidate_owner=item.candidate_owner,
                decision_code=decision_code,
                evidence_ids=evidence_ids,
                live_source_state=item.live_source_state,
                prior_classification=classification,
                proposal_id=artifact.proposal_id,
                proposal_path=artifact.relative_path,
                proposal_sha256=artifact.sha256,
                proposal_size=artifact.size,
                refined_status=refined_status,
                snapshot_path=item.snapshot_path,
                snapshot_sha256=item.snapshot_sha256,
                source_path=artifact.source_path,
                source_sha256=artifact.source_sha256,
            )
        )
    items = tuple(sorted(items, key=lambda value: (value.proposal_path, value.proposal_id)))
    prior_counts = {key: 0 for key in _PRIOR_CLASSIFICATIONS}
    refined_counts = {key: 0 for key in _REFINED_STATUSES}
    for item in items:
        prior_counts[item.prior_classification] += 1
        refined_counts[item.refined_status] += 1
    return ProposalReviewModel(
        evidence=evidence,
        items=items,
        prior_classification_counts=prior_counts,
        refined_status_counts=refined_counts,
        total=len(items),
    )


def _canonical_report_bytes(value: Mapping[str, object]) -> bytes:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (encoded + "\n").encode("utf-8")


def _proposal_set_digest(items) -> str:
    proposals = [
        {
            "path": item["proposal_path"],
            "sha256": item["proposal_sha256"],
            "size": item["proposal_size"],
        }
        for item in items
    ]
    proposals.sort(key=lambda item: (item["path"], item["sha256"], item["size"]))
    return hashlib.sha256(_canonical_report_bytes(proposals)).hexdigest()


def _review_identity(classifier_version, inputs) -> str:
    bundle = inputs["bundle"]
    values = (
        classifier_version,
        bundle["sha256"],
        bundle["plan_id"],
        bundle["source_revision"],
        inputs["apply_journal"]["sha256"],
        inputs["catalog"]["sha256"],
        inputs["proposal_set_sha256"],
    )
    payload = b"agent-memory-proposal-review-v1\0" + b"\0".join(
        value.encode("utf-8") for value in values
    )
    return "review-" + hashlib.sha256(payload).hexdigest()


def build_proposal_review_artifact(
    *, model: ProposalReviewModel, code_identity: Mapping[str, object],
    apply_journal: Mapping[str, object], bundle: Mapping[str, object],
    catalog: Mapping[str, object], run_context: Mapping[str, object],
) -> ProposalReviewArtifact:
    if len(model.items) > _MAX_REVIEW_ITEMS:
        raise ValidationError("proposal review item limit exceeded")
    if len(model.evidence) > _MAX_EVIDENCE_GROUPS:
        raise ValidationError("proposal review evidence limit exceeded")
    if sum(len(group.occurrences) for group in model.evidence) > _MAX_EVIDENCE_OCCURRENCES:
        raise ValidationError("proposal review occurrence limit exceeded")
    items = [dataclasses.asdict(item) for item in model.items]
    evidence = [dataclasses.asdict(group) for group in model.evidence]
    inputs = {
        "apply_journal": dict(apply_journal),
        "bundle": dict(bundle),
        "catalog": dict(catalog),
        "proposal_set_sha256": _proposal_set_digest(items),
    }
    document = {
        "classifier_version": "owner-block-v1",
        "code_identity": dict(code_identity),
        "evidence": evidence,
        "inputs": inputs,
        "items": items,
        "report_kind": "migration-proposal-review",
        "review_id": _review_identity("owner-block-v1", inputs),
        "run_context": dict(run_context),
        "schema_version": 1,
        "summary": {
            "prior_classification_counts": dict(model.prior_classification_counts),
            "refined_status_counts": dict(model.refined_status_counts),
            "total": model.total,
        },
    }
    raw = _canonical_report_bytes(document)
    if len(raw) > _MAX_REPORT_BYTES:
        raise ValidationError("proposal review report limit exceeded")
    return _parse_proposal_review_bytes(raw)


def _reject_report_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("proposal review duplicate key")
        value[key] = item
    return value


def _exact_mapping(value, keys, field):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValidationError("invalid proposal review {0}".format(field))
    return value


def _string(value, field, maximum=1024):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValidationError("invalid proposal review {0}".format(field))
    return value


def _identifier(value, field):
    try:
        return validate_identifier(value, "proposal review " + field)
    except ValidationError as error:
        raise ValidationError("invalid proposal review {0}".format(field)) from error


def _digest(value, field):
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValidationError("invalid proposal review {0}".format(field))
    return value


def _integer(value, field, maximum=None):
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise ValidationError("invalid proposal review {0}".format(field))
    return value


def _portable_relative(value, field):
    if not _portable_path_is_safe(value):
        raise ValidationError("invalid proposal review {0}".format(field))
    path = PurePosixPath(value)
    if (
        path.as_posix() != value
        or not path.parts
        or any(part in ("", ".", "..") or part.endswith((" ", ".")) for part in path.parts)
    ):
        raise ValidationError("invalid proposal review {0}".format(field))
    return value


def _timestamp(value):
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise ValidationError("invalid proposal review timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        raise ValidationError("invalid proposal review timestamp") from error
    return value


def _candidate_owner(value, nullable=False):
    if value is None and nullable:
        return None
    owner = _exact_mapping(
        value,
        ("candidate_memory_id", "owner_scope", "project_id", "record_type"),
        "candidate owner",
    )
    if not isinstance(owner["candidate_memory_id"], str) or _MIGRATION_ID.fullmatch(
        owner["candidate_memory_id"]
    ) is None:
        raise ValidationError("invalid proposal review candidate owner")
    _identifier(owner["owner_scope"], "owner scope")
    if owner["project_id"] is not None:
        _identifier(owner["project_id"], "project id")
    _identifier(owner["record_type"], "record type")
    return owner


def _owner_key(owner):
    if owner is None:
        return None
    return (
        owner["candidate_memory_id"], owner["owner_scope"],
        owner["project_id"], owner["record_type"],
    )


def _validate_code_identity(value, scope):
    if not isinstance(value, dict):
        raise ValidationError("invalid proposal review code identity")
    kind = value.get("kind")
    if kind == "fixture":
        _exact_mapping(value, ("kind", "revision"), "code identity")
        if scope != "fixture":
            raise ValidationError("invalid proposal review code identity")
        _identifier(value["revision"], "fixture revision")
    elif kind == "git-commit":
        _exact_mapping(value, ("kind", "revision", "tree_state"), "code identity")
        if scope != "real" or not re.fullmatch(r"[0-9a-f]{40}", str(value["revision"])):
            raise ValidationError("invalid proposal review code identity")
        if value["tree_state"] != "clean":
            raise ValidationError("invalid proposal review code identity")
    elif kind == "pack-manifest":
        _exact_mapping(
            value,
            ("kind", "manifest_sha256", "version", "verification_status"),
            "code identity",
        )
        if scope != "real" or value["verification_status"] != "managed-valid":
            raise ValidationError("invalid proposal review code identity")
        _digest(value["manifest_sha256"], "manifest digest")
        _string(value["version"], "pack version", 128)
    else:
        raise ValidationError("invalid proposal review code identity")


def _validate_inputs(value, items):
    inputs = _exact_mapping(
        value,
        ("apply_journal", "bundle", "catalog", "proposal_set_sha256"),
        "inputs",
    )
    journal = _exact_mapping(
        inputs["apply_journal"], ("path", "sha256", "transaction_id"), "apply journal"
    )
    transaction_id = _identifier(journal["transaction_id"], "transaction id")
    if _portable_relative(journal["path"], "journal path") != (
        ".agent-memory/transactions/{0}/journal.json".format(transaction_id)
    ):
        raise ValidationError("invalid proposal review journal path")
    _digest(journal["sha256"], "journal digest")
    bundle = _exact_mapping(
        inputs["bundle"], ("plan_id", "sha256", "source_revision"), "bundle"
    )
    _identifier(bundle["plan_id"], "plan id")
    _digest(bundle["sha256"], "bundle digest")
    _digest(bundle["source_revision"], "source revision")
    catalog = _exact_mapping(inputs["catalog"], ("revision", "sha256"), "catalog")
    _integer(catalog["revision"], "catalog revision")
    _digest(catalog["sha256"], "catalog digest")
    _digest(inputs["proposal_set_sha256"], "proposal set digest")
    if inputs["proposal_set_sha256"] != _proposal_set_digest(items):
        raise ValidationError("proposal review proposal set mismatch")
    return inputs


def _validate_item(value):
    keys = (
        "candidate_owner", "decision_code", "evidence_ids", "live_source_state",
        "prior_classification", "proposal_id", "proposal_path", "proposal_sha256",
        "proposal_size", "refined_status", "snapshot_path", "snapshot_sha256",
        "source_path", "source_sha256",
    )
    item = _exact_mapping(value, keys, "item")
    owner = _candidate_owner(item["candidate_owner"], nullable=True)
    decision = _identifier(item["decision_code"], "decision code")
    if not isinstance(item["evidence_ids"], list) or len(item["evidence_ids"]) > _MAX_EVIDENCE_GROUPS:
        raise ValidationError("invalid proposal review evidence ids")
    evidence_ids = item["evidence_ids"]
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or not re.fullmatch(r"evidence-[0-9a-f]{64}", evidence_id):
            raise ValidationError("invalid proposal review evidence id")
    if evidence_ids != sorted(set(evidence_ids)):
        raise ValidationError("invalid proposal review evidence ordering")
    if item["live_source_state"] not in _LIVE_SOURCE_STATES:
        raise ValidationError("invalid proposal review live source state")
    if item["prior_classification"] not in _PRIOR_CLASSIFICATIONS:
        raise ValidationError("invalid proposal review prior classification")
    if item["refined_status"] not in _REFINED_STATUSES:
        raise ValidationError("invalid proposal review refined status")
    proposal_id = _identifier(item["proposal_id"], "proposal id")
    expected_path = ".agent-memory/state/proposals/{0}.json".format(proposal_id)
    if _portable_relative(item["proposal_path"], "proposal path") != expected_path:
        raise ValidationError("invalid proposal review proposal path")
    _digest(item["proposal_sha256"], "proposal digest")
    _integer(item["proposal_size"], "proposal size")
    _portable_relative(item["snapshot_path"], "snapshot path")
    _digest(item["snapshot_sha256"], "snapshot digest")
    _portable_relative(item["source_path"], "source path")
    _digest(item["source_sha256"], "source digest")
    if item["snapshot_sha256"] != item["source_sha256"]:
        raise ValidationError("proposal review snapshot digest mismatch")

    status = item["refined_status"]
    if status == "path-owner-candidate":
        valid = owner is not None and not evidence_ids and decision == "review-path-owner"
    elif status == "manual-owner-review":
        valid = owner is not None and bool(evidence_ids) and decision == "choose-fact-owner"
    elif status == "manual-parse-review":
        valid = not evidence_ids and (
            (decision == "inspect-unparseable-source")
            or (decision == "candidate-owner-unavailable" and owner is None)
        )
    else:
        expected = {
            "manual-format-review": ("unknown-format", "choose-source-format"),
            "knowledge-routing-review": (
                "embedded-knowledge-external", "choose-knowledge-destination"
            ),
            "focus-history-review": ("legacy-focus-input", "extract-or-dismiss-focus-history"),
            "project-id-routing-review": (
                "legacy-project-id-mapping-required", "supply-project-id-mapping"
            ),
        }.get(status)
        valid = owner is None and not evidence_ids and expected == (
            item["prior_classification"], decision
        )
    if not valid or (status in ("path-owner-candidate", "manual-owner-review", "manual-parse-review") and item["prior_classification"] != "ambiguous-owner"):
        raise ValidationError("proposal review item matrix mismatch")
    return item


def _validate_evidence(value):
    group = _exact_mapping(value, ("evidence_id", "fact_sha256", "occurrences"), "evidence")
    fact = _digest(group["fact_sha256"], "fact digest")
    if group["evidence_id"] != "evidence-" + fact:
        raise ValidationError("proposal review evidence identity mismatch")
    occurrences = group["occurrences"]
    if not isinstance(occurrences, list) or len(occurrences) < 2:
        raise ValidationError("invalid proposal review occurrences")
    parsed = []
    for value in occurrences:
        occurrence = _exact_mapping(
            value,
            ("candidate_owner", "end_line", "source_category", "source_path", "source_sha256", "start_line"),
            "evidence occurrence",
        )
        _candidate_owner(occurrence["candidate_owner"])
        _integer(occurrence["start_line"], "start line")
        _integer(occurrence["end_line"], "end line")
        if occurrence["start_line"] < 1 or occurrence["end_line"] < occurrence["start_line"]:
            raise ValidationError("invalid proposal review occurrence lines")
        if occurrence["source_category"] not in {item.value for item in SourceCategory}:
            raise ValidationError("invalid proposal review source category")
        _portable_relative(occurrence["source_path"], "occurrence source path")
        _digest(occurrence["source_sha256"], "occurrence source digest")
        parsed.append(occurrence)
    ordering = lambda item: (
        item["source_path"], item["start_line"], item["end_line"],
        item["candidate_owner"]["candidate_memory_id"],
    )
    if occurrences != sorted(occurrences, key=ordering) or len({tuple(ordering(item)) for item in occurrences}) != len(occurrences):
        raise ValidationError("invalid proposal review occurrence ordering")
    if len({_owner_key(item["candidate_owner"]) for item in occurrences}) < 2:
        raise ValidationError("proposal review evidence requires distinct owners")
    return group


def _validate_summary(value, items):
    summary = _exact_mapping(
        value, ("prior_classification_counts", "refined_status_counts", "total"), "summary"
    )
    prior = _exact_mapping(summary["prior_classification_counts"], _PRIOR_CLASSIFICATIONS, "prior counts")
    refined = _exact_mapping(summary["refined_status_counts"], _REFINED_STATUSES, "refined counts")
    expected_prior = {key: 0 for key in _PRIOR_CLASSIFICATIONS}
    expected_refined = {key: 0 for key in _REFINED_STATUSES}
    for item in items:
        expected_prior[item["prior_classification"]] += 1
        expected_refined[item["refined_status"]] += 1
    if any(type(number) is not int or number < 0 for number in prior.values()):
        raise ValidationError("invalid proposal review prior counts")
    if any(type(number) is not int or number < 0 for number in refined.values()):
        raise ValidationError("invalid proposal review refined counts")
    if prior != expected_prior or refined != expected_refined or summary["total"] != len(items) or type(summary["total"]) is not int:
        raise ValidationError("proposal review summary mismatch")


def _parse_proposal_review_bytes(raw: bytes) -> ProposalReviewArtifact:
    if not isinstance(raw, bytes) or len(raw) > _MAX_REPORT_BYTES:
        raise ValidationError("invalid proposal review bytes")
    try:
        document = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_reject_report_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("invalid proposal review JSON") from error
    if not isinstance(document, dict) or raw != _canonical_report_bytes(document):
        raise ValidationError("noncanonical proposal review")
    _exact_mapping(
        document,
        ("classifier_version", "code_identity", "evidence", "inputs", "items", "report_kind", "review_id", "run_context", "schema_version", "summary"),
        "document",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValidationError("invalid proposal review schema")
    if document["report_kind"] != "migration-proposal-review" or document["classifier_version"] != "owner-block-v1":
        raise ValidationError("invalid proposal review kind")

    context = _exact_mapping(
        document["run_context"], ("actor", "authorization_ref", "observed_at", "scope"), "run context"
    )
    if context["scope"] not in ("fixture", "real"):
        raise ValidationError("invalid proposal review scope")
    _identifier(context["actor"], "actor")
    _timestamp(context["observed_at"])
    if context["scope"] == "fixture":
        if context["authorization_ref"] is not None:
            raise ValidationError("invalid proposal review authorization")
    else:
        _string(context["authorization_ref"], "authorization", 4096)
    _validate_code_identity(document["code_identity"], context["scope"])

    if not isinstance(document["items"], list) or len(document["items"]) > _MAX_REVIEW_ITEMS:
        raise ValidationError("invalid proposal review items")
    items = [_validate_item(item) for item in document["items"]]
    item_order = lambda item: (item["proposal_path"], item["proposal_id"])
    if document["items"] != sorted(document["items"], key=item_order):
        raise ValidationError("invalid proposal review item ordering")
    identities = [(item["proposal_path"], item["proposal_id"]) for item in items]
    if len(identities) != len(set(identities)):
        raise ValidationError("duplicate proposal review item")

    inputs = _validate_inputs(document["inputs"], items)
    if not isinstance(document["evidence"], list) or len(document["evidence"]) > _MAX_EVIDENCE_GROUPS:
        raise ValidationError("invalid proposal review evidence")
    evidence = [_validate_evidence(group) for group in document["evidence"]]
    occurrence_count = sum(len(group["occurrences"]) for group in evidence)
    if occurrence_count > _MAX_EVIDENCE_OCCURRENCES:
        raise ValidationError("proposal review occurrence limit exceeded")
    evidence_ids = [group["evidence_id"] for group in evidence]
    if evidence_ids != sorted(evidence_ids) or len(evidence_ids) != len(set(evidence_ids)):
        raise ValidationError("invalid proposal review evidence ordering")

    groups = {group["evidence_id"]: group for group in evidence}
    referenced = {evidence_id for item in items for evidence_id in item["evidence_ids"]}
    if referenced != set(groups):
        raise ValidationError("proposal review evidence reference mismatch")
    for item in items:
        identity = (item["source_path"], item["source_sha256"], _owner_key(item["candidate_owner"]))
        for evidence_id in item["evidence_ids"]:
            group = groups.get(evidence_id)
            if group is None:
                raise ValidationError("dangling proposal review evidence")
            occurrence_identities = {
                (occurrence["source_path"], occurrence["source_sha256"], _owner_key(occurrence["candidate_owner"]))
                for occurrence in group["occurrences"]
            }
            if identity not in occurrence_identities or not any(owner != identity[2] for _, _, owner in occurrence_identities):
                raise ValidationError("proposal review evidence item mismatch")
    for group in evidence:
        for occurrence in group["occurrences"]:
            identity = (occurrence["source_path"], occurrence["source_sha256"], _owner_key(occurrence["candidate_owner"]))
            matches = [
                item for item in items
                if (item["source_path"], item["source_sha256"], _owner_key(item["candidate_owner"])) == identity
            ]
            if len(matches) != 1 or group["evidence_id"] not in matches[0]["evidence_ids"]:
                raise ValidationError("proposal review occurrence item mismatch")

    _validate_summary(document["summary"], items)
    expected_review_id = _review_identity(document["classifier_version"], inputs)
    if document["review_id"] != expected_review_id:
        raise ValidationError("proposal review identity mismatch")
    return ProposalReviewArtifact(
        document=document,
        raw=raw,
        review_id=expected_review_id,
        report_sha256=hashlib.sha256(raw).hexdigest(),
    )


def load_proposal_review(path: Path) -> ProposalReviewArtifact:
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as error:
        raise ValidationError("proposal review cannot be read") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or getattr(before, "st_file_attributes", 0) & _REPARSE_FLAG
        or before.st_size > _MAX_REPORT_BYTES
    ):
        raise ValidationError("invalid proposal review file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValidationError("proposal review changed during read")
            raw = handle.read(_MAX_REPORT_BYTES + 1)
            after = os.fstat(handle.fileno())
    except ValidationError:
        raise
    except OSError as error:
        raise ValidationError("proposal review cannot be read") from error
    if len(raw) > _MAX_REPORT_BYTES or len(raw) != opened.st_size or (opened.st_dev, opened.st_ino, opened.st_size) != (after.st_dev, after.st_ino, after.st_size):
        raise ValidationError("proposal review changed during read")
    return _parse_proposal_review_bytes(raw)


def _strip_comments(lines):
    output = []
    comment_end = None
    for line_number, original in lines:
        line = original
        cursor = 0
        kept = []
        while cursor < len(line):
            if comment_end is not None:
                end = line.find(comment_end, cursor)
                if end < 0:
                    cursor = len(line)
                    break
                cursor = end + len(comment_end)
                comment_end = None
                continue
            html = line.find("<!--", cursor)
            obsidian = line.find("%%", cursor)
            candidates = [
                (position, terminator)
                for position, terminator in ((html, "-->"), (obsidian, "%%"))
                if position >= 0
            ]
            if not candidates:
                kept.append(line[cursor:])
                break
            start, terminator = min(candidates, key=lambda item: item[0])
            kept.append(line[cursor:start])
            cursor = start + (4 if terminator == "-->" else 2)
            comment_end = terminator
        output.append((line_number, "".join(kept)))
    if comment_end is not None:
        raise FactParseError(FactParseCode.UNCLOSED_COMMENT)
    return output


def _table_delimiter(line):
    value = line.strip()
    if "|" not in value:
        return False
    cells = value.split("|")
    if cells and cells[0].strip() == "":
        cells = cells[1:]
    if cells and cells[-1].strip() == "":
        cells = cells[:-1]
    return bool(cells) and all(_TABLE_CELL.fullmatch(cell.strip()) for cell in cells)


def _structural_line(line):
    return bool(
        _ATX_HEADING.match(line)
        or _THEMATIC.fullmatch(line)
        or _table_delimiter(line)
    )


def _pure_structural_block(value, physical_lines):
    if physical_lines == 1 and value.lstrip().lower().startswith("source:"):
        return True
    if _INLINE_CODE.fullmatch(value):
        return True
    if _MARKDOWN_LINK.fullmatch(value) or _WIKILINK.fullmatch(value):
        return True
    if _SCHEME_URL.fullmatch(value):
        return True
    if value.startswith(("/", "./", "../")):
        return True
    return PureWindowsPath(value).is_absolute()


def _normalized(line):
    return re.sub(r"\s+", " ", line).strip()


def extract_fact_blocks(raw: bytes) -> Tuple[FactBlock, ...]:
    """Implement the approved parser contract without fuzzy normalization."""
    if not isinstance(raw, bytes) or len(raw) > _MAX_OWNER_SOURCE_BYTES:
        raise FactParseError(FactParseCode.RESOURCE_LIMIT)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise FactParseError(FactParseCode.INVALID_UTF8) from error
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if text.startswith("\ufeff"):
        text = text[1:]
    numbered = list(enumerate(text.split("\n"), 1))

    start = 0
    if numbered and numbered[0][1] == "---":
        for index in range(1, len(numbered)):
            if numbered[index][1] in ("---", "..."):
                start = index + 1
                break
        else:
            raise FactParseError(FactParseCode.UNCLOSED_FRONTMATTER)

    lines = _strip_comments(numbered[start:])
    blocks = []
    fence_character = None
    fence_length = 0
    block_lines = []

    def finish_block():
        if not block_lines:
            return
        value = _normalized("\n".join(item[1] for item in block_lines))
        if value and not _pure_structural_block(value, len(block_lines)):
            blocks.append(
                FactBlock(
                    value.encode("utf-8"),
                    block_lines[0][0],
                    block_lines[-1][0],
                )
            )
        block_lines[:] = []

    for line_number, line in lines:
        if fence_character is not None:
            if re.fullmatch(
                r" {0,3}" + re.escape(fence_character) + "{" + str(fence_length) + r",}[ \t]*",
                line,
            ):
                fence_character = None
                fence_length = 0
            continue
        opener = _FENCE_OPEN.match(line)
        if opener is not None:
            finish_block()
            marker = opener.group(1)
            fence_character = marker[0]
            fence_length = len(marker)
            continue
        if not line.strip() or _structural_line(line):
            finish_block()
            continue
        list_item = _LIST_ITEM.match(line)
        if list_item is not None:
            finish_block()
            value = line[list_item.end() :]
            block_lines.append((line_number, value))
            continue
        block_lines.append((line_number, line))
    if fence_character is not None:
        raise FactParseError(FactParseCode.UNCLOSED_FENCE)
    finish_block()
    return tuple(blocks)
