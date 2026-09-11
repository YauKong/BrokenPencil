"""Exact tagged readers for immutable proposal artifacts."""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import PurePosixPath
from typing import Mapping, Optional, Tuple, Union

from .errors import ValidationError
from .manifest import _portable_path_is_safe
from .coordination import _validate_unbound_session_candidate
from .models import RecordCandidate, RecordEnvelope, UnboundSessionCandidate
from .paths import validate_identifier
from .records import normalize_body, record_relative_path, render_record
from .story_profiles import StoryDelta, _validate_delta


_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_MIGRATION_KEYS = {
    "actor",
    "desired",
    "expected_base",
    "occurred_at",
    "operation",
    "schema_version",
    "status",
    "target",
    "transaction_id",
}
_MIGRATION_DESIRED_KEYS = {
    "action_id",
    "classification",
    "source_path",
    "source_sha256",
}
_TRANSACTION_KEYS = {
    "actor",
    "conflict_code",
    "desired",
    "expected_base",
    "observed_base",
    "occurred_at",
    "operation",
    "schema_version",
    "target",
    "transaction_id",
}
_TRANSACTION_OPERATIONS = {"commit-record", "knowledge-promotion", "update_focus"}
_UNBOUND_KEYS = {
    "actor",
    "desired",
    "expected_base",
    "observed_base",
    "occurred_at",
    "operation",
    "schema_version",
    "status",
    "target",
    "transaction_id",
}
_UNBOUND_DESIRED_KEYS = {
    "candidate_primary_story",
    "candidate_related_stories",
    "coordinator_task_id",
    "intended_story_delta",
    "origin_task_id",
    "project_id",
    "session_candidate",
    "session_candidate_sha256",
}


class ProposalFamily(str, Enum):
    TRANSACTION_CONFLICT = "transaction-conflict"
    MIGRATION_REVIEW = "migration-review"
    UNBOUND_SESSION = "unbound-session"


class MigrationReviewClassification(str, Enum):
    AMBIGUOUS_OWNER = "ambiguous-owner"
    UNKNOWN_FORMAT = "unknown-format"
    EMBEDDED_KNOWLEDGE_EXTERNAL = "embedded-knowledge-external"
    LEGACY_FOCUS_INPUT = "legacy-focus-input"
    LEGACY_PROJECT_ID_MAPPING_REQUIRED = "legacy-project-id-mapping-required"


@dataclass(frozen=True)
class TransactionConflictProposal:
    relative_path: str
    proposal_id: str
    actor: str
    occurred_at: str
    target: str
    transaction_id: str
    sha256: str
    size: int
    operation: str
    conflict_code: str
    desired: Mapping[str, object]
    expected_base: Mapping[str, object]
    observed_base: Mapping[str, object]


@dataclass(frozen=True)
class MigrationReviewProposal:
    relative_path: str
    proposal_id: str
    actor: str
    occurred_at: str
    target: str
    transaction_id: str
    sha256: str
    size: int
    source_revision: str
    classification: MigrationReviewClassification
    source_path: str
    source_sha256: str


@dataclass(frozen=True)
class UnboundSessionProposal:
    relative_path: str
    proposal_id: str
    actor: str
    occurred_at: str
    target: str
    transaction_id: str
    sha256: str
    size: int
    project_id: str
    session_candidate: RecordCandidate
    candidate_primary_story_id: Optional[str]
    candidate_primary_evidence: Optional[str]
    candidate_related_story_ids: Tuple[str, ...]
    candidate_related_evidence: Tuple[str, ...]
    intended_story_delta: Optional[StoryDelta]
    origin_task_id: str
    coordinator_task_id: Optional[str]


ProposalArtifact = Union[
    TransactionConflictProposal,
    MigrationReviewProposal,
    UnboundSessionProposal,
]


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("proposal-duplicate-key")
        value[key] = item
    return value


def _decode_canonical(raw: bytes):
    if not isinstance(raw, bytes):
        raise ValidationError("proposal-invalid-bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except UnicodeDecodeError as error:
        raise ValidationError("proposal-invalid-utf8") from error
    except json.JSONDecodeError as error:
        raise ValidationError("proposal-invalid-json") from error
    canonical = (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    if raw != canonical:
        raise ValidationError("proposal-noncanonical")
    return document


def _portable_relative(value, code):
    if not _portable_path_is_safe(value):
        raise ValidationError(code)
    path = PurePosixPath(value)
    if path.as_posix() != value or any(
        part in ("", ".", "..") or part.endswith((" ", "."))
        for part in path.parts
    ):
        raise ValidationError(code)
    return value


def _timestamp(value):
    if not isinstance(value, str) or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValidationError("proposal-invalid-timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        raise ValidationError("proposal-invalid-timestamp") from error
    return value


def _digest(value, code):
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValidationError(code)
    return value


def _proposal_id(relative_path):
    _portable_relative(relative_path, "proposal-invalid-path")
    path = PurePosixPath(relative_path)
    if path.parts[:3] != (".agent-memory", "state", "proposals") or len(path.parts) != 4:
        raise ValidationError("proposal-invalid-path")
    if path.suffix != ".json":
        raise ValidationError("proposal-invalid-path")
    proposal_id = path.stem
    validate_identifier(proposal_id, "proposal id")
    return proposal_id


def _parse_migration_review(relative_path, raw, document):
    if not isinstance(document, dict) or set(document) != _MIGRATION_KEYS:
        raise ValidationError("proposal-invalid-shape")
    desired = document.get("desired")
    expected = document.get("expected_base")
    if (
        document.get("schema_version") != 2
        or type(document.get("schema_version")) is not int
        or document.get("status") != "proposed"
        or not isinstance(desired, dict)
        or set(desired) != _MIGRATION_DESIRED_KEYS
        or not isinstance(expected, dict)
        or set(expected) != {"source_revision"}
    ):
        raise ValidationError("proposal-invalid-shape")
    proposal_id = _proposal_id(relative_path)
    try:
        actor = validate_identifier(document.get("actor"), "proposal actor")
        transaction_id = validate_identifier(
            document.get("transaction_id"), "proposal transaction id"
        )
        action_id = validate_identifier(desired.get("action_id"), "proposal action id")
    except ValidationError as error:
        raise ValidationError("proposal-invalid-identity") from error
    if proposal_id != transaction_id or transaction_id != action_id:
        raise ValidationError("proposal-invalid-identity")
    source_path = _portable_relative(desired.get("source_path"), "proposal-invalid-source-path")
    target = _portable_relative(document.get("target"), "proposal-invalid-target")
    if target != source_path:
        raise ValidationError("proposal-target-mismatch")
    try:
        classification = MigrationReviewClassification(desired.get("classification"))
    except (TypeError, ValueError) as error:
        raise ValidationError("proposal-invalid-classification") from error
    return MigrationReviewProposal(
        relative_path=relative_path,
        proposal_id=proposal_id,
        actor=actor,
        occurred_at=_timestamp(document.get("occurred_at")),
        target=target,
        transaction_id=transaction_id,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        source_revision=_digest(
            expected.get("source_revision"), "proposal-invalid-source-revision"
        ),
        classification=classification,
        source_path=source_path,
        source_sha256=_digest(
            desired.get("source_sha256"), "proposal-invalid-source-digest"
        ),
    )


def _valid_record_desired(value, target):
    if not isinstance(value, dict) or set(value) != {
        "memory_id",
        "record_candidate",
        "record_candidate_sha256",
        "record_revision",
        "record_sha256",
        "relative_path",
    }:
        return False
    semantic = value.get("record_candidate")
    if not isinstance(semantic, dict) or set(semantic) != {"body", "envelope"}:
        return False
    envelope_value = semantic.get("envelope")
    if not isinstance(envelope_value, dict) or set(envelope_value) != {
        "body_sha256",
        "created_at",
        "memory_id",
        "observed_at",
        "owner_scope",
        "project",
        "record_type",
        "revision",
        "schema_version",
        "source",
        "source_revision",
        "supersedes",
    }:
        return False
    try:
        envelope = RecordEnvelope(**envelope_value)
        rendered = render_record(envelope, semantic.get("body")).encode("utf-8")
        relative_path = record_relative_path(envelope).as_posix()
    except (TypeError, ValidationError):
        return False
    semantic_bytes = (
        json.dumps(semantic, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    return bool(
        value.get("memory_id") == envelope.memory_id
        and value.get("record_revision") == envelope.revision
        and value.get("relative_path") == relative_path
        and target == relative_path
        and value.get("record_sha256") == hashlib.sha256(rendered).hexdigest()
        and value.get("record_candidate_sha256")
        == hashlib.sha256(semantic_bytes).hexdigest()
    )


def _valid_update_focus_desired(value, target):
    if not isinstance(value, dict) or set(value) != {
        "observed_at",
        "project_id",
        "record_ids",
    }:
        return False
    record_ids = value.get("record_ids")
    try:
        project_id = validate_identifier(value.get("project_id"), "project id")
        _timestamp(value.get("observed_at"))
        if not isinstance(record_ids, list):
            return False
        for memory_id in record_ids:
            validate_identifier(memory_id, "memory id")
    except ValidationError:
        return False
    return bool(
        record_ids == sorted(set(record_ids))
        and target == ".agent-memory/state/focus/{0}.json".format(project_id)
    )


def _parse_transaction_conflict(relative_path, raw, document):
    if not isinstance(document, dict) or set(document) != _TRANSACTION_KEYS:
        raise ValidationError("proposal-invalid-shape")
    operation = document.get("operation")
    if operation not in _TRANSACTION_OPERATIONS:
        raise ValidationError("proposal-unsupported-operation")
    desired = document.get("desired")
    expected = document.get("expected_base")
    observed = document.get("observed_base")
    conflict_code = document.get("conflict_code")
    if (
        document.get("schema_version") != 2
        or type(document.get("schema_version")) is not int
        or not isinstance(desired, dict)
        or not isinstance(expected, dict)
        or not isinstance(observed, dict)
        or not isinstance(conflict_code, str)
        or not conflict_code
    ):
        raise ValidationError("proposal-invalid-shape")
    proposal_id = _proposal_id(relative_path)
    try:
        actor = validate_identifier(document.get("actor"), "proposal actor")
        transaction_id = validate_identifier(
            document.get("transaction_id"), "proposal transaction id"
        )
    except ValidationError as error:
        raise ValidationError("proposal-invalid-identity") from error
    target = _portable_relative(document.get("target"), "proposal-invalid-target")
    valid = False
    if operation == "commit-record":
        valid = bool(
            proposal_id == transaction_id
            and _valid_record_desired(desired, target)
            and set(expected) == {"catalog_revision", "record_revision"}
            and type(expected.get("catalog_revision")) is int
            and expected["catalog_revision"] >= 0
            and (
                expected.get("record_revision") is None
                or type(expected.get("record_revision")) is int
                and expected["record_revision"] >= 1
            )
            and set(observed).issubset({"catalog_revision", "record_revision"})
        )
    elif operation == "update_focus":
        valid = bool(
            proposal_id == transaction_id
            and _valid_update_focus_desired(desired, target)
            and set(expected) == {"focus_revision"}
            and type(expected.get("focus_revision")) is int
            and expected["focus_revision"] >= 0
            and set(observed).issubset({"focus_revision", "missing_record_ids"})
        )
    else:
        source_ids = desired.get("source_record_ids")
        valid = bool(
            set(desired)
            == {"candidate_id", "rationale", "source_record_ids", "suggested_target"}
            and proposal_id == desired.get("candidate_id")
            and isinstance(source_ids, list)
            and bool(source_ids)
            and isinstance(desired.get("rationale"), str)
            and bool(desired["rationale"].strip())
            and target == desired.get("suggested_target")
            and conflict_code == "knowledge-promotion-candidate"
            and expected == {"source_record_ids": source_ids}
            and set(observed) == {"catalog_revision"}
            and type(observed.get("catalog_revision")) is int
            and observed["catalog_revision"] >= 0
        )
        try:
            validate_identifier(proposal_id, "proposal id")
            for memory_id in source_ids if isinstance(source_ids, list) else ():
                validate_identifier(memory_id, "source record id")
            _portable_relative(desired.get("suggested_target"), "proposal-invalid-target")
        except ValidationError:
            valid = False
    if not valid:
        raise ValidationError("proposal-invalid-shape")
    return TransactionConflictProposal(
        relative_path=relative_path,
        proposal_id=proposal_id,
        actor=actor,
        occurred_at=_timestamp(document.get("occurred_at")),
        target=target,
        transaction_id=transaction_id,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        operation=operation,
        conflict_code=conflict_code,
        desired=desired,
        expected_base=expected,
        observed_base=observed,
    )


def _parse_unbound_session(relative_path, raw, document):
    if not isinstance(document, dict) or set(document) != _UNBOUND_KEYS:
        raise ValidationError("proposal-invalid-shape")
    desired = document.get("desired")
    if (
        document.get("schema_version") != 2
        or type(document.get("schema_version")) is not int
        or document.get("status") != "proposed"
        or not isinstance(desired, dict)
        or set(desired) != _UNBOUND_DESIRED_KEYS
        or document.get("expected_base") != {}
        or document.get("observed_base") != {}
    ):
        raise ValidationError("proposal-invalid-shape")
    proposal_id = _proposal_id(relative_path)
    target = _portable_relative(document.get("target"), "proposal-invalid-target")
    if target != relative_path:
        raise ValidationError("proposal-target-mismatch")
    try:
        actor = validate_identifier(document.get("actor"), "proposal actor")
        transaction_id = validate_identifier(
            document.get("transaction_id"), "proposal transaction id"
        )
        project_id = validate_identifier(desired.get("project_id"), "proposal project id")
        origin_task_id = validate_identifier(
            desired.get("origin_task_id"), "proposal origin task id"
        )
        coordinator_task_id = desired.get("coordinator_task_id")
        if coordinator_task_id is not None:
            validate_identifier(coordinator_task_id, "proposal coordinator task id")
    except ValidationError as error:
        raise ValidationError("proposal-invalid-identity") from error
    if proposal_id != transaction_id:
        raise ValidationError("proposal-invalid-identity")

    semantic = desired.get("session_candidate")
    if not isinstance(semantic, dict) or set(semantic) != {"body", "envelope"}:
        raise ValidationError("proposal-invalid-shape")
    envelope_value = semantic.get("envelope")
    if not isinstance(envelope_value, dict):
        raise ValidationError("proposal-invalid-shape")
    try:
        envelope = RecordEnvelope(**envelope_value)
        session_candidate = RecordCandidate(envelope, semantic.get("body"))
        render_record(envelope, session_candidate.body)
    except (TypeError, ValidationError) as error:
        raise ValidationError("proposal-invalid-shape") from error
    if envelope.record_type != "session" or envelope.project != project_id:
        raise ValidationError("proposal-invalid-shape")
    semantic_bytes = (
        json.dumps(semantic, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    if (
        semantic.get("body") != normalize_body(session_candidate.body)
        or desired.get("session_candidate_sha256")
        != hashlib.sha256(semantic_bytes).hexdigest()
    ):
        raise ValidationError("proposal-invalid-shape")

    primary = desired.get("candidate_primary_story")
    if primary is None:
        primary_story_id = None
        primary_evidence = None
    elif isinstance(primary, dict) and set(primary) == {"evidence", "story_id"}:
        primary_story_id = primary.get("story_id")
        primary_evidence = primary.get("evidence")
    else:
        raise ValidationError("proposal-invalid-shape")
    related_value = desired.get("candidate_related_stories")
    if not isinstance(related_value, list):
        raise ValidationError("proposal-invalid-shape")
    related_ids = []
    related_evidence = []
    for item in related_value:
        if not isinstance(item, dict) or set(item) != {"evidence", "story_id"}:
            raise ValidationError("proposal-invalid-shape")
        related_ids.append(item.get("story_id"))
        related_evidence.append(item.get("evidence"))

    delta_value = desired.get("intended_story_delta")
    if delta_value is None:
        delta = None
    else:
        if not isinstance(delta_value, dict) or set(delta_value) != {
            "current_state",
            "expected_revision",
            "failure_mode",
            "open_questions",
            "related_decision_ids",
            "resolution",
            "source_session_id",
            "story_id",
            "turning_points",
        }:
            raise ValidationError("proposal-invalid-shape")
        converted = dict(delta_value)
        for field in ("turning_points", "open_questions", "related_decision_ids"):
            if not isinstance(converted[field], list):
                raise ValidationError("proposal-invalid-shape")
            converted[field] = tuple(converted[field])
        try:
            delta = StoryDelta(**converted)
            _validate_delta(delta)
        except (TypeError, ValidationError) as error:
            raise ValidationError("proposal-invalid-shape") from error
    candidate = UnboundSessionCandidate(
        project_id=project_id,
        session_candidate=session_candidate,
        candidate_primary_story_id=primary_story_id,
        candidate_primary_evidence=primary_evidence,
        candidate_related_story_ids=tuple(related_ids),
        candidate_related_evidence=tuple(related_evidence),
        intended_story_delta=delta,
        origin_task_id=origin_task_id,
        coordinator_task_id=coordinator_task_id,
    )
    try:
        _validate_unbound_session_candidate(candidate)
    except ValidationError as error:
        raise ValidationError("proposal-invalid-shape") from error
    return UnboundSessionProposal(
        relative_path=relative_path,
        proposal_id=proposal_id,
        actor=actor,
        occurred_at=_timestamp(document.get("occurred_at")),
        target=target,
        transaction_id=transaction_id,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        project_id=project_id,
        session_candidate=session_candidate,
        candidate_primary_story_id=primary_story_id,
        candidate_primary_evidence=primary_evidence,
        candidate_related_story_ids=tuple(related_ids),
        candidate_related_evidence=tuple(related_evidence),
        intended_story_delta=delta,
        origin_task_id=origin_task_id,
        coordinator_task_id=coordinator_task_id,
    )


def parse_proposal_artifact(relative_path: str, raw: bytes) -> ProposalArtifact:
    """Reject duplicate keys, noncanonical bytes, unknown fields, and identity drift."""
    document = _decode_canonical(raw)
    if not isinstance(document, dict):
        raise ValidationError("proposal-invalid-shape")
    if document.get("operation") == "migration-review-proposal":
        return _parse_migration_review(relative_path, raw, document)
    if document.get("operation") == "unbound-session":
        return _parse_unbound_session(relative_path, raw, document)
    if document.get("operation") in _TRANSACTION_OPERATIONS:
        return _parse_transaction_conflict(relative_path, raw, document)
    raise ValidationError("proposal-unsupported-operation")
