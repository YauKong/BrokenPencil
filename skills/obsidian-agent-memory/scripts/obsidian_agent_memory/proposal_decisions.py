"""Strict loading and report binding for reviewed proposal decisions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping, Optional, Tuple

from .errors import ValidationError
from .paths import validate_identifier
from .proposal_review import ProposalReviewArtifact


_MAX_DECISION_BYTES = 4 * 1024 * 1024
_MAX_NOTE_CHARACTERS = 4096
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PROJECT_OWNER = re.compile(
    r"project\.([a-z0-9][a-z0-9._-]{0,127})\.(session|story|decision)\Z"
)
_GLOBAL_OWNERS = {
    "agent.runbook": "runbook",
    "user.preference": "preference",
    "meta.migration": "migration",
    "meta.maintenance": "maintenance",
}
_ACCEPTED_STATES = frozenset(("confirm-candidate", "change-owner"))
_NO_RECORD_STATES = frozenset(
    ("sources-only", "knowledge-base-candidate", "keep-unresolved")
)
_DECISION_KEYS = frozenset(
    ("proposal_id", "state", "owner_scope", "project_id", "note")
)
_DOCUMENT_KEYS = frozenset(
    (
        "schema_version",
        "evidence_kind",
        "review_id",
        "report_sha256",
        "mutation_authorized",
        "decisions",
    )
)


@dataclass(frozen=True)
class ProposalDecision:
    proposal_id: str
    state: Literal[
        "confirm-candidate",
        "change-owner",
        "sources-only",
        "knowledge-base-candidate",
        "keep-unresolved",
    ]
    owner_scope: Optional[str]
    project_id: Optional[str]
    note: str


@dataclass(frozen=True)
class ProposalDecisionEnvelope:
    review_id: str
    report_sha256: str
    decisions_sha256: str
    decisions: Tuple[ProposalDecision, ...]
    raw: bytes


def _reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("duplicate decision-envelope key")
        value[key] = item
    return value


def _exact_mapping(value, keys, label):
    if not isinstance(value, dict) or frozenset(value) != keys:
        raise ValidationError("invalid {0}".format(label))
    return value


def _digest(value, label):
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValidationError("invalid {0}".format(label))
    return value


def _owner(value, project_id):
    if not isinstance(value, str):
        raise ValidationError("accepted decision requires owner_scope")
    matched = _PROJECT_OWNER.fullmatch(value)
    if matched is not None:
        owner_project = validate_identifier(matched.group(1), "project_id")
        if project_id != owner_project:
            raise ValidationError("project owner does not match project_id")
        return matched.group(2)
    if value not in _GLOBAL_OWNERS or project_id is not None:
        raise ValidationError("invalid decision owner")
    return _GLOBAL_OWNERS[value]


def _decision(value) -> ProposalDecision:
    document = _exact_mapping(value, _DECISION_KEYS, "proposal decision")
    proposal_id = validate_identifier(document["proposal_id"], "proposal_id")
    state = document["state"]
    if state not in _ACCEPTED_STATES | _NO_RECORD_STATES:
        raise ValidationError("invalid proposal decision state")
    project_id = document["project_id"]
    if project_id is not None:
        project_id = validate_identifier(project_id, "project_id")
    owner_scope = document["owner_scope"]
    if state in _ACCEPTED_STATES:
        _owner(owner_scope, project_id)
    elif owner_scope is not None or project_id is not None:
        raise ValidationError("no-record decision cannot select an owner")
    note = document["note"]
    if not isinstance(note, str) or len(note) > _MAX_NOTE_CHARACTERS:
        raise ValidationError("invalid proposal decision note")
    return ProposalDecision(proposal_id, state, owner_scope, project_id, note)


def load_proposal_decisions(path: Path) -> ProposalDecisionEnvelope:
    """Load one complete reviewed decision envelope while preserving exact bytes."""

    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise ValidationError("decision envelope cannot be read") from error
    if not raw or len(raw) > _MAX_DECISION_BYTES:
        raise ValidationError("invalid decision envelope size")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("invalid decision envelope JSON") from error
    document = _exact_mapping(value, _DOCUMENT_KEYS, "decision envelope")
    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        raise ValidationError("unsupported decision envelope schema")
    if document["evidence_kind"] != "proposal-review-decisions":
        raise ValidationError("unsupported decision envelope kind")
    review_id = validate_identifier(document["review_id"], "review_id")
    report_sha256 = _digest(document["report_sha256"], "report_sha256")
    if document["mutation_authorized"] is not False:
        raise ValidationError("decision envelope cannot authorize mutation")
    if not isinstance(document["decisions"], list) or not document["decisions"]:
        raise ValidationError("decision envelope requires decisions")
    decisions = tuple(_decision(item) for item in document["decisions"])
    proposal_ids = tuple(item.proposal_id for item in decisions)
    if proposal_ids != tuple(sorted(proposal_ids)) or len(set(proposal_ids)) != len(proposal_ids):
        raise ValidationError("proposal decisions must be unique and sorted")
    return ProposalDecisionEnvelope(
        review_id=review_id,
        report_sha256=report_sha256,
        decisions_sha256=hashlib.sha256(raw).hexdigest(),
        decisions=decisions,
        raw=raw,
    )


def _source_stable_memory_id(item: Mapping[str, object]) -> str:
    source_path = item.get("source_path")
    snapshot_sha256 = item.get("snapshot_sha256")
    if not isinstance(source_path, str) or not source_path or "\0" in source_path:
        raise ValidationError("invalid report source path")
    _digest(snapshot_sha256, "snapshot_sha256")
    material = source_path.encode("utf-8") + b"\0" + snapshot_sha256.encode("ascii")
    return "migr-" + hashlib.sha256(material).hexdigest()[:24]


def _bind_candidate_owner(item, decision):
    candidate = item.get("candidate_owner")
    if not isinstance(candidate, dict):
        raise ValidationError("accepted report item requires candidate owner")
    expected_memory_id = _source_stable_memory_id(item)
    if candidate.get("candidate_memory_id") != expected_memory_id:
        raise ValidationError("candidate memory ID is not source-stable")
    candidate_type = _owner(candidate.get("owner_scope"), candidate.get("project_id"))
    if candidate.get("record_type") != candidate_type:
        raise ValidationError("candidate record type does not match owner")
    if decision.state == "confirm-candidate" and (
        decision.owner_scope != candidate.get("owner_scope")
        or decision.project_id != candidate.get("project_id")
    ):
        raise ValidationError("confirmed decision does not match report candidate")


def bind_proposal_decisions(
    envelope: ProposalDecisionEnvelope,
    report: ProposalReviewArtifact,
) -> ProposalDecisionEnvelope:
    """Bind a complete decision envelope to the exact proposal-review report."""

    if not isinstance(envelope, ProposalDecisionEnvelope):
        raise ValidationError("invalid decision envelope")
    if not isinstance(report, ProposalReviewArtifact):
        raise ValidationError("invalid proposal review artifact")
    if envelope.review_id != report.review_id or envelope.report_sha256 != report.report_sha256:
        raise ValidationError("decision envelope does not match report")
    items = report.document.get("items")
    if not isinstance(items, list):
        raise ValidationError("proposal review items are invalid")
    by_id = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValidationError("proposal review item is invalid")
        proposal_id = item.get("proposal_id")
        if not isinstance(proposal_id, str) or proposal_id in by_id:
            raise ValidationError("proposal review proposal_id is invalid")
        by_id[proposal_id] = item
    decisions_by_id = {item.proposal_id: item for item in envelope.decisions}
    if set(decisions_by_id) != set(by_id):
        raise ValidationError("decision envelope must cover the complete report")
    for proposal_id in sorted(by_id):
        decision = decisions_by_id[proposal_id]
        if decision.state in _ACCEPTED_STATES:
            _bind_candidate_owner(by_id[proposal_id], decision)
            _owner(decision.owner_scope, decision.project_id)
    return envelope
