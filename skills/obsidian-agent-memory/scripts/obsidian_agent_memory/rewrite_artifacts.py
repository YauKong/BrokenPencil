"""Strict semantic rewrite and independent-review artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Optional, Tuple

from .errors import ValidationError
from .paths import validate_identifier
from .proposal_decisions import ProposalDecision, _owner, _source_stable_memory_id
from .records import normalize_body
from .session_relationships import parse_session_relationship
from .story_profiles import parse_story_profile


_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_TOP_KEYS = frozenset(
    (
        "schema_version",
        "evidence_kind",
        "review_id",
        "report_sha256",
        "decisions_sha256",
        "proposal_id",
        "decision_state",
        "source",
        "target",
        "rewrite",
    )
)
_SOURCE_KEYS = frozenset(
    ("source_path", "snapshot_path", "snapshot_sha256", "proposal_sha256")
)
_TARGET_KEYS = frozenset(
    ("memory_id", "record_type", "owner_scope", "project_id")
)
_REWRITE_KEYS = frozenset(
    ("title", "body", "body_sha256", "writer_profile", "evidence_spans")
)
_SPAN_KEYS = frozenset(
    ("start_line", "end_line", "text_sha256", "supports_sections")
)
_REVIEW_KEYS = frozenset(
    (
        "schema_version",
        "evidence_kind",
        "proposal_id",
        "rewrite_sha256",
        "reviewer_profile",
        "checks",
        "outcome",
        "reason_codes",
    )
)
_CHECK_KEYS = frozenset(
    (
        "material_facts_retained",
        "no_unsupported_claims",
        "ownership_not_duplicated",
        "evidence_spans_support_sections",
        "story_membership_not_inferred",
    )
)
_HEADINGS = {
    "session": (
        "Session Relationship",
        "User Goal",
        "Outcome",
        "Work Done",
        "Decisions Observed",
        "Commands Verified",
        "Files Changed",
        "Promotion Candidates",
        "Follow-Ups",
    ),
    "story": (
        "Situation",
        "Current State",
        "Turning Points",
        "Failure Mode",
        "Resolution",
        "Open Questions",
        "Related Decision IDs",
    ),
    "decision": (
        "Context",
        "Decision",
        "Consequences",
        "Evidence",
        "Related Record IDs",
    ),
    "preference": ("Preference", "Decision Test", "Evidence"),
    "runbook": ("Preconditions", "Procedure", "Verification", "Failure Handling"),
    "migration": (
        "Source Snapshot",
        "Reviewed Plan",
        "Applied Changes",
        "Verification",
        "Unresolved Proposals",
    ),
    "maintenance": (
        "Audit Scope",
        "Findings",
        "Reviewed Actions",
        "Applied Transactions",
        "Verification",
    ),
}
_TITLE_PREFIX = {
    "session": "Session",
    "story": "Story",
    "decision": "Decision",
    "preference": "Preference",
    "runbook": "Runbook",
    "migration": "Migration",
    "maintenance": "Maintenance",
}


@dataclass(frozen=True)
class EvidenceSpan:
    start_line: int
    end_line: int
    text_sha256: str
    supports_sections: Tuple[str, ...]


@dataclass(frozen=True)
class RewriteCandidateArtifact:
    review_id: str
    report_sha256: str
    decisions_sha256: str
    proposal_id: str
    decision_state: str
    source_path: str
    snapshot_path: str
    snapshot_sha256: str
    proposal_sha256: str
    memory_id: str
    record_type: str
    owner_scope: str
    project_id: Optional[str]
    title: str
    body: str
    body_sha256: str
    writer_profile: str
    evidence_spans: Tuple[EvidenceSpan, ...]
    rewrite_sha256: str
    raw: bytes


@dataclass(frozen=True)
class SemanticReviewArtifact:
    proposal_id: str
    rewrite_sha256: str
    reviewer_profile: str
    checks: Tuple[Tuple[str, bool], ...]
    outcome: str
    reason_codes: Tuple[str, ...]
    semantic_review_sha256: str
    raw: bytes

    @property
    def passed(self) -> bool:
        return self.outcome == "pass"


def _reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("duplicate rewrite artifact key")
        value[key] = item
    return value


def _canonical(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _load(path: Path, label: str):
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise ValidationError("{0} cannot be read".format(label)) from error
    if not raw or len(raw) > _MAX_ARTIFACT_BYTES:
        raise ValidationError("invalid {0} size".format(label))
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("invalid {0} JSON".format(label)) from error
    if _canonical(value) != raw:
        raise ValidationError("{0} is not canonical JSON".format(label))
    return raw, value


def _exact(value, keys, label):
    if not isinstance(value, dict) or frozenset(value) != keys:
        raise ValidationError("invalid {0}".format(label))
    return value


def _digest(value, label):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValidationError("invalid {0}".format(label))
    return value


def _portable_relative(value, label):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise ValidationError("invalid {0}".format(label))
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValidationError("invalid {0}".format(label))
    return value


def _span(value) -> EvidenceSpan:
    document = _exact(value, _SPAN_KEYS, "evidence span")
    start = document["start_line"]
    end = document["end_line"]
    if (
        type(start) is not int
        or type(end) is not int
        or start < 1
        or end < start
    ):
        raise ValidationError("invalid evidence span range")
    sections = document["supports_sections"]
    if (
        not isinstance(sections, list)
        or not sections
        or any(not isinstance(item, str) or not item for item in sections)
        or sections != sorted(sections)
        or len(sections) != len(set(sections))
    ):
        raise ValidationError("invalid evidence span sections")
    return EvidenceSpan(start, end, _digest(document["text_sha256"], "span hash"), tuple(sections))


def load_rewrite_candidate(path: Path) -> RewriteCandidateArtifact:
    """Load one canonical semantic rewrite candidate without trusting its prose."""

    raw, value = _load(path, "rewrite candidate")
    document = _exact(value, _TOP_KEYS, "rewrite candidate")
    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        raise ValidationError("unsupported rewrite schema")
    if document["evidence_kind"] != "proposal-resolution-rewrite":
        raise ValidationError("unsupported rewrite kind")
    review_id = validate_identifier(document["review_id"], "review_id")
    report_sha256 = _digest(document["report_sha256"], "report_sha256")
    decisions_sha256 = _digest(document["decisions_sha256"], "decisions_sha256")
    proposal_id = validate_identifier(document["proposal_id"], "proposal_id")
    decision_state = document["decision_state"]
    if decision_state not in ("confirm-candidate", "change-owner"):
        raise ValidationError("invalid rewrite decision state")

    source = _exact(document["source"], _SOURCE_KEYS, "rewrite source")
    source_path = _portable_relative(source["source_path"], "source path")
    snapshot_path = _portable_relative(source["snapshot_path"], "snapshot path")
    snapshot_sha256 = _digest(source["snapshot_sha256"], "snapshot_sha256")
    proposal_sha256 = _digest(source["proposal_sha256"], "proposal_sha256")

    target = _exact(document["target"], _TARGET_KEYS, "rewrite target")
    memory_id = validate_identifier(target["memory_id"], "memory_id")
    project_id = target["project_id"]
    if project_id is not None:
        project_id = validate_identifier(project_id, "project_id")
    owner_scope = target["owner_scope"]
    record_type = _owner(owner_scope, project_id)
    if target["record_type"] != record_type or record_type not in _HEADINGS:
        raise ValidationError("rewrite record type does not match owner")

    rewrite = _exact(document["rewrite"], _REWRITE_KEYS, "rewrite body")
    title = rewrite["title"]
    body = rewrite["body"]
    if (
        not isinstance(title, str)
        or not title
        or len(title) > 256
        or title != title.strip()
        or any(character in title for character in "\r\n")
    ):
        raise ValidationError("invalid rewrite title")
    if not isinstance(body, str) or normalize_body(body) != body:
        raise ValidationError("rewrite body is not normalized")
    body_sha256 = _digest(rewrite["body_sha256"], "body_sha256")
    if hashlib.sha256(body.encode("utf-8")).hexdigest() != body_sha256:
        raise ValidationError("rewrite body hash mismatch")
    if body.splitlines()[0:1] != ["# " + title]:
        raise ValidationError("rewrite title does not match body")
    expected_prefix = _TITLE_PREFIX[record_type] + ": "
    if not title.startswith(expected_prefix) or len(title[len(expected_prefix) :].strip()) < 8:
        raise ValidationError("rewrite title is not readable")
    if rewrite["writer_profile"] != "luna-medium":
        raise ValidationError("unsupported rewrite writer profile")
    raw_spans = rewrite["evidence_spans"]
    if not isinstance(raw_spans, list) or not raw_spans:
        raise ValidationError("rewrite requires evidence spans")
    spans = tuple(_span(item) for item in raw_spans)
    ranges = tuple((item.start_line, item.end_line) for item in spans)
    if len(ranges) != len(set(ranges)):
        raise ValidationError("duplicate evidence span range")

    return RewriteCandidateArtifact(
        review_id,
        report_sha256,
        decisions_sha256,
        proposal_id,
        decision_state,
        source_path,
        snapshot_path,
        snapshot_sha256,
        proposal_sha256,
        memory_id,
        record_type,
        owner_scope,
        project_id,
        title,
        body,
        body_sha256,
        rewrite["writer_profile"],
        spans,
        hashlib.sha256(raw).hexdigest(),
        raw,
    )


def _body_sections(candidate: RewriteCandidateArtifact):
    lines = candidate.body.splitlines()
    headings = tuple(line[3:] for line in lines if line.startswith("## "))
    if headings != _HEADINGS[candidate.record_type]:
        raise ValidationError("rewrite body does not match current template")
    rows = [index for index, line in enumerate(lines) if line.startswith("## ")]
    sections = {}
    for offset, row in enumerate(rows):
        end = rows[offset + 1] if offset + 1 < len(rows) else len(lines)
        heading = lines[row][3:]
        if heading == "Session Relationship":
            content = lines[row + 1 : end]
        else:
            if row + 1 >= len(lines) or lines[row + 1] != "":
                raise ValidationError("rewrite body does not follow template spacing")
            content = lines[row + 2 : end]
        while content and content[0] == "":
            content.pop(0)
        while content and content[-1] == "":
            content.pop()
        if not content:
            raise ValidationError("rewrite section is empty")
        sections[heading] = tuple(content)
    return sections


def _validate_profile(candidate: RewriteCandidateArtifact, sections):
    if candidate.record_type == "session":
        relationship = parse_session_relationship(candidate.body)
        observed = sections["Decisions Observed"]
        if observed != ("none",):
            if any(not line.startswith("- ") for line in observed):
                raise ValidationError("Session Decisions Observed must contain record IDs")
            decision_ids = tuple(line[2:] for line in observed)
            for decision_id in decision_ids:
                validate_identifier(decision_id, "Decision ID")
            if decision_ids != tuple(sorted(set(decision_ids))):
                raise ValidationError("Session Decision IDs must be deterministic")
        return relationship.primary_story_id is not None or bool(relationship.related_story_ids)
    if candidate.record_type == "story":
        parse_story_profile(candidate.body)
    if candidate.record_type == "runbook":
        procedure = sections["Procedure"]
        if procedure != ("none",) and any(
            not line.startswith("{0}. ".format(index))
            for index, line in enumerate(procedure, 1)
        ):
            raise ValidationError("Runbook procedure must be ordered")
    return False


def bind_rewrite_candidate(
    candidate: RewriteCandidateArtifact,
    decision: ProposalDecision,
    report_item: Mapping[str, object],
    snapshot_bytes: bytes,
) -> RewriteCandidateArtifact:
    """Bind candidate claims and spans to one reviewed report snapshot."""

    if not isinstance(candidate, RewriteCandidateArtifact) or not isinstance(decision, ProposalDecision):
        raise ValidationError("invalid rewrite binding")
    if candidate.proposal_id != decision.proposal_id or candidate.decision_state != decision.state:
        raise ValidationError("rewrite does not match decision")
    if decision.state not in ("confirm-candidate", "change-owner"):
        raise ValidationError("no-record decision cannot have a rewrite")
    if candidate.owner_scope != decision.owner_scope or candidate.project_id != decision.project_id:
        raise ValidationError("rewrite target does not match decision owner")
    for field in ("proposal_id", "source_path", "snapshot_path", "snapshot_sha256", "proposal_sha256"):
        candidate_value = getattr(candidate, field)
        if report_item.get(field) != candidate_value:
            raise ValidationError("rewrite source does not match report item")
    if candidate.memory_id != _source_stable_memory_id(report_item):
        raise ValidationError("rewrite memory ID is not source-stable")
    if decision.state == "confirm-candidate":
        report_owner = report_item.get("candidate_owner")
        if not isinstance(report_owner, dict) or any(
            (
                report_owner.get("candidate_memory_id") != candidate.memory_id,
                report_owner.get("record_type") != candidate.record_type,
                report_owner.get("owner_scope") != candidate.owner_scope,
                report_owner.get("project_id") != candidate.project_id,
            )
        ):
            raise ValidationError("confirmed rewrite target does not match report candidate")
    if not isinstance(snapshot_bytes, bytes) or hashlib.sha256(snapshot_bytes).hexdigest() != candidate.snapshot_sha256:
        raise ValidationError("rewrite snapshot bytes do not match report")

    lines = snapshot_bytes.splitlines(keepends=True)
    supported = set()
    for span in candidate.evidence_spans:
        if span.end_line > len(lines):
            raise ValidationError("evidence span is outside snapshot")
        selected = b"".join(lines[span.start_line - 1 : span.end_line])
        if hashlib.sha256(selected).hexdigest() != span.text_sha256:
            raise ValidationError("evidence span hash mismatch")
        supported.update(span.supports_sections)

    sections = _body_sections(candidate)
    relationship_claim = _validate_profile(candidate, sections)
    unknown_sections = supported - set(sections)
    if unknown_sections:
        raise ValidationError("evidence span names an unknown section")
    for heading, content in sections.items():
        semantic = content not in (("none",), ("- none",))
        if heading == "Session Relationship":
            semantic = relationship_claim
        if semantic and heading not in supported:
            raise ValidationError("rewrite section lacks source evidence")
    return candidate


def load_semantic_review(path: Path) -> SemanticReviewArtifact:
    """Load one independent semantic review without treating failure as approval."""

    raw, value = _load(path, "semantic review")
    document = _exact(value, _REVIEW_KEYS, "semantic review")
    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        raise ValidationError("unsupported semantic review schema")
    if document["evidence_kind"] != "proposal-resolution-semantic-review":
        raise ValidationError("unsupported semantic review kind")
    proposal_id = validate_identifier(document["proposal_id"], "proposal_id")
    rewrite_sha256 = _digest(document["rewrite_sha256"], "rewrite_sha256")
    if document["reviewer_profile"] != "independent-luna-medium":
        raise ValidationError("unsupported semantic reviewer profile")
    checks = _exact(document["checks"], _CHECK_KEYS, "semantic review checks")
    if any(type(value) is not bool for value in checks.values()):
        raise ValidationError("semantic review checks must be booleans")
    outcome = document["outcome"]
    if outcome not in ("pass", "fail", "rewrite-needs-split"):
        raise ValidationError("invalid semantic review outcome")
    reason_codes = document["reason_codes"]
    if (
        not isinstance(reason_codes, list)
        or any(not isinstance(item, str) for item in reason_codes)
        or reason_codes != sorted(reason_codes)
        or len(reason_codes) != len(set(reason_codes))
    ):
        raise ValidationError("invalid semantic review reason codes")
    for reason in reason_codes:
        validate_identifier(reason, "semantic review reason")
    all_passed = all(checks.values())
    if (outcome == "pass" and (not all_passed or reason_codes)) or (
        outcome != "pass" and (all_passed or not reason_codes)
    ):
        raise ValidationError("semantic review outcome does not match checks")
    return SemanticReviewArtifact(
        proposal_id,
        rewrite_sha256,
        document["reviewer_profile"],
        tuple(sorted(checks.items())),
        outcome,
        tuple(reason_codes),
        hashlib.sha256(raw).hexdigest(),
        raw,
    )
