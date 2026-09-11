"""Validated adapter context and unbound Session proposal candidates."""

from typing import Optional, Tuple

from .errors import ValidationError
from .models import CoordinationContext, RecordCandidate, UnboundSessionCandidate
from .paths import validate_identifier
from .records import normalize_body, render_record
from .session_relationships import (
    SessionRelationship,
    SessionStatus,
    parse_session_relationship,
    render_session_relationship,
)
from .story_profiles import StoryDelta, _validate_delta


_ALLOWED_SCOPES = frozenset(("records", "projections"))


def validate_coordination_context(value: CoordinationContext) -> CoordinationContext:
    """Validate explicit routing supplied by a controller or future Harness."""
    if not isinstance(value, CoordinationContext):
        raise ValidationError("invalid coordination context")
    validate_identifier(value.project_id, "project_id")
    validate_identifier(value.coordinator_task_id, "coordinator_task_id")
    if value.primary_story_id is not None:
        validate_identifier(value.primary_story_id, "primary_story_id")
    if not isinstance(value.related_story_ids, tuple):
        raise ValidationError("invalid related story ids")
    for story_id in value.related_story_ids:
        validate_identifier(story_id, "related_story_id")
    if len(set(value.related_story_ids)) != len(value.related_story_ids):
        raise ValidationError("duplicate related story id")
    if value.primary_story_id in value.related_story_ids:
        raise ValidationError("primary story cannot also be related")
    if (value.primary_story_id is None) != (value.expected_story_revision is None):
        raise ValidationError("primary story and expected revision must appear together")
    if value.expected_story_revision is not None and (
        type(value.expected_story_revision) is not int or value.expected_story_revision < 1
    ):
        raise ValidationError("invalid expected story revision")
    if (
        not isinstance(value.allowed_scope, tuple)
        or not value.allowed_scope
        or len(set(value.allowed_scope)) != len(value.allowed_scope)
        or any(scope not in _ALLOWED_SCOPES for scope in value.allowed_scope)
    ):
        raise ValidationError("invalid allowed scope")
    return value


def relationship_from_context(
    value: CoordinationContext,
    status: SessionStatus,
) -> SessionRelationship:
    """Convert confirmed adapter routing into canonical Session membership."""
    validate_coordination_context(value)
    relationship = SessionRelationship(status, value.primary_story_id, value.related_story_ids)
    # Reuse the canonical renderer/parser pair for status and relationship validation.
    return parse_session_relationship(
        "# Session: Context validation\n\n"
        + render_session_relationship(relationship)
        + "\n## Outcome\n\nPending.\n"
    )


def build_unbound_session_candidate(
    session_candidate: RecordCandidate,
    suggested_primary: Optional[str] = None,
    *,
    primary_evidence: Optional[str] = None,
    suggested_related: Tuple[Tuple[str, str], ...] = (),
    intended_story_delta: Optional[StoryDelta] = None,
    origin_task_id: str,
    coordinator_task_id: Optional[str] = None,
) -> UnboundSessionCandidate:
    """Build an explicit proposal candidate without inferring Story membership."""
    if not isinstance(session_candidate, RecordCandidate):
        raise ValidationError("invalid Session candidate")
    envelope = session_candidate.envelope
    normalized_body = normalize_body(session_candidate.body)
    render_record(envelope, normalized_body)
    if envelope.record_type != "session" or envelope.project is None:
        raise ValidationError("unbound candidate must contain a project Session")
    relationship = parse_session_relationship(normalized_body)
    if relationship.primary_story_id is not None or relationship.related_story_ids:
        raise ValidationError("unbound Session cannot contain confirmed Story membership")
    validate_identifier(origin_task_id, "origin_task_id")
    if coordinator_task_id is not None:
        validate_identifier(coordinator_task_id, "coordinator_task_id")
    if suggested_primary is not None:
        validate_identifier(suggested_primary, "candidate_primary_story_id")
        if not isinstance(primary_evidence, str) or not primary_evidence.strip():
            raise ValidationError("primary Story suggestion requires evidence")
    elif primary_evidence is not None:
        raise ValidationError("primary evidence requires a Story suggestion")
    if not isinstance(suggested_related, tuple):
        raise ValidationError("invalid related Story suggestions")
    related = []
    for suggestion in suggested_related:
        if not isinstance(suggestion, tuple) or len(suggestion) != 2:
            raise ValidationError("invalid related Story suggestion")
        story_id, evidence = suggestion
        validate_identifier(story_id, "candidate_related_story_id")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValidationError("related Story suggestion requires evidence")
        related.append((story_id, evidence))
    if len({story_id for story_id, _ in related}) != len(related):
        raise ValidationError("duplicate related Story suggestion")
    if suggested_primary in {story_id for story_id, _ in related}:
        raise ValidationError("primary Story suggestion cannot also be related")
    related.sort(key=lambda item: item[0])
    suggested_ids = {story_id for story_id, _ in related}
    if suggested_primary is not None:
        suggested_ids.add(suggested_primary)
    if intended_story_delta is not None:
        if not isinstance(intended_story_delta, StoryDelta):
            raise ValidationError("invalid intended Story delta")
        _validate_delta(intended_story_delta)
        if (
            intended_story_delta.source_session_id != envelope.memory_id
            or intended_story_delta.story_id not in suggested_ids
        ):
            raise ValidationError("intended Story delta is not bound to this proposal")
    normalized_candidate = RecordCandidate(envelope, normalized_body)
    return UnboundSessionCandidate(
        project_id=envelope.project,
        session_candidate=normalized_candidate,
        candidate_primary_story_id=suggested_primary,
        candidate_primary_evidence=primary_evidence,
        candidate_related_story_ids=tuple(story_id for story_id, _ in related),
        candidate_related_evidence=tuple(evidence for _, evidence in related),
        intended_story_delta=intended_story_delta,
        origin_task_id=origin_task_id,
        coordinator_task_id=coordinator_task_id,
    )


def _validate_unbound_session_candidate(
    value: UnboundSessionCandidate,
) -> UnboundSessionCandidate:
    if not isinstance(value, UnboundSessionCandidate):
        raise ValidationError("invalid unbound Session candidate")
    if len(value.candidate_related_story_ids) != len(value.candidate_related_evidence):
        raise ValidationError("related Story suggestion evidence is incomplete")
    rebuilt = build_unbound_session_candidate(
        value.session_candidate,
        suggested_primary=value.candidate_primary_story_id,
        primary_evidence=value.candidate_primary_evidence,
        suggested_related=tuple(
            zip(value.candidate_related_story_ids, value.candidate_related_evidence)
        ),
        intended_story_delta=value.intended_story_delta,
        origin_task_id=value.origin_task_id,
        coordinator_task_id=value.coordinator_task_id,
    )
    if rebuilt != value:
        raise ValidationError("invalid unbound Session candidate")
    return value
