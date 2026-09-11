"""Strict Story narrative profiles and source-bound revision deltas."""

from dataclasses import dataclass, replace
from typing import Optional, Tuple

from .errors import ValidationError
from .models import AcceptedRecord, RecordCandidate
from .paths import validate_identifier
from .records import compute_body_sha256, normalize_body, render_record


_HEADINGS = (
    "## Situation",
    "## Current State",
    "## Turning Points",
    "## Failure Mode",
    "## Resolution",
    "## Open Questions",
    "## Related Decision IDs",
)


@dataclass(frozen=True)
class StoryProfile:
    title: str
    situation: str
    current_state: str
    turning_points: Tuple[str, ...]
    failure_mode: Optional[str]
    resolution: Optional[str]
    open_questions: Tuple[str, ...]
    related_decision_ids: Tuple[str, ...]


@dataclass(frozen=True)
class StoryDelta:
    story_id: str
    expected_revision: int
    source_session_id: str
    current_state: Optional[str]
    turning_points: Tuple[str, ...]
    failure_mode: Optional[str]
    resolution: Optional[str]
    open_questions: Tuple[str, ...]
    related_decision_ids: Tuple[str, ...]


def parse_story_profile(body: str) -> StoryProfile:
    """Parse one canonical Story body with exact ordered sections."""
    if not isinstance(body, str):
        raise ValidationError("story body must be text")
    normalized = normalize_body(body)
    lines = normalized.splitlines()
    if "## Decision" in lines:
        raise ValidationError("story body cannot own Decision")
    if (
        len(lines) < 4
        or not lines[0].startswith("# Story: ")
        or lines[1] != ""
    ):
        raise ValidationError("invalid story body")
    title = lines[0][len("# Story: ") :]
    _validate_title(title)

    heading_rows = tuple(
        (index, line)
        for index, line in enumerate(lines)
        if line.startswith("## ")
    )
    if tuple(line for _, line in heading_rows) != _HEADINGS:
        raise ValidationError("invalid story sections")

    section_values = []
    for section_index, (row, _) in enumerate(heading_rows):
        if row + 1 >= len(lines) or lines[row + 1] != "":
            raise ValidationError("invalid story section spacing")
        end = (
            heading_rows[section_index + 1][0]
            if section_index + 1 < len(heading_rows)
            else len(lines)
        )
        content = lines[row + 2 : end]
        while content and content[-1] == "":
            content.pop()
        if not content:
            raise ValidationError("invalid story section content")
        section_values.append(tuple(content))

    situation = "\n".join(section_values[0])
    current_state = "\n".join(section_values[1])
    if situation == "none" or current_state == "none":
        raise ValidationError("story situation and current state are required")
    turning_points = _parse_list(section_values[2], "turning point", ordered=False)
    failure_mode = _parse_optional_prose(section_values[3])
    resolution = _parse_optional_prose(section_values[4])
    open_questions = _parse_list(section_values[5], "open question", ordered=True)
    related_decision_ids = _parse_list(
        section_values[6], "related decision id", ordered=True
    )
    for decision_id in related_decision_ids:
        validate_identifier(decision_id, "related decision id")
    _turning_point_sources(turning_points)
    return StoryProfile(
        title,
        situation,
        current_state,
        turning_points,
        failure_mode,
        resolution,
        open_questions,
        related_decision_ids,
    )


def render_story_profile(value: StoryProfile) -> str:
    """Render one deterministic Story body."""
    _validate_profile(value)
    sections = (
        ("Situation", value.situation),
        ("Current State", value.current_state),
        ("Turning Points", _render_list(value.turning_points, ordered=False)),
        ("Failure Mode", value.failure_mode or "none"),
        ("Resolution", value.resolution or "none"),
        ("Open Questions", _render_list(value.open_questions, ordered=True)),
        (
            "Related Decision IDs",
            _render_list(value.related_decision_ids, ordered=True),
        ),
    )
    return normalize_body(
        "# Story: {0}\n\n{1}".format(
            value.title,
            "\n\n".join(
                "## {0}\n\n{1}".format(heading, content)
                for heading, content in sections
            ),
        )
    )


def apply_story_delta(current: StoryProfile, delta: StoryDelta) -> StoryProfile:
    """Apply one source-Session-bound semantic delta without merging revisions."""
    _validate_profile(current)
    _validate_delta(delta)
    existing_sources = _turning_point_sources(current.turning_points)
    new_sources = _turning_point_sources(delta.turning_points)
    if any(source != delta.source_session_id for source in new_sources):
        raise ValidationError("turning point is not bound to source Session")
    if delta.source_session_id in existing_sources or len(new_sources) != len(set(new_sources)):
        raise ValidationError("duplicate turning point source Session")

    return StoryProfile(
        title=current.title,
        situation=current.situation,
        current_state=delta.current_state or current.current_state,
        turning_points=current.turning_points + delta.turning_points,
        failure_mode=delta.failure_mode or current.failure_mode,
        resolution=delta.resolution or current.resolution,
        open_questions=tuple(sorted(set(current.open_questions + delta.open_questions))),
        related_decision_ids=tuple(
            sorted(set(current.related_decision_ids + delta.related_decision_ids))
        ),
    )


def build_story_revision_candidate(
    current_record: AcceptedRecord,
    delta: StoryDelta,
    observed_at: str,
    source: str,
    source_revision: str,
) -> RecordCandidate:
    """Build the exact next Story revision candidate from accepted current state."""
    if not isinstance(current_record, AcceptedRecord):
        raise ValidationError("invalid current Story record")
    current_envelope = current_record.envelope
    if current_envelope.record_type != "story":
        raise ValidationError("current record is not a Story")
    if delta.story_id != current_envelope.memory_id:
        raise ValidationError("Story delta identity mismatch")
    if delta.expected_revision != current_envelope.revision:
        raise ValidationError("Story delta revision mismatch")
    render_record(current_envelope, current_record.body)
    updated_body = render_story_profile(
        apply_story_delta(parse_story_profile(current_record.body), delta)
    )
    envelope = replace(
        current_envelope,
        revision=current_envelope.revision + 1,
        supersedes="{0}@{1}".format(
            current_envelope.memory_id, current_envelope.revision
        ),
        observed_at=observed_at,
        source=source,
        source_revision=source_revision,
        body_sha256=compute_body_sha256(updated_body),
    )
    candidate = RecordCandidate(envelope, updated_body)
    render_record(candidate.envelope, candidate.body)
    return candidate


def _validate_title(title: str) -> None:
    if not isinstance(title, str) or not title or title != title.strip():
        raise ValidationError("invalid Story title")
    try:
        validate_identifier(title, "Story title")
    except ValidationError:
        return
    raise ValidationError("Story title must be readable narrative")


def _parse_optional_prose(lines: Tuple[str, ...]) -> Optional[str]:
    value = "\n".join(lines)
    return None if value == "none" else value


def _parse_list(
    lines: Tuple[str, ...],
    field: str,
    ordered: bool,
) -> Tuple[str, ...]:
    if any(not line.startswith("- ") or len(line) == 2 for line in lines):
        raise ValidationError("invalid {0} list".format(field))
    values = tuple(line[2:] for line in lines)
    if values == ("none",):
        return ()
    if "none" in values or len(values) != len(set(values)):
        raise ValidationError("invalid {0} list".format(field))
    if ordered and values != tuple(sorted(values)):
        raise ValidationError("{0} list must be deterministic".format(field))
    return values


def _render_list(values: Tuple[str, ...], ordered: bool) -> str:
    selected = tuple(sorted(values)) if ordered else values
    return "\n".join("- " + value for value in selected) if selected else "- none"


def _turning_point_sources(turning_points: Tuple[str, ...]) -> Tuple[str, ...]:
    sources = []
    for turning_point in turning_points:
        if not isinstance(turning_point, str) or ": " not in turning_point:
            raise ValidationError("invalid turning point")
        source, description = turning_point.split(": ", 1)
        validate_identifier(source, "turning point source Session")
        if not description:
            raise ValidationError("invalid turning point")
        sources.append(source)
    if len(sources) != len(set(sources)):
        raise ValidationError("duplicate turning point source Session")
    return tuple(sources)


def _validate_profile(value: StoryProfile) -> None:
    if not isinstance(value, StoryProfile):
        raise ValidationError("invalid Story profile")
    _validate_title(value.title)
    for field, content in (
        ("situation", value.situation),
        ("current state", value.current_state),
    ):
        if not isinstance(content, str) or not content or content == "none":
            raise ValidationError("Story {0} is required".format(field))
    for field, content in (
        ("failure mode", value.failure_mode),
        ("resolution", value.resolution),
    ):
        if content is not None and (not isinstance(content, str) or not content):
            raise ValidationError("invalid Story {0}".format(field))
    for field, values in (
        ("turning points", value.turning_points),
        ("open questions", value.open_questions),
        ("related Decision IDs", value.related_decision_ids),
    ):
        if not isinstance(values, tuple) or any(
            not isinstance(item, str) or not item for item in values
        ):
            raise ValidationError("invalid Story {0}".format(field))
        if len(values) != len(set(values)):
            raise ValidationError("duplicate Story {0}".format(field))
    _turning_point_sources(value.turning_points)
    for decision_id in value.related_decision_ids:
        validate_identifier(decision_id, "related decision id")


def _validate_delta(value: StoryDelta) -> None:
    if not isinstance(value, StoryDelta):
        raise ValidationError("invalid Story delta")
    validate_identifier(value.story_id, "Story delta story_id")
    validate_identifier(value.source_session_id, "Story delta source_session_id")
    if type(value.expected_revision) is not int or value.expected_revision <= 0:
        raise ValidationError("invalid Story delta revision")
    for field, content in (
        ("current state", value.current_state),
        ("failure mode", value.failure_mode),
        ("resolution", value.resolution),
    ):
        if content is not None and (not isinstance(content, str) or not content):
            raise ValidationError("invalid Story delta {0}".format(field))
    for field, values in (
        ("turning points", value.turning_points),
        ("open questions", value.open_questions),
        ("related Decision IDs", value.related_decision_ids),
    ):
        if not isinstance(values, tuple) or any(
            not isinstance(item, str) or not item for item in values
        ):
            raise ValidationError("invalid Story delta {0}".format(field))
        if len(values) != len(set(values)):
            raise ValidationError("duplicate Story delta {0}".format(field))
    for decision_id in value.related_decision_ids:
        validate_identifier(decision_id, "related decision id")
