"""Strict type-specific Session-to-Story relationship body profile."""

from dataclasses import dataclass
from typing import Literal, Optional, Tuple

from .errors import ValidationError
from .paths import validate_identifier
from .records import normalize_body


SessionStatus = Literal["completed", "failed", "cancelled"]
_VALID_STATUSES = frozenset(("completed", "failed", "cancelled"))
_SECTION = "## Session Relationship"
_STATUS_PREFIX = "session_status: "
_PRIMARY_PREFIX = "primary_story_id: "
_RELATED_PREFIX = "related_story_id: "


@dataclass(frozen=True)
class SessionRelationship:
    session_status: SessionStatus
    primary_story_id: Optional[str]
    related_story_ids: Tuple[str, ...]


def parse_session_relationship(body: str) -> SessionRelationship:
    """Parse the one canonical relationship section immediately after a Session title."""
    if not isinstance(body, str):
        raise ValidationError("session body must be text")
    lines = normalize_body(body).splitlines()
    if (
        len(lines) < 6
        or not lines[0].startswith("# Session: ")
        or not lines[0][len("# Session: ") :].strip()
        or lines[1] != ""
        or lines[2] != _SECTION
        or lines.count(_SECTION) != 1
    ):
        raise ValidationError("session-relationship-required")

    block_end = len(lines)
    for index in range(3, len(lines)):
        if lines[index] == "" or lines[index].startswith("## "):
            block_end = index
            break
    block = lines[3:block_end]
    if (
        len(block) < 3
        or not block[0].startswith(_STATUS_PREFIX)
        or not block[1].startswith(_PRIMARY_PREFIX)
        or any(not line.startswith(_RELATED_PREFIX) for line in block[2:])
    ):
        raise ValidationError("invalid session relationship")

    status = block[0][len(_STATUS_PREFIX) :]
    primary_value = block[1][len(_PRIMARY_PREFIX) :]
    related_values = tuple(line[len(_RELATED_PREFIX) :] for line in block[2:])
    value = SessionRelationship(
        status,
        None if primary_value == "none" else primary_value,
        () if related_values == ("none",) else related_values,
    )
    _validate_relationship(value, parsed_related=related_values)
    return value


def render_session_relationship(value: SessionRelationship) -> str:
    """Render a canonical relationship block with lexically ordered related IDs."""
    _validate_relationship(value)
    related = tuple(sorted(value.related_story_ids))
    primary = value.primary_story_id if value.primary_story_id is not None else "none"
    related_lines = related if related else ("none",)
    return "".join(
        (
            _SECTION + "\n",
            _STATUS_PREFIX + value.session_status + "\n",
            _PRIMARY_PREFIX + primary + "\n",
            "".join(_RELATED_PREFIX + item + "\n" for item in related_lines),
        )
    )


def _validate_relationship(
    value: SessionRelationship,
    parsed_related: Optional[Tuple[str, ...]] = None,
) -> None:
    if not isinstance(value, SessionRelationship) or value.session_status not in _VALID_STATUSES:
        raise ValidationError("invalid session status")
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
    if parsed_related is not None:
        if "none" in parsed_related and parsed_related != ("none",):
            raise ValidationError("none cannot be mixed with related story ids")
        if parsed_related != ("none",) and parsed_related != tuple(sorted(parsed_related)):
            raise ValidationError("related story ids must be lexically ordered")
