"""Strict parsing and deterministic rendering for immutable memory records."""

import hashlib
import hmac
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from .errors import ValidationError
from .models import RecordEnvelope
from .paths import validate_identifier


_FIELD_NAMES = (
    "memory_id",
    "record_type",
    "schema_version",
    "owner_scope",
    "project",
    "revision",
    "supersedes",
    "created_at",
    "observed_at",
    "source",
    "source_revision",
    "body_sha256",
)
_RECORD_OWNERS = {
    "session": "project.{project}.session",
    "story": "project.{project}.story",
    "decision": "project.{project}.decision",
    "preference": "user.preference",
    "runbook": "agent.runbook",
    "migration": "meta.migration",
    "maintenance": "meta.maintenance",
}
_PROJECT_RECORD_TYPES = frozenset(("session", "story", "decision"))
_RECORD_DIRECTORIES = {
    "session": ("_records", "projects", "{project}", "sessions"),
    "story": ("_records", "projects", "{project}", "stories"),
    "decision": ("_records", "projects", "{project}", "decisions"),
    "preference": ("_records", "preferences"),
    "runbook": ("_records", "runbooks"),
    "migration": ("_records", "meta", "migrations"),
    "maintenance": ("_records", "meta", "maintenance"),
}
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_REVISION_PATTERN = re.compile(r"[1-9][0-9]*\Z")
_SUPERSEDES_PATTERN = re.compile(r"([a-z0-9][a-z0-9._-]{0,127})@([1-9][0-9]*)\Z")
_FORBIDDEN_SCALAR_MARKERS = frozenset(("[", "]", "{", "}", "|", ">", "&", "*", "!", "'", '"', "#", ","))


def normalize_body(body: str) -> str:
    """Normalize record body line endings, trailing horizontal space, and EOF."""
    if not isinstance(body, str):
        raise ValidationError("body must be a string")
    normalized_lines = [
        line.rstrip(" \t") for line in body.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ]
    return "\n".join(normalized_lines).rstrip("\n") + "\n"


def compute_body_sha256(body: str) -> str:
    """Return the SHA-256 hex digest of the UTF-8 normalized body."""
    return hashlib.sha256(normalize_body(body).encode("utf-8")).hexdigest()


def parse_record(text: str) -> Tuple[RecordEnvelope, str]:
    """Parse one strict scalar-frontmatter record and validate its body hash."""
    if not isinstance(text, str):
        raise ValidationError("record must be text")

    lines = text.splitlines(keepends=True)
    expected_header_lines = len(_FIELD_NAMES) + 2
    header_lines = [line.rstrip("\r\n") for line in lines[:expected_header_lines]]
    if (
        len(header_lines) < expected_header_lines
        or header_lines[0] != "---"
        or header_lines[len(_FIELD_NAMES) + 1] != "---"
    ):
        raise ValidationError("invalid record frontmatter")

    scalar_values = []
    for field_name, line in zip(_FIELD_NAMES, header_lines[1 : len(_FIELD_NAMES) + 1]):
        prefix = field_name + ": "
        if not line.startswith(prefix):
            raise ValidationError("invalid record frontmatter")
        scalar = line[len(prefix) :]
        _validate_scalar(scalar)
        scalar_values.append(scalar)

    envelope = _envelope_from_scalars(scalar_values)
    body = normalize_body(text[sum(len(line) for line in lines[:expected_header_lines]) :])
    _validate_envelope(envelope, body)
    return envelope, body


def render_record(envelope: RecordEnvelope, body: str) -> str:
    """Validate and deterministically render a record with canonical frontmatter."""
    normalized_body = normalize_body(body)
    _validate_envelope(envelope, normalized_body)
    values = (
        envelope.memory_id,
        envelope.record_type,
        str(envelope.schema_version),
        envelope.owner_scope,
        _optional_scalar(envelope.project),
        str(envelope.revision),
        _optional_scalar(envelope.supersedes),
        envelope.created_at,
        envelope.observed_at,
        envelope.source,
        envelope.source_revision,
        envelope.body_sha256,
    )
    return "---\n" + "".join(
        "{0}: {1}\n".format(name, value) for name, value in zip(_FIELD_NAMES, values)
    ) + "---\n" + normalized_body


def record_relative_path(envelope: RecordEnvelope) -> Path:
    """Return the canonical relative storage path for a validated record envelope."""
    _validate_envelope(envelope, None)
    directories = tuple(
        envelope.project if component == "{project}" else component
        for component in _RECORD_DIRECTORIES[envelope.record_type]
    )
    return Path(*directories, "{0}--r{1}.md".format(envelope.memory_id, _format_revision(envelope.revision)))


def _validate_scalar(value: str) -> None:
    if not value or value != value.strip(" \t"):
        raise ValidationError("invalid record scalar")
    if any(marker in value for marker in _FORBIDDEN_SCALAR_MARKERS):
        raise ValidationError("invalid record scalar")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValidationError("invalid record scalar")


def _envelope_from_scalars(values: list) -> RecordEnvelope:
    memory_id, record_type, schema_version, owner_scope, project, revision, supersedes, created_at, observed_at, source, source_revision, body_sha256 = values
    if not _REVISION_PATTERN.fullmatch(schema_version) or not _REVISION_PATTERN.fullmatch(revision):
        raise ValidationError("invalid record revision")
    return RecordEnvelope(
        memory_id=memory_id,
        record_type=record_type,
        schema_version=int(schema_version),
        owner_scope=owner_scope,
        project=None if project == "none" else project,
        revision=int(revision),
        supersedes=None if supersedes == "none" else supersedes,
        created_at=created_at,
        observed_at=observed_at,
        source=source,
        source_revision=source_revision,
        body_sha256=body_sha256,
    )


def _validate_envelope(envelope: RecordEnvelope, body: Optional[str]) -> None:
    if not isinstance(envelope, RecordEnvelope):
        raise ValidationError("invalid record envelope")
    validate_identifier(envelope.memory_id, "memory_id")
    if envelope.record_type not in _RECORD_OWNERS:
        raise ValidationError("invalid record type")
    if type(envelope.schema_version) is not int or envelope.schema_version != 2:
        raise ValidationError("invalid schema version")
    if type(envelope.revision) is not int or envelope.revision <= 0:
        raise ValidationError("invalid record revision")
    _validate_owner_scope(envelope)
    _validate_timestamp(envelope.created_at, "created_at")
    _validate_timestamp(envelope.observed_at, "observed_at")
    validate_identifier(envelope.source, "source")
    validate_identifier(envelope.source_revision, "source_revision")
    if not isinstance(envelope.body_sha256, str) or not _HASH_PATTERN.fullmatch(envelope.body_sha256):
        raise ValidationError("invalid body hash")
    _validate_supersedes(envelope)
    if body is not None and not hmac.compare_digest(envelope.body_sha256, compute_body_sha256(body)):
        raise ValidationError("record body hash mismatch")


def _validate_owner_scope(envelope: RecordEnvelope) -> None:
    if envelope.record_type in _PROJECT_RECORD_TYPES:
        if not isinstance(envelope.project, str):
            raise ValidationError("project record requires project")
        validate_identifier(envelope.project, "project")
        expected_scope = _RECORD_OWNERS[envelope.record_type].format(project=envelope.project)
    else:
        if envelope.project is not None:
            raise ValidationError("global record cannot have project")
        expected_scope = _RECORD_OWNERS[envelope.record_type]
    if envelope.owner_scope != expected_scope:
        raise ValidationError("invalid owner scope")


def _validate_timestamp(value: str, field: str) -> None:
    if not isinstance(value, str) or not _TIMESTAMP_PATTERN.fullmatch(value):
        raise ValidationError("invalid {0}".format(field))
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        raise ValidationError("invalid {0}".format(field)) from error


def _validate_supersedes(envelope: RecordEnvelope) -> None:
    if envelope.supersedes is None:
        return
    if not isinstance(envelope.supersedes, str):
        raise ValidationError("invalid supersedes")
    matched = _SUPERSEDES_PATTERN.fullmatch(envelope.supersedes)
    if matched is None or matched.group(1) != envelope.memory_id:
        raise ValidationError("invalid supersedes")
    validate_identifier(matched.group(1), "supersedes memory_id")


def _optional_scalar(value: Optional[str]) -> str:
    return "none" if value is None else value


def _format_revision(revision: int) -> str:
    return "{0:04d}".format(revision) if revision < 10000 else str(revision)
