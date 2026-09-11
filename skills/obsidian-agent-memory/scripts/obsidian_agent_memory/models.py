"""Immutable value objects and static seams for Agent Memory operations."""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Literal, Optional, Protocol, Sequence, Tuple


if TYPE_CHECKING:
    from .story_profiles import StoryDelta


class ReadAdapter(Protocol):
    """Read-only search seam supplied by a selected adapter."""

    def read(self, relative_path: str) -> str: ...

    def search(self, query: str, limit: int = 20) -> Tuple["SearchHit", ...]: ...

    def files(self, prefix: str, limit: int = 200) -> Tuple[str, ...]: ...



CommandRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess]


@dataclass(frozen=True)
class RootBinding:
    memory_root: Path
    project_id: Optional[str]
    obsidian_vault: Optional[str]


@dataclass(frozen=True)
class RecordEnvelope:
    memory_id: str
    record_type: str
    schema_version: int
    owner_scope: str
    project: Optional[str]
    revision: int
    supersedes: Optional[str]
    created_at: str
    observed_at: str
    source: str
    source_revision: str
    body_sha256: str


@dataclass(frozen=True)
class RecordCandidate:
    envelope: RecordEnvelope
    body: str


@dataclass(frozen=True)
class TransactionContext:
    transaction_id: str
    actor: str
    occurred_at: str


@dataclass(frozen=True)
class RootWriteGuard:
    root: Path
    lock_path: Path
    token: str
    transaction_id: str


@dataclass(frozen=True)
class RootGuardRecovery:
    guard: RootWriteGuard
    evidence_path: Path
    recovered_kind: Literal["canonical-lock", "candidate-only"]
    recovered_artifact_sha256: str


@dataclass(frozen=True)
class CommitOutcome:
    status: Literal["accepted", "proposed"]
    transaction_id: str
    catalog_revision: int
    record_path: Optional[Path]
    proposal_path: Optional[Path]
    conflict_code: Optional[str]


@dataclass(frozen=True)
class FocusUpdateOutcome:
    status: Literal["accepted", "proposed"]
    transaction_id: str
    focus_revision: int
    proposal_path: Optional[Path]
    conflict_code: Optional[str]


@dataclass(frozen=True)
class FocusState:
    project_id: str
    revision: int
    record_ids: Tuple[str, ...]
    observed_at: str


@dataclass(frozen=True)
class ProjectionDocument:
    relative_path: str
    content: str
    source_revision: str
    observed_at: str
    expected_target_sha256: Optional[str]


@dataclass(frozen=True)
class CatalogEntry:
    memory_id: str
    revision: int
    relative_path: str
    record_type: str
    owner_scope: str
    project: Optional[str]


@dataclass(frozen=True)
class CatalogSnapshot:
    revision: int
    entries: Tuple[CatalogEntry, ...]


@dataclass(frozen=True)
class AcceptedRecord:
    envelope: RecordEnvelope
    body: str
    relative_path: str
    catalog_revision: int


@dataclass(frozen=True)
class PromotionCandidate:
    candidate_id: str
    source_record_ids: Tuple[str, ...]
    suggested_target: str
    rationale: str


@dataclass(frozen=True)
class CoordinationContext:
    project_id: str
    coordinator_task_id: str
    primary_story_id: Optional[str]
    related_story_ids: Tuple[str, ...]
    expected_story_revision: Optional[int]
    allowed_scope: Tuple[str, ...]


@dataclass(frozen=True)
class UnboundSessionCandidate:
    project_id: str
    session_candidate: RecordCandidate
    candidate_primary_story_id: Optional[str]
    candidate_primary_evidence: Optional[str]
    candidate_related_story_ids: Tuple[str, ...]
    candidate_related_evidence: Tuple[str, ...]
    intended_story_delta: Optional["StoryDelta"]
    origin_task_id: str
    coordinator_task_id: Optional[str]


@dataclass(frozen=True)
class SearchHit:
    relative_path: str
    excerpt: str


@dataclass(frozen=True)
class AdapterSelection:
    adapter: ReadAdapter
    mode: Literal["obsidian-cli", "filesystem"]
    reason: str


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Literal["error", "warning"]
    path: str
    message: str


@dataclass(frozen=True)
class ManifestFile:
    path: str
    sha256: str


@dataclass(frozen=True)
class PackManifest:
    name: str
    version: str
    minimum_python: str
    schema_versions: Tuple[int, ...]
    active_members: Tuple[str, ...]
    removed_members: Tuple[str, ...]
    required_capabilities: Tuple[str, ...]
    optional_capabilities: Tuple[str, ...]
    release_archive: str
    release_checksum: str
    release_manifest: str
    files: Tuple[ManifestFile, ...]
