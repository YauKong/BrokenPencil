"""Immutable value objects for Skill pack release and lifecycle operations."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional, Tuple

from obsidian_agent_memory.models import ManifestFile


@dataclass(frozen=True)
class RemovalProfile:
    profile_id: str
    directories: Tuple[str, ...]
    files: Tuple[ManifestFile, ...]


@dataclass(frozen=True)
class RemovalProfileSet:
    schema_version: int
    profiles: Tuple[RemovalProfile, ...]


@dataclass(frozen=True)
class ReleaseArtifacts:
    archive_path: Path
    checksum_path: Path
    manifest_path: Path
    archive_sha256: str
    content_revision: str


@dataclass(frozen=True)
class VerifiedReleaseSource:
    artifacts: ReleaseArtifacts
    source_root: Path


@dataclass(frozen=True)
class SkillRootSelection:
    skills_root: Path
    state_root: Path
    target_lock_path: Path
    target_digest: str
    runtime: Optional[str]


@dataclass(frozen=True)
class LifecycleAction:
    action_id: str
    kind: Literal[
        "create-skills-root",
        "archive-member",
        "activate-member",
        "write-installed-state",
        "archive-installed-state",
    ]
    member: Optional[str]
    source_relative: Optional[str]
    target_relative: str
    expected_files: Tuple[ManifestFile, ...]


@dataclass(frozen=True)
class LifecycleBlocker:
    code: str
    path: str
    message: str


@dataclass(frozen=True)
class LifecyclePlan:
    schema_version: int
    operation: Literal["install", "uninstall"]
    transaction_id: str
    actor: str
    occurred_at: str
    pack_name: str
    from_version: Optional[str]
    to_version: Optional[str]
    source: Optional[str]
    source_revision: Optional[str]
    target_revision: str
    installed_state_sha256: Optional[str]
    skills_root: Path
    state_root: Path
    target_digest: str
    legacy_profile_id: Optional[str]
    actions: Tuple[LifecycleAction, ...]
    blockers: Tuple[LifecycleBlocker, ...]


@dataclass(frozen=True)
class LifecycleResult:
    status: Literal["installed", "uninstalled", "rolled-back", "recovered"]
    transaction_id: str
    version: Optional[str]
    moved_paths: Tuple[str, ...]
    rollback_path: Path
    actor: str
    occurred_at: str
    authorization_ref: str
    target_digest: str


@dataclass(frozen=True)
class DoctorCheck:
    code: str
    status: Literal["pass", "warning", "fail"]
    message: str


@dataclass(frozen=True)
class DoctorReport:
    ok: bool
    checks: Tuple[DoctorCheck, ...]
    authorization_ref: Optional[str]


@dataclass(frozen=True)
class SmokeReport:
    ok: bool
    steps: Tuple[str, ...]
