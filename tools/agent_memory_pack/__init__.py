"""Public contract for portable Agent Memory Skill pack operations."""

from .metadata import (
    ACTIVE_MEMBERS,
    OPTIONAL_CAPABILITIES,
    REMOVED_MEMBERS,
    REQUIRED_CAPABILITIES,
    collect_manifest_files,
    load_removal_profiles,
    refresh_pack_manifest,
    validate_release_metadata,
)
from .lifecycle import (
    apply_install,
    apply_uninstall,
    load_lifecycle_plan,
    plan_install,
    plan_uninstall,
    recover_lifecycle,
    rollback_lifecycle,
    write_lifecycle_plan,
)
from .models import (
    DoctorCheck,
    DoctorReport,
    LifecycleAction,
    LifecycleBlocker,
    LifecyclePlan,
    LifecycleResult,
    ReleaseArtifacts,
    RemovalProfile,
    RemovalProfileSet,
    SkillRootSelection,
    SmokeReport,
    VerifiedReleaseSource,
)
from .release import build_release, verified_release_source, verify_release
from .roots import resolve_skill_roots
from .doctor import run_doctor
from .smoke import SMOKE_STEPS, run_fixture_smoke


__all__ = [
    "ACTIVE_MEMBERS",
    "apply_install",
    "apply_uninstall",
    "build_release",
    "collect_manifest_files",
    "DoctorCheck",
    "DoctorReport",
    "LifecycleAction",
    "LifecycleBlocker",
    "LifecyclePlan",
    "LifecycleResult",
    "load_lifecycle_plan",
    "load_removal_profiles",
    "OPTIONAL_CAPABILITIES",
    "plan_install",
    "plan_uninstall",
    "refresh_pack_manifest",
    "recover_lifecycle",
    "ReleaseArtifacts",
    "REMOVED_MEMBERS",
    "RemovalProfile",
    "RemovalProfileSet",
    "REQUIRED_CAPABILITIES",
    "resolve_skill_roots",
    "rollback_lifecycle",
    "run_doctor",
    "run_fixture_smoke",
    "SkillRootSelection",
    "SmokeReport",
    "SMOKE_STEPS",
    "validate_release_metadata",
    "verified_release_source",
    "verify_release",
    "VerifiedReleaseSource",
    "write_lifecycle_plan",
]
