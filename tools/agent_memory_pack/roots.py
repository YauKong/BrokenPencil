"""Explicit, no-discovery Skill and lifecycle-state root selection."""

import hashlib
import os
import stat
from pathlib import Path
from typing import Mapping, Optional

from obsidian_agent_memory import ValidationError

from .io import _assert_plain_components, _is_reparse
from .models import SkillRootSelection


_LOCK_DIRECTORY = ".obsidian-agent-memory-pack-target-locks"
_STATE_DIRECTORY = ".obsidian-agent-memory-pack-state"


def _resolved_absolute(path: Path, field: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValidationError("{0} must be absolute".format(field))
    raw = Path(os.path.abspath(os.fspath(candidate)))
    _assert_plain_components(raw, allow_missing=True)
    try:
        resolved = raw.resolve(strict=False)
    except OSError as error:
        raise ValidationError("{0} cannot be resolved".format(field)) from error
    _assert_plain_components(resolved, allow_missing=True)
    try:
        metadata = resolved.lstat()
    except FileNotFoundError:
        return resolved
    except OSError as error:
        raise ValidationError("{0} cannot be inspected".format(field)) from error
    if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValidationError("{0} must be an ordinary directory".format(field))
    return resolved


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _nearest_existing_directory(path: Path, field: str) -> Path:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if current.parent == current:
                raise ValidationError("{0} has no existing volume anchor".format(field))
            current = current.parent
            continue
        except OSError as error:
            raise ValidationError("{0} volume cannot be inspected".format(field)) from error
        if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise ValidationError("{0} ancestor is not an ordinary directory".format(field))
        return current


def _require_same_volume(first: Path, second: Path) -> None:
    if os.name == "nt":
        first_anchor = os.path.normcase(first.anchor)
        second_anchor = os.path.normcase(second.anchor)
        if not first_anchor or first_anchor != second_anchor:
            raise ValidationError("skills_root and state_root must share a volume")
        return
    first_parent = _nearest_existing_directory(first, "skills_root")
    second_parent = _nearest_existing_directory(second, "state_root")
    try:
        if first_parent.stat().st_dev != second_parent.stat().st_dev:
            raise ValidationError("skills_root and state_root must share a volume")
    except OSError as error:
        raise ValidationError("root volume cannot be inspected") from error


def _target_digest(skills_root: Path) -> str:
    normalized = os.path.normcase(str(skills_root))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _inspect_lock_endpoint(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise ValidationError("target lock cannot be inspected") from error
    if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError("target lock must be an ordinary file")


def resolve_skill_roots(
    explicit_skills_root: Optional[Path],
    runtime: Optional[str],
    env: Mapping[str, str],
    explicit_state_root: Optional[Path],
) -> SkillRootSelection:
    """Resolve one explicit target and target-bound state/lock identities."""
    if (explicit_skills_root is None) == (runtime is None):
        raise ValidationError("select exactly one Skill root source")
    if not isinstance(env, Mapping):
        raise ValidationError("env must be an explicit mapping")

    selected_runtime = None
    if runtime is not None:
        if runtime != "codex":
            raise ValidationError("unsupported Skill runtime")
        codex_home = env.get("CODEX_HOME")
        if not isinstance(codex_home, str) or not codex_home:
            raise ValidationError("CODEX_HOME is required")
        if any(ord(character) < 32 for character in codex_home):
            raise ValidationError("CODEX_HOME is invalid")
        home_root = _resolved_absolute(Path(codex_home), "CODEX_HOME")
        skills_root = _resolved_absolute(home_root / "skills", "skills_root")
        selected_runtime = "codex"
    else:
        skills_root = _resolved_absolute(Path(explicit_skills_root), "skills_root")

    digest = _target_digest(skills_root)
    lock_directory = _resolved_absolute(
        skills_root.parent / _LOCK_DIRECTORY, "target lock directory"
    )
    target_lock_path = lock_directory / (digest + ".lock")
    try:
        if target_lock_path.parent.resolve(strict=False) != lock_directory:
            raise ValidationError("target lock escapes its canonical directory")
    except OSError as error:
        raise ValidationError("target lock cannot be resolved") from error
    _inspect_lock_endpoint(target_lock_path)

    if explicit_state_root is None:
        state_root = _resolved_absolute(
            skills_root.parent / _STATE_DIRECTORY / digest, "state_root"
        )
    else:
        state_root = _resolved_absolute(Path(explicit_state_root), "state_root")

    if _overlaps(skills_root, state_root):
        raise ValidationError("skills_root and state_root overlap")
    if _overlaps(skills_root, lock_directory) or _overlaps(
        skills_root, target_lock_path
    ):
        raise ValidationError("skills_root overlaps the target lock")
    if _overlaps(state_root, lock_directory) or _overlaps(
        state_root, target_lock_path
    ):
        raise ValidationError("state_root overlaps the target lock")
    _require_same_volume(skills_root, state_root)

    return SkillRootSelection(
        skills_root=skills_root,
        state_root=state_root,
        target_lock_path=target_lock_path,
        target_digest=digest,
        runtime=selected_runtime,
    )
