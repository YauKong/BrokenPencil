"""Deterministic, explicit-input workstation checks for the Skill pack."""

import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Optional, Sequence, Tuple

from obsidian_agent_memory import (
    AgentMemoryError,
    RootBinding,
    doctor_memory_root,
    load_pack_manifest,
    resolve_binding,
    select_local_config_path,
    select_read_adapter,
    validate_repository,
)

from .lifecycle import _read_installed_state, _target_inventory
from .metadata import validate_release_metadata
from .models import DoctorCheck, DoctorReport, SkillRootSelection
from .roots import resolve_skill_roots


def _check(code: str, status: str, message: str) -> DoctorCheck:
    return DoctorCheck(code, status, message)


def _authorization(value: Optional[str]) -> Optional[str]:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        return None
    return value


def _bounded_file(path: Path) -> None:
    metadata = path.lstat()
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0) & reparse
        or metadata.st_size > 1024 * 1024
    ):
        raise OSError("bounded memory file is invalid")
    with path.open("rb") as handle:
        while handle.read(64 * 1024):
            pass


def _default_runner(command: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        tuple(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def run_doctor(
    source: Path,
    selection: SkillRootSelection,
    workspace: Path,
    memory_root: Optional[Path] = None,
    project_id: Optional[str] = None,
    config_path: Optional[Path] = None,
    authorization_ref: Optional[str] = None,
    probe_cli: bool = False,
    cli_executable: Optional[Path] = None,
    obsidian_vault: Optional[str] = None,
    platform: Optional[str] = None,
    config_env: Optional[Mapping[str, str]] = None,
    python_version: Optional[Tuple[int, int]] = None,
    runner=None,
) -> DoctorReport:
    """Run checks using only caller-selected source, roots, config, and probes."""
    checks = []
    version = python_version if python_version is not None else sys.version_info[:2]
    checks.append(
        _check(
            "python-version",
            "pass" if tuple(version) >= (3, 9) else "fail",
            "Python {0}.{1}; requires 3.9 or newer".format(*version),
        )
    )

    manifest = None
    try:
        source_root = Path(os.path.abspath(os.fspath(source)))
        manifest = load_pack_manifest(source_root / "pack.json")
        findings = validate_repository(source_root, manifest)
        findings += validate_release_metadata(source_root, manifest)
        if any(item.severity == "error" for item in findings):
            raise ValueError("source repository validation failed")
    except (AgentMemoryError, OSError, TypeError, ValueError) as error:
        checks.append(_check("source-manifest", "fail", str(error)))
    else:
        checks.append(_check("source-manifest", "pass", "release source is valid"))

    resolved = None
    try:
        if not isinstance(selection, SkillRootSelection):
            raise ValueError("invalid Skill root selection")
        resolved = resolve_skill_roots(
            selection.skills_root, None, {}, selection.state_root
        )
        if (
            resolved.skills_root != selection.skills_root
            or resolved.state_root != selection.state_root
            or resolved.target_digest != selection.target_digest
            or resolved.target_lock_path != selection.target_lock_path
        ):
            raise ValueError("Skill root selection binding mismatch")
    except (AgentMemoryError, OSError, TypeError, ValueError) as error:
        checks.append(_check("skill-root-selection", "fail", str(error)))
    else:
        checks.append(_check("skill-root-selection", "pass", "Skill roots are explicit"))

    installed = None
    target = None
    if resolved is None or manifest is None:
        checks.append(_check("installed-state", "fail", "installed state was not checked"))
        checks.append(_check("active-family", "fail", "active family was not checked"))
        checks.append(_check("removed-members", "fail", "removed members were not checked"))
    else:
        try:
            installed = _read_installed_state(resolved, manifest)
            if installed is None:
                raise ValueError("managed installed state is missing")
            if installed.document["pack_version"] != manifest.version:
                raise ValueError("installed pack version mismatch")
        except (AgentMemoryError, OSError, ValueError) as error:
            checks.append(_check("installed-state", "fail", str(error)))
        else:
            checks.append(_check("installed-state", "pass", "installed state is exact"))
        try:
            target = _target_inventory(resolved, manifest)
            if installed is None or target != installed.inventory:
                raise ValueError("active family differs from installed state")
        except (AgentMemoryError, OSError, ValueError) as error:
            checks.append(_check("active-family", "fail", str(error)))
        else:
            checks.append(_check("active-family", "pass", "active family is exact"))
        active_removed = []
        for member in manifest.removed_members:
            try:
                (resolved.skills_root / member).lstat()
            except FileNotFoundError:
                continue
            except OSError:
                active_removed.append(member)
            else:
                active_removed.append(member)
        if active_removed:
            checks.append(
                _check(
                    "removed-members",
                    "fail",
                    "removed member is active: " + ", ".join(active_removed),
                )
            )
        else:
            checks.append(_check("removed-members", "pass", "removed members are absent"))

    selected_config = None
    binding = None
    selected = memory_root is not None or config_path is not None or platform is not None
    retained_authorization = _authorization(authorization_ref) if selected else None
    if not selected:
        checks.append(
            _check("memory-binding", "warning", "no configured memory root selected")
        )
    elif retained_authorization is None:
        checks.append(
            _check(
                "memory-binding",
                "fail",
                "selected memory root requires a nonblank authorization reference",
            )
        )
    else:
        try:
            selected_workspace = Path(workspace)
            if not selected_workspace.is_absolute():
                raise ValueError("workspace must be an explicit absolute path")
            selected_config = select_local_config_path(
                config_path,
                platform if platform is not None else "explicit",
                {} if config_env is None else dict(config_env),
            )
            binding = resolve_binding(
                memory_root,
                project_id,
                {},
                selected_config,
                selected_workspace,
            )
            if obsidian_vault is not None:
                if (
                    not isinstance(obsidian_vault, str)
                    or not obsidian_vault.strip()
                    or any(ord(character) < 32 for character in obsidian_vault)
                ):
                    raise ValueError("invalid explicit Obsidian vault")
                binding = RootBinding(
                    binding.memory_root, binding.project_id, obsidian_vault
                )
        except (AgentMemoryError, OSError, TypeError, ValueError) as error:
            checks.append(_check("memory-binding", "warning", str(error)))
        else:
            checks.append(_check("memory-binding", "pass", "memory binding is explicit"))

    if binding is None:
        checks.append(
            _check("memory-root-health", "warning", "memory root health was not read")
        )
        checks.append(
            _check("filesystem-read", "warning", "bounded filesystem read was not selected")
        )
    else:
        try:
            findings = tuple(
                sorted(
                    doctor_memory_root(binding.memory_root),
                    key=lambda item: (item.severity, item.code, item.path, item.message),
                )
            )
        except (AgentMemoryError, OSError) as error:
            checks.append(_check("memory-root-health", "fail", str(error)))
        else:
            if findings:
                status = (
                    "fail"
                    if any(item.severity == "error" for item in findings)
                    else "warning"
                )
                message = " | ".join(
                    "{0}:{1}:{2}:{3}".format(
                        item.severity, item.code, item.path, item.message
                    )
                    for item in findings
                )
                checks.append(_check("memory-root-health", status, message))
            else:
                checks.append(_check("memory-root-health", "pass", "memory root is healthy"))
        try:
            _bounded_file(binding.memory_root / "AGENTS.md")
            _bounded_file(binding.memory_root / "README.md")
        except OSError as error:
            checks.append(_check("filesystem-read", "fail", str(error)))
        else:
            checks.append(_check("filesystem-read", "pass", "bounded files are readable"))

    if not probe_cli:
        checks.append(
            _check(
                "obsidian-cli",
                "warning",
                "optional capability not probed; filesystem mode verified",
            )
        )
    elif binding is None or cli_executable is None or obsidian_vault is None:
        checks.append(
            _check("obsidian-cli", "warning", "explicit CLI executable and vault are required")
        )
    else:
        selection_result = select_read_adapter(
            binding,
            _default_runner if runner is None else runner,
            cli_executable,
        )
        status = "pass" if selection_result.mode == "obsidian-cli" else "warning"
        checks.append(_check("obsidian-cli", status, selection_result.reason))

    result = tuple(checks)
    return DoctorReport(
        not any(check.status == "fail" for check in result),
        result,
        retained_authorization,
    )
