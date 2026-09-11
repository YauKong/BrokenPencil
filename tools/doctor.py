"""Run deterministic explicit-input workstation checks for the Skill pack."""

import argparse
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from _bootstrap import bootstrap


bootstrap()

from obsidian_agent_memory import AgentMemoryError
from agent_memory_pack import resolve_skill_roots, run_doctor


def add_root_arguments(parser):
    roots = parser.add_mutually_exclusive_group(required=True)
    roots.add_argument("--skills-root", type=Path)
    roots.add_argument("--runtime", choices=("codex",))
    parser.add_argument("--state-root", type=Path)


def add_doctor_arguments(parser):
    parser.add_argument("--source", required=True, type=Path)
    add_root_arguments(parser)
    parser.add_argument("--workspace", required=True, type=Path)
    binding = parser.add_mutually_exclusive_group()
    binding.add_argument("--memory-root", type=Path)
    binding.add_argument("--config", type=Path)
    binding.add_argument("--use-platform-registry", action="store_true")
    parser.add_argument("--project-id")
    parser.add_argument("--authorization-ref")
    parser.add_argument("--probe-cli", action="store_true")
    parser.add_argument("--cli-executable", type=Path)
    parser.add_argument("--obsidian-vault")


def _selected_env(arguments):
    selected = {}
    if arguments.runtime == "codex" and "CODEX_HOME" in os.environ:
        selected["CODEX_HOME"] = os.environ["CODEX_HOME"]
    return selected


def _registry_env(platform):
    if platform == "win32":
        names = ("APPDATA",)
    elif platform == "darwin":
        names = ("HOME",)
    elif platform.startswith("linux"):
        names = ("XDG_CONFIG_HOME", "HOME")
    else:
        names = ()
    return {name: os.environ[name] for name in names if name in os.environ}


def _authorization_is_valid(value):
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not any(ord(character) < 32 for character in value)
    )


def run_arguments(parser, arguments):
    binding_selected = (
        arguments.memory_root is not None
        or arguments.config is not None
        or arguments.use_platform_registry
    )
    if binding_selected and not _authorization_is_valid(arguments.authorization_ref):
        parser.error("selected memory binding requires --authorization-ref")
    if arguments.probe_cli and (
        arguments.cli_executable is None or arguments.obsidian_vault is None
    ):
        parser.error("--probe-cli requires --cli-executable and --obsidian-vault")
    selection = resolve_skill_roots(
        arguments.skills_root,
        arguments.runtime,
        _selected_env(arguments),
        arguments.state_root,
    )
    platform = sys.platform if arguments.use_platform_registry else None
    report = run_doctor(
        arguments.source,
        selection,
        arguments.workspace,
        memory_root=arguments.memory_root,
        project_id=arguments.project_id,
        config_path=arguments.config,
        authorization_ref=arguments.authorization_ref,
        probe_cli=arguments.probe_cli,
        cli_executable=arguments.cli_executable,
        obsidian_vault=arguments.obsidian_vault,
        platform=platform,
        config_env=_registry_env(platform) if platform is not None else {},
    )
    labels = {"pass": "PASS", "warning": "WARN", "fail": "FAIL"}
    for check in report.checks:
        print("{0} {1} {2}".format(labels[check.status], check.code, check.message))
    if report.ok:
        return 0
    failed = {check.code for check in report.checks if check.status == "fail"}
    if failed.intersection(("python-version", "source-manifest", "filesystem-read")):
        return 5
    return 3


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_doctor_arguments(parser)
    arguments = parser.parse_args(argv)
    try:
        return run_arguments(parser, arguments)
    except (AgentMemoryError, OSError) as error:
        print("ERROR {0}".format(error), file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
