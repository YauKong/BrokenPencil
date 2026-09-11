"""Explicit pack bootstrap with four independent command dispatches."""

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from _bootstrap import bootstrap


bootstrap()

from obsidian_agent_memory import AgentMemoryError
from agent_memory_pack import (
    apply_install,
    load_lifecycle_plan,
    plan_install,
    resolve_skill_roots,
    write_lifecycle_plan,
)
from doctor import add_doctor_arguments, run_arguments as run_doctor_arguments


def _add_source(parser):
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--checksum", type=Path)
    parser.add_argument("--release-manifest", type=Path)


def _add_roots(parser):
    roots = parser.add_mutually_exclusive_group(required=True)
    roots.add_argument("--skills-root", type=Path)
    roots.add_argument("--runtime", choices=("codex",))
    parser.add_argument("--state-root", type=Path)


def _selection(arguments):
    selected = {}
    if arguments.runtime == "codex" and "CODEX_HOME" in os.environ:
        selected["CODEX_HOME"] = os.environ["CODEX_HOME"]
    return resolve_skill_roots(
        arguments.skills_root,
        arguments.runtime,
        selected,
        arguments.state_root,
    )


def _mode(plan):
    if plan.legacy_profile_id is not None:
        return "unmanaged"
    if plan.from_version is not None:
        return "managed"
    return "fresh"


def _print_blockers(plan):
    for blocker in plan.blockers:
        print(
            "BLOCKED {0} {1}: {2}".format(
                blocker.code, blocker.path, blocker.message
            )
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, usage="bootstrap.py {check,plan,apply,doctor} ..."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    check_parser = commands.add_parser("check")
    _add_source(check_parser)
    _add_roots(check_parser)

    plan_parser = commands.add_parser("plan")
    _add_source(plan_parser)
    _add_roots(plan_parser)
    plan_parser.add_argument("--transaction-id", required=True)
    plan_parser.add_argument("--actor", required=True)
    plan_parser.add_argument("--occurred-at", required=True)
    plan_parser.add_argument("--plan-out", required=True, type=Path)

    apply_parser = commands.add_parser("apply")
    _add_source(apply_parser)
    apply_parser.add_argument("--plan", required=True, type=Path)
    apply_parser.add_argument("--plan-sha256", required=True)
    apply_parser.add_argument("--actor", required=True)
    apply_parser.add_argument("--occurred-at", required=True)
    apply_parser.add_argument("--authorization-ref", required=True)

    doctor_parser = commands.add_parser("doctor")
    add_doctor_arguments(doctor_parser)

    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "check":
            plan = plan_install(
                arguments.source,
                _selection(arguments),
                "bootstrap-check",
                "bootstrap-checker",
                "2026-08-30T00:00:00Z",
                arguments.checksum,
                arguments.release_manifest,
            )
            if plan.blockers:
                _print_blockers(plan)
                return 3
            print("CHECK valid mode={0} blockers=0".format(_mode(plan)))
            return 0
        if arguments.command == "plan":
            plan = plan_install(
                arguments.source,
                _selection(arguments),
                arguments.transaction_id,
                arguments.actor,
                arguments.occurred_at,
                arguments.checksum,
                arguments.release_manifest,
            )
            if plan.blockers:
                _print_blockers(plan)
                return 3
            plan_path = write_lifecycle_plan(plan, arguments.plan_out)
            digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
            print(
                "PLAN install transaction={0} mode={1} actions={2} blockers=0 sha256={3}".format(
                    plan.transaction_id, _mode(plan), len(plan.actions), digest
                )
            )
            return 0
        if arguments.command == "apply":
            result = apply_install(
                arguments.source,
                load_lifecycle_plan(arguments.plan),
                arguments.plan_sha256,
                arguments.actor,
                arguments.occurred_at,
                arguments.authorization_ref,
                arguments.checksum,
                arguments.release_manifest,
            )
            print(
                "INSTALLED version={0} transaction={1} rollback-retained=true".format(
                    result.version, result.transaction_id
                )
            )
            return 0
        if arguments.command == "doctor":
            return run_doctor_arguments(doctor_parser, arguments)
        raise AssertionError("unreachable bootstrap command")
    except (AgentMemoryError, OSError) as error:
        print("ERROR {0}".format(error), file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
