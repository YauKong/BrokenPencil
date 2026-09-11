"""Plan explicit Agent Memory Skill pack lifecycle operations."""

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
    recover_lifecycle,
    resolve_skill_roots,
    rollback_lifecycle,
    write_lifecycle_plan,
)


def _mode(plan):
    if plan.legacy_profile_id is not None:
        return "unmanaged"
    if plan.from_version is not None:
        return "managed"
    return "fresh"


def _add_root_arguments(parser):
    root_group = parser.add_mutually_exclusive_group(required=True)
    root_group.add_argument("--skills-root", type=Path)
    root_group.add_argument("--runtime", choices=("codex",))
    parser.add_argument("--state-root", type=Path)


def _add_operation_arguments(parser):
    parser.add_argument("--actor", required=True)
    parser.add_argument("--occurred-at", required=True)
    parser.add_argument("--authorization-ref", required=True)


def _selection(arguments):
    selected_env = {}
    if arguments.runtime == "codex" and "CODEX_HOME" in os.environ:
        selected_env["CODEX_HOME"] = os.environ["CODEX_HOME"]
    return resolve_skill_roots(
        arguments.skills_root,
        arguments.runtime,
        selected_env,
        arguments.state_root,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("--source", required=True, type=Path)
    plan_parser.add_argument("--checksum", type=Path)
    plan_parser.add_argument("--release-manifest", type=Path)
    _add_root_arguments(plan_parser)
    plan_parser.add_argument("--transaction-id", required=True)
    plan_parser.add_argument("--actor", required=True)
    plan_parser.add_argument("--occurred-at", required=True)
    plan_parser.add_argument("--plan-out", required=True, type=Path)

    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("--source", required=True, type=Path)
    apply_parser.add_argument("--plan", required=True, type=Path)
    apply_parser.add_argument("--plan-sha256", required=True)
    apply_parser.add_argument("--checksum", type=Path)
    apply_parser.add_argument("--release-manifest", type=Path)
    _add_operation_arguments(apply_parser)

    for command in ("rollback", "recover"):
        operation_parser = commands.add_parser(command)
        _add_root_arguments(operation_parser)
        operation_parser.add_argument("--transaction-id", required=True)
        _add_operation_arguments(operation_parser)
    arguments = parser.parse_args(argv)

    try:
        if arguments.command == "plan":
            selection = _selection(arguments)
            plan = plan_install(
                arguments.source,
                selection,
                arguments.transaction_id,
                arguments.actor,
                arguments.occurred_at,
                arguments.checksum,
                arguments.release_manifest,
            )
            if plan.blockers:
                for blocker in plan.blockers:
                    print(
                        "BLOCKED {0} {1}: {2}".format(
                            blocker.code, blocker.path, blocker.message
                        )
                    )
                return 3
            plan_path = write_lifecycle_plan(plan, arguments.plan_out)
            digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
            print(
                "PLAN install transaction={0} mode={1} actions={2} blockers=0 sha256={3}".format(
                    plan.transaction_id, _mode(plan), len(plan.actions), digest
                )
            )
        elif arguments.command == "apply":
            plan = load_lifecycle_plan(arguments.plan)
            result = apply_install(
                arguments.source,
                plan,
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
        else:
            selection = _selection(arguments)
            operation = (
                rollback_lifecycle
                if arguments.command == "rollback"
                else recover_lifecycle
            )
            result = operation(
                selection,
                arguments.transaction_id,
                arguments.actor,
                arguments.occurred_at,
                arguments.authorization_ref,
            )
            if arguments.command == "rollback":
                print(
                    "ROLLED-BACK transaction={0} rollback-retained=true".format(
                        result.transaction_id
                    )
                )
            else:
                print(
                    "RECOVERED transaction={0} target-state=unchanged".format(
                        result.transaction_id
                    )
                )
    except (AgentMemoryError, OSError) as error:
        print("ERROR {0}".format(error), file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
