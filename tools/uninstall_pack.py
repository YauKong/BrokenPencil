"""Plan, apply, roll back, or recover one strict managed pack uninstall."""

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Optional, Sequence

from _bootstrap import bootstrap


bootstrap()

from obsidian_agent_memory import AgentMemoryError
from agent_memory_pack import (
    apply_uninstall,
    load_lifecycle_plan,
    plan_uninstall,
    recover_lifecycle,
    resolve_skill_roots,
    rollback_lifecycle,
    write_lifecycle_plan,
)


def _add_roots(parser):
    parser.add_argument("--skills-root", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)


def _add_operation(parser):
    parser.add_argument("--actor", required=True)
    parser.add_argument("--occurred-at", required=True)
    parser.add_argument("--authorization-ref", required=True)


def _selection(arguments):
    return resolve_skill_roots(
        arguments.skills_root, None, {}, arguments.state_root
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    plan_parser = commands.add_parser("plan")
    _add_roots(plan_parser)
    plan_parser.add_argument("--transaction-id", required=True)
    plan_parser.add_argument("--actor", required=True)
    plan_parser.add_argument("--occurred-at", required=True)
    plan_parser.add_argument("--plan-out", required=True, type=Path)

    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("--plan", required=True, type=Path)
    apply_parser.add_argument("--plan-sha256", required=True)
    _add_operation(apply_parser)

    for command in ("rollback", "recover"):
        operation_parser = commands.add_parser(command)
        _add_roots(operation_parser)
        operation_parser.add_argument("--transaction-id", required=True)
        _add_operation(operation_parser)

    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "plan":
            plan = plan_uninstall(
                _selection(arguments),
                arguments.transaction_id,
                arguments.actor,
                arguments.occurred_at,
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
                "PLAN uninstall transaction={0} actions={1} blockers=0 sha256={2}".format(
                    plan.transaction_id, len(plan.actions), digest
                )
            )
        elif arguments.command == "apply":
            result = apply_uninstall(
                load_lifecycle_plan(arguments.plan),
                arguments.plan_sha256,
                arguments.actor,
                arguments.occurred_at,
                arguments.authorization_ref,
            )
            print(
                "UNINSTALLED transaction={0} rollback-retained=true".format(
                    result.transaction_id
                )
            )
        else:
            operation = (
                rollback_lifecycle
                if arguments.command == "rollback"
                else recover_lifecycle
            )
            result = operation(
                _selection(arguments),
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
