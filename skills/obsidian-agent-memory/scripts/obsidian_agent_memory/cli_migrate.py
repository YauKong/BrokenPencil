"""Stable command-line dispatch for reviewed vault migration operations."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional, Sequence

from .errors import AgentMemoryError, ConflictError, PlanInvalidatedError, ValidationError
from .migration import (
    MigrationBundle,
    MigrationResult,
    MigrationVerification,
    VaultDetection,
    apply_migration,
    detect_vault,
    load_migration_bundle,
    plan_v1_to_v2,
    rollback_migration,
    verify_migration,
)
from .models import Finding, TransactionContext
from .operation_scope import AuthorizationGate, OperationScope
from .paths import validate_identifier
from .records import _validate_timestamp


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _UsageError(message)


def _digest(value: str) -> str:
    if not _DIGEST.fullmatch(value):
        raise argparse.ArgumentTypeError("must be 64 lowercase hexadecimal characters")
    return value


def _identifier(value: str) -> str:
    try:
        return validate_identifier(value, "identifier")
    except ValidationError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _timestamp(value: str) -> str:
    try:
        _validate_timestamp(value, "occurred_at")
    except ValidationError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    return value


def _project_id_mapping(value: str):
    source_project_id, separator, target_project_id = value.partition("=")
    if not separator or not source_project_id or not target_project_id:
        raise argparse.ArgumentTypeError(
            "project id mapping must be LEGACY_ID=TARGET_ID"
        )
    return source_project_id, _identifier(target_project_id)


def _project_id_mappings(values):
    seen = set()
    mappings = []
    for source_project_id, target_project_id in values:
        if source_project_id in seen:
            raise ValidationError("duplicate project id mapping source")
        seen.add(source_project_id)
        mappings.append((source_project_id, target_project_id))
    return tuple(mappings)


def _add_gate(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--scope", required=True, choices=("fixture", "real"))
    parser.add_argument("--authorization-ref")


def _add_context(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--transaction-id", required=True, type=_identifier)
    parser.add_argument("--actor", required=True, type=_identifier)
    parser.add_argument("--occurred-at", required=True, type=_timestamp)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="vault_migrate.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    detect = subparsers.add_parser("detect", help="detect a gated vault generation")
    _add_gate(detect)

    plan = subparsers.add_parser("plan", help="build an external reviewed migration bundle")
    _add_gate(plan)
    plan.add_argument("--work-dir", required=True, type=Path)
    plan.add_argument(
        "--project-id-map",
        action="append",
        default=[],
        type=_project_id_mapping,
        metavar="LEGACY_ID=TARGET_ID",
    )
    _add_context(plan)

    apply = subparsers.add_parser("apply", help="apply one exact reviewed migration bundle")
    _add_gate(apply)
    apply.add_argument("--bundle", required=True, type=Path)
    apply.add_argument("--bundle-sha256", required=True, type=_digest)
    _add_context(apply)

    verify = subparsers.add_parser("verify", help="verify one applied migration bundle")
    _add_gate(verify)
    verify.add_argument("--bundle", required=True, type=Path)

    rollback = subparsers.add_parser("rollback", help="hash-safe rollback of one apply transaction")
    _add_gate(rollback)
    rollback.add_argument("--apply-transaction-id", required=True, type=_identifier)
    _add_context(rollback)
    return parser


def _gate(scope: str, authorization_ref: Optional[str]) -> AuthorizationGate:
    if scope == "real" and (
        not isinstance(authorization_ref, str) or not authorization_ref.strip()
    ):
        raise ValidationError("authorization reference is required for real scope")
    return AuthorizationGate(OperationScope(scope), authorization_ref)


def _context(arguments) -> TransactionContext:
    return TransactionContext(
        arguments.transaction_id,
        arguments.actor,
        arguments.occurred_at,
    )


def _finding(finding: Finding):
    return {
        "code": finding.code,
        "message": finding.message,
        "path": finding.path,
        "severity": finding.severity,
    }


def _detection(value: VaultDetection):
    return {
        "entries": [
            {
                "category": item.category.value,
                "relative_path": item.relative_path,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in value.entries
        ],
        "findings": [_finding(item) for item in value.findings],
        "generation": value.generation.value,
        "source_revision": value.source_revision,
        "status": "detected",
    }


def _bundle(value: MigrationBundle):
    return {
        "authorization_ref": value.plan.authorization_ref,
        "bundle_path": str(value.bundle_dir),
        "bundle_sha256": value.bundle_sha256,
        "plan_id": value.plan.plan_id,
        "snapshot_id": value.snapshot.snapshot_id,
        "source_revision": value.plan.source_revision,
        "status": "planned",
    }


def _result(value: MigrationResult):
    return {
        "apply_authorization_ref": value.apply_authorization_ref,
        "archived_paths": list(value.archived_paths),
        "created_paths": list(value.created_paths),
        "plan_authorization_ref": value.plan_authorization_ref,
        "proposal_paths": list(value.proposal_paths),
        "replaced_paths": list(value.replaced_paths),
        "reviewed_bundle_sha256": value.reviewed_bundle_sha256,
        "rollback_authorization_ref": value.rollback_authorization_ref,
        "source_revision": value.source_revision,
        "status": value.status,
        "transaction_id": value.transaction_id,
    }


def _verification(value: MigrationVerification):
    return {
        "bundle_sha256": value.bundle_sha256,
        "findings": [_finding(item) for item in value.findings],
        "projection_paths": list(value.projection_paths),
        "source_revision": value.source_revision,
        "status": "verified" if value.valid else "verification-failed",
        "valid": value.valid,
    }


def _emit(value) -> None:
    sys.stdout.write(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    )


def _dispatch(arguments):
    gate = _gate(arguments.scope, arguments.authorization_ref)
    if arguments.command == "detect":
        value = detect_vault(arguments.root, gate)
        return 0, _detection(value)
    if arguments.command == "plan":
        value = plan_v1_to_v2(
            arguments.root,
            arguments.work_dir,
            _context(arguments),
            gate,
            project_id_map=_project_id_mappings(arguments.project_id_map),
        )
        return 0, _bundle(value)
    if arguments.command == "apply":
        try:
            bundle = load_migration_bundle(arguments.bundle)
        except ValidationError as error:
            if arguments.bundle.exists():
                raise PlanInvalidatedError("reviewed migration bundle changed") from error
            raise
        value = apply_migration(
            arguments.root,
            bundle,
            arguments.bundle_sha256,
            _context(arguments),
            gate,
        )
        return (4 if value.status == "proposed" else 0), _result(value)
    if arguments.command == "verify":
        try:
            bundle = load_migration_bundle(arguments.bundle)
        except ValidationError as error:
            raise _VerificationRefusal(str(error)) from error
        value = verify_migration(arguments.root, bundle, gate)
        return (0 if value.valid else 5), _verification(value)
    if arguments.command == "rollback":
        if arguments.apply_transaction_id == arguments.transaction_id:
            raise ValidationError("rollback context must be distinct")
        try:
            value = rollback_migration(
                arguments.root,
                arguments.apply_transaction_id,
                _context(arguments),
                gate,
            )
        except PlanInvalidatedError as error:
            raise _RollbackRefusal(str(error)) from error
        return 0, _result(value)
    raise ValidationError("invalid migration command")


class _VerificationRefusal(AgentMemoryError):
    pass


class _RollbackRefusal(AgentMemoryError):
    pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        code, value = _dispatch(arguments)
        _emit(value)
        return code
    except _UsageError as error:
        sys.stderr.write("error: {0}\n".format(error))
        return 2
    except _VerificationRefusal as error:
        sys.stderr.write("error: {0}\n".format(error))
        return 5
    except _RollbackRefusal as error:
        sys.stderr.write("error: {0}\n".format(error))
        return 5
    except PlanInvalidatedError as error:
        sys.stderr.write("error: {0}\n".format(error))
        return 3
    except ConflictError as error:
        sys.stderr.write("error: {0}\n".format(error))
        return 4
    except (ValidationError, OSError) as error:
        sys.stderr.write("error: {0}\n".format(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
