"""Stable command-line dispatch for read-only maintenance and guard recovery."""

import argparse
import dataclasses
import json
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Optional, Sequence

from .errors import ConflictError, PlanInvalidatedError, ValidationError
from .maintenance import (
    CleanupPlan,
    GuardRecoveryResult,
    MaintenanceAudit,
    audit_vault,
    build_cleanup_plan,
    recover_stale_root_guard,
)
from .migration import load_migration_bundle
from .models import Finding, TransactionContext
from .operation_scope import AuthorizationGate, OperationScope, require_operation_gate
from .paths import validate_identifier
from .proposal_review import (
    ProposalReviewArtifact,
    ProposalReviewContext,
    _parse_proposal_review_bytes,
    bind_proposal_review,
    build_proposal_review,
    load_proposal_review,
)
from .proposal_decisions import load_proposal_decisions
from .proposal_resolution import (
    ResolutionPlan,
    ResolutionVerification,
    _parse_resolution_plan_bytes,
    load_resolution_plan,
    plan_proposal_resolution,
)
from .publication import publish_immutable_report
from .records import _validate_timestamp
from .runtime_identity import observe_runtime_identity
from .rewrite_packet import load_rewrite_packet
from .resolution_transactions import (
    ResolutionResult,
    _load_resolution_journal,
    apply_proposal_resolution,
    load_proposal_resolution_result,
    recover_proposal_resolution,
    verify_proposal_resolution,
)


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


def _add_gate(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--scope", required=True, choices=("fixture", "real"))
    parser.add_argument("--authorization-ref")


def _add_context(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--transaction-id", required=True, type=_identifier)
    parser.add_argument("--actor", required=True, type=_identifier)
    parser.add_argument("--occurred-at", required=True, type=_timestamp)


def _add_code_identity(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fixture-code-revision", type=_identifier)


def _add_resolution_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--report-sha256", required=True, type=_digest)
    parser.add_argument("--decisions", required=True, type=Path)
    parser.add_argument("--decisions-sha256", required=True, type=_digest)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--packet-sha256", required=True, type=_digest)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True, type=_digest)
    _add_code_identity(parser)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="vault_maintain.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="write a deterministic external audit")
    _add_gate(audit)
    audit.add_argument("--output", required=True, type=Path)

    plan = subparsers.add_parser("plan", help="write an external approval-only cleanup plan")
    _add_gate(plan)
    plan.add_argument("--audit", required=True, type=Path)
    plan.add_argument("--output", required=True, type=Path)
    _add_context(plan)

    recover = subparsers.add_parser(
        "recover-root-guard",
        help="recover one reviewed stale root guard without cleanup",
    )
    _add_gate(recover)
    recover.add_argument("--target-transaction-id", required=True, type=_identifier)
    selector = recover.add_mutually_exclusive_group(required=True)
    selector.add_argument("--expected-lock-sha256", type=_digest)
    selector.add_argument("--candidate-only", action="store_true")
    _add_context(recover)

    review = subparsers.add_parser(
        "review-proposals", help="write one external migration proposal review"
    )
    _add_gate(review)
    review.add_argument("--bundle", required=True, type=Path)
    review.add_argument("--bundle-sha256", required=True, type=_digest)
    review.add_argument("--output", required=True, type=Path)
    review.add_argument("--actor", required=True, type=_identifier)
    review.add_argument("--observed-at", required=True, type=_timestamp)
    review.add_argument("--fixture-code-revision", type=_identifier)

    resolution_plan = subparsers.add_parser(
        "plan-proposal-resolution",
        help="write one external reviewed proposal resolution plan",
    )
    _add_gate(resolution_plan)
    _add_resolution_inputs(resolution_plan)
    resolution_plan.add_argument("--output", required=True, type=Path)
    _add_context(resolution_plan)

    resolution_apply = subparsers.add_parser(
        "apply-proposal-resolution",
        help="apply one separately authorized reviewed resolution plan",
    )
    _add_gate(resolution_apply)
    _add_resolution_inputs(resolution_apply)
    resolution_apply.add_argument("--plan", required=True, type=Path)
    resolution_apply.add_argument(
        "--resolution-plan-sha256", required=True, type=_digest
    )
    _add_context(resolution_apply)

    resolution_verify = subparsers.add_parser(
        "verify-proposal-resolution",
        help="verify one completed proposal resolution",
    )
    _add_gate(resolution_verify)
    resolution_verify.add_argument("--plan", required=True, type=Path)
    resolution_verify.add_argument(
        "--resolution-plan-sha256", required=True, type=_digest
    )
    resolution_verify.add_argument(
        "--target-transaction-id", required=True, type=_identifier
    )

    resolution_recover = subparsers.add_parser(
        "recover-proposal-resolution",
        help="finish one exact interrupted proposal resolution journal",
    )
    _add_gate(resolution_recover)
    resolution_recover.add_argument(
        "--target-transaction-id", required=True, type=_identifier
    )
    resolution_recover.add_argument(
        "--resolution-plan-sha256", required=True, type=_digest
    )
    resolution_recover.add_argument("--packet-sha256", required=True, type=_digest)
    _add_context(resolution_recover)
    return parser


def _gate(scope: str, authorization_ref: Optional[str], recovery=False):
    if (scope == "real" or recovery) and (
        not isinstance(authorization_ref, str) or not authorization_ref.strip()
    ):
        raise ValidationError("authorization reference is required")
    return AuthorizationGate(OperationScope(scope), authorization_ref)


def _context(arguments) -> TransactionContext:
    return TransactionContext(arguments.transaction_id, arguments.actor, arguments.occurred_at)


def _outside_root(root: Path, path: Path, label: str) -> Path:
    resolved_root = root.resolve(strict=False)
    resolved = path.resolve(strict=False)
    if resolved == resolved_root:
        raise ValidationError("{0} must be outside memory root".format(label))
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        return resolved
    raise ValidationError("{0} must be outside memory root".format(label))


def _json_value(value):
    if dataclasses.is_dataclass(value):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    return value


def _json_bytes(value) -> bytes:
    return (
        json.dumps(_json_value(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(value))


def _read_audit(path: Path) -> MaintenanceAudit:
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("invalid maintenance audit") from error
    if not isinstance(value, dict) or set(value) != {
        "authorization_ref",
        "counts",
        "findings",
        "schema_version",
        "source_revision",
    }:
        raise ValidationError("invalid maintenance audit")
    try:
        findings = tuple(
            Finding(item["code"], item["severity"], item["path"], item["message"])
            for item in value["findings"]
            if isinstance(item, dict)
            and set(item) == {"code", "message", "path", "severity"}
        )
        counts = tuple((item[0], item[1]) for item in value["counts"])
    except (KeyError, TypeError, IndexError) as error:
        raise ValidationError("invalid maintenance audit") from error
    if len(findings) != len(value["findings"]) or any(
        not isinstance(key, str) or type(count) is not int for key, count in counts
    ):
        raise ValidationError("invalid maintenance audit")
    audit = MaintenanceAudit(
        value["schema_version"],
        value["source_revision"],
        value["authorization_ref"],
        findings,
        counts,
    )
    if _json_bytes(audit) != path.read_bytes():
        raise ValidationError("invalid maintenance audit")
    return audit


def _public_document(value, artifact_path: Optional[Path] = None):
    if isinstance(value, MaintenanceAudit):
        return {
            "output_path": str(artifact_path),
            "source_revision": value.source_revision,
            "status": "audited",
        }
    if isinstance(value, CleanupPlan):
        return {
            "output_path": str(artifact_path),
            "plan_id": value.plan_id,
            "source_revision": value.source_revision,
            "status": "planned",
        }
    if isinstance(value, GuardRecoveryResult):
        return _json_value(value)
    if isinstance(value, ProposalReviewArtifact):
        summary = value.document["summary"]
        return {
            "output_path": str(artifact_path),
            "prior_classification_counts": sorted(
                summary["prior_classification_counts"].items()
            ),
            "refined_status_counts": sorted(
                summary["refined_status_counts"].items()
            ),
            "report_sha256": value.report_sha256,
            "review_id": value.review_id,
            "status": "reviewed",
            "total": summary["total"],
        }
    if isinstance(value, ResolutionPlan):
        return {
            "accepted_count": sum(
                action.record_candidate is not None for action in value.actions
            ),
            "evidence_count": len(value.resolution_evidence),
            "output_path": str(artifact_path),
            "packet_sha256": value.packet_sha256,
            "resolution_plan_sha256": value.resolution_plan_sha256,
            "status": "planned",
        }
    if isinstance(value, ResolutionResult):
        return {
            "accepted_count": len(value.record_paths),
            "catalog_revision": value.catalog_revision,
            "evidence_count": len(value.evidence_paths),
            "packet_sha256": value.packet_sha256,
            "resolution_plan_sha256": value.resolution_plan_sha256,
            "status": value.status,
            "transaction_id": value.transaction_id,
        }
    if isinstance(value, ResolutionVerification):
        return {
            "accepted_count": value.accepted_count,
            "evidence_count": value.evidence_count,
            "finding_codes": sorted({item.code for item in value.findings}),
            "root_revision": value.root_revision,
            "status": "valid" if value.valid else "invalid",
        }
    raise ValidationError("invalid maintenance command result")


def _emit(value, artifact_path: Optional[Path] = None) -> None:
    document = _public_document(value, artifact_path)
    sys.stdout.write(
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    )


def _resolution_identity(arguments):
    scope = OperationScope(arguments.scope)
    revision = getattr(arguments, "fixture_code_revision", None)
    if scope is OperationScope.FIXTURE and revision is None:
        raise ValidationError("fixture code revision is required")
    if scope is OperationScope.REAL and revision is not None:
        raise ValidationError("fixture code revision is forbidden for real scope")
    return observe_runtime_identity(scope, revision)


def _resolution_inputs(arguments):
    report_path = _outside_root(arguments.root, arguments.report, "proposal report input")
    decisions_path = _outside_root(
        arguments.root, arguments.decisions, "proposal decisions input"
    )
    packet_path = _outside_root(arguments.root, arguments.packet, "rewrite packet input")
    bundle_path = _outside_root(arguments.root, arguments.bundle, "migration bundle input")
    report = load_proposal_review(report_path)
    decisions = load_proposal_decisions(decisions_path)
    packet = load_rewrite_packet(packet_path)
    bundle = load_migration_bundle(bundle_path)
    if (
        report.report_sha256 != arguments.report_sha256
        or decisions.decisions_sha256 != arguments.decisions_sha256
        or packet.packet_sha256 != arguments.packet_sha256
        or bundle.bundle_sha256 != arguments.bundle_sha256
    ):
        raise PlanInvalidatedError("proposal resolution input hash mismatch")
    return report, decisions, packet, bundle, _resolution_identity(arguments)


def _dispatch(arguments):
    recovery = arguments.command == "recover-root-guard"
    gate = _gate(arguments.scope, arguments.authorization_ref, recovery=recovery)
    selected_root = None
    if arguments.command in {
        "plan-proposal-resolution",
        "apply-proposal-resolution",
        "verify-proposal-resolution",
        "recover-proposal-resolution",
    }:
        selected_root = require_operation_gate(
            arguments.root, gate, "proposal-resolution-cli"
        )
    if arguments.command == "audit":
        output = _outside_root(arguments.root, arguments.output, "audit output")
        audit = audit_vault(arguments.root, gate)
        _write(output, audit)
        return audit, output
    if arguments.command == "plan":
        audit_path = _outside_root(arguments.root, arguments.audit, "audit input")
        output = _outside_root(arguments.root, arguments.output, "cleanup plan output")
        audit = _read_audit(audit_path)
        plan = build_cleanup_plan(arguments.root, audit, _context(arguments), gate)
        _write(output, plan)
        return plan, output
    if arguments.command == "recover-root-guard":
        if arguments.target_transaction_id == arguments.transaction_id:
            raise ValidationError("recovery context must be distinct")
        result = recover_stale_root_guard(
            arguments.root,
            arguments.target_transaction_id,
            arguments.expected_lock_sha256,
            _context(arguments),
            gate,
        )
        return result, None
    if arguments.command == "review-proposals":
        scope = OperationScope(arguments.scope)
        if scope is OperationScope.FIXTURE and arguments.fixture_code_revision is None:
            raise ValidationError("fixture code revision is required")
        if scope is OperationScope.REAL and arguments.fixture_code_revision is not None:
            raise ValidationError("fixture code revision is forbidden for real scope")
        proof = observe_runtime_identity(scope, arguments.fixture_code_revision)
        context = ProposalReviewContext(
            actor=arguments.actor,
            observed_at=arguments.observed_at,
            fixture_code_revision=arguments.fixture_code_revision,
        )
        gate = AuthorizationGate(scope, arguments.authorization_ref)
        artifact = build_proposal_review(
            arguments.root,
            arguments.bundle,
            arguments.bundle_sha256,
            context,
            gate,
            proof,
        )
        outcome = publish_immutable_report(
            arguments.output,
            artifact.raw,
            ".proposal-review-",
            (arguments.root.resolve(), arguments.bundle.resolve())
            + proof.protected_roots,
            _parse_proposal_review_bytes,
        )
        if outcome == "occupied":
            try:
                existing = load_proposal_review(arguments.output)
                bound = bind_proposal_review(
                    arguments.root,
                    arguments.bundle,
                    arguments.bundle_sha256,
                    context,
                    gate,
                    proof,
                    existing,
                )
            except (ValidationError, PlanInvalidatedError, OSError) as error:
                raise ConflictError("proposal review output is occupied") from error
            if (
                bound.raw != artifact.raw
                or bound.report_sha256 != artifact.report_sha256
            ):
                raise ConflictError("proposal review output is occupied")
            artifact = bound
        return artifact, arguments.output
    if arguments.command == "plan-proposal-resolution":
        report, decisions, packet, bundle, proof = _resolution_inputs(arguments)
        plan = plan_proposal_resolution(
            arguments.root,
            gate,
            report,
            decisions,
            packet,
            bundle,
            _context(arguments),
            proof,
        )
        output = _outside_root(arguments.root, arguments.output, "resolution plan output")
        outcome = publish_immutable_report(
            output,
            plan.raw,
            ".resolution-plan-",
            (
                arguments.root.resolve(),
                arguments.bundle.resolve(),
                arguments.packet.resolve(),
            )
            + proof.protected_roots,
            _parse_resolution_plan_bytes,
        )
        if outcome == "occupied":
            existing = load_resolution_plan(output)
            if existing.raw != plan.raw:
                raise ConflictError("resolution plan output is occupied")
            plan = existing
        return plan, output
    if arguments.command == "apply-proposal-resolution":
        report, decisions, packet, bundle, proof = _resolution_inputs(arguments)
        plan_path = _outside_root(arguments.root, arguments.plan, "resolution plan input")
        plan = load_resolution_plan(plan_path)
        result = apply_proposal_resolution(
            arguments.root,
            gate,
            plan,
            report,
            decisions,
            packet,
            bundle,
            proof,
            arguments.resolution_plan_sha256,
            arguments.packet_sha256,
            _context(arguments),
        )
        return result, None
    if arguments.command == "verify-proposal-resolution":
        plan_path = _outside_root(arguments.root, arguments.plan, "resolution plan input")
        plan = load_resolution_plan(plan_path)
        if plan.resolution_plan_sha256 != arguments.resolution_plan_sha256:
            raise PlanInvalidatedError("proposal resolution plan hash mismatch")
        result = load_proposal_resolution_result(
            arguments.root, gate, arguments.target_transaction_id
        )
        return verify_proposal_resolution(arguments.root, gate, plan, result), None
    if arguments.command == "recover-proposal-resolution":
        unused_path, unused_raw, journal = _load_resolution_journal(
            selected_root, arguments.target_transaction_id
        )
        del unused_path, unused_raw
        if (
            journal["resolution_plan_sha256"]
            != arguments.resolution_plan_sha256
            or journal["packet_sha256"] != arguments.packet_sha256
        ):
            raise PlanInvalidatedError("proposal resolution recovery hash mismatch")
        return (
            recover_proposal_resolution(
                arguments.root,
                gate,
                arguments.target_transaction_id,
                _context(arguments),
            ),
            None,
        )
    raise ValidationError("invalid maintenance command")


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        value, output = _dispatch(arguments)
        _emit(value, output)
        return 0
    except _UsageError as error:
        sys.stderr.write("error: {0}\n".format(error))
        return 2
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
