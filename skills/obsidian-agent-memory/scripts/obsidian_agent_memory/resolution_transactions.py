"""Root-guarded activation for reviewed proposal resolution plans."""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Tuple

from .catalog import load_catalog
from .errors import AgentMemoryError, PlanInvalidatedError, ValidationError
from .migration import MigrationBundle, load_migration_bundle
from .models import Finding, TransactionContext
from .operation_scope import AuthorizationGate, require_operation_gate
from .projections import build_project_views, build_root_views
from .proposal_decisions import (
    ProposalDecisionEnvelope,
    bind_proposal_decisions,
)
from .proposal_resolution import (
    ResolutionPlan,
    ResolutionVerification,
    bind_resolution_plan,
)
from .proposal_review import ProposalReviewArtifact
from .records import parse_record, render_record
from .rewrite_packet import RewritePacket, bind_rewrite_packet
from .runtime_identity import CodeIdentityProof
from .paths import validate_identifier
from .session_relationships import parse_session_relationship
from .transactions import (
    _publish_exclusive,
    _replace_cas,
    _validate_context,
    root_write_guard,
)


_JOURNAL_KEYS = frozenset(
    (
        "schema_version",
        "operation",
        "status",
        "transaction_id",
        "actor",
        "occurred_at",
        "resolution_plan_sha256",
        "packet_sha256",
        "catalog_revision",
        "predicted_catalog_revision",
        "record_paths",
        "evidence_paths",
        "projection_paths",
        "activations",
    )
)
_ACTIVATION_KEYS = frozenset(
    ("kind", "target", "stage_path", "desired_sha256", "expected_sha256")
)
_ACTIVATION_KINDS = frozenset(("record", "evidence", "projection", "catalog"))
_JOURNAL_STATUSES = frozenset(("prepared", "staged", "activating", "completed"))


@dataclass(frozen=True)
class ResolutionResult:
    status: str
    transaction_id: str
    resolution_plan_sha256: str
    packet_sha256: str
    catalog_revision: int
    record_paths: Tuple[str, ...]
    evidence_paths: Tuple[str, ...]
    projection_paths: Tuple[str, ...]
    journal_path: str


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("resolution journal contains duplicate keys")
        value[key] = item
    return value


def _valid_digest(value, allow_none=False):
    if allow_none and value is None:
        return True
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _plain_bytes(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValidationError("missing {0}".format(label)) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError("invalid {0}".format(label))
    try:
        return path.read_bytes()
    except OSError as error:
        raise ValidationError("cannot read {0}".format(label)) from error


def _load_resolution_journal(root: Path, transaction_id: str, read=None):
    validate_identifier(transaction_id, "transaction_id")
    relative = ".agent-memory/transactions/{0}/journal.json".format(transaction_id)
    path = _relative_target(root, relative)
    raw = _plain_bytes(path, "resolution journal") if read is None else read(relative)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError) as error:
        raise ValidationError("invalid resolution journal") from error
    if (
        not isinstance(document, dict)
        or set(document) != _JOURNAL_KEYS
        or raw != _json_bytes(document)
        or document["schema_version"] != 1
        or document["operation"] != "apply-proposal-resolution"
        or document["status"] not in _JOURNAL_STATUSES
        or document["transaction_id"] != transaction_id
        or not _valid_digest(document["resolution_plan_sha256"])
        or not _valid_digest(document["packet_sha256"])
        or type(document["catalog_revision"]) is not int
        or type(document["predicted_catalog_revision"]) is not int
        or document["predicted_catalog_revision"]
        not in (document["catalog_revision"], document["catalog_revision"] + 1)
    ):
        raise ValidationError("invalid resolution journal")
    for key in ("actor", "occurred_at"):
        if not isinstance(document[key], str) or not document[key].strip():
            raise ValidationError("invalid resolution journal")
    for key in ("record_paths", "evidence_paths", "projection_paths", "activations"):
        if not isinstance(document[key], list):
            raise ValidationError("invalid resolution journal")

    seen_targets = set()
    seen_stages = set()
    kind_paths = {"record": [], "evidence": [], "projection": [], "catalog": []}
    for index, activation in enumerate(document["activations"]):
        if (
            not isinstance(activation, dict)
            or set(activation) != _ACTIVATION_KEYS
            or activation["kind"] not in _ACTIVATION_KINDS
            or not _valid_digest(activation["desired_sha256"])
            or not _valid_digest(activation["expected_sha256"], allow_none=True)
        ):
            raise ValidationError("invalid resolution journal activation")
        target = activation["target"]
        stage_path = activation["stage_path"]
        _relative_target(root, target)
        _relative_target(root, stage_path)
        expected_stage = ".agent-memory/transactions/{0}/stage/{1:04d}.bin".format(
            transaction_id, index
        )
        if (
            target in seen_targets
            or stage_path in seen_stages
            or stage_path != expected_stage
        ):
            raise ValidationError("invalid resolution journal activation inventory")
        seen_targets.add(target)
        seen_stages.add(stage_path)
        kind_paths[activation["kind"]].append(target)
    if (
        sorted(kind_paths["record"]) != document["record_paths"]
        or sorted(kind_paths["evidence"]) != document["evidence_paths"]
        or sorted(kind_paths["projection"]) != document["projection_paths"]
        or kind_paths["catalog"] != [".agent-memory/state/catalog.json"]
        or not document["activations"]
        or document["activations"][-1]["kind"] != "catalog"
    ):
        raise ValidationError("invalid resolution journal inventory")
    return path, raw, document


def _staged_bytes(root: Path, journal):
    values = {}
    for activation in journal["activations"]:
        raw = _plain_bytes(
            _relative_target(root, activation["stage_path"]),
            "resolution stage",
        )
        if _sha256(raw) != activation["desired_sha256"]:
            raise ValidationError("resolution stage digest changed")
        values[activation["target"]] = raw
    return values


def _target_state(root: Path, activation):
    target = _relative_target(root, activation["target"])
    if not target.exists():
        if activation["expected_sha256"] is None:
            return "before", None
        raise ValidationError("resolution target disappeared")
    raw = _plain_bytes(target, "resolution target")
    digest = _sha256(raw)
    if digest == activation["desired_sha256"]:
        return "after", raw
    if digest == activation["expected_sha256"]:
        return "before", raw
    raise ValidationError("resolution target digest changed")


def _result_from_journal(journal):
    return ResolutionResult(
        "applied",
        journal["transaction_id"],
        journal["resolution_plan_sha256"],
        journal["packet_sha256"],
        journal["predicted_catalog_revision"],
        tuple(journal["record_paths"]),
        tuple(journal["evidence_paths"]),
        tuple(journal["projection_paths"]),
        ".agent-memory/transactions/{0}/journal.json".format(
            journal["transaction_id"]
        ),
    )


def _validate_completed_targets(root: Path, journal) -> None:
    _staged_bytes(root, journal)
    for activation in journal["activations"]:
        state, unused = _target_state(root, activation)
        del unused
        if state != "after":
            raise ValidationError("completed resolution target is not activated")


def _bind_replay_inputs(
    root,
    plan,
    report,
    decisions,
    packet,
    bundle,
    code_identity_proof,
):
    if not isinstance(code_identity_proof, CodeIdentityProof):
        raise ValidationError("invalid code identity proof")
    bind_proposal_decisions(decisions, report)
    current_packet = bind_rewrite_packet(
        packet, report, decisions, code_identity_proof.identity
    )
    if not isinstance(bundle, MigrationBundle):
        raise ValidationError("invalid migration bundle")
    current_bundle = load_migration_bundle(bundle.bundle_dir)
    if (
        report.report_sha256 != plan.report_sha256
        or decisions.decisions_sha256 != plan.decisions_sha256
        or current_packet.packet_sha256 != plan.packet_sha256
        or current_bundle.bundle_sha256 != plan.bundle_sha256
        or code_identity_proof.proof_sha256 != plan.code_identity_proof_sha256
    ):
        raise PlanInvalidatedError("proposal resolution replay inputs changed")
    actions = {action.proposal_id: action for action in plan.actions}
    items = report.document.get("items")
    if not isinstance(items, list) or len(items) != len(actions):
        raise ValidationError("proposal resolution replay inventory changed")
    for item in items:
        if not isinstance(item, dict) or item.get("proposal_id") not in actions:
            raise ValidationError("proposal resolution replay inventory changed")
        action = actions[item["proposal_id"]]
        proposal = _plain_bytes(
            _relative_target(root, item.get("proposal_path")), "resolution proposal"
        )
        snapshot = _plain_bytes(
            _relative_target(current_bundle.bundle_dir, item.get("snapshot_path")),
            "resolution snapshot",
        )
        if (
            _sha256(proposal) != action.proposal_sha256
            or _sha256(snapshot) != action.snapshot_sha256
        ):
            raise PlanInvalidatedError("proposal resolution replay evidence changed")


def _resolution_apply_checkpoint(stage: str, path: Path) -> None:
    del stage, path


def _json_bytes(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _relative_target(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValidationError("invalid resolution target path")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise ValidationError("invalid resolution target path")
    target = root.joinpath(*pure.parts)
    try:
        target.resolve(strict=False).relative_to(root)
    except (OSError, ValueError, RuntimeError) as error:
        raise ValidationError("resolution target escapes root") from error
    return target


def _catalog_bytes(root, plan):
    catalog = load_catalog(root)
    if catalog.revision != plan.catalog_revision:
        raise PlanInvalidatedError("resolution catalog revision changed")
    records = {
        entry.memory_id: {
            "memory_id": entry.memory_id,
            "owner_scope": entry.owner_scope,
            "project": entry.project,
            "record_type": entry.record_type,
            "relative_path": entry.relative_path,
            "revision": entry.revision,
        }
        for entry in catalog.entries
    }
    for action in plan.actions:
        if action.record_candidate is None:
            continue
        envelope = action.record_candidate.envelope
        if envelope.memory_id in records:
            raise PlanInvalidatedError("resolution record target became occupied")
        records[envelope.memory_id] = {
            "memory_id": envelope.memory_id,
            "owner_scope": envelope.owner_scope,
            "project": envelope.project,
            "record_type": envelope.record_type,
            "relative_path": action.relative_path,
            "revision": envelope.revision,
        }
    return _json_bytes(
        {
            "records": {key: records[key] for key in sorted(records)},
            "revision": plan.predicted_catalog_revision,
            "schema_version": 2,
        }
    )


def _evidence_bytes(plan, transaction_id):
    action_by_id = {action.proposal_id: action for action in plan.actions}
    values = {}
    for evidence in plan.resolution_evidence:
        action = action_by_id[evidence.proposal_id]
        document = asdict(evidence)
        document.update(
            {
                "schema_version": 1,
                "evidence_kind": "proposal-resolution-outcome",
                "transaction_id": transaction_id,
                "record_path": action.relative_path,
                "record_revision": (
                    None
                    if action.record_candidate is None
                    else action.record_candidate.envelope.revision
                ),
                "body_sha256": (
                    None
                    if action.record_candidate is None
                    else action.record_candidate.envelope.body_sha256
                ),
            }
        )
        relative = (
            ".agent-memory/transactions/{0}/resolution-evidence/{1}.json".format(
                transaction_id, evidence.proposal_id
            )
        )
        values[relative] = _json_bytes(document)
    return values


def _shadow_projection_bytes(root, plan, catalog_bytes, record_bytes, evidence_bytes, context):
    with tempfile.TemporaryDirectory(prefix="proposal-resolution-shadow-") as temporary:
        shadow = Path(temporary) / "root"
        shutil.copytree(
            root,
            shadow,
            ignore=shutil.ignore_patterns(".agent-memory-root-write.anchor"),
        )
        for relative, content in record_bytes.items():
            target = _relative_target(shadow, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        catalog_path = shadow / ".agent-memory" / "state" / "catalog.json"
        catalog_path.write_bytes(catalog_bytes)
        # Materialize the desired canonical endpoint only inside the disposable
        # shadow. Projection bytes must not authenticate themselves: the reader
        # consumes record/evidence/catalog activations, never projection hashes.
        canonical = list(("record", path, raw) for path, raw in record_bytes.items())
        canonical.extend(("evidence", path, raw) for path, raw in evidence_bytes.items())
        canonical.append(("catalog", ".agent-memory/state/catalog.json", catalog_bytes))
        activations = []
        for index, (kind, relative, raw) in enumerate(canonical):
            stage = ".agent-memory/transactions/{0}/stage/{1:04d}.bin".format(context.transaction_id, index)
            for destination in (relative, stage):
                target = _relative_target(shadow, destination)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            activations.append(_activation_entry(kind, relative, stage, raw, None))
        journal = _journal_document(plan, context, "completed", activations,
                                    tuple(sorted(record_bytes)), tuple(sorted(evidence_bytes)), ())
        journal_path = _relative_target(shadow, ".agent-memory/transactions/{0}/journal.json".format(context.transaction_id))
        journal_path.write_bytes(_json_bytes(journal))
        documents = list(build_root_views(shadow, "proposal-resolution-v1"))
        project_ids = sorted(
            {
                action.record_candidate.envelope.project
                for action in plan.actions
                if action.record_candidate is not None
                and action.record_candidate.envelope.project is not None
            }
        )
        for project_id in project_ids:
            documents.extend(
                build_project_views(shadow, project_id, "proposal-resolution-v1")
            )
        selected = {
            document.relative_path: document.content.encode("utf-8")
            for document in documents
            if document.relative_path in set(plan.projection_effects)
        }
        if set(selected) != set(plan.projection_effects):
            raise ValidationError("resolution projection plan is incomplete")
        return selected


def _activation_entry(kind, target_relative, stage_relative, desired, expected):
    return {
        "kind": kind,
        "target": target_relative,
        "stage_path": stage_relative,
        "desired_sha256": _sha256(desired),
        "expected_sha256": None if expected is None else _sha256(expected),
    }


def _journal_document(
    plan,
    context,
    status,
    activations,
    record_paths,
    evidence_paths,
    projection_paths,
):
    return {
        "schema_version": 1,
        "operation": "apply-proposal-resolution",
        "status": status,
        "transaction_id": context.transaction_id,
        "actor": context.actor,
        "occurred_at": context.occurred_at,
        "resolution_plan_sha256": plan.resolution_plan_sha256,
        "packet_sha256": plan.packet_sha256,
        "catalog_revision": plan.catalog_revision,
        "predicted_catalog_revision": plan.predicted_catalog_revision,
        "record_paths": list(record_paths),
        "evidence_paths": list(evidence_paths),
        "projection_paths": list(projection_paths),
        "activations": activations,
    }


def _publish_or_replace(root, target, expected, desired, token):
    if expected is None:
        _publish_exclusive(target, desired, token, root=root)
    else:
        _replace_cas(target, expected, desired, token, root=root)


def apply_proposal_resolution(
    root: Path,
    gate: AuthorizationGate,
    plan: ResolutionPlan,
    report: ProposalReviewArtifact,
    decisions: ProposalDecisionEnvelope,
    packet: RewritePacket,
    bundle: MigrationBundle,
    code_identity_proof: CodeIdentityProof,
    expected_resolution_plan_sha256: str,
    expected_packet_sha256: str,
    context: TransactionContext,
) -> ResolutionResult:
    """Activate one fully bound resolution plan under a root-wide guard."""

    if (
        not isinstance(plan, ResolutionPlan)
        or expected_resolution_plan_sha256 != plan.resolution_plan_sha256
        or expected_packet_sha256 != plan.packet_sha256
    ):
        raise PlanInvalidatedError("reviewed proposal resolution hashes do not match")
    selected_root = require_operation_gate(root, gate, "apply-proposal-resolution")
    _validate_context(context)
    record_bytes = {
        action.relative_path: render_record(
            action.record_candidate.envelope, action.record_candidate.body
        ).encode("utf-8")
        for action in plan.actions
        if action.record_candidate is not None
    }
    evidence_bytes = _evidence_bytes(plan, context.transaction_id)
    record_paths = tuple(sorted(record_bytes))
    evidence_paths = tuple(sorted(evidence_bytes))
    projection_paths = tuple(plan.projection_effects)
    journal_relative = ".agent-memory/transactions/{0}/journal.json".format(
        context.transaction_id
    )
    journal_path = _relative_target(selected_root, journal_relative)

    with root_write_guard(selected_root, context):
        if journal_path.exists() or journal_path.is_symlink():
            _bind_replay_inputs(
                selected_root,
                plan,
                report,
                decisions,
                packet,
                bundle,
                code_identity_proof,
            )
            unused_path, unused_raw, existing = _load_resolution_journal(
                selected_root, context.transaction_id
            )
            del unused_path, unused_raw
            if (
                existing["status"] != "completed"
                or existing["resolution_plan_sha256"]
                != plan.resolution_plan_sha256
                or existing["packet_sha256"] != plan.packet_sha256
            ):
                raise PlanInvalidatedError(
                    "resolution transaction id is already occupied"
                )
            _validate_completed_targets(selected_root, existing)
            return _result_from_journal(existing)
        bind_resolution_plan(
            plan,
            selected_root,
            gate,
            report,
            decisions,
            packet,
            bundle,
            code_identity_proof,
        )
        catalog_path = selected_root / ".agent-memory" / "state" / "catalog.json"
        expected_catalog = catalog_path.read_bytes()
        desired_catalog = (
            _catalog_bytes(selected_root, plan) if record_bytes else expected_catalog
        )
        projection_bytes = _shadow_projection_bytes(
            selected_root, plan, desired_catalog, record_bytes, evidence_bytes, context
        )

        desired_by_target = {}
        for relative, content in record_bytes.items():
            desired_by_target[("record", relative)] = content
        for relative, content in evidence_bytes.items():
            desired_by_target[("evidence", relative)] = content
        for relative, content in projection_bytes.items():
            desired_by_target[("projection", relative)] = content
        desired_by_target[("catalog", ".agent-memory/state/catalog.json")] = desired_catalog

        activations = []
        expected_by_target = {}
        for index, ((kind, relative), desired) in enumerate(desired_by_target.items()):
            target = _relative_target(selected_root, relative)
            if kind in ("record", "evidence"):
                if target.exists() or target.is_symlink():
                    raise PlanInvalidatedError("resolution target became occupied")
                expected = None
            else:
                expected = target.read_bytes() if target.exists() else None
            if kind == "catalog":
                expected = expected_catalog
            stage_relative = ".agent-memory/transactions/{0}/stage/{1:04d}.bin".format(
                context.transaction_id, index
            )
            activations.append(
                _activation_entry(kind, relative, stage_relative, desired, expected)
            )
            expected_by_target[(kind, relative)] = expected

        prepared = _journal_document(
            plan,
            context,
            "prepared",
            activations,
            record_paths,
            evidence_paths,
            projection_paths,
        )
        prepared_bytes = _json_bytes(prepared)
        _publish_exclusive(
            journal_path,
            prepared_bytes,
            _sha256((context.transaction_id + "\0journal").encode("utf-8")),
            root=selected_root,
        )
        _resolution_apply_checkpoint("journal-prepared", journal_path)

        for activation, ((kind, relative), desired) in zip(
            activations, desired_by_target.items()
        ):
            stage_path = _relative_target(selected_root, activation["stage_path"])
            _publish_exclusive(
                stage_path,
                desired,
                _sha256((context.transaction_id + "\0" + activation["stage_path"]).encode("utf-8")),
                root=selected_root,
            )
        staged = dict(prepared)
        staged["status"] = "staged"
        staged_bytes = _json_bytes(staged)
        _replace_cas(
            journal_path,
            prepared_bytes,
            staged_bytes,
            _sha256((context.transaction_id + "\0journal-staged").encode("utf-8")),
            root=selected_root,
        )
        activating = dict(staged)
        activating["status"] = "activating"
        activating_bytes = _json_bytes(activating)
        _replace_cas(
            journal_path,
            staged_bytes,
            activating_bytes,
            _sha256((context.transaction_id + "\0journal-activating").encode("utf-8")),
            root=selected_root,
        )

        catalog_activation = None
        for activation, ((kind, relative), desired) in zip(
            activations, desired_by_target.items()
        ):
            if kind == "catalog":
                catalog_activation = (activation, relative, desired)
                continue
            target = _relative_target(selected_root, relative)
            _resolution_apply_checkpoint("before-{0}-activation".format(kind), target)
            _publish_or_replace(
                selected_root,
                target,
                expected_by_target[(kind, relative)],
                desired,
                _sha256((context.transaction_id + "\0activate\0" + relative).encode("utf-8")),
            )
            _resolution_apply_checkpoint("after-{0}-activation".format(kind), target)

        _, unused_catalog_relative, catalog_desired = catalog_activation
        del unused_catalog_relative
        _resolution_apply_checkpoint("before-catalog-activation", catalog_path)
        if catalog_desired != expected_catalog:
            _replace_cas(
                catalog_path,
                expected_catalog,
                catalog_desired,
                _sha256(
                    (context.transaction_id + "\0activate-catalog").encode("utf-8")
                ),
                root=selected_root,
            )
        _resolution_apply_checkpoint("after-catalog-activation", catalog_path)

        completed = dict(activating)
        completed["status"] = "completed"
        completed_bytes = _json_bytes(completed)
        _replace_cas(
            journal_path,
            activating_bytes,
            completed_bytes,
            _sha256((context.transaction_id + "\0journal-completed").encode("utf-8")),
            root=selected_root,
        )
        if load_catalog(selected_root).revision != plan.predicted_catalog_revision:
            raise PlanInvalidatedError("resolution catalog activation failed")

    return ResolutionResult(
        "applied",
        context.transaction_id,
        plan.resolution_plan_sha256,
        plan.packet_sha256,
        plan.predicted_catalog_revision,
        record_paths,
        evidence_paths,
        projection_paths,
        journal_relative,
    )


def recover_proposal_resolution(
    root: Path,
    gate: AuthorizationGate,
    transaction_id: str,
    context: TransactionContext,
) -> ResolutionResult:
    """Finish only the exact transition sealed by an interrupted journal."""

    selected_root = require_operation_gate(root, gate, "recover-proposal-resolution")
    _validate_context(context)
    if context.transaction_id == transaction_id:
        raise ValidationError("recovery context must be distinct")
    with root_write_guard(selected_root, context):
        journal_path, journal_raw, journal = _load_resolution_journal(
            selected_root, transaction_id
        )
        staged = _staged_bytes(selected_root, journal)
        states = []
        for activation in journal["activations"]:
            state, before = _target_state(selected_root, activation)
            states.append((activation, state, before))

        if journal["status"] == "completed":
            if any(state != "after" for unused, state, before in states):
                raise ValidationError("completed resolution has incomplete targets")
            return _result_from_journal(journal)

        activating = dict(journal)
        activating["status"] = "activating"
        activating_raw = _json_bytes(activating)
        if journal["status"] != "activating":
            _replace_cas(
                journal_path,
                journal_raw,
                activating_raw,
                _sha256((transaction_id + "\0recovery-activating").encode("utf-8")),
                root=selected_root,
            )
        else:
            activating_raw = journal_raw

        for activation, state, before in states:
            if state == "after":
                continue
            target = _relative_target(selected_root, activation["target"])
            desired = staged[activation["target"]]
            _publish_or_replace(
                selected_root,
                target,
                before,
                desired,
                _sha256(
                    (transaction_id + "\0recover\0" + activation["target"]).encode(
                        "utf-8"
                    )
                ),
            )

        completed = dict(activating)
        completed["status"] = "completed"
        completed_raw = _json_bytes(completed)
        _replace_cas(
            journal_path,
            activating_raw,
            completed_raw,
            _sha256((transaction_id + "\0recovery-completed").encode("utf-8")),
            root=selected_root,
        )
        _validate_completed_targets(selected_root, completed)
        return _result_from_journal(completed)


def load_proposal_resolution_result(
    root: Path,
    gate: AuthorizationGate,
    transaction_id: str,
) -> ResolutionResult:
    """Load one completed, digest-verified resolution result without mutation."""

    selected_root = require_operation_gate(root, gate, "read-proposal-resolution")
    unused_path, unused_raw, journal = _load_resolution_journal(
        selected_root, transaction_id
    )
    del unused_path, unused_raw
    if journal["status"] != "completed":
        raise ValidationError("proposal resolution is not completed")
    _validate_completed_targets(selected_root, journal)
    return _result_from_journal(journal)


def _verification_finding(code: str, path: str, message: str) -> Finding:
    return Finding(code, "error", path, message)


def verify_proposal_resolution(
    root: Path,
    gate: AuthorizationGate,
    plan: ResolutionPlan,
    result: ResolutionResult,
) -> ResolutionVerification:
    """Verify journal, catalog, record, evidence, and projection endpoints."""

    selected_root = require_operation_gate(root, gate, "verify-proposal-resolution")
    findings = []
    accepted = tuple(
        action for action in plan.actions if action.record_candidate is not None
    )
    evidence_count = len(plan.resolution_evidence)
    root_revision = -1
    catalog_entries = {}
    if not isinstance(result, ResolutionResult):
        finding = _verification_finding(
            "resolution-result-mismatch",
            ".agent-memory/transactions",
            "resolution result does not match the reviewed plan",
        )
        return ResolutionVerification(
            False, (finding,), len(accepted), evidence_count, root_revision
        )
    if (
        result.resolution_plan_sha256 != plan.resolution_plan_sha256
        or result.packet_sha256 != plan.packet_sha256
        or result.record_paths != tuple(
            sorted(action.relative_path for action in accepted)
        )
        or result.evidence_paths
        != tuple(
            sorted(
                ".agent-memory/transactions/{0}/resolution-evidence/{1}.json".format(
                    result.transaction_id, evidence.proposal_id
                )
                for evidence in plan.resolution_evidence
            )
        )
        or result.projection_paths != tuple(plan.projection_effects)
    ):
        findings.append(
            _verification_finding(
                "resolution-result-mismatch",
                ".agent-memory/transactions",
                "resolution result does not match the reviewed plan",
            )
        )

    journal = None
    try:
        unused_path, unused_raw, journal = _load_resolution_journal(
            selected_root, result.transaction_id
        )
        del unused_path, unused_raw
        if (
            journal["status"] != "completed"
            or journal["resolution_plan_sha256"] != plan.resolution_plan_sha256
            or journal["packet_sha256"] != plan.packet_sha256
        ):
            raise ValidationError("completed journal does not match plan")
        _validate_completed_targets(selected_root, journal)
    except (OSError, ValidationError):
        findings.append(
            _verification_finding(
                "resolution-target-drift",
                result.journal_path,
                "completed resolution endpoints do not match the journal",
            )
        )

    try:
        catalog = load_catalog(selected_root)
        root_revision = catalog.revision
        entries = {entry.memory_id: entry for entry in catalog.entries}
        catalog_entries = entries
        if catalog.revision != plan.predicted_catalog_revision:
            raise ValidationError("catalog revision does not match plan")
        for action in accepted:
            envelope = action.record_candidate.envelope
            entry = entries.get(envelope.memory_id)
            if (
                entry is None
                or entry.relative_path != action.relative_path
                or entry.revision != envelope.revision
                or entry.owner_scope != envelope.owner_scope
                or entry.project != envelope.project
                or entry.record_type != envelope.record_type
            ):
                raise ValidationError("accepted record is not selected by catalog")
    except (OSError, ValidationError):
        findings.append(
            _verification_finding(
                "resolution-catalog-mismatch",
                ".agent-memory/state/catalog.json",
                "accepted catalog does not match the reviewed resolution plan",
            )
        )

    for action in accepted:
        try:
            raw = _plain_bytes(
                _relative_target(selected_root, action.relative_path),
                "accepted resolution record",
            )
            envelope, body = parse_record(raw.decode("utf-8"))
            if (
                envelope != action.record_candidate.envelope
                or body != action.record_candidate.body
            ):
                raise ValidationError("accepted record differs from plan")
            if envelope.record_type == "session":
                relationship = parse_session_relationship(body)
                story_ids = (
                    (() if relationship.primary_story_id is None else (
                        relationship.primary_story_id,
                    ))
                    + relationship.related_story_ids
                )
                for story_id in story_ids:
                    story_entry = catalog_entries.get(story_id)
                    if (
                        story_entry is None
                        or story_entry.record_type != "story"
                        or story_entry.project != envelope.project
                    ):
                        raise ValidationError(
                            "session story relationship is not accepted"
                        )
        except (OSError, UnicodeDecodeError, ValidationError):
            findings.append(
                _verification_finding(
                    "resolution-record-mismatch",
                    action.relative_path,
                    "accepted record does not match the reviewed rewrite",
                )
            )

    try:
        for relative, expected in _evidence_bytes(plan, result.transaction_id).items():
            if _plain_bytes(_relative_target(selected_root, relative), "resolution evidence") != expected:
                raise ValidationError("resolution evidence differs from reviewed plan")
    except (OSError, ValidationError):
        findings.append(_verification_finding(
            "resolution-evidence-mismatch", result.journal_path,
            "resolution outcomes do not match the reviewed plan",
        ))

    # Matching staged bytes is necessary but not sufficient: an old implementation
    # could have sealed a semantically incorrect pending view into the journal.
    try:
        documents = list(build_root_views(selected_root, "proposal-resolution-v1"))
        for project_id in sorted({action.record_candidate.envelope.project for action in accepted
                                  if action.record_candidate.envelope.project is not None}):
            documents.extend(build_project_views(selected_root, project_id, "proposal-resolution-v1"))
        expected_documents = {doc.relative_path: doc.content.encode("utf-8") for doc in documents}
        for relative in plan.projection_effects:
            if _plain_bytes(_relative_target(selected_root, relative), "resolution projection") != expected_documents[relative]:
                raise ValidationError("resolution projection differs from canonical rebuild")
    except (OSError, KeyError, AgentMemoryError):
        findings.append(_verification_finding(
            "resolution-projection-mismatch", "_index/stale-or-uncertain.md",
            "resolution projections do not match disposition-aware canonical state",
        ))

    ordered = tuple(
        sorted(
            findings,
            key=lambda item: (item.severity, item.code, item.path, item.message),
        )
    )
    return ResolutionVerification(
        not ordered,
        ordered,
        len(accepted),
        evidence_count,
        root_revision,
    )
