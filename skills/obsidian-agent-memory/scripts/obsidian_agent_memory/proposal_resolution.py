"""Read-only planning for deterministic proposal resolution transactions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Optional, Tuple

from .artifact_schemas import MigrationReviewProposal, parse_proposal_artifact
from .catalog import load_catalog
from .errors import PlanInvalidatedError, ValidationError
from .migration import MigrationBundle, load_migration_bundle
from .models import Finding, RecordCandidate, RecordEnvelope, TransactionContext
from .operation_scope import AuthorizationGate, require_operation_gate
from .paths import validate_identifier
from .proposal_decisions import ProposalDecisionEnvelope, bind_proposal_decisions
from .proposal_review import ProposalReviewArtifact
from .records import record_relative_path, render_record
from .rewrite_artifacts import bind_rewrite_candidate
from .rewrite_packet import RewritePacket, bind_rewrite_packet
from .runtime_identity import CodeIdentityProof
from .session_relationships import parse_session_relationship


_PLAN_KEYS = frozenset(
    (
        "schema_version",
        "evidence_kind",
        "review_id",
        "report_sha256",
        "decisions_sha256",
        "packet_sha256",
        "bundle_sha256",
        "code_identity_proof_sha256",
        "catalog_revision",
        "root_revision",
        "predicted_catalog_revision",
        "transaction_id",
        "actor",
        "created_at",
        "actions",
        "resolution_evidence",
        "projection_effects",
        "resolution_plan_sha256",
    )
)
_ACTION_KEYS = frozenset(
    (
        "proposal_id",
        "decision_state",
        "outcome",
        "proposal_sha256",
        "snapshot_sha256",
        "record_candidate",
        "relative_path",
        "expected_record_revision",
        "dependencies",
    )
)
_EVIDENCE_KEYS = frozenset(
    (
        "proposal_id",
        "decision_state",
        "outcome",
        "proposal_sha256",
        "snapshot_sha256",
        "report_sha256",
        "decisions_sha256",
        "packet_sha256",
        "rewrite_sha256",
        "memory_id",
    )
)
_ENVELOPE_KEYS = frozenset(
    (
        "memory_id",
        "record_type",
        "schema_version",
        "owner_scope",
        "project",
        "revision",
        "supersedes",
        "created_at",
        "observed_at",
        "source",
        "source_revision",
        "body_sha256",
    )
)
_NO_RECORD_OUTCOMES = {
    "keep-unresolved": "unresolved",
    "sources-only": "source-retained",
    "knowledge-base-candidate": "knowledge-base-candidate",
}


@dataclass(frozen=True)
class ResolutionAction:
    proposal_id: str
    decision_state: str
    outcome: str
    proposal_sha256: str
    snapshot_sha256: str
    record_candidate: Optional[RecordCandidate]
    relative_path: Optional[str]
    expected_record_revision: Optional[int]
    dependencies: Tuple[str, ...]


@dataclass(frozen=True)
class ResolutionEvidence:
    proposal_id: str
    decision_state: str
    outcome: str
    proposal_sha256: str
    snapshot_sha256: str
    report_sha256: str
    decisions_sha256: str
    packet_sha256: str
    rewrite_sha256: Optional[str]
    memory_id: Optional[str]


@dataclass(frozen=True)
class ResolutionPlan:
    review_id: str
    report_sha256: str
    decisions_sha256: str
    packet_sha256: str
    bundle_sha256: str
    code_identity_proof_sha256: str
    catalog_revision: int
    root_revision: int
    predicted_catalog_revision: int
    transaction_id: str
    actor: str
    created_at: str
    actions: Tuple[ResolutionAction, ...]
    resolution_evidence: Tuple[ResolutionEvidence, ...]
    projection_effects: Tuple[str, ...]
    resolution_plan_sha256: str
    raw: bytes


@dataclass(frozen=True)
class ResolutionVerification:
    valid: bool
    findings: Tuple[Finding, ...]
    accepted_count: int
    evidence_count: int
    root_revision: int


def _resolution_plan_checkpoint(stage: str) -> None:
    del stage


def _canonical(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _digest(value, label):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValidationError("invalid {0}".format(label))
    return value


def _portable_path(value, label):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValidationError("invalid {0}".format(label))
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValidationError("invalid {0}".format(label))
    return value


def _validate_context(context):
    if not isinstance(context, TransactionContext):
        raise ValidationError("invalid resolution plan context")
    validate_identifier(context.transaction_id, "transaction_id")
    validate_identifier(context.actor, "actor")
    probe = RecordEnvelope(
        "timestamp-probe",
        "runbook",
        2,
        "agent.runbook",
        None,
        1,
        None,
        context.occurred_at,
        context.occurred_at,
        "proposal-resolution",
        "plan",
        "0" * 64,
    )
    record_relative_path(probe)


def _contained_bytes(root, relative, expected_sha256, label):
    normalized = _portable_path(relative, label)
    target = root.joinpath(*PurePosixPath(normalized).parts)
    try:
        resolved = target.resolve(strict=True)
        resolved.relative_to(root)
        raw = resolved.read_bytes()
    except (OSError, ValueError, RuntimeError) as error:
        raise ValidationError("invalid {0}".format(label)) from error
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValidationError("{0} hash mismatch".format(label))
    return raw


@dataclass(frozen=True)
class _CapturedInputs:
    catalog: object
    proposal_artifacts: Mapping[str, MigrationReviewProposal]
    snapshot_bytes: Mapping[str, bytes]
    packet_sha256: str
    bundle_sha256: str
    revision: str


def _capture_inputs(root, report, decisions, packet, bundle, proof):
    bind_proposal_decisions(decisions, report)
    current_packet = bind_rewrite_packet(packet, report, decisions, proof.identity)
    if not isinstance(bundle, MigrationBundle):
        raise ValidationError("invalid migration bundle")
    current_bundle = load_migration_bundle(bundle.bundle_dir)
    if current_bundle.bundle_sha256 != bundle.bundle_sha256:
        raise PlanInvalidatedError("migration bundle changed")
    report_bundle = report.document.get("inputs", {}).get("bundle", {})
    if report_bundle.get("sha256") != current_bundle.bundle_sha256:
        raise ValidationError("proposal report does not match migration bundle")
    items = report.document.get("items")
    if not isinstance(items, list):
        raise ValidationError("invalid proposal review items")
    proposal_artifacts = {}
    snapshot_bytes = {}
    revision_material = []
    for item in items:
        if not isinstance(item, dict):
            raise ValidationError("invalid proposal review item")
        proposal_id = item.get("proposal_id")
        proposal_path = item.get("proposal_path")
        proposal_sha256 = _digest(item.get("proposal_sha256"), "proposal_sha256")
        proposal_raw = _contained_bytes(
            root, proposal_path, proposal_sha256, "proposal"
        )
        artifact = parse_proposal_artifact(proposal_path, proposal_raw)
        if not isinstance(artifact, MigrationReviewProposal) or artifact.proposal_id != proposal_id:
            raise ValidationError("proposal report item does not match proposal")
        snapshot_sha256 = _digest(item.get("snapshot_sha256"), "snapshot_sha256")
        snapshot_raw = _contained_bytes(
            current_bundle.bundle_dir,
            item.get("snapshot_path"),
            snapshot_sha256,
            "snapshot",
        )
        proposal_artifacts[proposal_id] = artifact
        snapshot_bytes[proposal_id] = snapshot_raw
        revision_material.append((proposal_id, proposal_sha256, snapshot_sha256))
    catalog = load_catalog(root)
    revision = hashlib.sha256(
        _canonical(
            {
                "bundle_sha256": current_bundle.bundle_sha256,
                "catalog_revision": catalog.revision,
                "packet_sha256": current_packet.packet_sha256,
                "sources": revision_material,
            }
        )
    ).hexdigest()
    return _CapturedInputs(
        catalog,
        proposal_artifacts,
        snapshot_bytes,
        current_packet.packet_sha256,
        current_bundle.bundle_sha256,
        revision,
    )


def _record_candidate(rewrite, artifact, created_at):
    envelope = RecordEnvelope(
        memory_id=rewrite.memory_id,
        record_type=rewrite.record_type,
        schema_version=2,
        owner_scope=rewrite.owner_scope,
        project=rewrite.project_id,
        revision=1,
        supersedes=None,
        created_at=created_at,
        observed_at=artifact.occurred_at,
        source="migration-snapshot",
        source_revision=rewrite.snapshot_sha256,
        body_sha256=rewrite.body_sha256,
    )
    render_record(envelope, rewrite.body)
    return RecordCandidate(envelope, rewrite.body)


def _ordered_actions(actions, existing_entries):
    action_by_memory = {
        action.record_candidate.envelope.memory_id: action
        for action in actions
        if action.record_candidate is not None
    }
    entry_by_memory = {entry.memory_id: entry for entry in existing_entries}
    dependency_map = {}
    updated = []
    for action in actions:
        dependencies = ()
        if (
            action.record_candidate is not None
            and action.record_candidate.envelope.record_type == "session"
        ):
            session = action.record_candidate
            relationship = parse_session_relationship(session.body)
            story_ids = (() if relationship.primary_story_id is None else (relationship.primary_story_id,)) + relationship.related_story_ids
            selected = []
            for story_id in story_ids:
                planned = action_by_memory.get(story_id)
                existing = entry_by_memory.get(story_id)
                if planned is not None:
                    envelope = planned.record_candidate.envelope
                    if envelope.record_type != "story" or envelope.project != session.envelope.project:
                        raise ValidationError("Session references a cross-project or non-Story plan")
                    selected.append(planned.proposal_id)
                elif existing is None or existing.record_type != "story" or existing.project != session.envelope.project:
                    raise ValidationError("Session references a missing or cross-project Story")
            dependencies = tuple(sorted(selected))
        dependency_map[action.proposal_id] = set(dependencies)
        updated.append(
            ResolutionAction(
                action.proposal_id,
                action.decision_state,
                action.outcome,
                action.proposal_sha256,
                action.snapshot_sha256,
                action.record_candidate,
                action.relative_path,
                action.expected_record_revision,
                dependencies,
            )
        )
    pending = {action.proposal_id: action for action in updated}
    ordered = []
    while pending:
        ready = sorted(
            proposal_id
            for proposal_id in pending
            if not (dependency_map[proposal_id] & set(pending))
        )
        if not ready:
            raise ValidationError("cyclic Story-Session resolution dependency")
        for proposal_id in ready:
            ordered.append(pending.pop(proposal_id))
    return tuple(ordered)


def _action_document(action):
    candidate = None
    if action.record_candidate is not None:
        candidate = {
            "envelope": asdict(action.record_candidate.envelope),
            "body": action.record_candidate.body,
        }
    return {
        "proposal_id": action.proposal_id,
        "decision_state": action.decision_state,
        "outcome": action.outcome,
        "proposal_sha256": action.proposal_sha256,
        "snapshot_sha256": action.snapshot_sha256,
        "record_candidate": candidate,
        "relative_path": action.relative_path,
        "expected_record_revision": action.expected_record_revision,
        "dependencies": list(action.dependencies),
    }


def _evidence_document(evidence):
    return asdict(evidence)


def plan_proposal_resolution(
    root: Path,
    gate: AuthorizationGate,
    report: ProposalReviewArtifact,
    decisions: ProposalDecisionEnvelope,
    packet: RewritePacket,
    bundle: MigrationBundle,
    context: TransactionContext,
    code_identity_proof: CodeIdentityProof,
) -> ResolutionPlan:
    """Build a complete read-only plan from reviewed fixture inputs."""

    selected_root = require_operation_gate(root, gate, "plan-proposal-resolution")
    _validate_context(context)
    if not isinstance(code_identity_proof, CodeIdentityProof):
        raise ValidationError("invalid code identity proof")
    _digest(code_identity_proof.proof_sha256, "code identity proof")
    first = _capture_inputs(
        selected_root, report, decisions, packet, bundle, code_identity_proof
    )
    _resolution_plan_checkpoint("before-recapture")
    second = _capture_inputs(
        selected_root, report, decisions, packet, bundle, code_identity_proof
    )
    if first.revision != second.revision or first.catalog != second.catalog:
        raise PlanInvalidatedError("proposal resolution inputs changed during planning")

    report_by_id = {item["proposal_id"]: item for item in report.document["items"]}
    rewrite_by_id = {item.proposal_id: item for item in packet.rewrites}
    catalog_ids = {entry.memory_id for entry in second.catalog.entries}
    target_paths = set()
    actions = []
    evidence = []
    for decision in decisions.decisions:
        item = report_by_id[decision.proposal_id]
        rewrite = rewrite_by_id.get(decision.proposal_id)
        candidate = None
        relative_path = None
        rewrite_sha256 = None
        memory_id = None
        if decision.state in ("confirm-candidate", "change-owner"):
            if rewrite is None:
                raise ValidationError("accepted decision lacks rewrite")
            bind_rewrite_candidate(
                rewrite,
                decision,
                item,
                second.snapshot_bytes[decision.proposal_id],
            )
            candidate = _record_candidate(
                rewrite,
                second.proposal_artifacts[decision.proposal_id],
                context.occurred_at,
            )
            memory_id = candidate.envelope.memory_id
            if memory_id in catalog_ids:
                raise ValidationError("proposal resolution target is already occupied")
            relative_path = record_relative_path(candidate.envelope).as_posix()
            if relative_path in target_paths:
                raise ValidationError("proposal resolution target path collides")
            target_paths.add(relative_path)
            outcome = "accepted-record"
            rewrite_sha256 = rewrite.rewrite_sha256
        else:
            outcome = _NO_RECORD_OUTCOMES[decision.state]
        actions.append(
            ResolutionAction(
                decision.proposal_id,
                decision.state,
                outcome,
                item["proposal_sha256"],
                item["snapshot_sha256"],
                candidate,
                relative_path,
                None,
                (),
            )
        )
        evidence.append(
            ResolutionEvidence(
                decision.proposal_id,
                decision.state,
                outcome,
                item["proposal_sha256"],
                item["snapshot_sha256"],
                report.report_sha256,
                decisions.decisions_sha256,
                packet.packet_sha256,
                rewrite_sha256,
                memory_id,
            )
        )
    ordered_actions = _ordered_actions(actions, second.catalog.entries)
    accepted_actions = tuple(
        action for action in ordered_actions if action.record_candidate is not None
    )
    # Dispositions change pending state even when no canonical record is added.
    projection_paths = {"_index/stale-or-uncertain.md"}
    if accepted_actions:
        projection_paths.update(
            (
                "_index/current-focus.md",
                "_index/home.md",
                "_index/memory-map.md",
                "_index/stale-or-uncertain.md",
            )
        )
    for project_id in sorted(
        {
            action.record_candidate.envelope.project
            for action in accepted_actions
            if action.record_candidate.envelope.project is not None
        }
    ):
        projection_paths.add("projects/{0}/current-focus.md".format(project_id))
        projection_paths.add("projects/{0}/overview.md".format(project_id))
    for action in accepted_actions:
        envelope = action.record_candidate.envelope
        if envelope.record_type == "story":
            projection_paths.add(
                "projects/{0}/stories/{1}.md".format(
                    envelope.project, envelope.memory_id
                )
            )
    projection_effects = tuple(sorted(projection_paths))
    core = {
        "schema_version": 1,
        "evidence_kind": "proposal-resolution-plan",
        "review_id": report.review_id,
        "report_sha256": report.report_sha256,
        "decisions_sha256": decisions.decisions_sha256,
        "packet_sha256": packet.packet_sha256,
        "bundle_sha256": second.bundle_sha256,
        "code_identity_proof_sha256": code_identity_proof.proof_sha256,
        "catalog_revision": second.catalog.revision,
        "root_revision": second.catalog.revision,
        "predicted_catalog_revision": second.catalog.revision + (1 if rewrite_by_id else 0),
        "transaction_id": context.transaction_id,
        "actor": context.actor,
        "created_at": context.occurred_at,
        "actions": [_action_document(action) for action in ordered_actions],
        "resolution_evidence": [
            _evidence_document(item) for item in sorted(evidence, key=lambda value: value.proposal_id)
        ],
        "projection_effects": list(projection_effects),
    }
    resolution_plan_sha256 = hashlib.sha256(
        b"proposal-resolution-plan-v1\n" + _canonical(core)
    ).hexdigest()
    document = dict(core)
    document["resolution_plan_sha256"] = resolution_plan_sha256
    raw = _canonical(document)
    return _plan_from_document(document, raw)


def _reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("duplicate resolution plan key")
        value[key] = item
    return value


def _record_candidate_from_value(value):
    if not isinstance(value, dict) or set(value) != {"envelope", "body"}:
        raise ValidationError("invalid resolution record candidate")
    envelope_value = value["envelope"]
    if not isinstance(envelope_value, dict) or frozenset(envelope_value) != _ENVELOPE_KEYS:
        raise ValidationError("invalid resolution record envelope")
    try:
        envelope = RecordEnvelope(**envelope_value)
    except TypeError as error:
        raise ValidationError("invalid resolution record envelope") from error
    body = value["body"]
    render_record(envelope, body)
    return RecordCandidate(envelope, body)


def _plan_from_document(document, raw):
    if not isinstance(document, dict) or frozenset(document) != _PLAN_KEYS:
        raise ValidationError("invalid resolution plan")
    if document["schema_version"] != 1 or document["evidence_kind"] != "proposal-resolution-plan":
        raise ValidationError("unsupported resolution plan")
    core = dict(document)
    digest = _digest(core.pop("resolution_plan_sha256"), "resolution_plan_sha256")
    if hashlib.sha256(b"proposal-resolution-plan-v1\n" + _canonical(core)).hexdigest() != digest:
        raise ValidationError("resolution plan digest mismatch")
    actions = []
    for value in document["actions"]:
        if not isinstance(value, dict) or frozenset(value) != _ACTION_KEYS:
            raise ValidationError("invalid resolution action")
        candidate = None if value["record_candidate"] is None else _record_candidate_from_value(value["record_candidate"])
        dependencies = value["dependencies"]
        if not isinstance(dependencies, list) or dependencies != sorted(set(dependencies)):
            raise ValidationError("invalid resolution dependencies")
        actions.append(
            ResolutionAction(
                value["proposal_id"],
                value["decision_state"],
                value["outcome"],
                _digest(value["proposal_sha256"], "proposal_sha256"),
                _digest(value["snapshot_sha256"], "snapshot_sha256"),
                candidate,
                value["relative_path"],
                value["expected_record_revision"],
                tuple(dependencies),
            )
        )
    action_ids = tuple(action.proposal_id for action in actions)
    if len(action_ids) != len(set(action_ids)):
        raise ValidationError("duplicate resolution action")
    action_positions = {proposal_id: index for index, proposal_id in enumerate(action_ids)}
    for index, action in enumerate(actions):
        validate_identifier(action.proposal_id, "resolution proposal_id")
        accepted = action.decision_state in ("confirm-candidate", "change-owner")
        if accepted:
            if (
                action.outcome != "accepted-record"
                or action.record_candidate is None
                or action.relative_path
                != record_relative_path(action.record_candidate.envelope).as_posix()
                or action.expected_record_revision is not None
            ):
                raise ValidationError("accepted resolution action is inconsistent")
        else:
            if (
                _NO_RECORD_OUTCOMES.get(action.decision_state) != action.outcome
                or action.record_candidate is not None
                or action.relative_path is not None
                or action.expected_record_revision is not None
                or action.dependencies
            ):
                raise ValidationError("no-record resolution action is inconsistent")
        if any(
            dependency not in action_positions
            or action_positions[dependency] >= index
            or dependency == action.proposal_id
            for dependency in action.dependencies
        ):
            raise ValidationError("resolution dependency order is invalid")
    evidence = []
    for value in document["resolution_evidence"]:
        if not isinstance(value, dict) or frozenset(value) != _EVIDENCE_KEYS:
            raise ValidationError("invalid resolution evidence")
        evidence.append(ResolutionEvidence(**value))
    evidence_ids = tuple(item.proposal_id for item in evidence)
    if evidence_ids != tuple(sorted(action_ids)) or len(evidence_ids) != len(set(evidence_ids)):
        raise ValidationError("resolution evidence does not cover actions exactly")
    action_by_id = {action.proposal_id: action for action in actions}
    for item in evidence:
        action = action_by_id[item.proposal_id]
        accepted = action.record_candidate is not None
        if (
            item.decision_state != action.decision_state
            or item.outcome != action.outcome
            or item.proposal_sha256 != action.proposal_sha256
            or item.snapshot_sha256 != action.snapshot_sha256
            or item.report_sha256 != document["report_sha256"]
            or item.decisions_sha256 != document["decisions_sha256"]
            or item.packet_sha256 != document["packet_sha256"]
        ):
            raise ValidationError("resolution evidence is inconsistent")
        _digest(item.proposal_sha256, "proposal_sha256")
        _digest(item.snapshot_sha256, "snapshot_sha256")
        if accepted:
            if (
                item.rewrite_sha256 is None
                or item.memory_id != action.record_candidate.envelope.memory_id
            ):
                raise ValidationError("accepted resolution evidence is incomplete")
            _digest(item.rewrite_sha256, "rewrite_sha256")
        elif item.rewrite_sha256 is not None or item.memory_id is not None:
            raise ValidationError("no-record resolution evidence names a record")
    effects = document["projection_effects"]
    if not isinstance(effects, list) or effects != sorted(set(effects)):
        raise ValidationError("invalid resolution projection effects")
    for field in ("catalog_revision", "root_revision", "predicted_catalog_revision"):
        if type(document[field]) is not int or document[field] < 0:
            raise ValidationError("invalid resolution plan revision")
    accepted_count = sum(action.record_candidate is not None for action in actions)
    if (
        document["catalog_revision"] != document["root_revision"]
        or document["predicted_catalog_revision"]
        != document["catalog_revision"] + (1 if accepted_count else 0)
    ):
        raise ValidationError("resolution plan revisions are inconsistent")
    return ResolutionPlan(
        document["review_id"],
        _digest(document["report_sha256"], "report_sha256"),
        _digest(document["decisions_sha256"], "decisions_sha256"),
        _digest(document["packet_sha256"], "packet_sha256"),
        _digest(document["bundle_sha256"], "bundle_sha256"),
        _digest(document["code_identity_proof_sha256"], "code identity proof"),
        document["catalog_revision"],
        document["root_revision"],
        document["predicted_catalog_revision"],
        document["transaction_id"],
        document["actor"],
        document["created_at"],
        tuple(actions),
        tuple(evidence),
        tuple(effects),
        digest,
        raw,
    )


def _parse_resolution_plan_bytes(raw: bytes) -> ResolutionPlan:
    try:
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("invalid resolution plan JSON") from error
    if _canonical(document) != raw:
        raise ValidationError("resolution plan is not canonical JSON")
    return _plan_from_document(document, raw)


def load_resolution_plan(path: Path) -> ResolutionPlan:
    """Load one canonical external resolution plan and verify its digest."""

    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise ValidationError("invalid resolution plan JSON") from error
    return _parse_resolution_plan_bytes(raw)


def bind_resolution_plan(
    plan: ResolutionPlan,
    root: Path,
    gate: AuthorizationGate,
    report: ProposalReviewArtifact,
    decisions: ProposalDecisionEnvelope,
    packet: RewritePacket,
    bundle: MigrationBundle,
    code_identity_proof: CodeIdentityProof,
) -> ResolutionPlan:
    """Rebuild and compare a plan against freshly captured selected inputs."""

    if not isinstance(plan, ResolutionPlan):
        raise ValidationError("invalid resolution plan")
    context = TransactionContext(plan.transaction_id, plan.actor, plan.created_at)
    current = plan_proposal_resolution(
        root,
        gate,
        report,
        decisions,
        packet,
        bundle,
        context,
        code_identity_proof,
    )
    if current.raw != plan.raw:
        raise PlanInvalidatedError("proposal resolution plan no longer matches inputs")
    return current
