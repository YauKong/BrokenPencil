"""Deterministic sealing and binding for reviewed semantic rewrite packets."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, Tuple

from .errors import ConflictError, ValidationError
from .proposal_decisions import (
    ProposalDecisionEnvelope,
    _source_stable_memory_id,
    bind_proposal_decisions,
)
from .proposal_review import ProposalReviewArtifact
from .rewrite_artifacts import (
    RewriteCandidateArtifact,
    SemanticReviewArtifact,
    load_rewrite_candidate,
    load_semantic_review,
)
from .runtime_identity import CodeIdentity


_MANIFEST_KEYS = frozenset(
    (
        "schema_version",
        "evidence_kind",
        "review_id",
        "report_sha256",
        "decisions_sha256",
        "code_identity",
        "decision_state_counts",
        "accepted_count",
        "items",
        "packet_sha256",
    )
)
_ITEM_KEYS = frozenset(
    (
        "proposal_id",
        "proposal_sha256",
        "snapshot_sha256",
        "rewrite_path",
        "rewrite_sha256",
        "semantic_review_path",
        "semantic_review_sha256",
    )
)
_STATES = (
    "change-owner",
    "confirm-candidate",
    "keep-unresolved",
    "knowledge-base-candidate",
    "sources-only",
)
_ACCEPTED_STATES = frozenset(("confirm-candidate", "change-owner"))


@dataclass(frozen=True)
class RewritePacketItem:
    proposal_id: str
    proposal_sha256: str
    snapshot_sha256: str
    rewrite_path: str
    rewrite_sha256: str
    semantic_review_path: str
    semantic_review_sha256: str


@dataclass(frozen=True)
class RewritePacket:
    root: Path
    review_id: str
    report_sha256: str
    decisions_sha256: str
    code_identity: Mapping[str, object]
    decision_state_counts: Tuple[Tuple[str, int], ...]
    accepted_count: int
    items: Tuple[RewritePacketItem, ...]
    rewrites: Tuple[RewriteCandidateArtifact, ...]
    semantic_reviews: Tuple[SemanticReviewArtifact, ...]
    packet_sha256: str
    manifest_raw: bytes


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


def _packet_digest(core_manifest) -> str:
    return hashlib.sha256(
        b"proposal-resolution-rewrite-packet-v1\n" + _canonical(core_manifest)
    ).hexdigest()


def _unique_by_proposal(values: Sequence[object], label: str):
    selected = {}
    for value in values:
        proposal_id = getattr(value, "proposal_id", None)
        if not isinstance(proposal_id, str) or proposal_id in selected:
            raise ValidationError("duplicate or invalid {0}".format(label))
        selected[proposal_id] = value
    return selected


def _report_items(report):
    items = report.document.get("items")
    if not isinstance(items, list):
        raise ValidationError("invalid proposal review items")
    selected = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("proposal_id"), str):
            raise ValidationError("invalid proposal review item")
        if item["proposal_id"] in selected:
            raise ValidationError("duplicate proposal review item")
        _digest(item.get("proposal_sha256"), "proposal_sha256")
        _digest(item.get("snapshot_sha256"), "snapshot_sha256")
        selected[item["proposal_id"]] = item
    return selected


def _identity_document(identity):
    if not isinstance(identity, CodeIdentity) or not isinstance(identity.document, Mapping):
        raise ValidationError("invalid code identity")
    try:
        raw = _canonical(identity.document)
        value = json.loads(raw.decode("utf-8"))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValidationError("invalid code identity") from error
    if not isinstance(value, dict):
        raise ValidationError("invalid code identity")
    return value


def _manifest_core(
    report,
    decisions,
    code_identity,
    counts,
    items,
):
    return {
        "schema_version": 1,
        "evidence_kind": "proposal-resolution-rewrite-packet",
        "review_id": report.review_id,
        "report_sha256": report.report_sha256,
        "decisions_sha256": decisions.decisions_sha256,
        "code_identity": code_identity,
        "decision_state_counts": dict(counts),
        "accepted_count": len(items),
        "items": items,
    }


def seal_rewrite_packet(
    output_root: Path,
    report: ProposalReviewArtifact,
    decisions: ProposalDecisionEnvelope,
    rewrites: Sequence[RewriteCandidateArtifact],
    reviews: Sequence[SemanticReviewArtifact],
    code_identity: CodeIdentity,
) -> RewritePacket:
    """Publish one complete immutable packet into a previously absent directory."""

    bind_proposal_decisions(decisions, report)
    output = Path(output_root)
    if output.exists() or output.is_symlink():
        raise ConflictError("rewrite packet destination is occupied")
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)

    report_by_id = _report_items(report)
    decision_by_id = {item.proposal_id: item for item in decisions.decisions}
    accepted_ids = {
        proposal_id
        for proposal_id, decision in decision_by_id.items()
        if decision.state in _ACCEPTED_STATES
    }
    rewrite_by_id = _unique_by_proposal(tuple(rewrites), "rewrite candidate")
    review_by_id = _unique_by_proposal(tuple(reviews), "semantic review")
    if set(rewrite_by_id) != accepted_ids or set(review_by_id) != accepted_ids:
        raise ValidationError("rewrite packet does not cover accepted decisions exactly")

    manifest_items = []
    for proposal_id in sorted(accepted_ids):
        candidate = rewrite_by_id[proposal_id]
        review = review_by_id[proposal_id]
        decision = decision_by_id[proposal_id]
        report_item = report_by_id[proposal_id]
        if (
            not isinstance(candidate, RewriteCandidateArtifact)
            or candidate.review_id != report.review_id
            or candidate.report_sha256 != report.report_sha256
            or candidate.decisions_sha256 != decisions.decisions_sha256
            or candidate.decision_state != decision.state
            or candidate.owner_scope != decision.owner_scope
            or candidate.project_id != decision.project_id
            or candidate.memory_id != _source_stable_memory_id(report_item)
            or candidate.proposal_sha256 != report_item["proposal_sha256"]
            or candidate.snapshot_sha256 != report_item["snapshot_sha256"]
        ):
            raise ValidationError("rewrite candidate is not bound to reviewed inputs")
        if (
            not isinstance(review, SemanticReviewArtifact)
            or not review.passed
            or review.rewrite_sha256 != candidate.rewrite_sha256
        ):
            raise ValidationError("rewrite candidate lacks a passing independent review")
        manifest_items.append(
            {
                "proposal_id": proposal_id,
                "proposal_sha256": candidate.proposal_sha256,
                "snapshot_sha256": candidate.snapshot_sha256,
                "rewrite_path": "rewrites/{0}.json".format(proposal_id),
                "rewrite_sha256": candidate.rewrite_sha256,
                "semantic_review_path": "semantic-review/{0}.json".format(proposal_id),
                "semantic_review_sha256": review.semantic_review_sha256,
            }
        )

    observed_counts = Counter(item.state for item in decisions.decisions)
    counts = tuple((state, observed_counts[state]) for state in _STATES)
    identity_document = _identity_document(code_identity)
    core = _manifest_core(
        report,
        decisions,
        identity_document,
        counts,
        manifest_items,
    )
    manifest = dict(core)
    manifest["packet_sha256"] = _packet_digest(core)
    manifest_raw = _canonical(manifest)

    stage = Path(tempfile.mkdtemp(prefix=".rewrite-packet-", dir=str(parent)))
    try:
        (stage / "rewrites").mkdir()
        (stage / "semantic-review").mkdir()
        for proposal_id in sorted(accepted_ids):
            (stage / "rewrites" / (proposal_id + ".json")).write_bytes(
                rewrite_by_id[proposal_id].raw
            )
            (stage / "semantic-review" / (proposal_id + ".json")).write_bytes(
                review_by_id[proposal_id].raw
            )
        (stage / "manifest.json").write_bytes(manifest_raw)
        try:
            os.rename(stage, output)
        except FileExistsError as error:
            raise ConflictError("rewrite packet destination is occupied") from error
        except OSError as error:
            if output.exists():
                raise ConflictError("rewrite packet destination is occupied") from error
            raise ValidationError("rewrite packet publication failed") from error
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return load_rewrite_packet(output)


def _load_manifest(path):
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("invalid rewrite packet manifest") from error
    if _canonical(value) != raw or not isinstance(value, dict) or frozenset(value) != _MANIFEST_KEYS:
        raise ValidationError("invalid rewrite packet manifest")
    return raw, value


def load_rewrite_packet(path: Path) -> RewritePacket:
    """Reload and verify a sealed packet's complete on-disk inventory."""

    root = Path(path)
    if not root.is_dir() or root.is_symlink():
        raise ValidationError("invalid rewrite packet root")
    manifest_raw, manifest = _load_manifest(root / "manifest.json")
    if manifest["schema_version"] != 1 or manifest["evidence_kind"] != "proposal-resolution-rewrite-packet":
        raise ValidationError("unsupported rewrite packet")
    core = dict(manifest)
    packet_sha256 = _digest(core.pop("packet_sha256"), "packet_sha256")
    if _packet_digest(core) != packet_sha256:
        raise ValidationError("rewrite packet digest mismatch")
    counts_value = manifest["decision_state_counts"]
    if (
        not isinstance(counts_value, dict)
        or tuple(sorted(counts_value)) != _STATES
        or any(type(value) is not int or value < 0 for value in counts_value.values())
        or sum(counts_value.values()) < 1
    ):
        raise ValidationError("invalid rewrite packet decision counts")
    accepted_count = manifest["accepted_count"]
    if type(accepted_count) is not int or accepted_count < 0:
        raise ValidationError("invalid rewrite packet accepted count")
    if accepted_count != (
        counts_value["confirm-candidate"] + counts_value["change-owner"]
    ):
        raise ValidationError("rewrite packet accepted count is inconsistent")
    raw_items = manifest["items"]
    if not isinstance(raw_items, list) or len(raw_items) != accepted_count:
        raise ValidationError("invalid rewrite packet items")
    items = []
    rewrites = []
    reviews = []
    proposal_ids = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or frozenset(raw_item) != _ITEM_KEYS:
            raise ValidationError("invalid rewrite packet item")
        proposal_id = raw_item["proposal_id"]
        if not isinstance(proposal_id, str):
            raise ValidationError("invalid rewrite packet proposal_id")
        proposal_ids.append(proposal_id)
        expected_rewrite_path = "rewrites/{0}.json".format(proposal_id)
        expected_review_path = "semantic-review/{0}.json".format(proposal_id)
        if (
            raw_item["rewrite_path"] != expected_rewrite_path
            or raw_item["semantic_review_path"] != expected_review_path
        ):
            raise ValidationError("invalid rewrite packet artifact path")
        candidate = load_rewrite_candidate(root / Path(*expected_rewrite_path.split("/")))
        review = load_semantic_review(root / Path(*expected_review_path.split("/")))
        if (
            _digest(raw_item["proposal_sha256"], "proposal_sha256") != candidate.proposal_sha256
            or _digest(raw_item["snapshot_sha256"], "snapshot_sha256") != candidate.snapshot_sha256
            or _digest(raw_item["rewrite_sha256"], "rewrite_sha256") != candidate.rewrite_sha256
            or _digest(raw_item["semantic_review_sha256"], "semantic_review_sha256")
            != review.semantic_review_sha256
            or review.proposal_id != proposal_id
            or review.rewrite_sha256 != candidate.rewrite_sha256
            or not review.passed
        ):
            raise ValidationError("rewrite packet artifact binding failed")
        items.append(RewritePacketItem(**raw_item))
        rewrites.append(candidate)
        reviews.append(review)
    if proposal_ids != sorted(proposal_ids) or len(proposal_ids) != len(set(proposal_ids)):
        raise ValidationError("rewrite packet items must be unique and sorted")
    expected_root_names = {"manifest.json", "rewrites", "semantic-review"}
    if {item.name for item in root.iterdir()} != expected_root_names:
        raise ValidationError("unexpected rewrite packet root inventory")
    expected_files = {proposal_id + ".json" for proposal_id in proposal_ids}
    for directory_name in ("rewrites", "semantic-review"):
        directory = root / directory_name
        if not directory.is_dir() or directory.is_symlink():
            raise ValidationError("invalid rewrite packet directory")
        if {item.name for item in directory.iterdir()} != expected_files:
            raise ValidationError("unexpected rewrite packet artifact inventory")
    return RewritePacket(
        root.resolve(),
        manifest["review_id"],
        _digest(manifest["report_sha256"], "report_sha256"),
        _digest(manifest["decisions_sha256"], "decisions_sha256"),
        manifest["code_identity"],
        tuple(sorted(counts_value.items())),
        accepted_count,
        tuple(items),
        tuple(rewrites),
        tuple(reviews),
        packet_sha256,
        manifest_raw,
    )


def bind_rewrite_packet(
    packet: RewritePacket,
    report: ProposalReviewArtifact,
    decisions: ProposalDecisionEnvelope,
    code_identity: CodeIdentity,
) -> RewritePacket:
    """Recapture and bind a sealed packet to its reviewed decision inputs."""

    if not isinstance(packet, RewritePacket):
        raise ValidationError("invalid rewrite packet")
    current = load_rewrite_packet(packet.root)
    if current.packet_sha256 != packet.packet_sha256 or current.manifest_raw != packet.manifest_raw:
        raise ValidationError("rewrite packet changed after load")
    bind_proposal_decisions(decisions, report)
    observed_counts = Counter(item.state for item in decisions.decisions)
    expected_counts = tuple((state, observed_counts[state]) for state in _STATES)
    if (
        current.review_id != report.review_id
        or current.report_sha256 != report.report_sha256
        or current.decisions_sha256 != decisions.decisions_sha256
        or current.code_identity != _identity_document(code_identity)
        or current.decision_state_counts != expected_counts
    ):
        raise ValidationError("rewrite packet does not match reviewed inputs")
    report_by_id = _report_items(report)
    accepted = {
        item.proposal_id: item
        for item in decisions.decisions
        if item.state in _ACCEPTED_STATES
    }
    if {item.proposal_id for item in current.items} != set(accepted):
        raise ValidationError("rewrite packet accepted inventory drifted")
    for item, candidate in zip(current.items, current.rewrites):
        report_item = report_by_id[item.proposal_id]
        decision = accepted[item.proposal_id]
        if (
            item.proposal_sha256 != report_item["proposal_sha256"]
            or item.snapshot_sha256 != report_item["snapshot_sha256"]
            or candidate.decision_state != decision.state
            or candidate.owner_scope != decision.owner_scope
            or candidate.project_id != decision.project_id
            or candidate.memory_id != _source_stable_memory_id(report_item)
        ):
            raise ValidationError("rewrite packet item drifted from reviewed inputs")
    return current
