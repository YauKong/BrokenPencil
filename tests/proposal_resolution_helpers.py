import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

from tests.helpers import tree_hashes
from tests.unit.test_artifact_schemas import _applied_golden_migration

from obsidian_agent_memory.artifact_schemas import parse_proposal_artifact
from obsidian_agent_memory.proposal_decisions import (
    bind_proposal_decisions,
    load_proposal_decisions,
)
from obsidian_agent_memory.proposal_review import (
    build_proposal_review_artifact,
    build_review_model,
    review_inputs_for_bundle,
)
from obsidian_agent_memory.rewrite_artifacts import (
    load_rewrite_candidate,
    load_semantic_review,
)
from obsidian_agent_memory.rewrite_packet import seal_rewrite_packet
from obsidian_agent_memory.runtime_identity import CodeIdentity, CodeIdentityProof


@dataclass(frozen=True)
class ResolutionFixture:
    root: Path
    bundle: object
    report: object
    decisions: object
    packet: object
    identity: CodeIdentity
    identity_proof: CodeIdentityProof
    before_tree: tuple


def _canonical(value):
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _report_for_applied(root, bundle, result):
    artifacts = tuple(
        parse_proposal_artifact(path, (root / path).read_bytes())
        for path in result.proposal_paths
    )
    model = build_review_model(
        bundle.bundle_sha256,
        bundle.plan.source_revision,
        review_inputs_for_bundle(bundle, artifacts),
    )
    journal_path = next((root / ".agent-memory" / "transactions").glob("*/journal.json"))
    catalog_path = root / ".agent-memory" / "state" / "catalog.json"
    catalog = json.loads(catalog_path.read_text("utf-8"))
    return build_proposal_review_artifact(
        model=model,
        code_identity={"kind": "fixture", "revision": "proposal-resolution-fixture-v1"},
        apply_journal={
            "path": journal_path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(journal_path.read_bytes()).hexdigest(),
            "transaction_id": journal_path.parent.name,
        },
        bundle={
            "plan_id": bundle.plan.plan_id,
            "sha256": bundle.bundle_sha256,
            "source_revision": bundle.plan.source_revision,
        },
        catalog={
            "revision": catalog["revision"],
            "sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
        },
        run_context={
            "actor": "fixture-agent",
            "authorization_ref": None,
            "observed_at": "2026-09-04T00:00:00Z",
            "scope": "fixture",
        },
    )


def _body(record_type, primary_story_id=None):
    if record_type == "session":
        return (
            "# Session: Golden cache investigation reached a bounded outcome\n\n"
            "## Session Relationship\n"
            "session_status: completed\n"
            "primary_story_id: {0}\n"
            "related_story_id: none\n\n"
            "## User Goal\n\nVerify the golden cache behavior.\n\n"
            "## Outcome\n\nThe reviewed fixture preserves the bounded result.\n\n"
            "## Work Done\n\n- Inspected the immutable snapshot.\n\n"
            "## Decisions Observed\n\nnone\n\n"
            "## Commands Verified\n\nnone\n\n"
            "## Files Changed\n\nnone\n\n"
            "## Promotion Candidates\n\nnone\n\n"
            "## Follow-Ups\n\nnone\n"
        ).format(primary_story_id or "none")
    if record_type == "story":
        return (
            "# Story: Golden cache ambiguity now has a bounded state\n\n"
            "## Situation\n\nThe legacy cache narrative was ambiguous.\n\n"
            "## Current State\n\nThe reviewed fixture preserves its current state.\n\n"
            "## Turning Points\n\n- migr-session-source: the source captured a bounded change\n\n"
            "## Failure Mode\n\nThe old narrative could mix work logs with state.\n\n"
            "## Resolution\n\nUse the current Story profile.\n\n"
            "## Open Questions\n\n- none\n\n"
            "## Related Decision IDs\n\n- none\n"
        )
    if record_type == "preference":
        return (
            "# Preference: Keep reviewed source evidence intact\n\n"
            "## Preference\n\nPreserve reviewed source evidence across projects.\n\n"
            "## Decision Test\n\nIf rewriting a record, retain its immutable source.\n\n"
            "## Evidence\n\nThe golden snapshot records the preservation rule.\n"
        )
    if record_type == "runbook":
        return (
            "# Runbook: Review one bounded proposal rewrite\n\n"
            "## Preconditions\n\nThe report and snapshot hashes are fixed.\n\n"
            "## Procedure\n\n1. Validate the candidate against the snapshot.\n\n"
            "## Verification\n\nRequire matching hashes and a passing review.\n\n"
            "## Failure Handling\n\nStop without sealing the candidate.\n"
        )
    raise AssertionError("unsupported fixture record type")


def build_resolution_fixture(
    test_case,
    decision_states: Optional[Mapping[str, str]] = None,
    session_story_id: Optional[str] = None,
    default_decision_state: str = "confirm-candidate",
):
    root, bundle, result = _applied_golden_migration(test_case)
    report = _report_for_applied(root, bundle, result)
    overrides = dict(decision_states or {})
    decisions_value = []
    for item in report.document["items"]:
        state = overrides.get(item["proposal_id"], default_decision_state)
        owner = item["candidate_owner"] if state == "confirm-candidate" else None
        decisions_value.append(
            {
                "proposal_id": item["proposal_id"],
                "state": state,
                "owner_scope": None if owner is None else owner["owner_scope"],
                "project_id": None if owner is None else owner["project_id"],
                "note": "synthetic reviewed decision",
            }
        )
    decision_document = {
        "schema_version": 1,
        "evidence_kind": "proposal-review-decisions",
        "review_id": report.review_id,
        "report_sha256": report.report_sha256,
        "mutation_authorized": False,
        "decisions": decisions_value,
    }
    outside = root.parent / (root.name + "-resolution-inputs")
    outside.mkdir()
    decision_path = outside / "decisions.json"
    decision_path.write_bytes(_canonical(decision_document))
    decisions = bind_proposal_decisions(load_proposal_decisions(decision_path), report)

    rewrites = []
    reviews = []
    decision_by_id = {item.proposal_id: item for item in decisions.decisions}
    for item in report.document["items"]:
        decision = decision_by_id[item["proposal_id"]]
        if decision.state not in ("confirm-candidate", "change-owner"):
            continue
        owner = item["candidate_owner"]
        snapshot = (bundle.bundle_dir / Path(*item["snapshot_path"].split("/"))).read_bytes()
        body = _body(
            owner["record_type"],
            session_story_id if owner["record_type"] == "session" else None,
        )
        headings = [line[3:] for line in body.splitlines() if line.startswith("## ")]
        semantic_headings = [
            heading
            for heading in headings
            if heading
            not in (
                "Commands Verified",
                "Decisions Observed",
                "Files Changed",
                "Follow-Ups",
                "Open Questions",
                "Promotion Candidates",
                "Related Decision IDs",
            )
        ]
        if owner["record_type"] == "session" and session_story_id is None:
            semantic_headings.remove("Session Relationship")
        candidate = {
            "schema_version": 1,
            "evidence_kind": "proposal-resolution-rewrite",
            "review_id": report.review_id,
            "report_sha256": report.report_sha256,
            "decisions_sha256": decisions.decisions_sha256,
            "proposal_id": item["proposal_id"],
            "decision_state": decision.state,
            "source": {
                "source_path": item["source_path"],
                "snapshot_path": item["snapshot_path"],
                "snapshot_sha256": item["snapshot_sha256"],
                "proposal_sha256": item["proposal_sha256"],
            },
            "target": {
                "memory_id": owner["candidate_memory_id"],
                "record_type": owner["record_type"],
                "owner_scope": owner["owner_scope"],
                "project_id": owner["project_id"],
            },
            "rewrite": {
                "title": body.splitlines()[0][2:],
                "body": body,
                "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                "writer_profile": "luna-medium",
                "evidence_spans": [
                    {
                        "start_line": 1,
                        "end_line": len(snapshot.splitlines()),
                        "text_sha256": hashlib.sha256(snapshot).hexdigest(),
                        "supports_sections": sorted(semantic_headings),
                    }
                ],
            },
        }
        candidate_path = outside / (item["proposal_id"] + "-rewrite.json")
        candidate_path.write_bytes(_canonical(candidate))
        rewrite = load_rewrite_candidate(candidate_path)
        rewrites.append(rewrite)
        review_document = {
            "schema_version": 1,
            "evidence_kind": "proposal-resolution-semantic-review",
            "proposal_id": item["proposal_id"],
            "rewrite_sha256": rewrite.rewrite_sha256,
            "reviewer_profile": "independent-luna-medium",
            "checks": {
                "material_facts_retained": True,
                "no_unsupported_claims": True,
                "ownership_not_duplicated": True,
                "evidence_spans_support_sections": True,
                "story_membership_not_inferred": True,
            },
            "outcome": "pass",
            "reason_codes": [],
        }
        review_path = outside / (item["proposal_id"] + "-review.json")
        review_path.write_bytes(_canonical(review_document))
        reviews.append(load_semantic_review(review_path))

    identity = CodeIdentity(
        {"kind": "fixture", "revision": "proposal-resolution-fixture-v1"}
    )
    packet = seal_rewrite_packet(
        outside / "packet",
        report,
        decisions,
        tuple(rewrites),
        tuple(reviews),
        identity,
    )
    proof = CodeIdentityProof(identity, "d" * 64, ())
    return ResolutionFixture(
        root,
        bundle,
        report,
        decisions,
        packet,
        identity,
        proof,
        tree_hashes(root),
    )
