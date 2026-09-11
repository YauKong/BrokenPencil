import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: F401 - installs the source package path

from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.proposal_decisions import ProposalDecision
from obsidian_agent_memory.records import normalize_body
from obsidian_agent_memory.rewrite_artifacts import (
    bind_rewrite_candidate,
    load_rewrite_candidate,
    load_semantic_review,
)


_PROPOSAL_ID = "action-11111111111111111111"
_MEMORY_ID = "migr-834e73b3c4bc6d52f0abb2a1"
_REVIEW_ID = "review-" + "9" * 64
_REPORT_SHA256 = "a" * 64
_DECISIONS_SHA256 = "b" * 64
_PROPOSAL_SHA256 = "5" * 64
_SNAPSHOT = (
    b"The user asked to verify the demo cache.\n"
    b"The cache check completed successfully.\n"
    b"The command was python -m demo.verify.\n"
    b"No files changed and follow-up is none.\n"
)
_SNAPSHOT_SHA256 = hashlib.sha256(_SNAPSHOT).hexdigest()


def _canonical(value):
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _session_body(primary_story_id="none"):
    return normalize_body(
        """# Session: Demo cache verification completed

## Session Relationship
session_status: completed
primary_story_id: {primary_story_id}
related_story_id: none

## User Goal

Verify the demo cache.

## Outcome

The cache check completed successfully.

## Work Done

- Ran the bounded verification.

## Decisions Observed

none

## Commands Verified

- python -m demo.verify

## Files Changed

none

## Promotion Candidates

none

## Follow-Ups

none
""".format(primary_story_id=primary_story_id)
    )


def _candidate_document(body=None, evidence_spans=None):
    selected_body = body or _session_body()
    sections = ["Commands Verified", "Outcome", "User Goal", "Work Done"]
    return {
        "schema_version": 1,
        "evidence_kind": "proposal-resolution-rewrite",
        "review_id": _REVIEW_ID,
        "report_sha256": _REPORT_SHA256,
        "decisions_sha256": _DECISIONS_SHA256,
        "proposal_id": _PROPOSAL_ID,
        "decision_state": "confirm-candidate",
        "source": {
            "source_path": "projects/demo/sessions/example.md",
            "snapshot_path": "snapshot/files/projects/demo/sessions/example.md",
            "snapshot_sha256": _SNAPSHOT_SHA256,
            "proposal_sha256": _PROPOSAL_SHA256,
        },
        "target": {
            "memory_id": _MEMORY_ID,
            "record_type": "session",
            "owner_scope": "project.demo.session",
            "project_id": "demo",
        },
        "rewrite": {
            "title": "Session: Demo cache verification completed",
            "body": selected_body,
            "body_sha256": hashlib.sha256(selected_body.encode("utf-8")).hexdigest(),
            "writer_profile": "luna-medium",
            "evidence_spans": evidence_spans
            or [
                {
                    "start_line": 1,
                    "end_line": 4,
                    "text_sha256": hashlib.sha256(_SNAPSHOT).hexdigest(),
                    "supports_sections": sections,
                }
            ],
        },
    }


def _report_item():
    return {
        "proposal_id": _PROPOSAL_ID,
        "proposal_sha256": _PROPOSAL_SHA256,
        "source_path": "projects/demo/sessions/example.md",
        "snapshot_path": "snapshot/files/projects/demo/sessions/example.md",
        "snapshot_sha256": _SNAPSHOT_SHA256,
        "candidate_owner": {
            "candidate_memory_id": _MEMORY_ID,
            "owner_scope": "project.demo.session",
            "project_id": "demo",
            "record_type": "session",
        },
    }


class RewriteArtifactLoaderTests(unittest.TestCase):
    def _load_candidate(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_bytes(raw)
            return load_rewrite_candidate(path)

    def _load_review(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.json"
            path.write_bytes(raw)
            return load_semantic_review(path)

    def test_loads_canonical_candidate_and_binds_exact_snapshot_span(self):
        raw = _canonical(_candidate_document())
        candidate = self._load_candidate(raw)
        decision = ProposalDecision(
            _PROPOSAL_ID,
            "confirm-candidate",
            "project.demo.session",
            "demo",
            "confirmed",
        )

        bound = bind_rewrite_candidate(candidate, decision, _report_item(), _SNAPSHOT)

        self.assertEqual(hashlib.sha256(raw).hexdigest(), bound.rewrite_sha256)
        self.assertEqual(_MEMORY_ID, bound.memory_id)
        self.assertEqual("Session: Demo cache verification completed", bound.title)

    def test_rejects_unknown_fields_noncanonical_json_and_body_hash_drift(self):
        unknown = _candidate_document()
        unknown["unexpected"] = True

        wrong_hash = _candidate_document()
        wrong_hash["rewrite"]["body_sha256"] = "0" * 64

        noncanonical = json.dumps(_candidate_document(), indent=2).encode("utf-8")

        for raw in (_canonical(unknown), _canonical(wrong_hash), noncanonical):
            with self.subTest(raw=raw[:80]):
                with self.assertRaises(ValidationError):
                    self._load_candidate(raw)

    def test_rejects_out_of_range_or_mismatched_evidence_spans(self):
        out_of_range = _candidate_document(
            evidence_spans=[
                {
                    "start_line": 1,
                    "end_line": 5,
                    "text_sha256": hashlib.sha256(_SNAPSHOT).hexdigest(),
                    "supports_sections": [
                        "Commands Verified",
                        "Outcome",
                        "User Goal",
                        "Work Done",
                    ],
                }
            ]
        )
        wrong_digest = _candidate_document()
        wrong_digest["rewrite"]["evidence_spans"][0]["text_sha256"] = "0" * 64

        decision = ProposalDecision(
            _PROPOSAL_ID,
            "confirm-candidate",
            "project.demo.session",
            "demo",
            "confirmed",
        )
        for document in (out_of_range, wrong_digest):
            with self.subTest(document=document):
                candidate = self._load_candidate(_canonical(document))
                with self.assertRaises(ValidationError):
                    bind_rewrite_candidate(candidate, decision, _report_item(), _SNAPSHOT)

    def test_requires_evidence_for_every_nonempty_semantic_section(self):
        document = _candidate_document()
        document["rewrite"]["evidence_spans"][0]["supports_sections"] = [
            "Outcome",
            "User Goal",
            "Work Done",
        ]
        candidate = self._load_candidate(_canonical(document))
        decision = ProposalDecision(
            _PROPOSAL_ID,
            "confirm-candidate",
            "project.demo.session",
            "demo",
            "confirmed",
        )

        with self.assertRaises(ValidationError):
            bind_rewrite_candidate(candidate, decision, _report_item(), _SNAPSHOT)

    def test_requires_relationship_evidence_when_story_membership_is_bound(self):
        document = _candidate_document(body=_session_body("migr-story-0001"))
        candidate = self._load_candidate(_canonical(document))
        decision = ProposalDecision(
            _PROPOSAL_ID,
            "confirm-candidate",
            "project.demo.session",
            "demo",
            "confirmed",
        )

        with self.assertRaises(ValidationError):
            bind_rewrite_candidate(candidate, decision, _report_item(), _SNAPSHOT)

        document["rewrite"]["evidence_spans"][0]["supports_sections"].append(
            "Session Relationship"
        )
        document["rewrite"]["evidence_spans"][0]["supports_sections"].sort()
        candidate = self._load_candidate(_canonical(document))
        bind_rewrite_candidate(candidate, decision, _report_item(), _SNAPSHOT)

    def test_semantic_review_pass_requires_all_checks_and_exact_rewrite_hash(self):
        review = {
            "schema_version": 1,
            "evidence_kind": "proposal-resolution-semantic-review",
            "proposal_id": _PROPOSAL_ID,
            "rewrite_sha256": "8" * 64,
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

        artifact = self._load_review(_canonical(review))
        self.assertTrue(artifact.passed)
        self.assertEqual("8" * 64, artifact.rewrite_sha256)

        review["checks"]["no_unsupported_claims"] = False
        with self.assertRaises(ValidationError):
            self._load_review(_canonical(review))

    def test_rewrite_needs_split_is_preserved_but_not_passing(self):
        review = {
            "schema_version": 1,
            "evidence_kind": "proposal-resolution-semantic-review",
            "proposal_id": _PROPOSAL_ID,
            "rewrite_sha256": "8" * 64,
            "reviewer_profile": "independent-luna-medium",
            "checks": {
                "material_facts_retained": True,
                "no_unsupported_claims": True,
                "ownership_not_duplicated": False,
                "evidence_spans_support_sections": True,
                "story_membership_not_inferred": True,
            },
            "outcome": "rewrite-needs-split",
            "reason_codes": ["multiple-durable-owners"],
        }

        artifact = self._load_review(_canonical(review))

        self.assertFalse(artifact.passed)
        self.assertEqual("rewrite-needs-split", artifact.outcome)


class RewriteTypeProfileTests(unittest.TestCase):
    _BODIES = {
        "story": """# Story: Demo cache failures now have a verified outcome

## Situation

The cache behavior was uncertain.

## Current State

The bounded check now passes.

## Turning Points

- migr-session-0001: verification completed

## Failure Mode

The old check could report stale state.

## Resolution

Use the bounded verification.

## Open Questions

- none

## Related Decision IDs

- none
""",
        "decision": """# Decision: Use bounded cache verification

## Context

The previous check could observe stale state.

## Decision

Use the bounded verification command.

## Consequences

Cache acceptance now requires a fresh result.

## Evidence

The fixture command completed successfully.

## Related Record IDs

none
""",
        "preference": """# Preference: Preserve all acquired products

## Preference

Acquire every available product before import selection.

## Decision Test

If a provider returns a product, retain it before applying import priority.

## Evidence

The reviewed source states the cross-project rule.
""",
        "runbook": """# Runbook: Verify the demo cache

## Preconditions

The fixture root is available.

## Procedure

1. Run the bounded cache command.

## Verification

Require a successful fresh result.

## Failure Handling

Stop and preserve the failed output.
""",
        "migration": """# Migration: Legacy cache note remains preserved

## Source Snapshot

The reviewed snapshot is immutable.

## Reviewed Plan

Create one rewritten record.

## Applied Changes

No real migration was applied.

## Verification

The fixture plan is deterministic.

## Unresolved Proposals

none
""",
        "maintenance": """# Maintenance: Proposal review remains non-mutating

## Audit Scope

The fixture proposal set only.

## Findings

One candidate needs deterministic binding.

## Reviewed Actions

Validate the candidate packet.

## Applied Transactions

none

## Verification

No real root was touched.
""",
    }

    _OWNERS = {
        "story": ("project.demo.story", "demo"),
        "decision": ("project.demo.decision", "demo"),
        "preference": ("user.preference", None),
        "runbook": ("agent.runbook", None),
        "migration": ("meta.migration", None),
        "maintenance": ("meta.maintenance", None),
    }

    def _candidate_for(self, record_type):
        body = normalize_body(self._BODIES[record_type])
        owner_scope, project_id = self._OWNERS[record_type]
        title = body.splitlines()[0][2:]
        document = _candidate_document(body=body)
        document["target"].update(
            {
                "record_type": record_type,
                "owner_scope": owner_scope,
                "project_id": project_id,
            }
        )
        document["decision_state"] = "change-owner"
        document["rewrite"]["title"] = title
        headings = [line[3:] for line in body.splitlines() if line.startswith("## ")]
        document["rewrite"]["evidence_spans"][0]["supports_sections"] = sorted(
            heading for heading in headings if heading != "Applied Transactions"
        )
        return document

    def test_accepts_each_current_non_session_template_profile(self):
        for record_type in self._BODIES:
            with self.subTest(record_type=record_type):
                document = self._candidate_for(record_type)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "candidate.json"
                    path.write_bytes(_canonical(document))
                    candidate = load_rewrite_candidate(path)
                owner_scope, project_id = self._OWNERS[record_type]
                decision = ProposalDecision(
                    _PROPOSAL_ID,
                    "change-owner",
                    owner_scope,
                    project_id,
                    "reviewed owner",
                )
                report_item = _report_item()
                report_item["candidate_owner"] = {
                    "candidate_memory_id": _MEMORY_ID,
                    "owner_scope": "project.demo.session",
                    "project_id": "demo",
                    "record_type": "session",
                }
                bind_rewrite_candidate(candidate, decision, report_item, _SNAPSHOT)

    def test_rejects_body_that_drops_current_template_spacing(self):
        document = self._candidate_for("decision")
        body = document["rewrite"]["body"].replace(
            "## Context\n\n", "## Context\n", 1
        )
        document["rewrite"]["body"] = body
        document["rewrite"]["body_sha256"] = hashlib.sha256(
            body.encode("utf-8")
        ).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_bytes(_canonical(document))
            candidate = load_rewrite_candidate(path)
        decision = ProposalDecision(
            _PROPOSAL_ID,
            "change-owner",
            "project.demo.decision",
            "demo",
            "reviewed owner",
        )

        with self.assertRaises(ValidationError):
            bind_rewrite_candidate(candidate, decision, _report_item(), _SNAPSHOT)


if __name__ == "__main__":
    unittest.main()
