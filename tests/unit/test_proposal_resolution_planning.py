import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.helpers import context, tree_hashes
from tests.proposal_resolution_helpers import build_resolution_fixture

from obsidian_agent_memory.errors import PlanInvalidatedError, ValidationError
from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope
from obsidian_agent_memory.proposal_resolution import (
    load_resolution_plan,
    plan_proposal_resolution,
)
from obsidian_agent_memory.records import record_relative_path


_GATE = AuthorizationGate(OperationScope.FIXTURE, None)


class ProposalResolutionPlanningTests(unittest.TestCase):
    def _plan(self, fixture):
        return plan_proposal_resolution(
            fixture.root,
            _GATE,
            fixture.report,
            fixture.decisions,
            fixture.packet,
            fixture.bundle,
            context("tx-resolution-plan"),
            fixture.identity_proof,
        )

    def test_plans_revision_one_records_without_mutating_fixture_root(self):
        fixture = build_resolution_fixture(self)

        plan = self._plan(fixture)

        self.assertEqual(fixture.before_tree, tree_hashes(fixture.root))
        self.assertEqual(4, len(plan.actions))
        self.assertEqual(4, len(plan.resolution_evidence))
        self.assertEqual(plan.catalog_revision, plan.root_revision)
        self.assertEqual(
            (
                "_index/current-focus.md",
                "_index/home.md",
                "_index/memory-map.md",
                "_index/stale-or-uncertain.md",
                "projects/demo/current-focus.md",
                "projects/demo/overview.md",
                "projects/demo/stories/migr-08abd43c55206132f42eb96f.md",
            ),
            plan.projection_effects,
        )
        for action in plan.actions:
            self.assertEqual("accepted-record", action.outcome)
            self.assertEqual(1, action.record_candidate.envelope.revision)
            self.assertIsNone(action.record_candidate.envelope.supersedes)
            self.assertEqual("migration-snapshot", action.record_candidate.envelope.source)
            self.assertEqual(
                action.relative_path,
                record_relative_path(action.record_candidate.envelope).as_posix(),
            )
            self.assertEqual("2026-08-30T00:00:00Z", action.record_candidate.envelope.created_at)
            self.assertEqual("2026-09-04T01:00:00Z", action.record_candidate.envelope.observed_at)

    def test_no_record_decision_has_evidence_but_no_target(self):
        proposal_id = "action-08abd43c55206132f42e"
        fixture = build_resolution_fixture(
            self, {proposal_id: "keep-unresolved"}
        )

        plan = self._plan(fixture)
        action = next(item for item in plan.actions if item.proposal_id == proposal_id)

        self.assertEqual("unresolved", action.outcome)
        self.assertIsNone(action.record_candidate)
        self.assertIsNone(action.relative_path)
        self.assertEqual(4, len(plan.resolution_evidence))

    def test_orders_explicit_story_before_bound_session(self):
        fixture = build_resolution_fixture(
            self, session_story_id="migr-08abd43c55206132f42eb96f"
        )

        plan = self._plan(fixture)
        ordered_types = [
            action.record_candidate.envelope.record_type
            for action in plan.actions
            if action.record_candidate is not None
        ]

        self.assertLess(ordered_types.index("story"), ordered_types.index("session"))

    def test_rejects_missing_explicit_story_dependency(self):
        fixture = build_resolution_fixture(
            self, session_story_id="migr-missing-story"
        )

        with self.assertRaises(ValidationError):
            self._plan(fixture)

    def test_two_pass_catalog_change_invalidates_plan(self):
        fixture = build_resolution_fixture(self)
        catalog_path = fixture.root / ".agent-memory" / "state" / "catalog.json"

        def mutate(stage):
            if stage == "before-recapture":
                value = json.loads(catalog_path.read_text("utf-8"))
                value["revision"] += 1
                catalog_path.write_text(
                    json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )

        with patch(
            "obsidian_agent_memory.proposal_resolution._resolution_plan_checkpoint",
            side_effect=mutate,
        ):
            with self.assertRaises(PlanInvalidatedError):
                self._plan(fixture)

    def test_canonical_plan_round_trips_and_rejects_tampering(self):
        fixture = build_resolution_fixture(self)
        plan = self._plan(fixture)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_bytes(plan.raw)
            loaded = load_resolution_plan(path)
            self.assertEqual(plan.resolution_plan_sha256, loaded.resolution_plan_sha256)

            document = json.loads(plan.raw.decode("utf-8"))
            document["catalog_revision"] += 1
            path.write_text(
                json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValidationError):
                load_resolution_plan(path)

    def test_loader_rejects_semantic_tampering_with_recomputed_digest(self):
        fixture = build_resolution_fixture(self)
        plan = self._plan(fixture)
        document = json.loads(plan.raw.decode("utf-8"))
        document["actions"][0]["outcome"] = "unresolved"
        core = dict(document)
        core.pop("resolution_plan_sha256")
        canonical_core = (
            json.dumps(core, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        document["resolution_plan_sha256"] = hashlib.sha256(
            b"proposal-resolution-plan-v1\n" + canonical_core
        ).hexdigest()
        raw = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered-plan.json"
            path.write_bytes(raw)
            with self.assertRaises(ValidationError):
                load_resolution_plan(path)


if __name__ == "__main__":
    unittest.main()
