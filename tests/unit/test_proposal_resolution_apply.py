import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.helpers import context, tree_hashes
from tests.proposal_resolution_helpers import build_resolution_fixture

from obsidian_agent_memory.catalog import load_catalog
from obsidian_agent_memory.errors import PlanInvalidatedError
from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope
from obsidian_agent_memory.proposal_resolution import plan_proposal_resolution
from obsidian_agent_memory.resolution_transactions import apply_proposal_resolution


_GATE = AuthorizationGate(OperationScope.FIXTURE, None)


class ProposalResolutionApplyTests(unittest.TestCase):
    def _fixture_and_plan(self, decision_states=None):
        fixture = build_resolution_fixture(self, decision_states)
        plan = plan_proposal_resolution(
            fixture.root,
            _GATE,
            fixture.report,
            fixture.decisions,
            fixture.packet,
            fixture.bundle,
            context("tx-resolution-plan"),
            fixture.identity_proof,
        )
        return fixture, plan

    def _apply(self, fixture, plan, context_value=None, plan_sha=None, packet_sha=None):
        return apply_proposal_resolution(
            fixture.root,
            _GATE,
            plan,
            fixture.report,
            fixture.decisions,
            fixture.packet,
            fixture.bundle,
            fixture.identity_proof,
            plan_sha or plan.resolution_plan_sha256,
            packet_sha or fixture.packet.packet_sha256,
            context_value or context("tx-resolution-apply"),
        )

    def test_applies_records_catalog_and_one_evidence_per_decision(self):
        unresolved_id = "action-08abd43c55206132f42e"
        fixture, plan = self._fixture_and_plan(
            {unresolved_id: "keep-unresolved"}
        )
        old_proposals = {
            item["proposal_path"]: hashlib.sha256(
                (fixture.root / item["proposal_path"]).read_bytes()
            ).hexdigest()
            for item in fixture.report.document["items"]
        }

        result = self._apply(fixture, plan)

        self.assertEqual("applied", result.status)
        self.assertEqual(plan.predicted_catalog_revision, load_catalog(fixture.root).revision)
        self.assertEqual(3, len(result.record_paths))
        self.assertEqual(4, len(result.evidence_paths))
        self.assertTrue(all((fixture.root / path).is_file() for path in result.record_paths))
        self.assertTrue(all((fixture.root / path).is_file() for path in result.evidence_paths))
        self.assertTrue(all((fixture.root / path).is_file() for path in plan.projection_effects))
        self.assertEqual(
            old_proposals,
            {
                path: hashlib.sha256((fixture.root / path).read_bytes()).hexdigest()
                for path in old_proposals
            },
        )

    def test_wrong_reviewed_hash_fails_before_any_root_change(self):
        fixture, plan = self._fixture_and_plan()
        before = tree_hashes(fixture.root)

        with self.assertRaises(PlanInvalidatedError):
            self._apply(fixture, plan, plan_sha="0" * 64)

        self.assertEqual(before, tree_hashes(fixture.root))

    def test_interruption_before_catalog_leaves_no_accepted_record(self):
        fixture, plan = self._fixture_and_plan()
        before_catalog = (
            fixture.root / ".agent-memory" / "state" / "catalog.json"
        ).read_bytes()

        def interrupt(stage, path):
            del path
            if stage == "before-catalog-activation":
                raise RuntimeError("simulated interruption")

        with patch(
            "obsidian_agent_memory.resolution_transactions._resolution_apply_checkpoint",
            side_effect=interrupt,
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                self._apply(fixture, plan)

        self.assertEqual(
            before_catalog,
            (fixture.root / ".agent-memory" / "state" / "catalog.json").read_bytes(),
        )
        journal = (
            fixture.root
            / ".agent-memory"
            / "transactions"
            / "tx-resolution-apply"
            / "journal.json"
        )
        self.assertTrue(journal.is_file())
        self.assertIn(
            json.loads(journal.read_text("utf-8"))["status"],
            ("prepared", "staged", "activating"),
        )


if __name__ == "__main__":
    unittest.main()
