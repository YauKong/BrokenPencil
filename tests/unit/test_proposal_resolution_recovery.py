import json
import unittest
from unittest.mock import patch

from tests.helpers import context, tree_hashes
from tests.proposal_resolution_helpers import build_resolution_fixture

from obsidian_agent_memory.catalog import load_catalog
from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope
from obsidian_agent_memory.proposal_resolution import plan_proposal_resolution
from obsidian_agent_memory.resolution_transactions import (
    apply_proposal_resolution,
    recover_proposal_resolution,
)


_GATE = AuthorizationGate(OperationScope.FIXTURE, None)


class ProposalResolutionRecoveryTests(unittest.TestCase):
    def _interrupted(self):
        fixture = build_resolution_fixture(self)
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

        def interrupt(stage, path):
            del path
            if stage == "before-catalog-activation":
                raise RuntimeError("simulated interruption")

        with patch(
            "obsidian_agent_memory.resolution_transactions._resolution_apply_checkpoint",
            side_effect=interrupt,
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                apply_proposal_resolution(
                    fixture.root,
                    _GATE,
                    plan,
                    fixture.report,
                    fixture.decisions,
                    fixture.packet,
                    fixture.bundle,
                    fixture.identity_proof,
                    plan.resolution_plan_sha256,
                    plan.packet_sha256,
                    context("tx-resolution-apply"),
                )
        return fixture, plan

    def test_recovery_completes_only_the_journaled_transition(self):
        fixture, plan = self._interrupted()

        result = recover_proposal_resolution(
            fixture.root,
            _GATE,
            "tx-resolution-apply",
            context("tx-resolution-recover"),
        )

        self.assertEqual("applied", result.status)
        self.assertEqual(plan.resolution_plan_sha256, result.resolution_plan_sha256)
        self.assertEqual(plan.predicted_catalog_revision, load_catalog(fixture.root).revision)
        journal_path = fixture.root / result.journal_path
        self.assertEqual("completed", json.loads(journal_path.read_text("utf-8"))["status"])

    def test_tampered_stage_is_rejected_before_further_live_mutation(self):
        fixture, unused_plan = self._interrupted()
        del unused_plan
        journal_path = (
            fixture.root
            / ".agent-memory"
            / "transactions"
            / "tx-resolution-apply"
            / "journal.json"
        )
        journal = json.loads(journal_path.read_text("utf-8"))
        stage = fixture.root / journal["activations"][-1]["stage_path"]
        stage.write_bytes(b"tampered\n")
        before = tree_hashes(fixture.root)

        with self.assertRaises(ValidationError):
            recover_proposal_resolution(
                fixture.root,
                _GATE,
                "tx-resolution-apply",
                context("tx-resolution-recover"),
            )

        self.assertEqual(before, tree_hashes(fixture.root))


if __name__ == "__main__":
    unittest.main()
