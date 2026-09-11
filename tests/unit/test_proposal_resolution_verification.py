import unittest

from tests.helpers import context, tree_hashes
from tests.proposal_resolution_helpers import build_resolution_fixture

from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope
from obsidian_agent_memory.proposal_resolution import plan_proposal_resolution
from obsidian_agent_memory.resolution_transactions import (
    apply_proposal_resolution,
    verify_proposal_resolution,
)


_GATE = AuthorizationGate(OperationScope.FIXTURE, None)


class ProposalResolutionVerificationTests(unittest.TestCase):
    def _applied(self):
        fixture = build_resolution_fixture(
            self, session_story_id="migr-08abd43c55206132f42eb96f"
        )
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
        result = apply_proposal_resolution(
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
        return fixture, plan, result

    def test_verifies_catalog_records_evidence_and_projections(self):
        fixture, plan, result = self._applied()

        verification = verify_proposal_resolution(fixture.root, _GATE, plan, result)

        self.assertTrue(verification.valid, verification.findings)
        self.assertEqual(4, verification.accepted_count)
        self.assertEqual(4, verification.evidence_count)
        self.assertEqual(plan.predicted_catalog_revision, verification.root_revision)

    def test_record_drift_is_reported(self):
        fixture, plan, result = self._applied()
        (fixture.root / result.record_paths[0]).write_text("drift\n", encoding="utf-8")

        verification = verify_proposal_resolution(fixture.root, _GATE, plan, result)

        self.assertFalse(verification.valid)
        self.assertIn("resolution-target-drift", {item.code for item in verification.findings})

    def test_exact_reapply_is_idempotent(self):
        fixture, plan, result = self._applied()
        before = tree_hashes(fixture.root)

        replay = apply_proposal_resolution(
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

        self.assertEqual(result, replay)
        self.assertEqual(before, tree_hashes(fixture.root))

    def test_no_record_resolution_preserves_catalog_bytes(self):
        fixture = build_resolution_fixture(
            self, default_decision_state="keep-unresolved"
        )
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
        catalog_path = fixture.root / ".agent-memory" / "state" / "catalog.json"
        before_catalog = catalog_path.read_bytes()

        result = apply_proposal_resolution(
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

        self.assertEqual((), result.record_paths)
        self.assertEqual(before_catalog, catalog_path.read_bytes())
        self.assertTrue(verify_proposal_resolution(fixture.root, _GATE, plan, result).valid)


if __name__ == "__main__":
    unittest.main()
