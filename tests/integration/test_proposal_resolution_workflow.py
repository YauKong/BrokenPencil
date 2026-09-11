import hashlib
import unittest

from tests.helpers import context, fixture_root, tree_hashes
from tests.proposal_resolution_helpers import build_resolution_fixture

from obsidian_agent_memory import (
    AuthorizationGate,
    OperationScope,
    apply_proposal_resolution,
    load_catalog,
    parse_record,
    plan_proposal_resolution,
    verify_proposal_resolution,
)


_GATE = AuthorizationGate(OperationScope.FIXTURE, None)


class ProposalResolutionWorkflowTests(unittest.TestCase):
    def test_reviewed_rewrites_are_applied_without_changing_legacy_evidence(self):
        marker_root = fixture_root("v2-proposal-resolution")
        self.assertTrue((marker_root / ".agent-memory-fixture.json").is_file())
        fixture = build_resolution_fixture(
            self, session_story_id="migr-08abd43c55206132f42eb96f"
        )
        before_bundle = tree_hashes(fixture.bundle.bundle_dir)
        protected_root_bytes = {
            path.relative_to(fixture.root).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in fixture.root.rglob("*")
            if path.is_file()
            and (
                ".agent-memory/migrations/" in path.relative_to(fixture.root).as_posix()
                or path.name == "journal.json"
            )
        }
        proposal_bytes = {
            item["proposal_path"]: hashlib.sha256(
                (fixture.root / item["proposal_path"]).read_bytes()
            ).hexdigest()
            for item in fixture.report.document["items"]
        }
        initial_catalog_ids = {
            entry.memory_id for entry in load_catalog(fixture.root).entries
        }
        plan = plan_proposal_resolution(
            fixture.root,
            _GATE,
            fixture.report,
            fixture.decisions,
            fixture.packet,
            fixture.bundle,
            context("tx-workflow-plan"),
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
            context("tx-workflow-apply"),
        )
        verification = verify_proposal_resolution(fixture.root, _GATE, plan, result)

        self.assertTrue(verification.valid, verification.findings)
        self.assertEqual(4, verification.accepted_count)
        self.assertEqual(4, verification.evidence_count)
        catalog = load_catalog(fixture.root)
        self.assertEqual(4, len(result.record_paths))
        titles = []
        for relative in result.record_paths:
            unused_envelope, body = parse_record(
                (fixture.root / relative).read_text("utf-8")
            )
            del unused_envelope
            titles.append(body.splitlines()[0])
        self.assertTrue(all(title.startswith("# ") and len(title) > 12 for title in titles))
        story_projection = (
            fixture.root
            / "projects"
            / "demo"
            / "stories"
            / "migr-08abd43c55206132f42eb96f.md"
        ).read_text("utf-8")
        session_id = next(
            action.record_candidate.envelope.memory_id
            for action in plan.actions
            if action.record_candidate.envelope.record_type == "session"
        )
        self.assertIn("`{0}` (completed, primary)".format(session_id), story_projection)
        self.assertEqual(
            proposal_bytes,
            {
                relative: hashlib.sha256(
                    (fixture.root / relative).read_bytes()
                ).hexdigest()
                for relative in proposal_bytes
            },
        )
        self.assertEqual(before_bundle, tree_hashes(fixture.bundle.bundle_dir))
        for relative, digest in protected_root_bytes.items():
            self.assertEqual(
                digest,
                hashlib.sha256((fixture.root / relative).read_bytes()).hexdigest(),
                relative,
            )
        self.assertEqual(
            {entry.memory_id for entry in catalog.entries},
            initial_catalog_ids
            | {
                action.record_candidate.envelope.memory_id
                for action in plan.actions
                if action.record_candidate is not None
            },
        )

        before_replay = tree_hashes(fixture.root)
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
            context("tx-workflow-apply"),
        )
        self.assertEqual(result, replay)
        self.assertEqual(before_replay, tree_hashes(fixture.root))


if __name__ == "__main__":
    unittest.main()
