import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests.unit import test_proposal_resolution_verification as verification_tests
from tests.unit import test_proposal_resolution_recovery as recovery_tests
from tests.helpers import context, tree_hashes, initialize
from tests.proposal_resolution_helpers import build_resolution_fixture
from obsidian_agent_memory.proposal_decisions import load_proposal_decisions, bind_proposal_decisions
from obsidian_agent_memory.rewrite_packet import seal_rewrite_packet
from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.proposal_resolution import plan_proposal_resolution
from obsidian_agent_memory.projections import build_root_views, build_projection_from_observed_target
from obsidian_agent_memory.projections import _ProjectionSnapshotReader
from obsidian_agent_memory.resolution_outcomes import load_resolution_outcomes
from obsidian_agent_memory.resolution_transactions import (
    apply_proposal_resolution, recover_proposal_resolution, verify_proposal_resolution,
)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class ResolutionVisibilityTests(unittest.TestCase):
    def test_malformed_catalog_rejected_before_disposition_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            initialize(root)
            path = root / ".agent-memory/state/catalog.json"
            original = json.loads(path.read_bytes())
            for field, value in (("revision", "not-an-int"), ("records", []), ("schema_version", 1)):
                with self.subTest(field=field):
                    changed = dict(original)
                    changed[field] = value
                    path.write_bytes(canonical(changed))
                    with self.assertRaises(ValidationError):
                        load_resolution_outcomes(_ProjectionSnapshotReader(root))

    def test_accepted_proposals_are_not_pending_after_apply_or_rebuild(self):
        fixture, plan, result = verification_tests.ProposalResolutionVerificationTests._applied(self)
        rebuilt = build_root_views(fixture.root, "proposal-resolution-v1")
        stale = next(doc for doc in rebuilt if doc.relative_path == "_index/stale-or-uncertain.md")
        for action in plan.actions:
            self.assertNotIn(action.proposal_id, stale.content)
        for doc in rebuilt:
            self.assertEqual(doc.content.encode("utf-8"), (fixture.root / doc.relative_path).read_bytes())
        doctor = build_projection_from_observed_target(
            fixture.root, stale.relative_path, "proposal-resolution-v1",
            hashlib.sha256(stale.content.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(stale.content, doctor.content)

    def test_all_dispositions_preserve_original_proposals_and_exact_replay(self):
        fixture = build_resolution_fixture(self, decision_states={
            "action-612f3330563f0e03ba70": "sources-only",
            "action-a6d2a9c1b7093f582ddf": "knowledge-base-candidate",
            "action-e2cb78b206a7dbd62b74": "keep-unresolved",
        })
        original = {path: path.read_bytes() for path in (fixture.root / ".agent-memory/state/proposals").glob("*.json")}
        gate = verification_tests._GATE
        plan = plan_proposal_resolution(fixture.root, gate, fixture.report, fixture.decisions, fixture.packet, fixture.bundle, context("tx-mixed-plan"), fixture.identity_proof)
        args = (fixture.root, gate, plan, fixture.report, fixture.decisions, fixture.packet, fixture.bundle, fixture.identity_proof, plan.resolution_plan_sha256, plan.packet_sha256, context("tx-mixed-apply"))
        result = apply_proposal_resolution(*args)
        stale = next(doc for doc in build_root_views(fixture.root, "proposal-resolution-v1") if doc.relative_path == "_index/stale-or-uncertain.md")
        self.assertNotIn("action-08abd43c55206132f42e", stale.content)
        self.assertNotIn("action-612f3330563f0e03ba70", stale.content)
        lines = stale.content.splitlines()
        self.assertIn("status=knowledge-base-candidate", next(line for line in lines if "action-a6d2a9c1b7093f582ddf" in line))
        self.assertIn("status=unresolved", next(line for line in lines if "action-e2cb78b206a7dbd62b74" in line))
        self.assertEqual(original, {path: path.read_bytes() for path in original})
        self.assertEqual(1, len(result.record_paths))
        before = tree_hashes(fixture.root)
        self.assertEqual(result, apply_proposal_resolution(*args))
        self.assertEqual(before, tree_hashes(fixture.root))

    def test_sources_only_batch_updates_pending_view_without_changing_catalog(self):
        fixture = build_resolution_fixture(self, default_decision_state="sources-only")
        gate = verification_tests._GATE
        plan = plan_proposal_resolution(fixture.root, gate, fixture.report, fixture.decisions, fixture.packet, fixture.bundle, context("tx-source-only-plan"), fixture.identity_proof)
        before_catalog = (fixture.root / ".agent-memory/state/catalog.json").read_bytes()
        result = apply_proposal_resolution(fixture.root, gate, plan, fixture.report, fixture.decisions, fixture.packet, fixture.bundle, fixture.identity_proof, plan.resolution_plan_sha256, plan.packet_sha256, context("tx-source-only-apply"))
        published = (fixture.root / "_index/stale-or-uncertain.md").read_text("utf-8")
        for action in plan.actions:
            self.assertNotIn(action.proposal_id, published)
        self.assertEqual(before_catalog, (fixture.root / ".agent-memory/state/catalog.json").read_bytes())
        self.assertEqual((), result.record_paths)

    def test_unresolved_history_does_not_block_later_authorized_acceptance(self):
        fixture = build_resolution_fixture(self)
        gate = verification_tests._GATE
        decision_document = {
            "schema_version": 1, "evidence_kind": "proposal-review-decisions",
            "review_id": fixture.report.review_id, "report_sha256": fixture.report.report_sha256,
            "mutation_authorized": False,
            "decisions": [{"proposal_id": item["proposal_id"], "state": "keep-unresolved",
                           "owner_scope": None, "project_id": None, "note": "synthetic defer"}
                          for item in fixture.report.document["items"]],
        }
        decision_path = fixture.packet.root.parent / "deferred-decisions.json"
        decision_path.write_bytes(canonical(decision_document))
        deferred = bind_proposal_decisions(load_proposal_decisions(decision_path), fixture.report)
        packet = seal_rewrite_packet(fixture.packet.root.parent / "deferred-packet", fixture.report, deferred, (), (), fixture.identity)
        first = plan_proposal_resolution(fixture.root, gate, fixture.report, deferred, packet, fixture.bundle, context("tx-defer-plan"), fixture.identity_proof)
        apply_proposal_resolution(fixture.root, gate, first, fixture.report, deferred, packet, fixture.bundle, fixture.identity_proof, first.resolution_plan_sha256, packet.packet_sha256, context("tx-defer-apply"))
        second = plan_proposal_resolution(fixture.root, gate, fixture.report, fixture.decisions, fixture.packet, fixture.bundle, context("tx-accept-plan"), fixture.identity_proof)
        result = apply_proposal_resolution(fixture.root, gate, second, fixture.report, fixture.decisions, fixture.packet, fixture.bundle, fixture.identity_proof, second.resolution_plan_sha256, fixture.packet.packet_sha256, context("tx-accept-apply"))
        self.assertTrue(verify_proposal_resolution(fixture.root, gate, second, result).valid)
        stale = (fixture.root / "_index/stale-or-uncertain.md").read_text("utf-8")
        for action in second.actions:
            self.assertNotIn(action.proposal_id, stale)

    def test_loose_evidence_and_incomplete_journal_cannot_hide_proposals(self):
        fixture, plan = recovery_tests.ProposalResolutionRecoveryTests._interrupted(self)
        stale = next(doc for doc in build_root_views(fixture.root, "proposal-resolution-v1") if doc.relative_path == "_index/stale-or-uncertain.md")
        for action in plan.actions:
            self.assertIn(action.proposal_id, stale.content)
        journal = fixture.root / ".agent-memory/transactions/tx-resolution-apply/journal.json"
        saved = journal.read_bytes()
        journal.unlink()  # Synthetic fixture only: leave orphaned real evidence.
        stale = next(doc for doc in build_root_views(fixture.root, "proposal-resolution-v1") if doc.relative_path == "_index/stale-or-uncertain.md")
        for action in plan.actions:
            self.assertIn(action.proposal_id, stale.content)
        journal.write_bytes(saved)
        result = recover_proposal_resolution(fixture.root, verification_tests._GATE, "tx-resolution-apply", context("tx-visibility-recover"))
        self.assertTrue(verify_proposal_resolution(fixture.root, verification_tests._GATE, plan, result).valid)
        for doc in build_root_views(fixture.root, "proposal-resolution-v1"):
            self.assertEqual(doc.content.encode("utf-8"), (fixture.root / doc.relative_path).read_bytes())

    def test_changed_evidence_proposal_or_catalog_is_fail_closed(self):
        fixture, plan, result = verification_tests.ProposalResolutionVerificationTests._applied(self)
        targets = [fixture.root / result.evidence_paths[0], fixture.root / (".agent-memory/state/proposals/" + plan.actions[0].proposal_id + ".json")]
        for target in targets:
            with self.subTest(target=target.name):
                saved = target.read_bytes()
                target.write_bytes(saved + b" ")
                with self.assertRaises(ValidationError):
                    build_root_views(fixture.root, "proposal-resolution-v1")
                target.write_bytes(saved)
        catalog = fixture.root / ".agent-memory/state/catalog.json"
        value = json.loads(catalog.read_bytes())
        value["revision"] = plan.catalog_revision
        catalog.write_bytes(canonical(value))
        with self.assertRaises(ValidationError):
            build_root_views(fixture.root, "proposal-resolution-v1")

    def test_verification_rejects_wrong_view_even_when_journal_matches_its_bytes(self):
        fixture, plan, result = verification_tests.ProposalResolutionVerificationTests._applied(self)
        journal_path = fixture.root / result.journal_path
        journal = json.loads(journal_path.read_bytes())
        activation = next(item for item in journal["activations"] if item["target"] == "_index/stale-or-uncertain.md")
        wrong = b"# Incorrect pending projection\n"
        (fixture.root / activation["target"]).write_bytes(wrong)
        (fixture.root / activation["stage_path"]).write_bytes(wrong)
        activation["desired_sha256"] = hashlib.sha256(wrong).hexdigest()
        journal_path.write_bytes(canonical(journal))
        result = verify_proposal_resolution(fixture.root, verification_tests._GATE, plan, result)
        self.assertFalse(result.valid)
        self.assertIn("resolution-projection-mismatch", {finding.code for finding in result.findings})

    def test_malformed_bound_outcome_is_rejected_as_validation_failure(self):
        fixture, plan, result = verification_tests.ProposalResolutionVerificationTests._applied(self)
        journal_path = fixture.root / result.journal_path
        journal = json.loads(journal_path.read_bytes())
        activation = next(item for item in journal["activations"] if item["kind"] == "evidence")
        evidence = json.loads((fixture.root / activation["target"]).read_bytes())
        evidence["decision_state"] = []
        raw = canonical(evidence)
        (fixture.root / activation["target"]).write_bytes(raw)
        (fixture.root / activation["stage_path"]).write_bytes(raw)
        activation["desired_sha256"] = hashlib.sha256(raw).hexdigest()
        journal_path.write_bytes(canonical(journal))
        with self.assertRaises(ValidationError):
            build_root_views(fixture.root, "proposal-resolution-v1")
        self.assertFalse(verify_proposal_resolution(fixture.root, verification_tests._GATE, plan, result).valid)


if __name__ == "__main__":
    unittest.main()
