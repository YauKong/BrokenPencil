import json
import unittest
import dataclasses
from unittest import mock
from types import SimpleNamespace

from tests.unit.test_artifact_schemas import _applied_golden_migration

from obsidian_agent_memory.errors import ConflictError, ValidationError
from obsidian_agent_memory.migration import MigrationAction, MigrationActionKind
from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope
from obsidian_agent_memory.proposal_review import (
    ProposalReviewArtifact,
    ProposalReviewContext,
    _CapturedPath,
    _CapturedPathState,
    _bind_captured_proposal_review,
    _build_captured_proposal_review,
    _canonical_report_bytes,
    _capture_review_inputs,
    _live_state,
    bind_proposal_review,
    build_proposal_review,
)
from obsidian_agent_memory.runtime_identity import (
    CodeIdentity,
    CodeIdentityProof,
    observe_runtime_identity,
)


CODE_IDENTITY = {"kind": "fixture", "revision": "proposal-review-fixture-v1"}
RUN_CONTEXT = {
    "actor": "fixture-agent",
    "authorization_ref": None,
    "observed_at": "2026-09-04T00:00:00Z",
    "scope": "fixture",
}
REVIEW_CONTEXT = ProposalReviewContext(
    actor="fixture-agent",
    observed_at="2026-09-04T00:00:00Z",
    fixture_code_revision="proposal-review-fixture-v1",
)
REVIEW_GATE = AuthorizationGate(OperationScope.FIXTURE, None)


class ProposalReviewBindingTests(unittest.TestCase):
    def _valid(self):
        root, bundle, _ = _applied_golden_migration(self)
        snapshot = _capture_review_inputs(root, bundle.bundle_dir, bundle.bundle_sha256)
        artifact = _build_captured_proposal_review(snapshot, CODE_IDENTITY, RUN_CONTEXT)
        return root, bundle, artifact

    def test_bound_validation_recomputes_snapshot_semantics(self):
        root, bundle, artifact = self._valid()

        rebound = _bind_captured_proposal_review(
            artifact,
            root,
            bundle.bundle_dir,
            bundle.bundle_sha256,
            CODE_IDENTITY,
            RUN_CONTEXT,
        )
        self.assertEqual(artifact.raw, rebound.raw)
        self.assertEqual(artifact.review_id, rebound.review_id)
        self.assertEqual(artifact.report_sha256, rebound.report_sha256)

        mutations = []
        paths = (
            ("items", 0, "candidate_owner"),
            ("items", 0, "refined_status"),
            ("items", 0, "decision_code"),
            ("items", 0, "live_source_state"),
            ("items", 0, "snapshot_sha256"),
            ("inputs", "catalog", "sha256"),
            ("inputs", "catalog", "revision"),
            ("inputs", "apply_journal", "sha256"),
            ("inputs", "proposal_set_sha256"),
            ("summary", "total"),
        )
        for path in paths:
            value = json.loads(artifact.raw.decode("utf-8"))
            target = value
            for part in path[:-1]:
                target = target[part]
            old = target[path[-1]]
            target[path[-1]] = 0 if isinstance(old, str) else "forged"
            mutations.append(value)
        for value in mutations:
            raw = _canonical_report_bytes(value)
            forged = ProposalReviewArtifact(value, raw, artifact.review_id, artifact.report_sha256)
            with self.assertRaises(ValidationError):
                _bind_captured_proposal_review(
                    forged,
                    root,
                    bundle.bundle_dir,
                    bundle.bundle_sha256,
                    CODE_IDENTITY,
                    RUN_CONTEXT,
                )

    def _synthetic_action(self):
        return MigrationAction(
            "action-11111111111111111111",
            MigrationActionKind.PRESERVE,
            "projects/demo/sessions/example.md",
            "1" * 64,
            None,
            None,
            None,
            None,
            None,
            (),
            None,
            "fixture",
        )

    def _state(self, digest):
        captured = _CapturedPath(
            "projects/demo/sessions/example.md", "file", 1, 2, 3, 4,
            digest, b"now",
        )
        return _CapturedPathState(captured.logical_path, "present", captured)

    def test_changed_replacement_falls_through_to_current_live_state(self):
        action = self._synthetic_action()
        snapshot = SimpleNamespace(
            journal_document={
                "actions": [{
                    "path": action.source_path,
                    "operation": "replace",
                    "completed": True,
                    "after_sha256": "2" * 64,
                }]
            }
        )
        self.assertEqual("drifted", _live_state(snapshot, action, self._state("3" * 64)))

    def test_recreated_archive_falls_through_to_current_live_state(self):
        action = self._synthetic_action()
        snapshot = SimpleNamespace(
            journal_document={
                "actions": [{
                    "path": action.source_path,
                    "operation": "archive",
                    "completed": True,
                    "after_sha256": None,
                }]
            }
        )
        self.assertEqual("unchanged", _live_state(snapshot, action, self._state("1" * 64)))

    def _public_arguments(self):
        root, bundle, _ = _applied_golden_migration(self)
        proof = observe_runtime_identity(
            OperationScope.FIXTURE, "proposal-review-fixture-v1"
        )
        return root, bundle, proof

    def test_public_build_and_bind_accept_matching_code_identity_proof(self):
        root, bundle, proof = self._public_arguments()
        artifact = build_proposal_review(
            root, bundle.bundle_dir, bundle.bundle_sha256,
            REVIEW_CONTEXT, REVIEW_GATE, proof,
        )
        rebound = bind_proposal_review(
            root, bundle.bundle_dir, bundle.bundle_sha256,
            REVIEW_CONTEXT, REVIEW_GATE, proof, artifact,
        )
        self.assertEqual(artifact.raw, rebound.raw)

    def test_public_build_and_bind_reject_forged_or_stale_code_identity_proof(self):
        root, bundle, proof = self._public_arguments()
        forged = (
            dataclasses.replace(proof, identity=CodeIdentity({"kind": "fixture", "revision": "forged"})),
            dataclasses.replace(proof, proof_sha256="0" * 64),
            dataclasses.replace(proof, protected_roots=(root,)),
        )
        for candidate in forged:
            with self.assertRaises(ConflictError):
                build_proposal_review(
                    root, bundle.bundle_dir, bundle.bundle_sha256,
                    REVIEW_CONTEXT, REVIEW_GATE, candidate,
                )

    def test_public_build_and_bind_reject_identity_change_between_passes(self):
        root, bundle, proof = self._public_arguments()
        changed = dataclasses.replace(proof, proof_sha256="f" * 64)
        observations = iter((proof, changed))

        with mock.patch(
            "obsidian_agent_memory.proposal_review.observe_runtime_identity",
            side_effect=lambda scope, revision: next(observations),
        ):
            with self.assertRaises(ConflictError):
                build_proposal_review(
                    root, bundle.bundle_dir, bundle.bundle_sha256,
                    REVIEW_CONTEXT, REVIEW_GATE, proof,
                )

    def test_second_read_pass_rejects_membership_or_byte_changes(self):
        root, bundle, proof = self._public_arguments()
        unresolved = next(
            action for action in bundle.plan.actions
            if action.unresolved_classification is not None
        )
        source = root / unresolved.source_path
        original = source.read_bytes()

        def mutate(*unused):
            source.write_bytes(original + b"changed")

        with mock.patch(
            "obsidian_agent_memory.proposal_review._proposal_review_consistency_checkpoint",
            side_effect=mutate,
        ):
            with self.assertRaises(ConflictError):
                build_proposal_review(
                    root, bundle.bundle_dir, bundle.bundle_sha256,
                    REVIEW_CONTEXT, REVIEW_GATE, proof,
                )

    def test_stable_preexisting_source_drift_is_reported(self):
        root, bundle, proof = self._public_arguments()
        unresolved = next(
            action for action in bundle.plan.actions
            if action.unresolved_classification is not None
        )
        source = root / unresolved.source_path
        source.write_bytes(source.read_bytes() + b"stable drift\n")
        artifact = build_proposal_review(
            root, bundle.bundle_dir, bundle.bundle_sha256,
            REVIEW_CONTEXT, REVIEW_GATE, proof,
        )
        item = next(
            item for item in artifact.document["items"]
            if item["proposal_id"] == unresolved.action_id
        )
        self.assertEqual("drifted", item["live_source_state"])


if __name__ == "__main__":
    unittest.main()
