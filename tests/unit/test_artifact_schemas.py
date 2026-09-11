import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers import candidate, context, initialize
from tests.unit.test_migration_bundle_compatibility import (
    FIXTURE_GATE,
    _apply_context,
    _bundle_path,
    _restore_snapshot_as_v1_root,
)

from obsidian_agent_memory.artifact_schemas import (
    MigrationReviewProposal,
    TransactionConflictProposal,
    UnboundSessionProposal,
    parse_proposal_artifact,
)
from obsidian_agent_memory.coordination import build_unbound_session_candidate
from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.migration import apply_migration, load_migration_bundle
from obsidian_agent_memory.models import PromotionCandidate
from obsidian_agent_memory.story_profiles import StoryDelta
from obsidian_agent_memory.transactions import (
    commit_record,
    preserve_promotion_candidate,
    preserve_unbound_session_candidate,
    update_focus,
)


def _canonical(document):
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def _applied_golden_migration(test_case):
    bundle = load_migration_bundle(_bundle_path("schema_2"))
    root = _restore_snapshot_as_v1_root(bundle, test_case.addCleanup)
    result = apply_migration(
        root,
        bundle,
        bundle.bundle_sha256,
        _apply_context("schema_2"),
        FIXTURE_GATE,
    )
    return root, bundle, result


def _duplicate_apply_journal(root):
    source = next((root / ".agent-memory" / "transactions").glob("*/journal.json"))
    document = json.loads(source.read_text("utf-8"))
    transaction_id = "proposal-review-golden-apply-duplicate"
    document["apply_transaction_id"] = transaction_id
    target = root / ".agent-memory" / "transactions" / transaction_id / "journal.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(_canonical(document))
    return target


class ProposalArtifactSchemaTests(unittest.TestCase):
    def test_unbound_session_writer_round_trips_complete_candidate_through_tagged_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "memory"
            initialize(root)
            body = (
                "# Session: Unbound work\n\n"
                "## Session Relationship\n"
                "session_status: completed\n"
                "primary_story_id: none\n"
                "related_story_id: none\n\n"
                "## Outcome\n\nAwaiting Story confirmation.\n"
            )
            session = candidate(
                memory_id="session-demo",
                body=body,
                record_type="session",
                project="demo",
                owner_scope="project.demo.session",
            )
            unbound = build_unbound_session_candidate(
                session,
                suggested_primary="story-demo",
                primary_evidence="User named this Story.",
                intended_story_delta=StoryDelta(
                    story_id="story-demo",
                    expected_revision=1,
                    source_session_id="session-demo",
                    current_state="Awaiting reconciliation.",
                    turning_points=("session-demo: Recorded the result.",),
                    failure_mode=None,
                    resolution=None,
                    open_questions=(),
                    related_decision_ids=(),
                ),
                origin_task_id="task-direct",
                coordinator_task_id="task-controller",
            )
            path = preserve_unbound_session_candidate(
                root,
                unbound,
                context("tx-unbound-session"),
            )
            relative_path = path.relative_to(root).as_posix()
            raw = path.read_bytes()

            artifact = parse_proposal_artifact(relative_path, raw)

            self.assertIsInstance(artifact, UnboundSessionProposal)
            self.assertEqual("session-demo", artifact.session_candidate.envelope.memory_id)
            self.assertEqual(body, artifact.session_candidate.body)
            self.assertEqual("story-demo", artifact.candidate_primary_story_id)
            self.assertEqual("story-demo", artifact.intended_story_delta.story_id)
            self.assertEqual("task-direct", artifact.origin_task_id)
            document = json.loads(raw.decode("utf-8"))
            self.assertEqual("unbound-session", document["operation"])
            self.assertEqual("proposed", document["status"])

            extra = json.loads(raw.decode("utf-8"))
            extra["desired"]["unexpected"] = "redacted-test-value"
            with self.assertRaisesRegex(ValidationError, "^proposal-invalid-shape$"):
                parse_proposal_artifact(relative_path, _canonical(extra))
            with self.assertRaisesRegex(ValidationError, "^proposal-noncanonical$"):
                parse_proposal_artifact(relative_path, json.dumps(document).encode("utf-8"))

    def _migration_proposal(self):
        root, _, result = _applied_golden_migration(self)
        relative_path = next(
            path
            for path in result.proposal_paths
            if path.endswith("action-a6d2a9c1b7093f582ddf.json")
        )
        return relative_path, (root / relative_path).read_bytes()

    def test_migration_writer_output_round_trips_through_tagged_reader(self):
        relative_path, raw = self._migration_proposal()

        artifact = parse_proposal_artifact(relative_path, raw)

        self.assertIsInstance(artifact, MigrationReviewProposal)
        self.assertEqual("action-a6d2a9c1b7093f582ddf", artifact.proposal_id)
        self.assertEqual("ambiguous-owner", artifact.classification.value)
        self.assertEqual(
            "projects/demo/sessions/2026-01-01-cache.md",
            artifact.source_path,
        )
        self.assertEqual(hashlib.sha256(raw).hexdigest(), artifact.sha256)
        self.assertEqual(len(raw), artifact.size)

    def test_migration_review_proposal_rejects_shape_identity_and_hash_tampering(self):
        relative_path, raw = self._migration_proposal()
        document = json.loads(raw.decode("utf-8"))

        mutations = []

        missing = dict(document)
        missing.pop("actor")
        mutations.append((relative_path, _canonical(missing), "proposal-invalid-shape"))

        extra = dict(document)
        extra["unexpected"] = "redacted-test-value"
        mutations.append((relative_path, _canonical(extra), "proposal-invalid-shape"))

        wrong_operation = dict(document)
        wrong_operation["operation"] = "unknown-operation"
        mutations.append(
            (relative_path, _canonical(wrong_operation), "proposal-unsupported-operation")
        )

        invalid_timestamp = dict(document)
        invalid_timestamp["occurred_at"] = "not-a-timestamp"
        mutations.append(
            (relative_path, _canonical(invalid_timestamp), "proposal-invalid-timestamp")
        )

        invalid_digest = json.loads(raw.decode("utf-8"))
        invalid_digest["desired"]["source_sha256"] = "A" * 64
        mutations.append(
            (relative_path, _canonical(invalid_digest), "proposal-invalid-source-digest")
        )

        invalid_revision = json.loads(raw.decode("utf-8"))
        invalid_revision["expected_base"]["source_revision"] = "0" * 63
        mutations.append(
            (
                relative_path,
                _canonical(invalid_revision),
                "proposal-invalid-source-revision",
            )
        )

        filename_mismatch = relative_path.replace(
            "action-a6d2a9c1b7093f582ddf", "different-action"
        )
        mutations.append((filename_mismatch, raw, "proposal-invalid-identity"))

        transaction_mismatch = dict(document)
        transaction_mismatch["transaction_id"] = "different-action"
        mutations.append(
            (relative_path, _canonical(transaction_mismatch), "proposal-invalid-identity")
        )

        action_mismatch = json.loads(raw.decode("utf-8"))
        action_mismatch["desired"]["action_id"] = "different-action"
        mutations.append(
            (relative_path, _canonical(action_mismatch), "proposal-invalid-identity")
        )

        target_mismatch = dict(document)
        target_mismatch["target"] = "skills/rebuild-index.md"
        mutations.append(
            (relative_path, _canonical(target_mismatch), "proposal-target-mismatch")
        )

        invalid_source = json.loads(raw.decode("utf-8"))
        invalid_source["desired"]["source_path"] = "../outside.md"
        mutations.append(
            (
                relative_path,
                _canonical(invalid_source),
                "proposal-invalid-source-path",
            )
        )

        unknown_classification = json.loads(raw.decode("utf-8"))
        unknown_classification["desired"]["classification"] = "redacted-test-value"
        mutations.append(
            (
                relative_path,
                _canonical(unknown_classification),
                "proposal-invalid-classification",
            )
        )

        duplicate = raw.replace(
            b'  "actor": "fixture-agent",\n',
            b'  "actor": "fixture-agent",\n  "actor": "fixture-agent",\n',
            1,
        )
        mutations.extend(
            (
                (relative_path, duplicate, "proposal-duplicate-key"),
                (relative_path, json.dumps(document).encode("utf-8"), "proposal-noncanonical"),
                (relative_path, b"\xff", "proposal-invalid-utf8"),
                ("../redacted-test-value.json", raw, "proposal-invalid-path"),
            )
        )

        for path, candidate_raw, reason in mutations:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValidationError, "^" + reason + "$") as caught:
                    parse_proposal_artifact(path, candidate_raw)
                self.assertNotIn("redacted-test-value", str(caught.exception))

    def test_transaction_conflict_family_preserves_existing_shapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "memory"
            initialize(root)
            commit_record(root, candidate(), 0, None, context("tx-record-accepted"))

            commit_outcome = commit_record(
                root,
                candidate(revision=2, supersedes="memory-1@1", body="stale"),
                0,
                1,
                context("tx-record-conflict"),
            )
            focus_outcome = update_focus(
                root,
                "demo",
                0,
                ("missing-record",),
                "2026-08-30T00:00:00Z",
                context("tx-focus-conflict"),
            )
            promotion_path = preserve_promotion_candidate(
                root,
                PromotionCandidate(
                    "promotion-1",
                    ("memory-1",),
                    "knowledge/topics/portable-memory.md",
                    "Reusable invariant",
                ),
                context("tx-promotion"),
            )

            proposal_paths = (
                commit_outcome.proposal_path,
                focus_outcome.proposal_path,
                promotion_path,
            )
            self.assertEqual(
                ("commit-record", "update_focus", "knowledge-promotion"),
                tuple(json.loads(path.read_text("utf-8"))["operation"] for path in proposal_paths),
            )
            for path in proposal_paths:
                relative_path = path.relative_to(root).as_posix()
                raw = path.read_bytes()
                artifact = parse_proposal_artifact(relative_path, raw)
                self.assertIsInstance(artifact, TransactionConflictProposal)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), artifact.sha256)
                self.assertEqual(len(raw), artifact.size)

                document = json.loads(raw.decode("utf-8"))
                invalid_documents = []
                missing = dict(document)
                missing.pop("conflict_code")
                invalid_documents.append(missing)
                extra = dict(document)
                extra["unexpected"] = "redacted-test-value"
                invalid_documents.append(extra)
                invalid_target = dict(document)
                invalid_target["target"] = "../redacted-test-value"
                invalid_documents.append(invalid_target)

                operation = document["operation"]
                if operation == "commit-record":
                    invalid_base = json.loads(raw.decode("utf-8"))
                    invalid_base["expected_base"] = {"catalog_revision": 0}
                    invalid_documents.append(invalid_base)
                elif operation == "update_focus":
                    invalid_desired = json.loads(raw.decode("utf-8"))
                    invalid_desired["desired"]["record_ids"] = [
                        "missing-record",
                        "missing-record",
                    ]
                    invalid_documents.append(invalid_desired)
                else:
                    invalid_conflict = dict(document)
                    invalid_conflict["conflict_code"] = "different-conflict"
                    invalid_documents.append(invalid_conflict)

                for invalid in invalid_documents:
                    with self.assertRaisesRegex(
                        ValidationError,
                        "^proposal-(?:invalid-shape|invalid-target)$",
                    ) as caught:
                        parse_proposal_artifact(relative_path, _canonical(invalid))
                    self.assertNotIn("redacted-test-value", str(caught.exception))

                changed_name = str(Path(relative_path).with_name("different-proposal.json")).replace(
                    "\\", "/"
                )
                with self.assertRaisesRegex(
                    ValidationError,
                    "^proposal-invalid-shape$",
                ):
                    parse_proposal_artifact(changed_name, raw)


if __name__ == "__main__":
    unittest.main()
