import dataclasses
import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT, fixture_root
from tests.unit.test_artifact_schemas import _applied_golden_migration
from tests.unit.test_migration_bundle_compatibility import _bundle_path

from obsidian_agent_memory.migration import (
    ProjectIdMapping,
    SourceCategory,
    SourceEntry,
    derive_legacy_owner_candidate,
    load_migration_bundle,
    plan_v1_to_v2,
)
from obsidian_agent_memory.models import TransactionContext
from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.artifact_schemas import (
    MigrationReviewClassification,
    MigrationReviewProposal,
    parse_proposal_artifact,
)
from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope
from obsidian_agent_memory.proposal_review import (
    FactBlock,
    FactOccurrenceInput,
    ReviewItemInput,
    _canonical_report_bytes,
    _parse_proposal_review_bytes,
    build_proposal_review_artifact,
    build_review_model,
    build_conflict_evidence,
    candidate_owner_for_action,
    group_conflict_evidence,
    load_proposal_review,
    review_inputs_for_bundle,
)
from obsidian_agent_memory.publication import publish_immutable_report


REPORT_FIXTURE = (
    REPO_ROOT / "tests" / "fixtures" / "reports" / "proposal-review-schema-1-minimal.json"
)
REPORT_DIGEST_FIXTURE = REPORT_FIXTURE.with_suffix(".sha256")


class ProposalReviewBuildTests(unittest.TestCase):
    def _built_golden_artifact(self):
        root, bundle, result = _applied_golden_migration(self)
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
            code_identity={
                "kind": "fixture",
                "revision": "proposal-review-fixture-v1",
            },
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

    def test_report_bytes_are_sorted_location_independent_and_plaintext_free(self):
        raw = REPORT_FIXTURE.read_bytes()
        self.assertEqual(
            "1a12b214ac0b5ffe35ce514d40e8db1d030a62e17accc9f81b70d70f2b483744",
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            REPORT_DIGEST_FIXTURE.read_text("ascii").strip(),
        )
        loaded = _parse_proposal_review_bytes(raw)
        self.assertEqual(raw, _canonical_report_bytes(loaded.document))
        self.assertEqual(
            "review-05df7a1e69fdf7cf07f92b68e3a12dd083837ebf189c3a08f502a5e7b6422df0",
            loaded.review_id,
        )

        first = self._built_golden_artifact()
        second = self._built_golden_artifact()
        self.assertEqual(first.raw, second.raw)
        self.assertEqual(first.review_id, second.review_id)
        self.assertNotIn(b"The asset cache is enabled.", first.raw)

    def _synthetic_input(
        self,
        index,
        classification,
        raw=b"synthetic fact\n",
        candidate_owner=None,
    ):
        proposal_id = "action-{0:020d}".format(index)
        source_path = "projects/demo/sessions/synthetic-{0}.md".format(index)
        source_sha256 = __import__("hashlib").sha256(raw).hexdigest()
        artifact = MigrationReviewProposal(
            relative_path=".agent-memory/state/proposals/{0}.json".format(proposal_id),
            proposal_id=proposal_id,
            actor="fixture-agent",
            occurred_at="2026-09-04T00:00:00Z",
            target=source_path,
            transaction_id=proposal_id,
            sha256=str(index) * 64 if index < 10 else "f" * 64,
            size=512 + index,
            source_revision="3" * 64,
            classification=MigrationReviewClassification(classification),
            source_path=source_path,
            source_sha256=source_sha256,
        )
        return ReviewItemInput(
            artifact=artifact,
            source_category="session",
            snapshot_path="snapshot/files/" + source_path,
            snapshot_sha256=source_sha256,
            snapshot_raw=raw,
            candidate_owner=candidate_owner,
            live_source_state="unchanged",
        )

    def test_report_conserves_all_selected_proposals_and_statuses(self):
        root, bundle, result = _applied_golden_migration(self)
        artifacts = tuple(
            parse_proposal_artifact(path, (root / path).read_bytes())
            for path in result.proposal_paths
        )
        inputs = list(review_inputs_for_bundle(bundle, artifacts))
        expected_status = {
            "unknown-format": ("manual-format-review", "choose-source-format"),
            "embedded-knowledge-external": (
                "knowledge-routing-review",
                "choose-knowledge-destination",
            ),
            "legacy-focus-input": (
                "focus-history-review",
                "extract-or-dismiss-focus-history",
            ),
            "legacy-project-id-mapping-required": (
                "project-id-routing-review",
                "supply-project-id-mapping",
            ),
        }
        for index, classification in enumerate(expected_status, 1):
            inputs.append(self._synthetic_input(index, classification))
        owner = {
            "candidate_memory_id": "migr-aaaaaaaaaaaaaaaaaaaaaaaa",
            "owner_scope": "project.demo.session",
            "project_id": "demo",
            "record_type": "session",
        }
        inputs.append(
            self._synthetic_input(
                5,
                "ambiguous-owner",
                raw=b"\xff",
                candidate_owner=owner,
            )
        )
        inputs.append(self._synthetic_input(6, "ambiguous-owner", candidate_owner=None))

        model = build_review_model(
            bundle.bundle_sha256,
            bundle.plan.source_revision,
            tuple(inputs),
        )

        self.assertEqual(len(inputs), len(model.items))
        self.assertEqual(
            {item.artifact.proposal_id for item in inputs},
            {item.proposal_id for item in model.items},
        )
        by_classification = {
            item.prior_classification: (item.refined_status, item.decision_code)
            for item in model.items
            if item.prior_classification != "ambiguous-owner"
        }
        self.assertEqual(expected_status, by_classification)
        by_id = {item.proposal_id: item for item in model.items}
        self.assertEqual(
            ("manual-parse-review", "inspect-unparseable-source"),
            (by_id["action-00000000000000000005"].refined_status,
             by_id["action-00000000000000000005"].decision_code),
        )
        self.assertEqual(
            ("manual-parse-review", "candidate-owner-unavailable"),
            (by_id["action-00000000000000000006"].refined_status,
             by_id["action-00000000000000000006"].decision_code),
        )
        golden_by_source = {
            item.source_path: item
            for item in model.items
            if "synthetic-" not in item.source_path
        }
        self.assertEqual(
            "manual-owner-review",
            golden_by_source["projects/demo/sessions/2026-01-01-cache.md"].refined_status,
        )
        self.assertEqual(
            "manual-owner-review",
            golden_by_source["projects/demo/stories/cache.md"].refined_status,
        )
        self.assertEqual(
            "path-owner-candidate",
            golden_by_source["preferences/review-style.md"].refined_status,
        )
        self.assertEqual(
            "path-owner-candidate",
            golden_by_source["skills/rebuild-index.md"].refined_status,
        )

    def test_report_model_does_not_retain_plaintext(self):
        sentinel = "api_key = fictional-secret-value-1234"
        item = self._synthetic_input(
            7,
            "ambiguous-owner",
            raw=(sentinel + "\n").encode("utf-8"),
            candidate_owner={
                "candidate_memory_id": "migr-bbbbbbbbbbbbbbbbbbbbbbbb",
                "owner_scope": "project.demo.session",
                "project_id": "demo",
                "record_type": "session",
            },
        )

        model = build_review_model("2" * 64, "3" * 64, (item,))
        value = dataclasses.asdict(model)
        encoded = json.dumps(value, sort_keys=True).encode("utf-8")

        self.assertNotIn(sentinel, repr(model))
        self.assertNotIn(sentinel, repr(value))
        self.assertNotIn(sentinel.encode("utf-8"), encoded)


class ProposalReviewLoaderTests(unittest.TestCase):
    def test_canonical_report_round_trips_with_literal_digest(self):
        raw = REPORT_FIXTURE.read_bytes()

        artifact = load_proposal_review(REPORT_FIXTURE)

        self.assertEqual(raw, artifact.raw)
        self.assertEqual(
            "1a12b214ac0b5ffe35ce514d40e8db1d030a62e17accc9f81b70d70f2b483744",
            artifact.report_sha256,
        )
        self.assertEqual(
            "review-05df7a1e69fdf7cf07f92b68e3a12dd083837ebf189c3a08f502a5e7b6422df0",
            artifact.review_id,
        )
        self.assertNotIn("report_sha256", artifact.document)

    def test_report_loader_rejects_schema_and_cross_field_tampering(self):
        raw = REPORT_FIXTURE.read_bytes()
        original = json.loads(raw.decode("utf-8"))
        mutations = []

        for key in tuple(original):
            value = json.loads(raw.decode("utf-8"))
            value.pop(key)
            mutations.append(value)
        extra = json.loads(raw.decode("utf-8"))
        extra["unexpected"] = 1
        mutations.append(extra)
        for key, replacement in (
            ("schema_version", 2),
            ("report_kind", "other"),
            ("classifier_version", "other"),
        ):
            value = json.loads(raw.decode("utf-8"))
            value[key] = replacement
            mutations.append(value)
        for code_identity in (
            {"kind": "fixture"},
            {"kind": "fixture", "revision": "Invalid Revision"},
            {"kind": "git-commit", "revision": "a" * 40, "tree_state": "dirty"},
            {"kind": "pack-manifest", "manifest_sha256": "1" * 64, "version": "2.0.0"},
        ):
            value = json.loads(raw.decode("utf-8"))
            value["code_identity"] = code_identity
            mutations.append(value)

        nested_mutations = (
            ("items", 0, "proposal_path", "C:/absolute/proposal.json"),
            ("items", 0, "refined_status", "other"),
            ("items", 0, "proposal_size", -1),
            ("items", 0, "evidence_ids", ["evidence-" + "7" * 64]),
            ("inputs", "proposal_set_sha256", None, "0" * 64),
            ("summary", "total", None, 2),
        )
        for section, selector, field, replacement in nested_mutations:
            value = json.loads(raw.decode("utf-8"))
            if section == "items":
                value[section][selector][field] = replacement
            else:
                value[section][selector] = replacement
            mutations.append(value)
        wrong_review = json.loads(raw.decode("utf-8"))
        wrong_review["review_id"] = "review-" + "0" * 64
        mutations.append(wrong_review)
        duplicate_item = json.loads(raw.decode("utf-8"))
        duplicate_item["items"].append(dict(duplicate_item["items"][0]))
        mutations.append(duplicate_item)

        invalid_raw = [
            raw.replace(
                b'{"classifier_version":',
                b'{"classifier_version":"owner-block-v1","classifier_version":',
                1,
            ),
            json.dumps(original, indent=2, sort_keys=True).encode("utf-8"),
        ]
        invalid_raw.extend(_canonical_report_bytes(value) for value in mutations)
        for candidate_raw in invalid_raw:
            with self.subTest(digest=hashlib.sha256(candidate_raw).hexdigest()):
                with self.assertRaises(ValidationError):
                    _parse_proposal_review_bytes(candidate_raw)


class ProposalReviewPublicationTests(unittest.TestCase):
    def test_external_output_rejects_overlap_and_reparse_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            protected = base / "protected"
            protected.mkdir()
            output = protected / "reports" / "report.json"
            with self.assertRaises(ValidationError):
                publish_immutable_report(
                    output, REPORT_FIXTURE.read_bytes(), ".proposal-review-",
                    (protected,), _parse_proposal_review_bytes,
                )

    def test_success_and_occupied_targets_are_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            output = base / "external" / "report.json"
            raw = REPORT_FIXTURE.read_bytes()
            self.assertEqual(
                "created",
                publish_immutable_report(
                    output, raw, ".proposal-review-", (), _parse_proposal_review_bytes,
                ),
            )
            self.assertEqual(raw, output.read_bytes())
            self.assertEqual(
                "occupied",
                publish_immutable_report(
                    output, raw, ".proposal-review-", (), _parse_proposal_review_bytes,
                ),
            )
            output.write_bytes(b"different")
            self.assertEqual(
                "occupied",
                publish_immutable_report(
                    output, raw, ".proposal-review-", (), _parse_proposal_review_bytes,
                ),
            )
            self.assertEqual(b"different", output.read_bytes())

    def test_failure_checkpoints_leave_output_parent_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            output = base / "external" / "nested" / "report.json"

            def reject(raw):
                raise ValidationError("injected candidate rejection")

            with self.assertRaises(ValidationError):
                publish_immutable_report(
                    output, REPORT_FIXTURE.read_bytes(), ".proposal-review-", (), reject,
                )
            self.assertFalse(output.exists())
            self.assertFalse((base / "external").exists())

    def test_conflict_evidence_requires_distinct_frozen_candidate_owners(self):
        bundle = load_migration_bundle(_bundle_path("schema_2"))

        evidence = build_conflict_evidence(bundle)

        self.assertEqual(1, len(evidence))
        self.assertEqual(
            "72526c139a59069e280125ffd25a91706c5a5dd150e149640307123a11d6ae59",
            evidence[0].fact_sha256,
        )
        self.assertEqual("evidence-" + evidence[0].fact_sha256, evidence[0].evidence_id)
        self.assertEqual(
            (
                "projects/demo/sessions/2026-01-01-cache.md",
                "projects/demo/stories/cache.md",
            ),
            tuple(item.source_path for item in evidence[0].occurrences),
        )
        self.assertEqual(
            ("project.demo.session", "project.demo.story"),
            tuple(item.candidate_owner["owner_scope"] for item in evidence[0].occurrences),
        )

        one_owner = {
            "candidate_memory_id": "migr-aaaaaaaaaaaaaaaaaaaaaaaa",
            "owner_scope": "project.demo.session",
            "project_id": "demo",
            "record_type": "session",
        }
        repeated = (
            FactOccurrenceInput(
                "projects/demo/sessions/repeated.md",
                "a" * 64,
                "session",
                one_owner,
                FactBlock(b"same fact", 1, 1),
            ),
            FactOccurrenceInput(
                "projects/demo/sessions/repeated.md",
                "a" * 64,
                "session",
                one_owner,
                FactBlock(b"same fact", 3, 3),
            ),
        )
        self.assertEqual(
            (),
            group_conflict_evidence(
                bundle.bundle_sha256,
                bundle.plan.source_revision,
                repeated,
            ),
        )

        with tempfile.TemporaryDirectory() as temporary:
            duplicate_bundle = plan_v1_to_v2(
                fixture_root("v1-duplicate-owners"),
                Path(temporary),
                TransactionContext(
                    "proposal-review-duplicate-plan",
                    "fixture-agent",
                    "2026-09-04T00:00:00Z",
                ),
                AuthorizationGate(OperationScope.FIXTURE, None),
            )
            duplicate_evidence = build_conflict_evidence(duplicate_bundle)
        self.assertEqual(1, len(duplicate_evidence))
        self.assertEqual(3, len(duplicate_evidence[0].occurrences))
        self.assertEqual(
            ("preference", "session", "story"),
            tuple(item.source_category for item in duplicate_evidence[0].occurrences),
        )

    def test_path_owner_candidates_replay_frozen_migration_rules(self):
        bundle = load_migration_bundle(_bundle_path("schema_2"))
        expected = {
            "preferences/review-style.md": (
                "migr-612f3330563f0e03ba709c06",
                "user.preference",
                None,
                "preference",
            ),
            "projects/demo/sessions/2026-01-01-cache.md": (
                "migr-a6d2a9c1b7093f582ddf07a2",
                "project.demo.session",
                "demo",
                "session",
            ),
            "projects/demo/stories/cache.md": (
                "migr-08abd43c55206132f42eb96f",
                "project.demo.story",
                "demo",
                "story",
            ),
            "skills/rebuild-index.md": (
                "migr-e2cb78b206a7dbd62b74b72d",
                "agent.runbook",
                None,
                "runbook",
            ),
        }
        entries = {entry.relative_path: entry for entry in bundle.detection.entries}
        actions = {action.source_path: action for action in bundle.plan.actions}

        for path, values in expected.items():
            with self.subTest(path=path):
                candidate = derive_legacy_owner_candidate(
                    entries[path], bundle.plan.project_id_mappings
                )
                self.assertIsNotNone(candidate)
                self.assertEqual(
                    values,
                    (
                        candidate.candidate_memory_id,
                        candidate.owner_scope,
                        candidate.project_id,
                        candidate.record_type,
                    ),
                )
                self.assertEqual(
                    {
                        "candidate_memory_id": values[0],
                        "owner_scope": values[1],
                        "project_id": values[2],
                        "record_type": values[3],
                    },
                    candidate_owner_for_action(bundle, actions[path]),
                )

        invalid_project = SourceEntry(
            "projects/Invalid Project/sessions/example.md",
            "0" * 64,
            0,
            SourceCategory.SESSION,
        )
        self.assertIsNone(derive_legacy_owner_candidate(invalid_project, ()))
        self.assertIsNotNone(
            derive_legacy_owner_candidate(
                invalid_project,
                (ProjectIdMapping("Invalid Project", "valid-project"),),
            )
        )
        non_owner = SourceEntry("AGENTS.md", "1" * 64, 0, SourceCategory.CONTRACT)
        self.assertIsNone(derive_legacy_owner_candidate(non_owner, ()))

        action = actions["projects/demo/sessions/2026-01-01-cache.md"]
        self.assertIsNone(
            candidate_owner_for_action(
                bundle,
                dataclasses.replace(action, source_sha256="f" * 64),
            )
        )
        self.assertIsNone(
            candidate_owner_for_action(
                bundle,
                dataclasses.replace(action, action_id="action-wrong"),
            )
        )


if __name__ == "__main__":
    unittest.main()
