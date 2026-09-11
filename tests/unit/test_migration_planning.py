import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.helpers import copy_vault_fixture, fixture_root, tree_hashes

from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.migration import (
    MigrationActionKind,
    UnresolvedClassification,
    apply_migration,
    detect_vault,
    load_migration_bundle,
    plan_v1_to_v2,
)
from obsidian_agent_memory.models import TransactionContext
from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope


FIXTURE_GATE = AuthorizationGate(OperationScope.FIXTURE, None)
CONTEXT = TransactionContext(
    transaction_id="migration-plan-0001",
    actor="fixture-agent",
    occurred_at="2026-08-30T01:00:00Z",
)


def _relative_files(root: Path):
    return {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file()
    }


class MigrationPlanningTests(unittest.TestCase):
    def test_unmapped_legacy_project_id_becomes_one_auditable_review_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            (root / "projects" / "demo").rename(
                root / "projects" / "JustDanceMobile"
            )

            bundle = plan_v1_to_v2(root, parent / "work", CONTEXT, FIXTURE_GATE)

            project_actions = tuple(
                action
                for action in bundle.plan.actions
                if action.source_path.startswith("projects/JustDanceMobile/")
            )
            self.assertTrue(project_actions)
            for action in project_actions:
                self.assertEqual(MigrationActionKind.UNRESOLVED_PROPOSAL, action.kind)
                self.assertEqual(
                    UnresolvedClassification.LEGACY_PROJECT_ID_MAPPING_REQUIRED,
                    action.unresolved_classification,
                )
                self.assertIsNone(action.target_path)
                self.assertIsNone(action.record_type)
                self.assertIsNone(action.owner_scope)
                self.assertIsNone(action.project_id)
                self.assertIsNone(action.memory_id)
                self.assertEqual((), action.projection_effects)

            mapping_findings = tuple(
                finding
                for finding in bundle.plan.findings
                if finding.code == "legacy-project-id-mapping-required"
            )
            self.assertEqual(1, len(mapping_findings))
            self.assertEqual(
                "projects/JustDanceMobile",
                mapping_findings[0].path,
            )

    def test_explicit_project_id_mapping_rewrites_all_targets_and_round_trips(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            (root / "projects" / "demo").rename(
                root / "projects" / "JustDanceMobile"
            )

            bundle = plan_v1_to_v2(
                root,
                parent / "work",
                CONTEXT,
                FIXTURE_GATE,
                {"JustDanceMobile": "just-dance-mobile"},
            )

            self.assertEqual(
                [("JustDanceMobile", "just-dance-mobile")],
                [
                    (mapping.source_project_id, mapping.target_project_id)
                    for mapping in bundle.plan.project_id_mappings
                ],
            )
            project_record_actions = tuple(
                action
                for action in bundle.plan.actions
                if action.record_type in {"session", "story", "decision"}
                and action.project_id is not None
            )
            self.assertTrue(project_record_actions)
            self.assertTrue(
                all(
                    action.owner_scope.startswith("project.just-dance-mobile.")
                    for action in project_record_actions
                )
            )
            self.assertTrue(
                all(action.project_id == "just-dance-mobile" for action in project_record_actions)
            )
            chronology = tuple(
                action
                for action in bundle.plan.actions
                if action.source_path == "snapshot.json"
                and action.record_type == "session"
            )
            self.assertEqual(1, len(chronology))
            self.assertEqual("just-dance-mobile", chronology[0].project_id)
            self.assertEqual(
                "project.just-dance-mobile.session",
                chronology[0].owner_scope,
            )
            self.assertTrue(
                chronology[0].target_path.startswith(
                    "_records/projects/just-dance-mobile/sessions/"
                )
            )
            self.assertEqual(
                (
                    "_index/current-focus.md",
                    "_index/home.md",
                    "_index/memory-map.md",
                    "_index/stale-or-uncertain.md",
                    "projects/just-dance-mobile/current-focus.md",
                    "projects/just-dance-mobile/overview.md",
                ),
                chronology[0].projection_effects,
            )

            actions = {
                action.source_path: action
                for action in bundle.plan.actions
                if action.source_path != "snapshot.json"
            }
            self.assertEqual(
                "_sources/projects/just-dance-mobile/raw/source.txt",
                actions["projects/JustDanceMobile/raw/source.txt"].target_path,
            )
            project_effects = tuple(
                effect
                for action in bundle.plan.actions
                for effect in action.projection_effects
                if effect.startswith("projects/")
            )
            self.assertTrue(project_effects)
            self.assertTrue(
                all(
                    effect.startswith("projects/just-dance-mobile/")
                    for effect in project_effects
                )
            )
            self.assertTrue(
                all(
                    action.source_path.startswith("projects/JustDanceMobile/")
                    for action in actions.values()
                    if action.source_path.startswith("projects/")
                )
            )
            self.assertTrue(
                any(
                    entry.relative_path.startswith("projects/JustDanceMobile/")
                    for entry in bundle.snapshot.entries
                )
            )
            plan_document = json.loads((bundle.bundle_dir / "plan.json").read_text("utf-8"))
            self.assertEqual(2, plan_document["schema_version"])
            self.assertEqual(
                [
                    {
                        "source_project_id": "JustDanceMobile",
                        "target_project_id": "just-dance-mobile",
                    }
                ],
                plan_document["project_id_mappings"],
            )
            self.assertEqual(bundle, load_migration_bundle(bundle.bundle_dir))

    def test_schema_one_plan_loads_with_empty_project_id_mappings(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = plan_v1_to_v2(
                fixture_root("v1-minimal"),
                Path(temporary),
                CONTEXT,
                FIXTURE_GATE,
            )
            plan_path = bundle.bundle_dir / "plan.json"
            legacy_plan = json.loads(plan_path.read_text("utf-8"))
            legacy_plan.pop("project_id_mappings")
            legacy_plan["schema_version"] = 1
            plan_path.write_bytes(
                (
                    json.dumps(
                        legacy_plan,
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8")
            )

            loaded = load_migration_bundle(bundle.bundle_dir)

            self.assertEqual((), loaded.plan.project_id_mappings)
            self.assertEqual(bundle.plan.actions, loaded.plan.actions)
            self.assertEqual(bundle.plan.findings, loaded.plan.findings)

    def test_project_id_mapping_arguments_are_strictly_validated_before_bundle_creation(self):
        cases = (
            (
                "undetected-source",
                {"missing-project": "other-project"},
                "project id mapping source was not detected",
                False,
            ),
            (
                "duplicate-source",
                (("demo", "first-target"), ("demo", "second-target")),
                "duplicate project id mapping source",
                False,
            ),
            (
                "nonportable-target",
                {"demo": "BadTarget"},
                "invalid target_project_id",
                False,
            ),
            (
                "no-op",
                {"demo": "demo"},
                "project id mapping is a no-op",
                False,
            ),
            (
                "case-only-windows-alias",
                {"JustDanceMobile": "justdancemobile"},
                "case-only project id alias",
                True,
            ),
        )
        for name, mapping, message, rename_demo in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root = copy_vault_fixture("v1-minimal", parent)
                if rename_demo:
                    (root / "projects" / "demo").rename(
                        root / "projects" / "JustDanceMobile"
                    )
                bundle_dir = parent / "work" / CONTEXT.transaction_id

                with self.assertRaisesRegex(ValidationError, message):
                    plan_v1_to_v2(
                        root,
                        parent / "work",
                        CONTEXT,
                        FIXTURE_GATE,
                        mapping,
                    )

                self.assertFalse(bundle_dir.exists())

    def test_effective_project_id_collision_refuses_before_bundle_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            demo = root / "projects" / "demo"
            shutil.copytree(demo, root / "projects" / "JustDanceMobile")
            demo.rename(root / "projects" / "just-dance-mobile")
            bundle_dir = parent / "work" / CONTEXT.transaction_id

            with self.assertRaisesRegex(ValidationError, "effective project id collision"):
                plan_v1_to_v2(
                    root,
                    parent / "work",
                    CONTEXT,
                    FIXTURE_GATE,
                    {"JustDanceMobile": "just-dance-mobile"},
                )

            self.assertFalse(bundle_dir.exists())

    def test_mapped_raw_target_occupied_by_another_source_refuses_before_bundle_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            (root / "projects" / "demo").rename(
                root / "projects" / "JustDanceMobile"
            )
            occupied = (
                root
                / "_sources"
                / "projects"
                / "just-dance-mobile"
                / "raw"
                / "source.txt"
            )
            occupied.parent.mkdir(parents=True)
            occupied.write_text("pre-existing unrelated source\n", "utf-8")
            bundle_dir = parent / "work" / CONTEXT.transaction_id

            with self.assertRaisesRegex(
                ValidationError,
                "raw source target is occupied by a different source",
            ):
                plan_v1_to_v2(
                    root,
                    parent / "work",
                    CONTEXT,
                    FIXTURE_GATE,
                    {"JustDanceMobile": "just-dance-mobile"},
                )

            self.assertFalse(bundle_dir.exists())

    def test_mapped_raw_target_case_equivalent_source_refuses_before_bundle_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            (root / "projects" / "demo").rename(
                root / "projects" / "JustDanceMobile"
            )
            occupied = (
                root
                / "_SOURCES"
                / "projects"
                / "just-dance-mobile"
                / "raw"
                / "source.txt"
            )
            occupied.parent.mkdir(parents=True)
            occupied.write_text("pre-existing case-equivalent source\n", "utf-8")
            detected_paths = {
                entry.relative_path
                for entry in detect_vault(root, FIXTURE_GATE).entries
            }
            self.assertIn(
                "_SOURCES/projects/just-dance-mobile/raw/source.txt",
                detected_paths,
            )
            bundle_dir = parent / "work" / CONTEXT.transaction_id

            with self.assertRaisesRegex(
                ValidationError,
                "raw source target is occupied by a different source",
            ):
                plan_v1_to_v2(
                    root,
                    parent / "work",
                    CONTEXT,
                    FIXTURE_GATE,
                    {"JustDanceMobile": "just-dance-mobile"},
                )

            self.assertFalse(bundle_dir.exists())

    def test_identical_mapped_inputs_produce_identical_bundle_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            (root / "projects" / "demo").rename(
                root / "projects" / "JustDanceMobile"
            )
            mapping = {"JustDanceMobile": "just-dance-mobile"}

            left = plan_v1_to_v2(
                root, parent / "first", CONTEXT, FIXTURE_GATE, mapping
            )
            right = plan_v1_to_v2(
                root, parent / "second", CONTEXT, FIXTURE_GATE, mapping
            )

            self.assertEqual(left.bundle_sha256, right.bundle_sha256)
            self.assertEqual(
                {
                    path: file.read_bytes()
                    for path, file in _relative_files(left.bundle_dir).items()
                },
                {
                    path: file.read_bytes()
                    for path, file in _relative_files(right.bundle_dir).items()
                },
            )

    def test_mapped_handled_sources_are_archived_but_unknown_sources_remain_active(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            (root / "projects" / "demo").rename(
                root / "projects" / "JustDanceMobile"
            )
            unknown = root / "projects" / "JustDanceMobile" / "unknown.txt"
            unknown.write_text("unresolved legacy input\n", "utf-8")
            bundle = plan_v1_to_v2(
                root,
                parent / "work",
                CONTEXT,
                FIXTURE_GATE,
                {"JustDanceMobile": "just-dance-mobile"},
            )

            result = apply_migration(
                root,
                bundle,
                bundle.bundle_sha256,
                TransactionContext(
                    "migration-apply-mapped",
                    "fixture-agent",
                    "2026-08-30T02:00:00Z",
                ),
                FIXTURE_GATE,
            )

            handled = {
                "projects/JustDanceMobile/current-focus.md",
                "projects/JustDanceMobile/decisions/cache-policy.md",
                "projects/JustDanceMobile/overview.md",
                "projects/JustDanceMobile/raw/source.txt",
                "projects/JustDanceMobile/sessions/2026-01-01-bootstrap.md",
                "projects/JustDanceMobile/stories/cache-failure.md",
            }
            self.assertTrue(handled.issubset(set(result.archived_paths)))
            self.assertNotIn(
                "projects/JustDanceMobile/unknown.txt",
                result.archived_paths,
            )
            self.assertTrue(unknown.is_file())

    def test_base_view_is_preserved_without_owning_story_or_knowledge(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            (root / "_index" / "story-knowledge.base").write_text(
                "filters:\n  and:\n    - file.folder == 'knowledge'\n", "utf-8"
            )
            knowledge = root / "knowledge" / "modeling" / "retopology.md"
            knowledge.parent.mkdir(parents=True)
            knowledge.write_text("# Retopology\n", "utf-8")
            bundle = plan_v1_to_v2(root, parent / "work", CONTEXT, FIXTURE_GATE)
            actions = {
                action.source_path: action
                for action in bundle.plan.actions
                if action.source_path != "snapshot.json"
            }
            base = actions["_index/story-knowledge.base"]
            self.assertEqual(MigrationActionKind.PRESERVE, base.kind)
            self.assertEqual("_index/story-knowledge.base", base.target_path)
            self.assertEqual((), base.projection_effects)
            self.assertEqual(
                MigrationActionKind.EMBEDDED_KNOWLEDGE_REVIEW,
                actions["knowledge/modeling/retopology.md"].kind,
            )
            self.assertEqual(
                MigrationActionKind.RECORD,
                actions["projects/demo/stories/cache-failure.md"].kind,
            )
            self.assertEqual(bundle, load_migration_bundle(bundle.bundle_dir))

    def test_snapshot_copies_every_detected_byte_and_round_trips_strictly(self):
        source = fixture_root("v1-minimal")
        before = tree_hashes(source)
        with tempfile.TemporaryDirectory() as temporary:
            bundle = plan_v1_to_v2(source, Path(temporary), CONTEXT, FIXTURE_GATE)
            files = _relative_files(bundle.bundle_dir)
            expected = {"detection.json", "snapshot.json", "plan.json"}
            expected.update(entry.snapshot_path for entry in bundle.snapshot.entries)
            self.assertEqual(expected, set(files))
            self.assertTrue(
                (bundle.bundle_dir / "snapshot/files/projects/demo/sessions/2026-01-01-bootstrap.md").is_file()
            )
            detected = {entry.relative_path: entry for entry in bundle.detection.entries}
            for entry in bundle.snapshot.entries:
                source_bytes = (source / entry.relative_path).read_bytes()
                copied_bytes = (bundle.bundle_dir / entry.snapshot_path).read_bytes()
                self.assertEqual(source_bytes, copied_bytes, entry.relative_path)
                self.assertEqual(entry.size, len(copied_bytes))
                self.assertEqual(entry.sha256, hashlib.sha256(copied_bytes).hexdigest())
                self.assertEqual(entry.sha256, detected[entry.relative_path].sha256)
            self.assertEqual(bundle.plan.source_revision, bundle.snapshot.source_revision)
            self.assertIsNone(bundle.plan.authorization_ref)
            self.assertEqual(2, bundle.plan.to_schema)
            self.assertRegex(bundle.bundle_sha256, r"^[0-9a-f]{64}$")
            loaded = load_migration_bundle(bundle.bundle_dir)
            self.assertEqual(bundle, loaded)
            serialized = b"".join(
                files[name].read_bytes()
                for name in ("detection.json", "snapshot.json", "plan.json")
            )
            self.assertNotIn(str(source.resolve()).encode("utf-8"), serialized)
        self.assertEqual(before, tree_hashes(source))

    def test_source_and_bundle_overlap_or_collision_refuses_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            before = tree_hashes(root)
            cases = (
                ("same-work-dir", root, CONTEXT),
                ("work-dir-below-source", root / "work", CONTEXT),
                (
                    "bundle-equals-source",
                    root.parent,
                    TransactionContext(root.name, "fixture-agent", CONTEXT.occurred_at),
                ),
            )
            for name, work_dir, context in cases:
                with self.subTest(name=name):
                    with self.assertRaisesRegex(
                        ValidationError, "migration bundle must be outside source root"
                    ):
                        plan_v1_to_v2(root, work_dir, context, FIXTURE_GATE)
                    self.assertEqual(before, tree_hashes(root))

            work_dir = parent / "external-work"
            work_dir.mkdir()
            (work_dir / CONTEXT.transaction_id).mkdir()
            before_parent = tree_hashes(parent)
            with self.assertRaisesRegex(ValidationError, "already exists"):
                plan_v1_to_v2(root, work_dir, CONTEXT, FIXTURE_GATE)
            self.assertEqual(before_parent, tree_hashes(parent))

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            work_dir = parent / "work"
            would_be_bundle = work_dir / CONTEXT.transaction_id
            would_be_bundle.mkdir(parents=True)
            root = copy_vault_fixture("v1-minimal", would_be_bundle)
            before = tree_hashes(parent)
            with self.assertRaisesRegex(
                ValidationError, "migration bundle must be outside source root"
            ):
                plan_v1_to_v2(root, work_dir, CONTEXT, FIXTURE_GATE)
            self.assertEqual(before, tree_hashes(parent))

    def test_semantic_actions_have_deterministic_owners_targets_and_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = plan_v1_to_v2(
                fixture_root("v1-minimal"), Path(temporary), CONTEXT, FIXTURE_GATE
            )
            actions = {
                action.source_path: action
                for action in bundle.plan.actions
                if action.source_path != "snapshot.json"
            }
            expected_records = {
                "projects/demo/sessions/2026-01-01-bootstrap.md": (
                    "session",
                    "project.demo.session",
                    "_records/projects/demo/sessions/",
                ),
                "projects/demo/stories/cache-failure.md": (
                    "story",
                    "project.demo.story",
                    "_records/projects/demo/stories/",
                ),
                "projects/demo/decisions/cache-policy.md": (
                    "decision",
                    "project.demo.decision",
                    "_records/projects/demo/decisions/",
                ),
                "preferences/review-style.md": (
                    "preference",
                    "user.preference",
                    "_records/preferences/",
                ),
                "skills/rebuild-index.md": (
                    "runbook",
                    "agent.runbook",
                    "_records/runbooks/",
                ),
            }
            for path, (record_type, owner, prefix) in expected_records.items():
                action = actions[path]
                self.assertEqual(MigrationActionKind.RECORD, action.kind)
                self.assertEqual(record_type, action.record_type)
                self.assertEqual(owner, action.owner_scope)
                self.assertTrue(action.target_path.startswith(prefix), action)
                digest = hashlib.sha256(
                    (path + "\0" + action.source_sha256).encode("utf-8")
                ).hexdigest()
                self.assertEqual("migr-" + digest[:24], action.memory_id)
                self.assertEqual("action-" + digest[:20], action.action_id)

            self.assertEqual(
                MigrationActionKind.RAW_SOURCE,
                actions["projects/demo/raw/source.txt"].kind,
            )
            self.assertEqual(
                "_sources/projects/demo/raw/source.txt",
                actions["projects/demo/raw/source.txt"].target_path,
            )
            self.assertEqual(MigrationActionKind.PRESERVE, actions["AGENTS.md"].kind)
            self.assertEqual(
                MigrationActionKind.REGENERATE_PROJECTION,
                actions["_index/home.md"].kind,
            )
            for path in ("_index/current-focus.md", "projects/demo/current-focus.md"):
                action = actions[path]
                self.assertEqual(MigrationActionKind.FOCUS_PROPOSAL, action.kind)
                self.assertIsNone(action.target_path)
                self.assertIsNone(action.record_type)
                self.assertIsNone(action.owner_scope)
                self.assertIsNone(action.memory_id)
                self.assertEqual(
                    UnresolvedClassification.LEGACY_FOCUS_INPUT,
                    action.unresolved_classification,
                )
            for action in bundle.plan.actions:
                self.assertEqual(tuple(sorted(set(action.projection_effects))), action.projection_effects)

            evidence = [
                action for action in bundle.plan.actions if action.source_path == "snapshot.json"
            ]
            self.assertEqual({"migration", "session"}, {item.record_type for item in evidence})
            self.assertEqual({"meta.migration", "project.demo.session"}, {item.owner_scope for item in evidence})

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v1-minimal", parent)
            additions = {
                "README.md": "# Portable legacy vault\n",
                "meta/migrations/import.md": "Migration evidence unique to this page.\n",
                "meta/maintenance/repair.md": "Maintenance evidence unique to this page.\n",
                "notes/unclassified.md": "Unknown legacy format unique to this page.\n",
            }
            for relative_path, content in additions.items():
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content.encode("utf-8"))
            bundle = plan_v1_to_v2(root, parent / "work", CONTEXT, FIXTURE_GATE)
            actions = {
                action.source_path: action
                for action in bundle.plan.actions
                if action.source_path != "snapshot.json"
            }
            self.assertEqual(MigrationActionKind.PRESERVE, actions["README.md"].kind)
            self.assertEqual("migration", actions["meta/migrations/import.md"].record_type)
            self.assertEqual("meta.migration", actions["meta/migrations/import.md"].owner_scope)
            self.assertEqual("maintenance", actions["meta/maintenance/repair.md"].record_type)
            self.assertEqual("meta.maintenance", actions["meta/maintenance/repair.md"].owner_scope)
            unknown = actions["notes/unclassified.md"]
            self.assertEqual(MigrationActionKind.UNRESOLVED_PROPOSAL, unknown.kind)
            self.assertEqual(
                UnresolvedClassification.UNKNOWN_FORMAT,
                unknown.unresolved_classification,
            )

    def test_identical_inputs_produce_identical_bundle_bytes(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            left = plan_v1_to_v2(
                fixture_root("v1-minimal"), Path(first), CONTEXT, FIXTURE_GATE
            )
            right = plan_v1_to_v2(
                fixture_root("v1-minimal"), Path(second), CONTEXT, FIXTURE_GATE
            )
            self.assertEqual(left.bundle_sha256, right.bundle_sha256)
            self.assertEqual(
                {
                    path: file.read_bytes()
                    for path, file in _relative_files(left.bundle_dir).items()
                },
                {
                    path: file.read_bytes()
                    for path, file in _relative_files(right.bundle_dir).items()
                },
            )

    def test_focus_duplicates_and_embedded_knowledge_never_gain_fact_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            embedded = plan_v1_to_v2(
                fixture_root("v1-embedded-knowledge"),
                Path(temporary),
                CONTEXT,
                FIXTURE_GATE,
            )
            knowledge = next(
                action
                for action in embedded.plan.actions
                if action.source_path == "knowledge/modeling/retopology.md"
            )
            self.assertEqual(MigrationActionKind.EMBEDDED_KNOWLEDGE_REVIEW, knowledge.kind)
            self.assertIsNone(knowledge.target_path)
            self.assertIsNone(knowledge.memory_id)
            self.assertEqual(
                UnresolvedClassification.EMBEDDED_KNOWLEDGE_EXTERNAL,
                knowledge.unresolved_classification,
            )
            self.assertIn(
                "knowledge-base-migration-required",
                {finding.code for finding in embedded.plan.findings},
            )

        with tempfile.TemporaryDirectory() as temporary:
            duplicate = plan_v1_to_v2(
                fixture_root("v1-duplicate-owners"),
                Path(temporary),
                CONTEXT,
                FIXTURE_GATE,
            )
            duplicate_actions = [
                action
                for action in duplicate.plan.actions
                if action.source_path != "AGENTS.md" and action.source_path != "snapshot.json"
            ]
            self.assertTrue(duplicate_actions)
            self.assertTrue(
                all(action.kind is MigrationActionKind.UNRESOLVED_PROPOSAL for action in duplicate_actions)
            )
            self.assertTrue(
                all(
                    action.unresolved_classification
                    is UnresolvedClassification.AMBIGUOUS_OWNER
                    for action in duplicate_actions
                )
            )

    def test_strict_loader_rejects_tampering_extra_missing_and_symlink_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            original = plan_v1_to_v2(
                fixture_root("v1-minimal"), parent / "build", CONTEXT, FIXTURE_GATE
            )

            def mutate_unknown_key(root):
                path = root / "detection.json"
                value = json.loads(path.read_text("utf-8"))
                value["unexpected"] = True
                path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", "utf-8")

            def mutate_action(root):
                path = root / "plan.json"
                value = json.loads(path.read_text("utf-8"))
                record = next(item for item in value["actions"] if item["kind"] == "record")
                record["owner_scope"] = "agent.runbook"
                path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", "utf-8")

            def mutate_snapshot_manifest(root):
                path = root / "snapshot.json"
                value = json.loads(path.read_text("utf-8"))
                value["entries"][0]["size"] += 1
                path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", "utf-8")

            def add_duplicate_key(root):
                path = root / "detection.json"
                raw = path.read_bytes()
                path.write_bytes(b'{"schema_version":1,' + raw[1:])

            def mutate_snapshot(root):
                path = next((root / "snapshot" / "files").rglob("*.md"))
                path.write_bytes(path.read_bytes() + b"tampered\n")

            def add_extra(root):
                (root / "extra.txt").write_text("extra\n", "utf-8")

            def remove_snapshot(root):
                next((root / "snapshot" / "files").rglob("*.md")).unlink()

            cases = (
                ("unknown-key", mutate_unknown_key),
                ("duplicate-key", add_duplicate_key),
                ("snapshot-manifest", mutate_snapshot_manifest),
                ("semantic-action", mutate_action),
                ("snapshot-byte", mutate_snapshot),
                ("extra-file", add_extra),
                ("missing-file", remove_snapshot),
            )
            for name, mutate in cases:
                with self.subTest(name=name):
                    copied = parent / ("tamper-" + name)
                    shutil.copytree(original.bundle_dir, copied)
                    mutate(copied)
                    before = tree_hashes(copied)
                    with self.assertRaises(ValidationError):
                        load_migration_bundle(copied)
                    self.assertEqual(before, tree_hashes(copied))

            copied = parent / "tamper-symlink"
            shutil.copytree(original.bundle_dir, copied)
            outside = parent / "outside.txt"
            outside.write_text("outside\n", "utf-8")
            try:
                os.symlink(outside, copied / "linked.txt")
            except OSError:
                return
            with self.assertRaisesRegex(ValidationError, "unsafe filesystem entry"):
                load_migration_bundle(copied)


if __name__ == "__main__":
    unittest.main()
