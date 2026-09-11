import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import copy_vault_fixture, tree_hashes

import obsidian_agent_memory.migration as migration_module
from obsidian_agent_memory.catalog import load_catalog, read_accepted_record
from obsidian_agent_memory.errors import (
    LockBusyError,
    PlanInvalidatedError,
    ValidationError,
)
from obsidian_agent_memory.migration import (
    MigrationBundle,
    VaultGeneration,
    apply_migration,
    detect_vault,
    load_migration_bundle,
    plan_v1_to_v2,
    rollback_migration,
    validate_migration_source,
    verify_migration,
)
from obsidian_agent_memory.models import TransactionContext
from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope
from obsidian_agent_memory.transactions import root_write_guard


FIXTURE_GATE = AuthorizationGate(OperationScope.FIXTURE, None)
PLAN_CONTEXT = TransactionContext(
    "migration-plan-0001",
    "fixture-agent",
    "2026-08-30T01:00:00Z",
)
APPLY_CONTEXT = TransactionContext(
    "migration-apply-0001",
    "fixture-agent",
    "2026-08-30T02:00:00Z",
)
ROLLBACK_CONTEXT = TransactionContext(
    "migration-rollback-0001",
    "fixture-agent",
    "2026-08-30T03:00:00Z",
)


def _write_canonical(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


class MigrationApplyTests(unittest.TestCase):
    def _planned(self, parent):
        root = copy_vault_fixture("v1-minimal", parent)
        bundle = plan_v1_to_v2(
            root,
            parent / "planning",
            PLAN_CONTEXT,
            FIXTURE_GATE,
        )
        return root, bundle

    def test_changed_source_invalidates_validation_and_apply_without_schema_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            source = root / "AGENTS.md"
            source.write_bytes(source.read_bytes() + b"changed\n")
            root_before = tree_hashes(root)
            bundle_before = tree_hashes(bundle.bundle_dir)

            with self.assertRaisesRegex(
                PlanInvalidatedError,
                "^migration source revision changed$",
            ):
                validate_migration_source(root, bundle, FIXTURE_GATE)
            with self.assertRaisesRegex(
                PlanInvalidatedError,
                "^migration source revision changed$",
            ):
                apply_migration(
                    root,
                    bundle,
                    bundle.bundle_sha256,
                    APPLY_CONTEXT,
                    FIXTURE_GATE,
                )

            self.assertEqual(root_before, tree_hashes(root))
            self.assertEqual(bundle_before, tree_hashes(bundle.bundle_dir))
            self.assertFalse((root / ".agent-memory").exists())
            self.assertFalse((root / ".agent-memory-root-write.anchor").exists())

    def test_reviewed_bundle_cas_and_strict_reload_refuse_before_root_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            root_before = tree_hashes(root)

            for value in (
                "not-a-digest",
                bundle.bundle_sha256.upper(),
                "0" * 64,
            ):
                with self.subTest(reviewed_digest=value):
                    with self.assertRaisesRegex(
                        PlanInvalidatedError,
                        "^reviewed migration bundle changed$",
                    ):
                        apply_migration(root, bundle, value, APPLY_CONTEXT, FIXTURE_GATE)
                    self.assertEqual(root_before, tree_hashes(root))
                    self.assertFalse((root / ".agent-memory").exists())

            def alter_detection(directory):
                path = directory / "detection.json"
                value = json.loads(path.read_text("utf-8"))
                value["unexpected"] = True
                _write_canonical(path, value)

            def alter_snapshot(directory):
                path = directory / "snapshot.json"
                value = json.loads(path.read_text("utf-8"))
                value["entries"][0]["size"] += 1
                _write_canonical(path, value)

            def alter_plan(directory):
                path = directory / "plan.json"
                value = json.loads(path.read_text("utf-8"))
                action = next(item for item in value["actions"] if item["kind"] == "record")
                action["owner_scope"] = "agent.runbook"
                _write_canonical(path, value)

            def alter_snapshot_byte(directory):
                path = next((directory / "snapshot" / "files").rglob("*.md"))
                path.write_bytes(path.read_bytes() + b"tampered\n")

            for name, mutate in (
                ("detection", alter_detection),
                ("snapshot", alter_snapshot),
                ("plan", alter_plan),
                ("snapshot-byte", alter_snapshot_byte),
            ):
                with self.subTest(bundle_member=name):
                    copied = parent / ("tampered-" + name)
                    shutil.copytree(bundle.bundle_dir, copied)
                    mutate(copied)
                    untrusted = MigrationBundle(
                        copied,
                        bundle.detection,
                        bundle.snapshot,
                        bundle.plan,
                        bundle.bundle_sha256,
                    )
                    with self.assertRaises(ValidationError):
                        apply_migration(
                            root,
                            untrusted,
                            bundle.bundle_sha256,
                            APPLY_CONTEXT,
                            FIXTURE_GATE,
                        )
                    self.assertEqual(root_before, tree_hashes(root))
                    self.assertFalse((root / ".agent-memory").exists())

    def test_after_stage_source_change_is_rechecked_under_root_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            bundle_before = tree_hashes(bundle.bundle_dir)
            changed = []

            def checkpoint(stage, live_root, stage_root, loaded_bundle):
                if stage == "after-stage":
                    self.assertNotEqual(live_root, stage_root)
                    self.assertEqual(bundle.bundle_sha256, loaded_bundle.bundle_sha256)
                    path = live_root / "AGENTS.md"
                    path.write_bytes(path.read_bytes() + b"late-change\n")
                    changed.append(True)

            with mock.patch.object(
                migration_module,
                "_migration_checkpoint",
                checkpoint,
            ):
                with self.assertRaisesRegex(
                    PlanInvalidatedError,
                    "^migration source revision changed$",
                ):
                    apply_migration(
                        root,
                        bundle,
                        bundle.bundle_sha256,
                        APPLY_CONTEXT,
                        FIXTURE_GATE,
                    )

            self.assertEqual([True], changed)
            self.assertEqual(bundle_before, tree_hashes(bundle.bundle_dir))
            self.assertFalse((root / ".agent-memory").exists())

    def test_successful_apply_owns_records_builds_views_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            source_bytes = {
                entry.relative_path: (root / entry.relative_path).read_bytes()
                for entry in bundle.snapshot.entries
            }
            bundle_before = tree_hashes(bundle.bundle_dir)
            during_stage = []

            def checkpoint(stage, live_root, stage_root, loaded_bundle):
                if stage == "after-stage":
                    during_stage.append(tree_hashes(loaded_bundle.bundle_dir))
                    self.assertTrue(stage_root.parent.samefile(bundle.bundle_dir.parent))
                    self.assertFalse(stage_root == bundle.bundle_dir)
                    self.assertFalse(stage_root == live_root)

            with mock.patch.object(
                migration_module,
                "_migration_checkpoint",
                checkpoint,
            ):
                result = apply_migration(
                    root,
                    bundle,
                    bundle.bundle_sha256,
                    APPLY_CONTEXT,
                    FIXTURE_GATE,
                )

            self.assertEqual("applied", result.status)
            self.assertEqual(APPLY_CONTEXT.transaction_id, result.transaction_id)
            self.assertEqual(bundle.plan.source_revision, result.source_revision)
            self.assertEqual(bundle.bundle_sha256, result.reviewed_bundle_sha256)
            self.assertEqual(bundle.plan.authorization_ref, result.plan_authorization_ref)
            self.assertEqual(FIXTURE_GATE.authorization_ref, result.apply_authorization_ref)
            self.assertIsNone(result.rollback_authorization_ref)
            self.assertEqual([bundle_before], during_stage)
            self.assertEqual(bundle_before, tree_hashes(bundle.bundle_dir))
            self.assertEqual(bundle, load_migration_bundle(bundle.bundle_dir))

            catalog = load_catalog(root)
            record_types = [entry.record_type for entry in catalog.entries]
            for record_type in (
                "session",
                "story",
                "decision",
                "preference",
                "runbook",
                "migration",
            ):
                self.assertIn(record_type, record_types)
            self.assertEqual(len(catalog.entries), len({item.memory_id for item in catalog.entries}))
            migration = next(item for item in catalog.entries if item.record_type == "migration")
            migration_record = read_accepted_record(root, migration.memory_id)
            self.assertIn(bundle.plan.plan_id, migration_record.body)
            self.assertIn(bundle.plan.source_revision, migration_record.body)

            raw_source = root / "_sources/projects/demo/raw/source.txt"
            self.assertEqual(
                hashlib.sha256(source_bytes["projects/demo/raw/source.txt"]).hexdigest(),
                hashlib.sha256(raw_source.read_bytes()).hexdigest(),
            )
            for legacy_owner in (
                "projects/demo/sessions/2026-01-01-bootstrap.md",
                "projects/demo/stories/cache-failure.md",
                "projects/demo/decisions/cache-policy.md",
                "preferences/review-style.md",
                "skills/rebuild-index.md",
            ):
                self.assertFalse((root / legacy_owner).exists(), legacy_owner)

            verification_one = verify_migration(root, bundle, FIXTURE_GATE)
            verification_two = verify_migration(root, bundle, FIXTURE_GATE)
            self.assertEqual(verification_one, verification_two)
            self.assertTrue(verification_one.valid, verification_one.findings)
            self.assertEqual(bundle.bundle_sha256, verification_one.bundle_sha256)
            self.assertEqual(7, len(verification_one.projection_paths))
            self.assertEqual(
                VaultGeneration.V2,
                detect_vault(root, FIXTURE_GATE).generation,
            )

            before_reapply = tree_hashes(root)
            reapplied = apply_migration(
                root,
                bundle,
                bundle.bundle_sha256,
                TransactionContext(
                    "migration-apply-second",
                    "fixture-agent",
                    "2026-08-30T04:00:00Z",
                ),
                FIXTURE_GATE,
            )
            self.assertEqual("already-applied", reapplied.status)
            self.assertEqual(result.transaction_id, reapplied.transaction_id)
            self.assertEqual(result.created_paths, reapplied.created_paths)
            self.assertEqual(result.replaced_paths, reapplied.replaced_paths)
            self.assertEqual(result.archived_paths, reapplied.archived_paths)
            self.assertEqual(before_reapply, tree_hashes(root))

    def test_apply_without_project_id_mapping_keeps_valid_project_raw_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            relative = "projects/demo/raw/source.txt"
            source = root / relative
            original = source.read_bytes()

            result = apply_migration(
                root,
                bundle,
                bundle.bundle_sha256,
                APPLY_CONTEXT,
                FIXTURE_GATE,
            )

            self.assertTrue(source.is_file())
            self.assertEqual(original, source.read_bytes())
            self.assertTrue((root / "projects/demo/overview.md").is_file())
            self.assertTrue((root / "projects/demo/current-focus.md").is_file())
            self.assertNotIn(relative, result.archived_paths)

    def test_schema_one_empty_mapping_apply_keeps_valid_project_raw_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
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
            legacy_bundle = load_migration_bundle(bundle.bundle_dir)
            relative = "projects/demo/raw/source.txt"
            source = root / relative
            original = source.read_bytes()

            result = apply_migration(
                root,
                legacy_bundle,
                legacy_bundle.bundle_sha256,
                APPLY_CONTEXT,
                FIXTURE_GATE,
            )

            self.assertTrue(source.is_file())
            self.assertEqual(original, source.read_bytes())
            self.assertNotIn(relative, result.archived_paths)

    def test_rollback_restores_reviewed_bytes_and_retains_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            source_bytes = {
                entry.relative_path: (root / entry.relative_path).read_bytes()
                for entry in bundle.snapshot.entries
            }
            applied = apply_migration(
                root,
                bundle,
                bundle.bundle_sha256,
                APPLY_CONTEXT,
                FIXTURE_GATE,
            )
            rolled_back = rollback_migration(
                root,
                APPLY_CONTEXT.transaction_id,
                ROLLBACK_CONTEXT,
                FIXTURE_GATE,
            )

            self.assertEqual("rolled-back", rolled_back.status)
            self.assertEqual(ROLLBACK_CONTEXT.transaction_id, rolled_back.transaction_id)
            self.assertEqual(applied.source_revision, rolled_back.source_revision)
            self.assertEqual(applied.reviewed_bundle_sha256, rolled_back.reviewed_bundle_sha256)
            self.assertEqual(applied.plan_authorization_ref, rolled_back.plan_authorization_ref)
            self.assertEqual(applied.apply_authorization_ref, rolled_back.apply_authorization_ref)
            self.assertEqual(FIXTURE_GATE.authorization_ref, rolled_back.rollback_authorization_ref)
            for relative_path, expected in source_bytes.items():
                self.assertEqual(expected, (root / relative_path).read_bytes(), relative_path)
            transaction_root = root / ".agent-memory/transactions"
            self.assertTrue(
                (transaction_root / APPLY_CONTEXT.transaction_id / "journal.json").is_file()
            )
            self.assertTrue(
                (transaction_root / APPLY_CONTEXT.transaction_id / "rollback/manifest.json").is_file()
            )
            self.assertTrue((transaction_root / (ROLLBACK_CONTEXT.transaction_id + ".json")).is_file())

    def test_rollback_preflights_all_endpoints_before_reverse_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            applied = apply_migration(
                root,
                bundle,
                bundle.bundle_sha256,
                APPLY_CONTEXT,
                FIXTURE_GATE,
            )
            target = root / sorted(applied.created_paths)[-1]
            target.write_bytes(target.read_bytes() + b"user-edit\n")
            before = tree_hashes(root)

            with self.assertRaisesRegex(
                PlanInvalidatedError,
                "^migration rollback endpoints changed$",
            ):
                rollback_migration(
                    root,
                    APPLY_CONTEXT.transaction_id,
                    ROLLBACK_CONTEXT,
                    FIXTURE_GATE,
                )

            after = tree_hashes(root)
            before_without_evidence = tuple(
                item
                for item in before
                if item[0] != ".agent-memory-root-write.anchor"
            )
            after_without_evidence = tuple(
                item
                for item in after
                if item[0]
                not in {
                    ".agent-memory-root-write.anchor",
                    ".agent-memory/transactions/" + ROLLBACK_CONTEXT.transaction_id + ".json",
                }
            )
            self.assertEqual(before_without_evidence, after_without_evidence)
            self.assertIn(b"user-edit", target.read_bytes())

    def test_incomplete_action_is_classified_before_later_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            source_bytes = {
                entry.relative_path: (root / entry.relative_path).read_bytes()
                for entry in bundle.snapshot.entries
            }
            interrupted = []

            def checkpoint(stage, live_root, stage_root, loaded_bundle):
                if stage == "after-endpoint" and not interrupted:
                    interrupted.append(True)
                    raise RuntimeError("simulated process interruption")

            with mock.patch.object(
                migration_module,
                "_migration_checkpoint",
                checkpoint,
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated process interruption"):
                    apply_migration(
                        root,
                        bundle,
                        bundle.bundle_sha256,
                        APPLY_CONTEXT,
                        FIXTURE_GATE,
                    )

            journal_path = (
                root
                / ".agent-memory/transactions"
                / APPLY_CONTEXT.transaction_id
                / "journal.json"
            )
            journal = json.loads(journal_path.read_text("utf-8"))
            self.assertEqual("rollback-required", journal["status"])
            self.assertTrue(any(not item["completed"] for item in journal["actions"]))
            result = rollback_migration(
                root,
                APPLY_CONTEXT.transaction_id,
                ROLLBACK_CONTEXT,
                FIXTURE_GATE,
            )
            self.assertEqual("rolled-back", result.status)
            for relative_path, expected in source_bytes.items():
                self.assertEqual(expected, (root / relative_path).read_bytes(), relative_path)

    def test_existing_root_guard_blocks_apply_before_recheck_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            competing = TransactionContext(
                "normal-writer",
                "fixture-agent",
                "2026-08-30T01:30:00Z",
            )
            (root / ".agent-memory-root-write.anchor").write_bytes(
                b'{"purpose":"root-write-namespace","schema_version":1}\n'
            )
            before = tree_hashes(root)
            with root_write_guard(root, competing):
                with self.assertRaises(LockBusyError):
                    apply_migration(
                        root,
                        bundle,
                        bundle.bundle_sha256,
                        APPLY_CONTEXT,
                        FIXTURE_GATE,
                    )
            self.assertEqual(before, tree_hashes(root))

    def test_real_scope_blank_authorization_rejects_before_source_or_bundle_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle = self._planned(parent)
            real_without_authorization = AuthorizationGate(OperationScope.REAL, None)
            with mock.patch.object(
                migration_module,
                "_detect_vault_gated",
                side_effect=AssertionError("source read occurred"),
            ), mock.patch.object(
                migration_module,
                "load_migration_bundle",
                side_effect=AssertionError("bundle read occurred"),
            ):
                with self.assertRaisesRegex(
                    ValidationError,
                    "authorization reference is required",
                ):
                    validate_migration_source(root, bundle, real_without_authorization)
                with self.assertRaisesRegex(
                    ValidationError,
                    "authorization reference is required",
                ):
                    verify_migration(root, bundle, real_without_authorization)


if __name__ == "__main__":
    unittest.main()
