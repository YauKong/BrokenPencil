import json
import re
import multiprocessing
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT, copy_vault_fixture, tree_hashes

from obsidian_agent_memory import (
    AuthorizationGate,
    MigrationActionKind,
    OperationScope,
    RecordCandidate,
    RecordEnvelope,
    TransactionContext,
    UnresolvedClassification,
    apply_migration,
    build_project_views,
    build_root_views,
    commit_record,
    compute_body_sha256,
    detect_vault,
    load_catalog,
    load_migration_bundle,
    plan_v1_to_v2,
    read_accepted_record,
    validate_migration_source,
)
import obsidian_agent_memory.migration as migration_module
from obsidian_agent_memory.errors import ValidationError


FIXTURE_GATE = AuthorizationGate(OperationScope.FIXTURE, None)
OPERATIONS_DOC = REPO_ROOT / "docs" / "vault-migration-operations.md"
MIGRATE_TOOL = "tools/vault_migrate.py"
MAINTAIN_TOOL = "tools/vault_maintain.py"


def run_tool(script: str, *arguments: str, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, script, *arguments],
        cwd=str(REPO_ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _json_result(result):
    return json.loads(result.stdout)


def _tree_bytes(root):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(Path(root).rglob("*"), key=lambda item: item.as_posix())
        if path.is_file()
    }


def _hold_root_guard(root, ready, release):
    from obsidian_agent_memory import root_write_guard

    context = TransactionContext(
        "task8-live-writer",
        "task8-agent",
        "2026-08-30T15:00:00Z",
    )
    with root_write_guard(Path(root), context):
        ready.set()
        release.wait(30)


class VaultMigrationWorkflowTests(unittest.TestCase):
    maxDiff = None

    def test_apply_uses_private_legacy_session_compatibility_only_while_staging(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            root = copy_vault_fixture("v1-minimal", parent / "source")
            bundle = plan_v1_to_v2(
                root,
                parent / "planning",
                TransactionContext(
                    "legacy-session-plan",
                    "fixture-agent",
                    "2026-09-09T00:00:00Z",
                ),
                FIXTURE_GATE,
            )
            original = migration_module._transactions._commit_record
            with mock.patch.object(
                migration_module._transactions,
                "_commit_record",
                wraps=original,
            ) as wrapped:
                result = apply_migration(
                    root,
                    bundle,
                    bundle.bundle_sha256,
                    TransactionContext(
                        "legacy-session-apply",
                        "fixture-agent",
                        "2026-09-09T00:01:00Z",
                    ),
                    FIXTURE_GATE,
                )

            self.assertEqual("applied", result.status)
            legacy_calls = [
                call
                for call in wrapped.call_args_list
                if call.kwargs.get("allow_legacy_migration_session") is True
            ]
            self.assertEqual(len(wrapped.call_args_list), len(legacy_calls))

    def _poisoned_environment(self, temporary):
        environment = os.environ.copy()
        poison_home = temporary / "poison-home"
        poison_config = temporary / "poison-config"
        poison_home.mkdir()
        environment.update(
            {
                "HOME": str(poison_home),
                "USERPROFILE": str(poison_home),
                "APPDATA": str(poison_config),
                "LOCALAPPDATA": str(poison_config),
                "OBSIDIAN_AGENT_MEMORY_ROOT": "unused-environment-root",
                "OBSIDIAN_EXECUTABLE": "unused-obsidian-executable",
                "OBSIDIAN_VAULT": "unused-obsidian-vault",
                "TASK8_UNRELATED_SECRET": "unrelated-secret-sentinel-9317",
            }
        )
        return environment, poison_home, poison_config

    def _plan_command(self, root, work_root, transaction_id, environment):
        result = run_tool(
            MIGRATE_TOOL,
            "plan",
            "--root",
            str(root),
            "--work-dir",
            str(work_root),
            "--scope",
            "fixture",
            "--transaction-id",
            transaction_id,
            "--actor",
            "task8-agent",
            "--occurred-at",
            "2026-08-30T14:00:00Z",
            env=environment,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return _json_result(result)

    def _apply_command(
        self,
        root,
        bundle,
        digest,
        transaction_id,
        environment,
    ):
        return run_tool(
            MIGRATE_TOOL,
            "apply",
            "--root",
            str(root),
            "--bundle",
            str(bundle),
            "--bundle-sha256",
            digest,
            "--scope",
            "fixture",
            "--transaction-id",
            transaction_id,
            "--actor",
            "task8-agent",
            "--occurred-at",
            "2026-08-30T14:01:00Z",
            env=environment,
        )

    def test_base_and_mapped_project_complete_fixture_workflow(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            temporary = Path(temporary_text)
            root = copy_vault_fixture("v1-embedded-knowledge", temporary)
            (root / "projects" / "demo").rename(
                root / "projects" / "JustDanceMobile"
            )
            base_path = root / "_index" / "legacy-review.base"
            base_path.parent.mkdir()
            base_bytes = b'{"views":["reviewed"]}\n'
            base_path.write_bytes(base_bytes)
            original_bytes = _tree_bytes(root)

            planned = run_tool(
                MIGRATE_TOOL,
                "plan",
                "--root",
                str(root),
                "--work-dir",
                str(temporary / "work"),
                "--scope",
                "fixture",
                "--transaction-id",
                "mapped-plan-0001",
                "--actor",
                "fixture-agent",
                "--occurred-at",
                "2026-08-30T16:00:00Z",
                "--project-id-map",
                "JustDanceMobile=just-dance-mobile",
            )
            self.assertEqual(0, planned.returncode, planned.stderr)
            planned_document = _json_result(planned)
            bundle_path = Path(planned_document["bundle_path"])
            bundle = load_migration_bundle(bundle_path)
            self.assertEqual(
                "JustDanceMobile",
                bundle.plan.project_id_mappings[0].source_project_id,
            )
            self.assertEqual(
                "just-dance-mobile",
                bundle.plan.project_id_mappings[0].target_project_id,
            )
            base_action = next(
                action
                for action in bundle.plan.actions
                if action.source_path == "_index/legacy-review.base"
            )
            self.assertEqual(MigrationActionKind.PRESERVE, base_action.kind)
            self.assertEqual(base_action.source_path, base_action.target_path)
            mapped_record = next(
                action
                for action in bundle.plan.actions
                if action.source_path
                == "projects/JustDanceMobile/sessions/2026-01-01-source.md"
            )
            self.assertEqual(MigrationActionKind.RECORD, mapped_record.kind)
            self.assertEqual("just-dance-mobile", mapped_record.project_id)
            self.assertEqual(
                "project.just-dance-mobile.session", mapped_record.owner_scope
            )
            self.assertIsNotNone(mapped_record.target_path)
            self.assertIn(
                "projects/just-dance-mobile/current-focus.md",
                mapped_record.projection_effects,
            )
            knowledge_review = next(
                action
                for action in bundle.plan.actions
                if action.source_path == "knowledge/modeling/retopology.md"
            )
            self.assertEqual(
                MigrationActionKind.EMBEDDED_KNOWLEDGE_REVIEW, knowledge_review.kind
            )
            self.assertIsNone(knowledge_review.target_path)
            self.assertIsNone(knowledge_review.memory_id)

            applied = run_tool(
                MIGRATE_TOOL,
                "apply",
                "--root",
                str(root),
                "--bundle",
                str(bundle_path),
                "--bundle-sha256",
                planned_document["bundle_sha256"],
                "--scope",
                "fixture",
                "--transaction-id",
                "mapped-apply-0001",
                "--actor",
                "fixture-agent",
                "--occurred-at",
                "2026-08-30T16:01:00Z",
            )
            self.assertEqual(0, applied.returncode, applied.stderr)
            applied_document = _json_result(applied)
            legacy_session = "projects/JustDanceMobile/sessions/2026-01-01-source.md"
            self.assertIn(legacy_session, applied_document["archived_paths"])
            self.assertFalse((root / legacy_session).exists())
            journal = json.loads(
                (
                    root
                    / ".agent-memory"
                    / "transactions"
                    / "mapped-apply-0001"
                    / "journal.json"
                ).read_text("utf-8")
            )
            self.assertIn(legacy_session, journal["result"]["archived_paths"])
            self.assertFalse(
                any((root / "projects" / "JustDanceMobile").rglob("*.md"))
            )
            self.assertEqual(base_bytes, base_path.read_bytes())
            self.assertTrue(
                (root / "projects" / "just-dance-mobile" / "overview.md").is_file()
            )
            self.assertTrue(
                (root / "projects" / "just-dance-mobile" / "current-focus.md").is_file()
            )
            self.assertTrue(
                any(
                    path.endswith(".json") for path in applied_document["proposal_paths"]
                )
            )
            migrated_record = read_accepted_record(root, mapped_record.memory_id)
            self.assertTrue((root / mapped_record.target_path).is_file())
            self.assertEqual("just-dance-mobile", migrated_record.envelope.project)
            self.assertEqual(
                "project.just-dance-mobile.session",
                migrated_record.envelope.owner_scope,
            )
            self.assertEqual(
                original_bytes["knowledge/modeling/retopology.md"],
                (root / "knowledge" / "modeling" / "retopology.md").read_bytes(),
            )

            verified = run_tool(
                MIGRATE_TOOL,
                "verify",
                "--root",
                str(root),
                "--bundle",
                str(bundle_path),
                "--scope",
                "fixture",
            )
            self.assertEqual(0, verified.returncode, verified.stderr)
            self.assertTrue(_json_result(verified)["valid"])

            base_path.write_bytes(base_bytes[:-1] + b"X")
            drifted = run_tool(
                MIGRATE_TOOL,
                "verify",
                "--root",
                str(root),
                "--bundle",
                str(bundle_path),
                "--scope",
                "fixture",
            )
            self.assertEqual(5, drifted.returncode, drifted.stderr)
            self.assertEqual(
                [
                    {
                        "code": "migration-preservation-drift",
                        "message": "preserved migration evidence differs from the reviewed snapshot",
                        "path": "_index/legacy-review.base",
                        "severity": "error",
                    }
                ],
                _json_result(drifted)["findings"],
            )

            base_path.write_bytes(base_bytes)
            before_reapply = tree_hashes(root)
            reapplied = run_tool(
                MIGRATE_TOOL,
                "apply",
                "--root",
                str(root),
                "--bundle",
                str(bundle_path),
                "--bundle-sha256",
                planned_document["bundle_sha256"],
                "--scope",
                "fixture",
                "--transaction-id",
                "mapped-apply-0002",
                "--actor",
                "fixture-agent",
                "--occurred-at",
                "2026-08-30T16:02:00Z",
            )
            self.assertEqual(0, reapplied.returncode, reapplied.stderr)
            self.assertEqual("already-applied", _json_result(reapplied)["status"])
            self.assertEqual(before_reapply, tree_hashes(root))

            rolled_back = run_tool(
                MIGRATE_TOOL,
                "rollback",
                "--root",
                str(root),
                "--apply-transaction-id",
                "mapped-apply-0001",
                "--scope",
                "fixture",
                "--transaction-id",
                "mapped-rollback-0001",
                "--actor",
                "fixture-agent",
                "--occurred-at",
                "2026-08-30T16:03:00Z",
            )
            self.assertEqual(0, rolled_back.returncode, rolled_back.stderr)
            self.assertEqual("rolled-back", _json_result(rolled_back)["status"])
            after_rollback = _tree_bytes(root)
            for relative_path, expected in original_bytes.items():
                self.assertEqual(expected, after_rollback[relative_path], relative_path)

    def test_full_temporary_fixture_workflow_and_operations_contract(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            temporary = Path(temporary_text).resolve()
            vault_root = temporary / "vaults"
            work_root = temporary / "work"
            report_root = temporary / "reports"
            vault_root.mkdir()
            work_root.mkdir()
            report_root.mkdir()
            environment, poison_home, poison_config = self._poisoned_environment(
                temporary
            )

            apply_parent = vault_root / "apply"
            apply_parent.mkdir()
            root = copy_vault_fixture("v1-minimal", apply_parent)
            original_hashes = tree_hashes(root)
            original_bytes = _tree_bytes(root)

            detected = run_tool(
                MIGRATE_TOOL,
                "detect",
                "--root",
                str(root),
                "--scope",
                "fixture",
                env=environment,
            )
            self.assertEqual(0, detected.returncode, detected.stderr)
            detection_document = _json_result(detected)
            self.assertEqual("v1", detection_document["generation"])
            self.assertEqual(original_hashes, tree_hashes(root))

            planned = self._plan_command(
                root,
                work_root / "apply",
                "task8-plan-apply",
                environment,
            )
            reviewed_digest = planned["bundle_sha256"]
            self.assertRegex(reviewed_digest, r"^[0-9a-f]{64}$")
            bundle_path = Path(planned["bundle_path"])
            bundle = load_migration_bundle(bundle_path)
            self.assertEqual(reviewed_digest, bundle.bundle_sha256)
            self.assertEqual(
                detection_document["source_revision"],
                bundle.plan.source_revision,
            )
            validated = validate_migration_source(root, bundle, FIXTURE_GATE)
            self.assertEqual(bundle.plan.source_revision, validated.source_revision)
            for entry in bundle.snapshot.entries:
                self.assertEqual(
                    original_bytes[entry.relative_path],
                    (bundle.bundle_dir / entry.snapshot_path).read_bytes(),
                )

            applied = self._apply_command(
                root,
                bundle_path,
                reviewed_digest,
                "task8-apply-0001",
                environment,
            )
            self.assertEqual(0, applied.returncode, applied.stderr)
            applied_document = _json_result(applied)
            self.assertEqual("applied", applied_document["status"])
            self.assertEqual(
                reviewed_digest,
                applied_document["reviewed_bundle_sha256"],
            )
            catalog = load_catalog(root)
            record_types = {entry.record_type for entry in catalog.entries}
            self.assertTrue(
                {"decision", "migration", "preference", "runbook", "session", "story"}
                <= record_types
            )
            migration_entry = next(
                entry for entry in catalog.entries if entry.record_type == "migration"
            )
            migration_record = read_accepted_record(root, migration_entry.memory_id)
            self.assertIn(reviewed_digest, migration_record.body)
            self.assertIn(bundle.plan.source_revision, migration_record.body)
            self.assertEqual(
                original_bytes["projects/demo/raw/source.txt"],
                (root / "_sources/projects/demo/raw/source.txt").read_bytes(),
            )
            focus = json.loads(
                (root / ".agent-memory/state/focus/demo.json").read_text("utf-8")
            )
            self.assertTrue(focus["record_ids"])
            self.assertEqual(sorted(focus["record_ids"]), focus["record_ids"])

            verified = run_tool(
                MIGRATE_TOOL,
                "verify",
                "--root",
                str(root),
                "--bundle",
                str(bundle_path),
                "--scope",
                "fixture",
                env=environment,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)
            verification_document = _json_result(verified)
            self.assertTrue(verification_document["valid"])
            self.assertEqual(reviewed_digest, verification_document["bundle_sha256"])

            expected_documents = list(build_root_views(root, "2.0.0"))
            expected_documents.extend(build_project_views(root, "demo", "2.0.0"))
            self.assertEqual(
                sorted(verification_document["projection_paths"]),
                sorted(document.relative_path for document in expected_documents),
            )
            for document in expected_documents:
                self.assertEqual(
                    document.content.encode("utf-8"),
                    root.joinpath(*document.relative_path.split("/")).read_bytes(),
                )

            journal_path = (
                root
                / ".agent-memory/transactions/task8-apply-0001/journal.json"
            )
            journal = json.loads(journal_path.read_text("utf-8"))
            self.assertEqual(reviewed_digest, journal["reviewed_bundle_sha256"])
            self.assertEqual(
                reviewed_digest,
                journal["result"]["reviewed_bundle_sha256"],
            )

            before_reapply = tree_hashes(root)
            reapplied = self._apply_command(
                root,
                bundle_path,
                reviewed_digest,
                "task8-apply-0002",
                environment,
            )
            self.assertEqual(0, reapplied.returncode, reapplied.stderr)
            self.assertEqual("already-applied", _json_result(reapplied)["status"])
            self.assertEqual(before_reapply, tree_hashes(root))

            invalidated = self._apply_command(
                root,
                bundle_path,
                "0" * 64,
                "task8-apply-invalid-digest",
                environment,
            )
            self.assertEqual(3, invalidated.returncode, invalidated.stderr)
            self.assertEqual(before_reapply, tree_hashes(root))

            audit_path = report_root / "audit.json"
            audit = run_tool(
                MAINTAIN_TOOL,
                "audit",
                "--root",
                str(root),
                "--output",
                str(audit_path),
                "--scope",
                "fixture",
                env=environment,
            )
            self.assertEqual(0, audit.returncode, audit.stderr)
            cleanup_plan_path = report_root / "cleanup-plan.json"
            cleanup_plan = run_tool(
                MAINTAIN_TOOL,
                "plan",
                "--root",
                str(root),
                "--audit",
                str(audit_path),
                "--output",
                str(cleanup_plan_path),
                "--scope",
                "fixture",
                "--transaction-id",
                "task8-cleanup-plan",
                "--actor",
                "task8-agent",
                "--occurred-at",
                "2026-08-30T14:02:00Z",
                env=environment,
            )
            self.assertEqual(0, cleanup_plan.returncode, cleanup_plan.stderr)
            self.assertTrue(audit_path.is_file())
            self.assertTrue(cleanup_plan_path.is_file())
            maintain_help = run_tool(MAINTAIN_TOOL, "--help", env=environment)
            self.assertEqual(0, maintain_help.returncode, maintain_help.stderr)
            command_choices = re.search(r"\{([^{}\n]+)\}", maintain_help.stdout)
            self.assertIsNotNone(command_choices)
            commands = set(command_choices.group(1).split(","))
            self.assertNotIn("apply", commands)
            self.assertNotIn("execute", commands)
            self.assertIn("apply-proposal-resolution", commands)

            rollback_parent = vault_root / "rollback"
            rollback_parent.mkdir()
            rollback_root = copy_vault_fixture("v1-minimal", rollback_parent)
            rollback_original = _tree_bytes(rollback_root)
            rollback_plan = self._plan_command(
                rollback_root,
                work_root / "rollback",
                "task8-plan-rollback",
                environment,
            )
            rollback_bundle = Path(rollback_plan["bundle_path"])
            rollback_digest = rollback_plan["bundle_sha256"]
            rollback_apply = self._apply_command(
                rollback_root,
                rollback_bundle,
                rollback_digest,
                "task8-apply-rollback-copy",
                environment,
            )
            self.assertEqual(0, rollback_apply.returncode, rollback_apply.stderr)
            rolled_back = run_tool(
                MIGRATE_TOOL,
                "rollback",
                "--root",
                str(rollback_root),
                "--apply-transaction-id",
                "task8-apply-rollback-copy",
                "--scope",
                "fixture",
                "--transaction-id",
                "task8-rollback-0001",
                "--actor",
                "task8-agent",
                "--occurred-at",
                "2026-08-30T14:03:00Z",
                env=environment,
            )
            self.assertEqual(0, rolled_back.returncode, rolled_back.stderr)
            self.assertEqual("rolled-back", _json_result(rolled_back)["status"])
            rollback_after = _tree_bytes(rollback_root)
            for relative_path, expected in rollback_original.items():
                self.assertEqual(expected, rollback_after[relative_path], relative_path)
            extras = set(rollback_after) - set(rollback_original)
            self.assertTrue(extras)
            self.assertTrue(
                all(
                    path == ".agent-memory-root-write.anchor"
                    or path.startswith(".agent-memory/transactions/")
                    for path in extras
                ),
                extras,
            )

            allowed_roots = (vault_root.resolve(), work_root.resolve(), report_root.resolve())
            for path in temporary.rglob("*"):
                if not path.is_file():
                    continue
                resolved = path.resolve()
                self.assertTrue(
                    any(
                        resolved == allowed or allowed in resolved.parents
                        for allowed in allowed_roots
                    ),
                    str(path),
                )
            self.assertEqual([], list(poison_home.rglob("*")))
            self.assertFalse(poison_config.exists())
            combined_output = "".join(
                (
                    detected.stdout,
                    applied.stdout,
                    verified.stdout,
                    audit.stdout,
                    cleanup_plan.stdout,
                    rolled_back.stdout,
                )
            )
            for forbidden in (
                "unused-environment-root",
                "unused-obsidian-executable",
                "unused-obsidian-vault",
                "unrelated-secret-sentinel-9317",
            ):
                self.assertNotIn(forbidden, combined_output)

            self.assertTrue(OPERATIONS_DOC.is_file(), str(OPERATIONS_DOC))
            operations = OPERATIONS_DOC.read_text("utf-8")
            normalized_operations = " ".join(operations.split())
            for required in (
                "skills/obsidian-agent-memory/scripts/vault_migrate.py",
                "skills/obsidian-agent-memory/scripts/vault_maintain.py",
                "tools/vault_migrate.py",
                "tools/vault_maintain.py",
                "bundle_sha256",
                "--bundle-sha256",
                "source revision",
                "persisted rollback",
                "distinct transaction",
                "real plan",
                "real apply",
                "real cleanup",
                "recover-root-guard",
                "candidate-only",
            ):
                self.assertIn(required, normalized_operations)
            for code in ("0", "2", "3", "4", "5"):
                self.assertRegex(operations, r"(?m)^\| {0} \|".format(code))

    def test_negative_fixture_matrix_preserves_review_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary_text, mock.patch.object(
            Path, "home", side_effect=AssertionError("home requested")
        ), mock.patch.object(
            socket, "socket", side_effect=AssertionError("network requested")
        ):
            temporary = Path(temporary_text)
            roots = temporary / "vaults"
            work = temporary / "work"
            roots.mkdir()
            work.mkdir()

            focus = copy_vault_fixture("v1-focus-drift", roots / "focus")
            focus_bundle = plan_v1_to_v2(
                focus,
                work / "focus",
                TransactionContext(
                    "task8-plan-focus", "task8-agent", "2026-08-30T15:00:00Z"
                ),
                FIXTURE_GATE,
            )
            focus_actions = [
                action
                for action in focus_bundle.plan.actions
                if action.kind is MigrationActionKind.FOCUS_PROPOSAL
            ]
            self.assertTrue(focus_actions)
            self.assertTrue(
                all(
                    action.memory_id is None
                    and action.owner_scope is None
                    and action.target_path is None
                    for action in focus_actions
                )
            )

            duplicate = copy_vault_fixture("v1-duplicate-owners", roots / "duplicate")
            duplicate_bundle = plan_v1_to_v2(
                duplicate,
                work / "duplicate",
                TransactionContext(
                    "task8-plan-duplicate",
                    "task8-agent",
                    "2026-08-30T15:01:00Z",
                ),
                FIXTURE_GATE,
            )
            duplicate_actions = [
                action
                for action in duplicate_bundle.plan.actions
                if action.unresolved_classification
                is UnresolvedClassification.AMBIGUOUS_OWNER
            ]
            self.assertTrue(duplicate_actions)
            self.assertTrue(
                all(
                    action.kind is MigrationActionKind.UNRESOLVED_PROPOSAL
                    and action.memory_id is None
                    and action.owner_scope is None
                    for action in duplicate_actions
                )
            )

            embedded = copy_vault_fixture("v1-embedded-knowledge", roots / "embedded")
            embedded_bundle = plan_v1_to_v2(
                embedded,
                work / "embedded",
                TransactionContext(
                    "task8-plan-embedded",
                    "task8-agent",
                    "2026-08-30T15:02:00Z",
                ),
                FIXTURE_GATE,
            )
            knowledge = [
                action
                for action in embedded_bundle.plan.actions
                if action.kind is MigrationActionKind.EMBEDDED_KNOWLEDGE_REVIEW
            ]
            self.assertTrue(knowledge)
            self.assertTrue(
                all(
                    action.unresolved_classification
                    is UnresolvedClassification.EMBEDDED_KNOWLEDGE_EXTERNAL
                    and action.target_path is None
                    and action.memory_id is None
                    for action in knowledge
                )
            )
            self.assertIn(
                "knowledge-base-migration-required",
                {finding.code for finding in embedded_bundle.plan.findings},
            )

            partial = copy_vault_fixture(
                "v1-partially-migrated", roots / "partial"
            )
            partial_before = tree_hashes(partial)
            with self.assertRaisesRegex(
                ValidationError, "source vault is not an unmigrated v1 root"
            ):
                plan_v1_to_v2(
                    partial,
                    work / "partial",
                    TransactionContext(
                        "task8-plan-partial",
                        "task8-agent",
                        "2026-08-30T15:03:00Z",
                    ),
                    FIXTURE_GATE,
                )
            self.assertEqual(partial_before, tree_hashes(partial))
            self.assertEqual("partial", detect_vault(partial, FIXTURE_GATE).generation.value)

    def test_changed_source_exits_three_without_apply_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            temporary = Path(temporary_text)
            environment, _, _ = self._poisoned_environment(temporary)
            roots = temporary / "vaults"
            roots.mkdir()
            root = copy_vault_fixture("v1-minimal", roots)
            planned = self._plan_command(
                root,
                temporary / "work",
                "task8-plan-source-change",
                environment,
            )
            source = root / "AGENTS.md"
            source.write_bytes(source.read_bytes() + b"changed after review\n")
            before_apply = tree_hashes(root)
            result = self._apply_command(
                root,
                Path(planned["bundle_path"]),
                planned["bundle_sha256"],
                "task8-apply-source-change",
                environment,
            )
            self.assertEqual(3, result.returncode, result.stderr)
            self.assertIn("source revision changed", result.stderr)
            self.assertEqual(before_apply, tree_hashes(root))

    def test_lock_exits_four_and_plan_one_cas_retains_one_proposal(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            temporary = Path(temporary_text)
            environment, _, _ = self._poisoned_environment(temporary)
            roots = temporary / "vaults"
            roots.mkdir()
            locked_root = copy_vault_fixture("v1-minimal", roots / "locked")
            planned = self._plan_command(
                locked_root,
                temporary / "work",
                "task8-plan-lock",
                environment,
            )
            (locked_root / ".agent-memory-root-write.anchor").write_bytes(
                b'{"purpose":"root-write-namespace","schema_version":1}\n'
            )
            before = tree_hashes(locked_root)
            ready = multiprocessing.Event()
            release = multiprocessing.Event()
            holder = multiprocessing.Process(
                target=_hold_root_guard,
                args=(locked_root, ready, release),
            )
            holder.start()
            try:
                self.assertTrue(ready.wait(10), "root guard holder did not start")
                result = self._apply_command(
                    locked_root,
                    Path(planned["bundle_path"]),
                    planned["bundle_sha256"],
                    "task8-apply-lock-conflict",
                    environment,
                )
                self.assertEqual(4, result.returncode, result.stderr)
            finally:
                release.set()
                holder.join(10)
                if holder.is_alive():
                    holder.terminate()
                    holder.join(10)
            self.assertEqual(0, holder.exitcode)
            self.assertEqual(before, tree_hashes(locked_root))

            proposal_root = copy_vault_fixture("v2-clean", roots / "proposal")
            catalog = load_catalog(proposal_root)
            current = next(
                entry for entry in catalog.entries if entry.memory_id == "story-demo-cache"
            )
            body = "reviewed concurrent story update"
            candidate = RecordCandidate(
                RecordEnvelope(
                    memory_id=current.memory_id,
                    record_type=current.record_type,
                    schema_version=2,
                    owner_scope=current.owner_scope,
                    project=current.project,
                    revision=current.revision + 1,
                    supersedes="{0}@{1}".format(current.memory_id, current.revision),
                    created_at="2026-08-30T15:05:00Z",
                    observed_at="2026-08-30T15:05:00Z",
                    source="task8-fixture",
                    source_revision="task8-source-1",
                    body_sha256=compute_body_sha256(body),
                ),
                body,
            )
            proposal_directory = proposal_root / ".agent-memory/state/proposals"
            before_proposals = set(proposal_directory.glob("*.json"))
            outcome = commit_record(
                proposal_root,
                candidate,
                expected_catalog_revision=catalog.revision - 1,
                expected_record_revision=current.revision,
                context=TransactionContext(
                    "task8-stale-cas",
                    "task8-agent",
                    "2026-08-30T15:05:00Z",
                ),
            )
            self.assertEqual("proposed", outcome.status)
            self.assertIsNotNone(outcome.proposal_path)
            after_proposals = set(proposal_directory.glob("*.json"))
            self.assertEqual(1, len(after_proposals - before_proposals))
            self.assertEqual(catalog, load_catalog(proposal_root))


if __name__ == "__main__":
    unittest.main()
