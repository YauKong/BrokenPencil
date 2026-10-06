import contextlib
import io
import json
import multiprocessing
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT, copy_vault_fixture, tree_hashes
from tests.unit.test_artifact_schemas import _applied_golden_migration

from obsidian_agent_memory import (
    AuthorizationGate,
    ConflictError,
    GuardRecoveryResult,
    load_migration_bundle,
    MigrationResult,
    OperationScope,
    TransactionContext,
)


MIGRATE_SCRIPTS = (
    "tools/vault_migrate.py",
    "skills/obsidian-agent-memory/scripts/vault_migrate.py",
)
MAINTAIN_SCRIPTS = (
    "tools/vault_maintain.py",
    "skills/obsidian-agent-memory/scripts/vault_maintain.py",
)
LOWER_HASH = "1" * 64


def run_tool(script: str, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, script, *arguments],
        cwd=str(REPO_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _json_result(result):
    return json.loads(result.stdout)


def _crash_during_apply(root, bundle_path, digest):
    import obsidian_agent_memory.migration as migration_module
    from obsidian_agent_memory.migration import apply_migration, load_migration_bundle

    def checkpoint(stage, live_root, stage_root, loaded_bundle):
        if stage == "after-prepared":
            os._exit(23)

    migration_module._migration_checkpoint = checkpoint
    apply_migration(
        Path(root),
        load_migration_bundle(Path(bundle_path)),
        digest,
        TransactionContext(
            "migration-apply-0001",
            "fixture-agent",
            "2026-08-30T02:01:00Z",
        ),
        AuthorizationGate(OperationScope.FIXTURE, None),
    )


class VaultToolCommandTests(unittest.TestCase):
    maxDiff = None

    def assert_wrapper_parity(self, scripts, *arguments):
        results = tuple(run_tool(script, *arguments) for script in scripts)
        self.assertEqual(results[0].returncode, results[1].returncode)
        self.assertEqual(results[0].stdout, results[1].stdout)
        self.assertEqual(results[0].stderr, results[1].stderr)
        return results[0]

    def test_review_proposals_has_wrapper_parity(self):
        root, bundle, _ = _applied_golden_migration(self)
        outputs = (root.parent / "review-a.json", root.parent / "review-b.json")
        results = []
        for script, output in zip(MAINTAIN_SCRIPTS, outputs):
            result = run_tool(
                script,
                "review-proposals",
                "--root", str(root),
                "--bundle", str(bundle.bundle_dir),
                "--bundle-sha256", bundle.bundle_sha256,
                "--output", str(output),
                "--scope", "fixture",
                "--actor", "fixture-agent",
                "--observed-at", "2026-09-04T00:00:00Z",
                "--fixture-code-revision", "proposal-review-fixture-v1",
            )
            self.assertEqual(0, result.returncode, result.stderr)
            results.append(result)
        documents = [json.loads(result.stdout) for result in results]
        for document in documents:
            document.pop("output_path")
        self.assertEqual(documents[0], documents[1])
        self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())

    def _plan(self, script, parent, scope="fixture", authorization_ref=None):
        root = copy_vault_fixture("v1-minimal", parent)
        work_dir = parent / "migration-work"
        arguments = [
            "plan",
            "--root",
            str(root),
            "--work-dir",
            str(work_dir),
            "--scope",
            scope,
            "--transaction-id",
            "migration-plan-0001",
            "--actor",
            "fixture-agent",
            "--occurred-at",
            "2026-08-30T02:00:00Z",
        ]
        if authorization_ref is not None:
            arguments.extend(("--authorization-ref", authorization_ref))
        result = run_tool(script, *arguments)
        self.assertEqual(0, result.returncode, result.stderr)
        document = _json_result(result)
        self.assertRegex(document["bundle_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn(str(root.resolve()), result.stdout)
        return root, Path(document["bundle_path"]), document["bundle_sha256"], result

    def _apply(self, script, root, bundle, digest, authorization_ref=None):
        arguments = [
            "apply",
            "--root",
            str(root),
            "--bundle",
            str(bundle),
            "--bundle-sha256",
            digest,
            "--scope",
            "fixture" if authorization_ref is None else "real",
            "--transaction-id",
            "migration-apply-0001",
            "--actor",
            "fixture-agent",
            "--occurred-at",
            "2026-08-30T02:01:00Z",
        ]
        if authorization_ref is not None:
            arguments.extend(("--authorization-ref", authorization_ref))
        return run_tool(script, *arguments)

    def test_unmarked_fixture_and_missing_real_authorization_are_exit_two_with_parity(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "unmarked"
            root.mkdir()
            result = self.assert_wrapper_parity(
                MIGRATE_SCRIPTS,
                "detect",
                "--root",
                str(root),
                "--scope",
                "fixture",
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("fixture marker", result.stderr)

            result = self.assert_wrapper_parity(
                MIGRATE_SCRIPTS,
                "plan",
                "--root",
                str(root),
                "--work-dir",
                str(parent / "work"),
                "--scope",
                "real",
                "--transaction-id",
                "plan-1",
                "--actor",
                "fixture-agent",
                "--occurred-at",
                "2026-08-30T02:00:00Z",
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("authorization reference", result.stderr)

    def test_help_and_parser_failures_have_installed_repo_parity(self):
        for scripts, commands in (
            (MIGRATE_SCRIPTS, ("detect", "plan", "apply", "verify", "rollback")),
            (MAINTAIN_SCRIPTS, ("audit", "plan", "recover-root-guard")),
        ):
            result = self.assert_wrapper_parity(scripts, "--help")
            self.assertEqual(0, result.returncode, result.stderr)
            for command in commands:
                self.assertIn(command, result.stdout)
            if scripts is MAINTAIN_SCRIPTS:
                command_choices = re.search(r"\{([^{}\n]+)\}", result.stdout)
                self.assertIsNotNone(command_choices)
                available_commands = set(command_choices.group(1).split(","))
                self.assertNotIn("execute", available_commands)
                self.assertNotIn("apply", available_commands)
                self.assertIn("apply-proposal-resolution", available_commands)

            result = self.assert_wrapper_parity(scripts, commands[0])
            self.assertEqual(2, result.returncode)

    def test_detect_is_safe_deterministic_json_through_both_wrappers(self):
        sentinel = "UNRELATED-ENVIRONMENT-SENTINEL-2817"
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ, {"VAULT_TOOL_UNRELATED": sentinel}
        ):
            root = copy_vault_fixture("v1-minimal", Path(temporary))
            result = self.assert_wrapper_parity(
                MIGRATE_SCRIPTS,
                "detect",
                "--root",
                str(root),
                "--scope",
                "fixture",
            )
            self.assertEqual(0, result.returncode, result.stderr)
            document = _json_result(result)
            self.assertEqual("v1", document["generation"])
            self.assertRegex(document["source_revision"], r"^[0-9a-f]{64}$")
            self.assertTrue(all("\\" not in item["relative_path"] for item in document["entries"]))
            self.assertNotIn(str(root.resolve()), result.stdout)
            self.assertNotIn(sentinel, result.stdout)

    def test_project_id_mapping_has_wrapper_parity_and_strict_validation(self):
        def mapped_root(parent):
            root = copy_vault_fixture("v1-minimal", parent)
            source = root / "projects" / "demo"
            target = root / "projects" / "JustDanceMobile"
            shutil.copytree(source, target)
            for path in target.rglob("*"):
                if path.is_file():
                    path.write_bytes(path.read_bytes() + b"\nJustDanceMobile fixture\n")
            return root

        def plan_arguments(root, work_dir, *project_id_maps):
            return (
                "plan",
                "--root",
                str(root),
                "--work-dir",
                str(work_dir),
                "--scope",
                "fixture",
                "--transaction-id",
                "mapping-plan-0001",
                "--actor",
                "fixture-agent",
                "--occurred-at",
                "2026-08-30T02:00:00Z",
                *(
                    item
                    for project_id_map in project_id_maps
                    for item in ("--project-id-map", project_id_map)
                ),
            )

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            results = []
            for index, script in enumerate(MIGRATE_SCRIPTS):
                root = mapped_root(parent / str(index))
                result = run_tool(
                    script,
                    *plan_arguments(
                        root,
                        parent / ("work-" + str(index)),
                        "JustDanceMobile=just-dance-mobile",
                    ),
                )
                self.assertEqual(0, result.returncode, result.stderr)
                document = _json_result(result)
                normalized = dict(document)
                normalized.pop("bundle_path")
                results.append((normalized, Path(document["bundle_path"])))
            self.assertEqual(results[0][0], results[1][0])
            for _, bundle_path in results:
                bundle = load_migration_bundle(bundle_path)
                self.assertEqual(
                    "JustDanceMobile",
                    bundle.plan.project_id_mappings[0].source_project_id,
                )
                self.assertEqual(
                    "just-dance-mobile",
                    bundle.plan.project_id_mappings[0].target_project_id,
                )

            invalid_maps = (
                ("malformed",),
                ("=just-dance-mobile",),
                ("JustDanceMobile=",),
                ("JustDanceMobile=not valid",),
                ("JustDanceMobile=just-dance-mobile", "JustDanceMobile=other"),
                ("missing=just-dance-mobile",),
                ("demo=demo",),
                ("demo=Demo",),
                ("JustDanceMobile=demo",),
            )
            for mapping_index, project_id_maps in enumerate(invalid_maps):
                for index, script in enumerate(MIGRATE_SCRIPTS):
                    with self.subTest(project_id_maps=project_id_maps, script=script):
                        root = mapped_root(
                            parent / "invalid" / (str(mapping_index) + "-" + str(index))
                        )
                        work_dir = parent / "invalid-work" / (
                            str(mapping_index) + "-" + str(index)
                        )
                        result = run_tool(
                            script,
                            *plan_arguments(root, work_dir, *project_id_maps),
                        )
                        self.assertEqual(2, result.returncode, result.stderr)
                        self.assertFalse(
                            work_dir.exists() and any(work_dir.iterdir()),
                            "invalid mapping retained a migration bundle",
                        )

    def test_plan_apply_verify_idempotent_and_fresh_rollback(self):
        for script in MIGRATE_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root, bundle, digest, _ = self._plan(script, parent)
                applied = self._apply(script, root, bundle, digest)
                self.assertEqual(0, applied.returncode, applied.stderr)
                applied_document = _json_result(applied)
                self.assertEqual("applied", applied_document["status"])
                self.assertEqual(digest, applied_document["reviewed_bundle_sha256"])
                self.assertIsNone(applied_document["plan_authorization_ref"])
                self.assertIsNone(applied_document["apply_authorization_ref"])
                self.assertIsNone(applied_document["rollback_authorization_ref"])
                self.assertNotIn(str(root.resolve()), applied.stdout)

                verified = run_tool(
                    script,
                    "verify",
                    "--root",
                    str(root),
                    "--bundle",
                    str(bundle),
                    "--scope",
                    "fixture",
                )
                self.assertEqual(0, verified.returncode, verified.stderr)
                self.assertTrue(_json_result(verified)["valid"])

                before = tree_hashes(root)
                reapplied = run_tool(
                    script,
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
                    "migration-apply-0002",
                    "--actor",
                    "fixture-agent",
                    "--occurred-at",
                    "2026-08-30T02:02:00Z",
                )
                self.assertEqual(0, reapplied.returncode, reapplied.stderr)
                self.assertEqual("already-applied", _json_result(reapplied)["status"])
                self.assertEqual(before, tree_hashes(root))

                rolled_back = run_tool(
                    script,
                    "rollback",
                    "--root",
                    str(root),
                    "--apply-transaction-id",
                    "migration-apply-0001",
                    "--scope",
                    "fixture",
                    "--transaction-id",
                    "migration-rollback-0001",
                    "--actor",
                    "fixture-agent",
                    "--occurred-at",
                    "2026-08-30T02:03:00Z",
                )
                self.assertEqual(0, rolled_back.returncode, rolled_back.stderr)
                rollback_document = _json_result(rolled_back)
                self.assertEqual("rolled-back", rollback_document["status"])
                self.assertIsNone(rollback_document["rollback_authorization_ref"])

    def test_invalidated_bundle_and_source_exit_three_without_root_mutation(self):
        for mutation in ("bundle", "source"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root, bundle, digest, _ = self._plan(MIGRATE_SCRIPTS[0], parent)
                if mutation == "bundle":
                    plan_path = bundle / "plan.json"
                    plan_path.write_bytes(plan_path.read_bytes() + b" ")
                else:
                    source = root / "AGENTS.md"
                    source.write_bytes(source.read_bytes() + b"changed\n")
                before = tree_hashes(root)
                result = self._apply(MIGRATE_SCRIPTS[0], root, bundle, digest)
                self.assertEqual(3, result.returncode, result.stderr)
                self.assertEqual(before, tree_hashes(root))

    def test_real_plan_apply_and_rollback_authorizations_must_be_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle, digest, _ = self._plan(
                MIGRATE_SCRIPTS[0], parent, scope="real", authorization_ref="review-plan"
            )
            before = tree_hashes(root)
            reused = self._apply(
                MIGRATE_SCRIPTS[0], root, bundle, digest, authorization_ref="review-plan"
            )
            self.assertEqual(2, reused.returncode, reused.stderr)
            self.assertEqual(before, tree_hashes(root))

            applied = self._apply(
                MIGRATE_SCRIPTS[0], root, bundle, digest, authorization_ref="approve-apply"
            )
            self.assertEqual(0, applied.returncode, applied.stderr)
            result = run_tool(
                MIGRATE_SCRIPTS[0],
                "rollback",
                "--root",
                str(root),
                "--apply-transaction-id",
                "migration-apply-0001",
                "--scope",
                "real",
                "--transaction-id",
                "migration-rollback-0001",
                "--actor",
                "fixture-agent",
                "--occurred-at",
                "2026-08-30T02:03:00Z",
                "--authorization-ref",
                "approve-apply",
            )
            self.assertEqual(2, result.returncode, result.stderr)

    def test_verify_failure_is_exit_five_and_proposed_apply_is_exit_four(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle, digest, _ = self._plan(MIGRATE_SCRIPTS[0], parent)
            result = run_tool(
                MIGRATE_SCRIPTS[0],
                "verify",
                "--root",
                str(root),
                "--bundle",
                str(bundle),
                "--scope",
                "fixture",
            )
            self.assertEqual(5, result.returncode, result.stderr)
            self.assertFalse(_json_result(result)["valid"])

        from obsidian_agent_memory import cli_migrate

        arguments = [
            "apply",
            "--root",
            "fictional-fixture-root",
            "--bundle",
            "fictional-reviewed-bundle",
            "--bundle-sha256",
            LOWER_HASH,
            "--scope",
            "fixture",
            "--transaction-id",
            "migration-apply-0001",
            "--actor",
            "fixture-agent",
            "--occurred-at",
            "2026-08-30T02:01:00Z",
        ]
        proposed = MigrationResult(
            "proposed",
            "migration-apply-0001",
            "2" * 64,
            LOWER_HASH,
            None,
            None,
            None,
            (),
            (),
            (),
            (".agent-memory/proposals/migration-apply-0001.json",),
        )
        stdout = io.StringIO()
        with mock.patch.object(cli_migrate, "load_migration_bundle", return_value=object()), mock.patch.object(
            cli_migrate, "apply_migration", return_value=proposed
        ), contextlib.redirect_stdout(stdout):
            self.assertEqual(4, cli_migrate.main(arguments))
        self.assertEqual("proposed", json.loads(stdout.getvalue())["status"])

        stderr = io.StringIO()
        with mock.patch.object(cli_migrate, "load_migration_bundle", return_value=object()), mock.patch.object(
            cli_migrate, "apply_migration", side_effect=ConflictError("root-write-busy")
        ), contextlib.redirect_stderr(stderr):
            self.assertEqual(4, cli_migrate.main(arguments))
        self.assertIn("root-write-busy", stderr.getvalue())

    def test_hash_safe_rollback_refusal_is_exit_five(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root, bundle, digest, _ = self._plan(MIGRATE_SCRIPTS[0], parent)
            applied = self._apply(MIGRATE_SCRIPTS[0], root, bundle, digest)
            self.assertEqual(0, applied.returncode, applied.stderr)
            created_path = _json_result(applied)["created_paths"][0]
            target = root.joinpath(*created_path.split("/"))
            target.write_bytes(target.read_bytes() + b"drift\n")

            result = run_tool(
                MIGRATE_SCRIPTS[0],
                "rollback",
                "--root",
                str(root),
                "--apply-transaction-id",
                "migration-apply-0001",
                "--scope",
                "fixture",
                "--transaction-id",
                "migration-rollback-0001",
                "--actor",
                "fixture-agent",
                "--occurred-at",
                "2026-08-30T02:03:00Z",
            )
            self.assertEqual(5, result.returncode, result.stderr)

    def test_stale_fixture_rollback_requires_authorization_before_recovery(self):
        for script in MIGRATE_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root, bundle, digest, _ = self._plan(script, parent)
                process = multiprocessing.Process(
                    target=_crash_during_apply,
                    args=(root, bundle, digest),
                )
                process.start()
                try:
                    process.join(30)
                    self.assertFalse(process.is_alive())
                    self.assertEqual(23, process.exitcode)
                    before = tree_hashes(root)
                    base = (
                        "rollback",
                        "--root",
                        str(root),
                        "--apply-transaction-id",
                        "migration-apply-0001",
                        "--scope",
                        "fixture",
                        "--transaction-id",
                        "migration-rollback-0001",
                        "--actor",
                        "fixture-agent",
                        "--occurred-at",
                        "2026-08-30T02:03:00Z",
                    )
                    refused = run_tool(script, *base)
                    self.assertEqual(2, refused.returncode, refused.stderr)
                    self.assertEqual(before, tree_hashes(root))

                    recovered = run_tool(
                        script,
                        *base,
                        "--authorization-ref",
                        "fixture-explicit-rollback-recovery",
                    )
                    self.assertEqual(0, recovered.returncode, recovered.stderr)
                    document = _json_result(recovered)
                    self.assertEqual(
                        "fixture-explicit-rollback-recovery",
                        document["rollback_authorization_ref"],
                    )
                finally:
                    if process.is_alive():
                        process.terminate()
                    process.join()

    def test_maintenance_outputs_and_saved_audit_must_be_outside_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = copy_vault_fixture("v2-clean", parent)
            before = tree_hashes(root)
            for script in MAINTAIN_SCRIPTS:
                for output in (root, root / "audit.json"):
                    result = run_tool(
                        script,
                        "audit",
                        "--root",
                        str(root),
                        "--output",
                        str(output),
                        "--scope",
                        "fixture",
                    )
                    self.assertEqual(2, result.returncode, result.stderr)
                    self.assertEqual(before, tree_hashes(root))

                result = run_tool(
                    script,
                    "plan",
                    "--root",
                    str(root),
                    "--audit",
                    str(root / "audit.json"),
                    "--output",
                    str(parent / "cleanup-plan.json"),
                    "--scope",
                    "fixture",
                    "--transaction-id",
                    "cleanup-plan-0001",
                    "--actor",
                    "fixture-agent",
                    "--occurred-at",
                    "2026-08-30T02:04:00Z",
                )
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertEqual(before, tree_hashes(root))

    def test_maintenance_audit_and_plan_are_deterministic_external_artifacts(self):
        for script in MAINTAIN_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root = copy_vault_fixture("v2-clean", parent)
                before = tree_hashes(root)
                audit_path = parent / "review" / "audit.json"
                audit = run_tool(
                    script,
                    "audit",
                    "--root",
                    str(root),
                    "--output",
                    str(audit_path),
                    "--scope",
                    "fixture",
                )
                self.assertEqual(0, audit.returncode, audit.stderr)
                self.assertTrue(audit_path.is_file())
                self.assertEqual(before, tree_hashes(root))
                audit_document = json.loads(audit_path.read_text("utf-8"))
                self.assertEqual(_json_result(audit)["source_revision"], audit_document["source_revision"])

                plan_path = parent / "review" / "cleanup-plan.json"
                planned = run_tool(
                    script,
                    "plan",
                    "--root",
                    str(root),
                    "--audit",
                    str(audit_path),
                    "--output",
                    str(plan_path),
                    "--scope",
                    "fixture",
                    "--transaction-id",
                    "cleanup-plan-0001",
                    "--actor",
                    "fixture-agent",
                    "--occurred-at",
                    "2026-08-30T02:04:00Z",
                )
                self.assertEqual(0, planned.returncode, planned.stderr)
                self.assertTrue(plan_path.is_file())
                self.assertEqual(before, tree_hashes(root))
                self.assertEqual(_json_result(planned)["plan_id"], json.loads(plan_path.read_text("utf-8"))["plan_id"])

    def test_recovery_parser_rejects_before_dispatch_and_forwards_exact_public_call(self):
        from obsidian_agent_memory import cli_maintain

        root = Path("fictional-fixture-root")
        base = [
            "recover-root-guard",
            "--root",
            str(root),
            "--scope",
            "fixture",
            "--target-transaction-id",
            "crashed-writer-1",
            "--transaction-id",
            "recovery-1",
            "--actor",
            "fixture-agent",
            "--occurred-at",
            "2026-08-30T02:05:00Z",
        ]
        invalid_forms = (
            base,
            base + ["--authorization-ref", "review-recovery"],
            base + ["--authorization-ref", "review-recovery", "--expected-lock-sha256", "A" * 64],
            base + ["--authorization-ref", "review-recovery", "--expected-lock-sha256", LOWER_HASH, "--candidate-only"],
        )
        for arguments in invalid_forms:
            with self.subTest(arguments=arguments), mock.patch.object(
                cli_maintain,
                "recover_stale_root_guard",
                side_effect=AssertionError("dispatch occurred"),
            ):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(2, cli_maintain.main(arguments))

        expected = GuardRecoveryResult(
            "recovered",
            "crashed-writer-1",
            "recovery-1",
            "canonical-lock",
            ".agent-memory/root-write-recoveries/recovery-1/result.json",
            "2" * 64,
        )
        with mock.patch.object(
            cli_maintain,
            "recover_stale_root_guard",
            return_value=expected,
        ) as operation, contextlib.redirect_stdout(io.StringIO()):
            result = cli_maintain.main(
                base
                + [
                    "--authorization-ref",
                    "review-recovery",
                    "--expected-lock-sha256",
                    LOWER_HASH,
                ]
            )
        self.assertEqual(0, result)
        operation.assert_called_once_with(
            root,
            "crashed-writer-1",
            LOWER_HASH,
            TransactionContext("recovery-1", "fixture-agent", "2026-08-30T02:05:00Z"),
            AuthorizationGate(OperationScope.FIXTURE, "review-recovery"),
        )

        candidate = GuardRecoveryResult(
            "recovered",
            "crashed-writer-1",
            "recovery-1",
            "candidate-only",
            ".agent-memory/root-write-recoveries/recovery-1/result.json",
            "3" * 64,
        )
        with mock.patch.object(
            cli_maintain,
            "recover_stale_root_guard",
            return_value=candidate,
        ) as operation, contextlib.redirect_stdout(io.StringIO()):
            result = cli_maintain.main(
                base + ["--authorization-ref", "review-recovery", "--candidate-only"]
            )
        self.assertEqual(0, result)
        self.assertIsNone(operation.call_args.args[2])


if __name__ == "__main__":
    unittest.main()
