import os
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT, copy_vault_fixture
from tests.unit.test_artifact_schemas import (
    _applied_golden_migration,
    _duplicate_apply_journal,
)
from tests.unit.test_install_lifecycle import _snapshot
from tests.unit.test_uninstall_lifecycle import _install_managed, _selection

from obsidian_agent_memory import (
    AdapterSelection,
    Finding,
    TransactionContext,
    initialize_memory_root,
)
from obsidian_agent_memory.validation import doctor_memory_root
from tools.agent_memory_pack import run_doctor
from tools.agent_memory_pack import doctor as pack_doctor


EXPECTED_CODES = (
    "python-version",
    "source-manifest",
    "skill-root-selection",
    "installed-state",
    "active-family",
    "removed-members",
    "memory-binding",
    "memory-root-health",
    "filesystem-read",
    "obsidian-cli",
)


class PackDoctorTests(unittest.TestCase):
    def test_migration_review_proposal_written_by_apply_is_valid(self):
        root, _, result = _applied_golden_migration(self)

        findings = doctor_memory_root(root)
        proposal_paths = set(result.proposal_paths)

        self.assertFalse(
            any(
                item.code == "proposal-invalid" and item.path in proposal_paths
                for item in findings
            )
        )
        self.assertFalse(
            any(
                item.code == "proposal-unbound" and item.path in proposal_paths
                for item in findings
            )
        )

    def test_migration_review_proposal_requires_one_applied_journal_binding(self):
        applied_root, _, result = _applied_golden_migration(self)
        selected_path = result.proposal_paths[0]
        selected_raw = (applied_root / selected_path).read_bytes()

        with tempfile.TemporaryDirectory() as temporary:
            unbound_root = copy_vault_fixture("v2-clean", Path(temporary))
            target = unbound_root / selected_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(selected_raw)
            findings = doctor_memory_root(unbound_root)
            self.assertTrue(
                any(item.code == "proposal-unbound" and item.path == selected_path for item in findings)
            )
            self.assertFalse(
                any(item.code == "proposal-invalid" and item.path == selected_path for item in findings)
            )

        _duplicate_apply_journal(applied_root)
        duplicate_findings = doctor_memory_root(applied_root)
        self.assertTrue(
            any(
                item.code == "proposal-unbound" and item.path == selected_path
                for item in duplicate_findings
            )
        )

        with tempfile.TemporaryDirectory() as temporary:
            malformed_root = copy_vault_fixture("v2-clean", Path(temporary))
            target = malformed_root / selected_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"{}\n")
            malformed_findings = doctor_memory_root(malformed_root)
            self.assertTrue(
                any(
                    item.code == "proposal-invalid" and item.path == selected_path
                    for item in malformed_findings
                )
            )
            self.assertFalse(
                any(
                    item.code == "proposal-unbound" and item.path == selected_path
                    for item in malformed_findings
                )
            )

    def test_preconfiguration_doctor_is_deterministic_and_never_discovers_ambient_state(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            _install_managed(selection, root)
            workspace = root / "workspace"
            workspace.mkdir()

            unexpected = AssertionError("ambient discovery was attempted")
            with mock.patch.object(Path, "home", side_effect=unexpected), mock.patch.object(
                Path, "expanduser", side_effect=unexpected
            ), mock.patch.dict(os.environ, {}, clear=True), mock.patch(
                "shutil.which", side_effect=unexpected
            ), mock.patch("subprocess.run", side_effect=unexpected):
                report = run_doctor(REPO_ROOT, selection, workspace)

            self.assertTrue(report.ok)
            self.assertIsNone(report.authorization_ref)
            self.assertEqual(EXPECTED_CODES, tuple(check.code for check in report.checks))
            by_code = {check.code: check for check in report.checks}
            self.assertEqual("warning", by_code["memory-binding"].status)
            self.assertEqual("warning", by_code["memory-root-health"].status)
            self.assertEqual("warning", by_code["filesystem-read"].status)
            self.assertEqual("warning", by_code["obsidian-cli"].status)
            self.assertEqual(
                "optional capability not probed; filesystem mode verified",
                by_code["obsidian-cli"].message,
            )

    def test_authorization_precedes_memory_reads_and_findings_are_not_repaired(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            _install_managed(selection, root)
            workspace = root / "workspace"
            workspace.mkdir()
            memory_root = root / "memory"
            initialize_memory_root(
                memory_root,
                "demo",
                TransactionContext(
                    "doctor-init-001", "memory-operator", "2026-08-30T06:20:00Z"
                ),
            )

            with mock.patch.object(
                pack_doctor,
                "resolve_binding",
                side_effect=AssertionError("binding read before authorization"),
            ) as resolver, mock.patch.object(
                pack_doctor,
                "doctor_memory_root",
                side_effect=AssertionError("memory read before authorization"),
            ) as core_doctor:
                unauthorized = run_doctor(
                    REPO_ROOT,
                    selection,
                    workspace,
                    memory_root=memory_root,
                    project_id="demo",
                )
            self.assertFalse(unauthorized.ok)
            self.assertFalse(resolver.called)
            self.assertFalse(core_doctor.called)
            self.assertEqual(
                "fail",
                {check.code: check for check in unauthorized.checks}["memory-binding"].status,
            )

            before = tuple(
                (path.relative_to(memory_root).as_posix(), path.read_bytes())
                for path in sorted(memory_root.rglob("*"))
                if path.is_file()
            )
            finding = Finding(
                "projection-finalization-incomplete",
                "error",
                ".agent-memory/transactions/example.json",
                "recoverable finalization evidence remains",
            )
            with mock.patch.object(
                pack_doctor, "doctor_memory_root", return_value=(finding,)
            ):
                report = run_doctor(
                    REPO_ROOT,
                    selection,
                    workspace,
                    memory_root=memory_root,
                    project_id="demo",
                    authorization_ref="doctor-read-approval-001",
                )
            health = {check.code: check for check in report.checks}["memory-root-health"]
            self.assertFalse(report.ok)
            self.assertEqual("doctor-read-approval-001", report.authorization_ref)
            self.assertEqual("fail", health.status)
            self.assertIn(finding.code, health.message)
            self.assertIn(finding.path, health.message)
            self.assertIn(finding.message, health.message)
            after = tuple(
                (path.relative_to(memory_root).as_posix(), path.read_bytes())
                for path in sorted(memory_root.rglob("*"))
                if path.is_file()
            )
            self.assertEqual(before, after)

    def test_cli_probe_is_opt_in_and_preserves_explicit_vault_binding(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            _install_managed(selection, root)
            workspace = root / "workspace"
            workspace.mkdir()
            memory_root = root / "memory"
            initialize_memory_root(
                memory_root,
                "demo",
                TransactionContext(
                    "doctor-init-002", "memory-operator", "2026-08-30T06:20:00Z"
                ),
            )
            observed = []

            def select(binding, runner, executable):
                observed.append((binding, runner, executable))
                return AdapterSelection(mock.Mock(), "obsidian-cli", "cli-healthy")

            runner = mock.Mock()
            executable = root / "obsidian-cli.exe"
            with mock.patch.object(
                pack_doctor, "select_read_adapter", side_effect=select
            ):
                report = run_doctor(
                    REPO_ROOT,
                    selection,
                    workspace,
                    memory_root=memory_root,
                    project_id="demo",
                    authorization_ref="cli-read-approval-001",
                    probe_cli=True,
                    cli_executable=executable,
                    obsidian_vault="Explicit Vault",
                    runner=runner,
                )
            self.assertTrue(report.ok)
            self.assertEqual(1, len(observed))
            binding, selected_runner, selected_executable = observed[0]
            self.assertEqual(memory_root, binding.memory_root)
            self.assertEqual("demo", binding.project_id)
            self.assertEqual("Explicit Vault", binding.obsidian_vault)
            self.assertIs(runner, selected_runner)
            self.assertEqual(executable, selected_executable)
            self.assertEqual(
                "pass", {check.code: check for check in report.checks}["obsidian-cli"].status
            )


class BootstrapCommandTests(unittest.TestCase):
    def _run(self, *arguments):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "bootstrap.py")]
            + list(arguments),
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def test_help_exposes_exactly_four_independent_commands(self):
        completed = self._run("--help")
        self.assertEqual(0, completed.returncode, completed.stdout)
        self.assertEqual(
            "usage: bootstrap.py {check,plan,apply,doctor} ...",
            completed.stdout.splitlines()[0],
        )
        self.assertIn("{check,plan,apply,doctor}", completed.stdout)

    def test_check_plan_apply_and_doctor_do_not_fall_through(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            workspace = root / "workspace"
            workspace.mkdir()
            plan_path = root / "reviewed-plan.json"
            before = _snapshot(root)

            checked = self._run(
                "check",
                "--source", str(REPO_ROOT),
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
            )
            self.assertEqual(0, checked.returncode, checked.stdout)
            self.assertRegex(checked.stdout, r"^CHECK valid mode=fresh blockers=0\n$")
            self.assertEqual(before, _snapshot(root))

            planned = self._run(
                "plan",
                "--source", str(REPO_ROOT),
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--transaction-id", "bootstrap-install-001",
                "--actor", "planning-operator",
                "--occurred-at", "2026-08-30T06:30:00Z",
                "--plan-out", str(plan_path),
            )
            self.assertEqual(0, planned.returncode, planned.stdout)
            self.assertRegex(
                planned.stdout,
                r"^PLAN install transaction=bootstrap-install-001 mode=fresh actions=11 blockers=0 sha256=[0-9a-f]{64}\n$",
            )
            self.assertFalse(selection.skills_root.exists())
            self.assertFalse(selection.state_root.exists())
            digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()

            invalid_apply = self._run(
                "apply",
                "--source", str(REPO_ROOT),
                "--plan", str(plan_path),
                "--plan-sha256", digest,
                "--authorization-ref", "install-approval-001",
            )
            self.assertEqual(2, invalid_apply.returncode, invalid_apply.stdout)
            self.assertFalse(selection.skills_root.exists())
            self.assertFalse(selection.state_root.exists())

            applied = self._run(
                "apply",
                "--source", str(REPO_ROOT),
                "--plan", str(plan_path),
                "--plan-sha256", digest,
                "--actor", "apply-operator",
                "--occurred-at", "2026-08-30T06:35:00Z",
                "--authorization-ref", "install-approval-001",
            )
            self.assertEqual(0, applied.returncode, applied.stdout)
            self.assertEqual(
                "INSTALLED version=2.0.2 transaction=bootstrap-install-001 rollback-retained=true\n",
                applied.stdout,
            )

            doctor = self._run(
                "doctor",
                "--source", str(REPO_ROOT),
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--workspace", str(workspace),
            )
            self.assertEqual(0, doctor.returncode, doctor.stdout)
            lines = doctor.stdout.splitlines()
            self.assertEqual(10, len(lines))
            self.assertTrue(lines[0].startswith("PASS python-version "))
            self.assertTrue(lines[-1].startswith("WARN obsidian-cli "))


if __name__ == "__main__":
    unittest.main()
