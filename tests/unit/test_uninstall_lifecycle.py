import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT
from tests.unit.test_install_lifecycle import (
    _plan as _install_plan,
    _review_plan,
    _selection,
    _snapshot,
)

from obsidian_agent_memory import ConflictError
from tools.agent_memory_pack import (
    ACTIVE_MEMBERS,
    apply_install,
    apply_uninstall,
    load_lifecycle_plan,
    plan_uninstall,
    recover_lifecycle,
    rollback_lifecycle,
    write_lifecycle_plan,
)
from tools.agent_memory_pack import lifecycle as pack_lifecycle
from tools.agent_memory_pack.io import canonical_json_bytes


PLANNED_AT = "2026-08-30T06:00:00Z"


def _install_managed(selection, root, transaction_id="managed-install-001"):
    plan, digest = _review_plan(
        _install_plan(selection, transaction_id=transaction_id),
        root,
        transaction_id + "-plan.json",
    )
    return apply_install(
        REPO_ROOT,
        plan,
        digest,
        "install-operator",
        "2026-08-30T05:05:00Z",
        transaction_id + "-approval",
    )


def _uninstall_plan(selection, root, transaction_id="pack-uninstall-001"):
    plan = plan_uninstall(
        selection,
        transaction_id,
        "workstation-operator",
        PLANNED_AT,
    )
    return _review_plan(plan, root, transaction_id + "-plan.json")


class UninstallPlanningTests(unittest.TestCase):
    def test_exact_managed_family_plans_ten_archives_and_ignores_unrelated_sentinel(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            _install_managed(selection, root)
            unrelated = selection.skills_root / "unrelated-skill" / "sentinel.txt"
            unrelated.parent.mkdir()
            unrelated.write_text("keep me\n", encoding="utf-8")
            installed_raw = (selection.state_root / "installed.json").read_bytes()
            before_skills = _snapshot(selection.skills_root)
            before_state = _snapshot(selection.state_root)

            plan = plan_uninstall(
                selection,
                "pack-uninstall-001",
                "workstation-operator",
                PLANNED_AT,
            )

            self.assertEqual("uninstall", plan.operation)
            self.assertEqual("workstation-operator", plan.actor)
            self.assertEqual(PLANNED_AT, plan.occurred_at)
            self.assertEqual("2.0.1", plan.from_version)
            self.assertIsNone(plan.to_version)
            self.assertIsNone(plan.source)
            self.assertIsNone(plan.source_revision)
            self.assertEqual((), plan.blockers)
            self.assertEqual(10, len(plan.actions))
            self.assertEqual(
                ["archive-member"] * 9 + ["archive-installed-state"],
                [action.kind for action in plan.actions],
            )
            self.assertEqual(
                list(ACTIVE_MEMBERS) + [None],
                [action.member for action in plan.actions],
            )
            self.assertEqual(
                hashlib.sha256(installed_raw).hexdigest(),
                plan.installed_state_sha256,
            )
            self.assertFalse(any("unrelated-skill" in action.target_relative for action in plan.actions))
            self.assertEqual(before_skills, _snapshot(selection.skills_root))
            self.assertEqual(before_state, _snapshot(selection.state_root))

            plan_path = write_lifecycle_plan(plan, root / "reviewed-uninstall.json")
            self.assertEqual(plan, load_lifecycle_plan(plan_path))

    def test_unmanaged_or_drifted_ownership_is_blocked_without_actions_or_writes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            unmanaged = _selection(root, "unmanaged")
            unmanaged.skills_root.mkdir(parents=True)
            (unmanaged.skills_root / "obsidian-agent-memory").mkdir()
            unmanaged_before = _snapshot(root)

            unmanaged_plan = plan_uninstall(
                unmanaged,
                "unmanaged-uninstall",
                "workstation-operator",
                PLANNED_AT,
            )

            self.assertEqual((), unmanaged_plan.actions)
            self.assertTrue(unmanaged_plan.blockers)
            self.assertEqual(unmanaged_before, _snapshot(root))

            selection = _selection(root, "managed")
            _install_managed(selection, root, "managed-install-002")
            installed_path = selection.state_root / "installed.json"
            installed_original = installed_path.read_bytes()

            changed = selection.skills_root / ACTIVE_MEMBERS[0] / "unexpected.txt"
            changed.write_text("unexpected\n", encoding="utf-8")
            before = _snapshot(selection.state_root)
            target_drift = plan_uninstall(
                selection, "target-drift", "workstation-operator", PLANNED_AT
            )
            self.assertEqual((), target_drift.actions)
            self.assertTrue(target_drift.blockers)
            self.assertEqual(before, _snapshot(selection.state_root))
            changed.unlink()

            installed_document = json.loads(installed_original.decode("utf-8"))
            installed_document["pack_version"] = "1.9.0"
            installed_path.write_bytes(canonical_json_bytes(installed_document))
            before = _snapshot(selection.skills_root)
            version_drift = plan_uninstall(
                selection, "version-drift", "workstation-operator", PLANNED_AT
            )
            self.assertEqual((), version_drift.actions)
            self.assertTrue(version_drift.blockers)
            self.assertEqual(before, _snapshot(selection.skills_root))
            installed_path.write_bytes(installed_original)

            removed = selection.skills_root / "obsidian-agent-memory-writer"
            removed.mkdir()
            before = _snapshot(selection.state_root)
            removed_active = plan_uninstall(
                selection, "removed-active", "workstation-operator", PLANNED_AT
            )
            self.assertEqual((), removed_active.actions)
            self.assertTrue(
                any(item.code == "active-removed-member" for item in removed_active.blockers)
            )
            self.assertEqual(before, _snapshot(selection.state_root))


class UninstallApplyRollbackTests(unittest.TestCase):
    def test_apply_archives_exact_family_preserves_sentinel_and_rollback_restores(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            _install_managed(selection, root)
            sentinel = selection.skills_root / "unrelated-skill" / "sentinel.txt"
            sentinel.parent.mkdir()
            sentinel.write_text("keep me\n", encoding="utf-8")
            family_before = {
                member: _snapshot(selection.skills_root / member)
                for member in ACTIVE_MEMBERS
            }
            installed_before = (selection.state_root / "installed.json").read_bytes()
            plan, digest = _uninstall_plan(selection, root)
            lock_events = []

            def record_lock(stage, path):
                lock_events.append((stage, Path(path).name))

            with mock.patch.object(
                pack_lifecycle, "_lock_checkpoint", side_effect=record_lock
            ):
                result = apply_uninstall(
                    plan,
                    digest,
                    "uninstall-operator",
                    "2026-08-30T06:05:00Z",
                    "uninstall-approval-001",
                )

            transaction = selection.state_root / "transactions" / "pack-uninstall-001"
            previous = transaction / "rollback" / "previous"
            self.assertEqual("uninstalled", result.status)
            self.assertIsNone(result.version)
            self.assertEqual(10, len(result.moved_paths))
            self.assertEqual("keep me\n", sentinel.read_text(encoding="utf-8"))
            self.assertFalse((selection.state_root / "installed.json").exists())
            for member in ACTIVE_MEMBERS:
                self.assertFalse((selection.skills_root / member).exists())
                self.assertEqual(
                    family_before[member], _snapshot(previous / "skills" / member)
                )
            self.assertEqual(installed_before, (previous / "installed.json").read_bytes())
            journal = json.loads((transaction / "journal.json").read_text(encoding="utf-8"))
            self.assertEqual("committed", journal["status"])
            self.assertEqual("uninstall", journal["operation"])
            self.assertEqual("uninstall-operator", journal["operation_actor"])
            self.assertEqual("uninstall-approval-001", journal["authorization_ref"])
            self.assertTrue((transaction / "result.json").is_file())
            self.assertEqual(
                [selection.target_lock_path.name, "lifecycle.lock"],
                [name for stage, name in lock_events if stage == "canonical-linked"],
            )
            self.assertEqual(
                ["lifecycle.lock", selection.target_lock_path.name],
                [name for stage, name in lock_events if stage == "canonical-unlinked"],
            )

            rolled_back = rollback_lifecycle(
                selection,
                "pack-uninstall-001",
                "rollback-operator",
                "2026-08-30T06:10:00Z",
                "uninstall-rollback-001",
            )
            self.assertEqual("rolled-back", rolled_back.status)
            self.assertEqual("2.0.1", rolled_back.version)
            self.assertEqual(installed_before, (selection.state_root / "installed.json").read_bytes())
            self.assertEqual("keep me\n", sentinel.read_text(encoding="utf-8"))
            for member in ACTIVE_MEMBERS:
                self.assertEqual(family_before[member], _snapshot(selection.skills_root / member))

    def test_reviewed_target_and_installed_state_cas_refuse_before_transaction(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            _install_managed(selection, root)
            plan, digest = _uninstall_plan(selection, root)
            transaction = selection.state_root / "transactions" / "pack-uninstall-001"

            changed = selection.skills_root / ACTIVE_MEMBERS[0] / "unexpected.txt"
            changed.write_text("unexpected\n", encoding="utf-8")
            before = _snapshot(root)
            with self.assertRaises(ConflictError):
                apply_uninstall(
                    plan,
                    digest,
                    "uninstall-operator",
                    "2026-08-30T06:05:00Z",
                    "target-drift-approval",
                )
            self.assertEqual(before, _snapshot(root))
            self.assertFalse(transaction.exists())
            self.assertFalse(selection.target_lock_path.exists())
            changed.unlink()

            installed_path = selection.state_root / "installed.json"
            document = json.loads(installed_path.read_text(encoding="utf-8"))
            document["actor"] = "changed-operator"
            installed_path.write_bytes(canonical_json_bytes(document))
            before = _snapshot(root)
            with self.assertRaises(ConflictError):
                apply_uninstall(
                    plan,
                    digest,
                    "uninstall-operator",
                    "2026-08-30T06:05:00Z",
                    "state-drift-approval",
                )
            self.assertEqual(before, _snapshot(root))
            self.assertFalse(transaction.exists())
            self.assertFalse(selection.target_lock_path.exists())

    def test_rollback_refuses_changed_evidence_or_occupied_target_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            _install_managed(selection, root)
            plan, digest = _uninstall_plan(selection, root)
            apply_uninstall(
                plan,
                digest,
                "uninstall-operator",
                "2026-08-30T06:05:00Z",
                "uninstall-approval-001",
            )
            rollback_member = (
                selection.state_root
                / "transactions"
                / "pack-uninstall-001"
                / "rollback"
                / "previous"
                / "skills"
                / ACTIVE_MEMBERS[0]
                / "SKILL.md"
            )
            original = rollback_member.read_bytes()
            rollback_member.write_bytes(original + b"\ndrift\n")
            before = _snapshot(root)
            with self.assertRaises(ConflictError):
                rollback_lifecycle(
                    selection,
                    "pack-uninstall-001",
                    "rollback-operator",
                    "2026-08-30T06:10:00Z",
                    "uninstall-rollback-001",
                )
            self.assertEqual(before, _snapshot(root))
            self.assertFalse(selection.target_lock_path.exists())
            rollback_member.write_bytes(original)

            occupied = selection.skills_root / ACTIVE_MEMBERS[-1]
            occupied.mkdir()
            (occupied / "sentinel.txt").write_text("occupied\n", encoding="utf-8")
            before = _snapshot(root)
            with self.assertRaises(ConflictError):
                rollback_lifecycle(
                    selection,
                    "pack-uninstall-001",
                    "rollback-operator",
                    "2026-08-30T06:10:00Z",
                    "uninstall-rollback-002",
                )
            self.assertEqual(before, _snapshot(root))
            self.assertFalse(selection.target_lock_path.exists())

    def test_terminal_uninstall_reuses_recovery_without_restoring_active_members(self):
        class SimulatedCrash(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            _install_managed(selection, root)
            plan, digest = _uninstall_plan(selection, root)

            def crash(stage):
                if stage == "before-state-lock-release":
                    raise SimulatedCrash()

            with mock.patch.object(
                pack_lifecycle, "_lifecycle_checkpoint", side_effect=crash
            ), self.assertRaises(SimulatedCrash):
                apply_uninstall(
                    plan,
                    digest,
                    "uninstall-operator",
                    "2026-08-30T06:05:00Z",
                    "uninstall-approval-001",
                )

            result = recover_lifecycle(
                selection,
                "pack-uninstall-001",
                "recovery-operator",
                "2026-08-30T06:15:00Z",
                "uninstall-recovery-001",
            )
            self.assertEqual("recovered", result.status)
            self.assertFalse((selection.state_root / "installed.json").exists())
            for member in ACTIVE_MEMBERS:
                self.assertFalse((selection.skills_root / member).exists())
            self.assertFalse(selection.target_lock_path.exists())
            self.assertFalse((selection.state_root / "lifecycle.lock").exists())


class UninstallCliTests(unittest.TestCase):
    def _run(self, *arguments):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "uninstall_pack.py")]
            + list(arguments),
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def test_plan_apply_rollback_and_recover_are_thin_exact_commands(self):
        class SimulatedCrash(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root, "cli")
            _install_managed(selection, root, "cli-managed-install")
            plan_path = root / "cli-uninstall-plan.json"

            planned = self._run(
                "plan",
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--transaction-id", "pack-uninstall-cli",
                "--actor", "workstation-operator",
                "--occurred-at", PLANNED_AT,
                "--plan-out", str(plan_path),
            )
            self.assertEqual(0, planned.returncode, planned.stdout)
            self.assertRegex(
                planned.stdout,
                r"^PLAN uninstall transaction=pack-uninstall-cli actions=10 blockers=0 sha256=[0-9a-f]{64}\n$",
            )
            digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
            applied = self._run(
                "apply",
                "--plan", str(plan_path),
                "--plan-sha256", digest,
                "--actor", "uninstall-operator",
                "--occurred-at", "2026-08-30T06:05:00Z",
                "--authorization-ref", "uninstall-approval-001",
            )
            self.assertEqual(0, applied.returncode, applied.stdout)
            self.assertEqual(
                "UNINSTALLED transaction=pack-uninstall-cli rollback-retained=true\n",
                applied.stdout,
            )
            rolled_back = self._run(
                "rollback",
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--transaction-id", "pack-uninstall-cli",
                "--actor", "rollback-operator",
                "--occurred-at", "2026-08-30T06:10:00Z",
                "--authorization-ref", "uninstall-rollback-001",
            )
            self.assertEqual(0, rolled_back.returncode, rolled_back.stdout)
            self.assertEqual(
                "ROLLED-BACK transaction=pack-uninstall-cli rollback-retained=true\n",
                rolled_back.stdout,
            )

            recovery_selection = _selection(root, "recover-cli")
            _install_managed(recovery_selection, root, "recover-managed-install")
            recovery_plan, recovery_digest = _uninstall_plan(
                recovery_selection, root, "pack-uninstall-recover"
            )

            def crash(stage):
                if stage == "before-state-lock-release":
                    raise SimulatedCrash()

            with mock.patch.object(
                pack_lifecycle, "_lifecycle_checkpoint", side_effect=crash
            ), self.assertRaises(SimulatedCrash):
                apply_uninstall(
                    recovery_plan,
                    recovery_digest,
                    "uninstall-operator",
                    "2026-08-30T06:05:00Z",
                    "recover-uninstall-approval",
                )
            recovered = self._run(
                "recover",
                "--skills-root", str(recovery_selection.skills_root),
                "--state-root", str(recovery_selection.state_root),
                "--transaction-id", "pack-uninstall-recover",
                "--actor", "recovery-operator",
                "--occurred-at", "2026-08-30T06:15:00Z",
                "--authorization-ref", "uninstall-recovery-001",
            )
            self.assertEqual(0, recovered.returncode, recovered.stdout)
            self.assertEqual(
                "RECOVERED transaction=pack-uninstall-recover target-state=unchanged\n",
                recovered.stdout,
            )

    def test_unmanaged_plan_is_blocked_and_no_force_form_exists(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            selection.skills_root.mkdir(parents=True)
            (selection.skills_root / "obsidian-agent-memory").mkdir()
            plan_path = root / "blocked.json"

            blocked = self._run(
                "plan",
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--transaction-id", "pack-uninstall-blocked",
                "--actor", "workstation-operator",
                "--occurred-at", PLANNED_AT,
                "--plan-out", str(plan_path),
            )
            self.assertEqual(3, blocked.returncode, blocked.stdout)
            self.assertRegex(blocked.stdout, r"^BLOCKED [a-z0-9-]+ .+: .+\n")
            self.assertFalse(plan_path.exists())

            forced = self._run(
                "plan",
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--transaction-id", "pack-uninstall-force",
                "--actor", "workstation-operator",
                "--occurred-at", PLANNED_AT,
                "--plan-out", str(plan_path),
                "--force",
            )
            self.assertEqual(2, forced.returncode, forced.stdout)


if __name__ == "__main__":
    unittest.main()
