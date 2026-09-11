"""Managed lifecycle compatibility across the 2.0.0 / 2.0.1 boundary."""

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT
from tests.unit.test_install_lifecycle import (
    _copy_active_family, _plan, _review_plan, _selection, _snapshot,
    _write_installed_state,
)
from obsidian_agent_memory import ValidationError
from tools.agent_memory_pack import (
    apply_install, apply_uninstall, plan_uninstall, recover_lifecycle,
    rollback_lifecycle,
    resolve_skill_roots,
)
from tools.agent_memory_pack import lifecycle
from tools.agent_memory_pack.io import canonical_json_bytes


def _managed_fixture(selection, version):
    _copy_active_family(selection.skills_root)
    # Distinct prior bytes make upgrade/rollback checks meaningful; this is a
    # synthetic owned installation, not a historical release artifact.
    prior = selection.skills_root / "obsidian-agent-memory" / "SKILL.md"
    prior.write_bytes(prior.read_bytes() + b"\nPrior managed fixture.\n")
    path = _write_installed_state(selection)
    document = json.loads(path.read_bytes())
    document["pack_version"] = version
    path.write_bytes(canonical_json_bytes(document))
    return path


class ReleaseVersionCompatibilityTests(unittest.TestCase):
    def test_actual_temporary_install_has_real_scope_managed_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            selection = resolve_skill_roots(root / "skills", None, {}, None)
            plan, digest = _review_plan(_plan(selection), root)
            apply_install(REPO_ROOT, plan, digest, "operator", "2026-09-11T01:00:00Z", "identity-install")
            scripts = selection.skills_root / "obsidian-agent-memory" / "scripts"
            cache = root / "fresh-cache"
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-X", "pycache_prefix=" + str(cache), "-c",
                 "import sys,json; sys.path.insert(0,sys.argv[1]); "
                 "from obsidian_agent_memory import observe_runtime_identity,OperationScope; "
                 "print(json.dumps(observe_runtime_identity(OperationScope.REAL,None).identity.document))",
                 str(scripts)],
                cwd=str(root), capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual({
                "kind": "pack-manifest", "version": "2.0.1",
                "verification_status": "managed-valid",
                "manifest_sha256": hashlib.sha256((selection.state_root / "installed.json").read_bytes()).hexdigest(),
            }, json.loads(result.stdout))
            self.assertFalse(cache.exists())

    def test_reviewed_install_plan_reads_both_supported_target_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(_selection(root))
            for version in ("2.0.0", "2.0.1"):
                with self.subTest(version=version):
                    candidate = replace(plan, to_version=version)
                    loaded, _ = _review_plan(candidate, root, version + ".json")
                    self.assertEqual(candidate, loaded)
            with self.assertRaises(ValidationError):
                _review_plan(replace(plan, to_version="9.0.0"), root, "unknown.json")

    def test_managed_200_to_201_upgrade_and_rollback_restore_exact_prior_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection = _selection(root)
            state_path = _managed_fixture(selection, "2.0.0")
            prior_state = state_path.read_bytes()
            prior_skills = _snapshot(selection.skills_root)
            plan, digest = _review_plan(_plan(selection), root)
            self.assertEqual((), plan.blockers)
            self.assertEqual("2.0.0", plan.from_version)
            self.assertEqual("2.0.1", plan.to_version)
            installed = apply_install(
                REPO_ROOT, plan, digest, "operator", "2026-09-11T01:00:00Z",
                "upgrade-approval",
            )
            self.assertEqual("2.0.1", installed.version)
            self.assertEqual("2.0.1", json.loads(state_path.read_bytes())["pack_version"])
            self.assertNotEqual(prior_skills, _snapshot(selection.skills_root))
            rolled_back = rollback_lifecycle(
                selection, plan.transaction_id, "operator",
                "2026-09-11T01:05:00Z", "rollback-approval",
            )
            self.assertEqual("2.0.0", rolled_back.version)
            self.assertEqual(prior_state, state_path.read_bytes())
            self.assertEqual(prior_skills, _snapshot(selection.skills_root))

    def test_both_versions_uninstall_recover_and_rollback_without_source(self):
        class SimulatedCrash(BaseException):
            pass

        def crash(stage):
            if stage == "before-state-lock-release":
                raise SimulatedCrash()

        for version in ("2.0.0", "2.0.1"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                selection = _selection(root)
                state_path = _managed_fixture(selection, version)
                prior_state = state_path.read_bytes()
                prior_skills = _snapshot(selection.skills_root)
                plan, digest = _review_plan(plan_uninstall(
                    selection, "uninstall-version", "operator", "2026-09-11T01:00:00Z",
                ), root)
                self.assertEqual((), plan.blockers)
                self.assertEqual(version, plan.from_version)
                with mock.patch.object(lifecycle, "_lifecycle_checkpoint", side_effect=crash):
                    with self.assertRaises(SimulatedCrash):
                        apply_uninstall(plan, digest, "operator", "2026-09-11T01:01:00Z", "uninstall-approval")
                recovered = recover_lifecycle(
                    selection, plan.transaction_id, "operator", "2026-09-11T01:02:00Z", "recover-approval",
                )
                self.assertEqual("recovered", recovered.status)
                self.assertFalse(state_path.exists())
                rolled_back = rollback_lifecycle(
                    selection, plan.transaction_id, "operator", "2026-09-11T01:03:00Z", "rollback-approval",
                )
                self.assertEqual(version, rolled_back.version)
                self.assertEqual(prior_state, state_path.read_bytes())
                self.assertEqual(prior_skills, _snapshot(selection.skills_root))

    def test_unknown_managed_version_blocks_install_and_uninstall_without_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection = _selection(root)
            _managed_fixture(selection, "9.0.0")
            before = _snapshot(root)
            plans = (_plan(selection), plan_uninstall(
                selection, "unknown-uninstall", "operator", "2026-09-11T01:00:00Z",
            ))
            for plan in plans:
                self.assertTrue(plan.blockers)
                self.assertEqual((), plan.actions)
            self.assertEqual(before, _snapshot(root))
