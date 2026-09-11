import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT

from tools.agent_memory_pack import run_fixture_smoke


EXPECTED_STEPS = (
    "release-built",
    "release-verified",
    "pack-installed",
    "installed-tools-verified",
    "doctor-headless",
    "memory-routed",
    "memory-initialized",
    "summary-and-add-accepted",
    "conflict-proposed",
    "accepted-record-catalog-verified",
    "promotion-candidate-preserved",
    "projection-cas-verified",
    "filesystem-query-accepted-only",
    "migration-planned",
    "migration-applied-with-archives",
    "migration-verified",
    "maintenance-planned",
    "installed-resolution-verified",
    "pack-uninstalled",
    "unrelated-sentinel-preserved",
)


class PackEndToEndTests(unittest.TestCase):
    def test_shipped_fixture_imports_win_over_unrelated_tests_package(self):
        result = subprocess.run(
            [sys.executable, "-I", "-B",
             str(REPO_ROOT / "tests/probes/fixture_import_precedence.py"), str(REPO_ROOT)],
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("INSTALLED FIXTURE PASS resolution-tests=4", result.stdout.strip())

    def test_fixture_workflow_does_not_use_source_runtime(self):
        with mock.patch(
            "tools.agent_memory_pack.smoke._record_projection_flow",
            side_effect=AssertionError("source runtime used instead of installed runtime"),
        ):
            report = run_fixture_smoke(REPO_ROOT)
        self.assertTrue(report.ok)

    def test_packaged_fixture_flow_reports_the_exact_ordered_tracer(self):
        report = run_fixture_smoke(REPO_ROOT)

        self.assertTrue(report.ok)
        self.assertEqual(EXPECTED_STEPS, report.steps)
        self.assertFalse((REPO_ROOT / "dist").exists())

    def test_smoke_ignores_ambient_roots_and_never_reads_home(self):
        sentinel = str(REPO_ROOT / "must-not-be-read")
        environment = {
            "CODEX_HOME": sentinel,
            "OBSIDIAN_AGENT_MEMORY_ROOT": sentinel,
            "OBSIDIAN_AGENT_MEMORY_PROJECT": "ambient-project",
            "OBSIDIAN_AGENT_MEMORY_CONFIG": sentinel,
            "OBSIDIAN_VAULT": "ambient-vault",
        }
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            Path,
            "home",
            side_effect=AssertionError("ambient home discovery attempted"),
        ):
            report = run_fixture_smoke(REPO_ROOT)

        self.assertTrue(report.ok)
        self.assertEqual(EXPECTED_STEPS, report.steps)

    def test_cli_rejects_every_mutable_or_real_scope_escape_hatch(self):
        command = (sys.executable, str(REPO_ROOT / "tools" / "smoke.py"))
        for option, value in (
            ("--scope", "real"),
            ("--root", "sentinel"),
            ("--skills-root", "sentinel"),
            ("--state-root", "sentinel"),
            ("--keep-temp", None),
        ):
            with self.subTest(option=option):
                arguments = command + (option,)
                if value is not None:
                    arguments += (value,)
                completed = subprocess.run(
                    arguments,
                    cwd=REPO_ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(0, completed.returncode)
                self.assertNotIn("SMOKE PASS", completed.stdout)


if __name__ == "__main__":
    unittest.main()
