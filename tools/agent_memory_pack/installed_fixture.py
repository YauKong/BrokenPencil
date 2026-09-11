"""Fresh-process smoke worker bound to the temporary installed runtime."""

import sys
import unittest
from pathlib import Path
from unittest import mock

from .smoke import _migration_and_maintenance_flow, _record_projection_flow


_RESOLUTION_TESTS = (
    "tests.unit.test_proposal_resolution_cli.ProposalResolutionCliContractTests."
    "test_fixture_cli_plans_applies_and_verifies",
    "tests.unit.test_resolution_visibility.ResolutionVisibilityTests."
    "test_all_dispositions_preserve_original_proposals_and_exact_replay",
    "tests.unit.test_resolution_visibility.ResolutionVisibilityTests."
    "test_loose_evidence_and_incomplete_journal_cannot_hide_proposals",
    "tests.integration.test_proposal_resolution_workflow.ProposalResolutionWorkflowTests."
    "test_reviewed_rewrites_are_applied_without_changing_legacy_evidence",
)


def _assert_module_origins(prefix, expected):
    expected = expected.resolve(strict=True)
    modules = tuple(
        module for name, module in sys.modules.items()
        if name == prefix or name.startswith(prefix + ".")
    )
    if not modules:
        raise AssertionError("fixture package was not loaded: " + prefix)
    for module in modules:
        origin = Path(module.__file__).resolve(strict=True)
        if expected not in origin.parents:
            raise AssertionError("fixture loaded a package outside its verified root: " + prefix)


def main(arguments):
    temporary_root, source_root, installed_umbrella = (
        Path(value).resolve(strict=True) for value in arguments
    )
    runtime_root = installed_umbrella / "scripts" / "obsidian_agent_memory"
    _assert_module_origins("obsidian_agent_memory", runtime_root)
    with mock.patch.object(
        Path, "home", side_effect=AssertionError("ambient home discovery attempted")
    ):
        _record_projection_flow(temporary_root, installed_umbrella)
        _migration_and_maintenance_flow(
            temporary_root, source_root,
            installed_umbrella / "scripts" / "vault_migrate.py",
            installed_umbrella / "scripts" / "vault_maintain.py",
        )

        # Reuse shipped behavioral fixtures, not a second resolution implementation.
        # Import the installed package first; test helpers must not replace it.
        sys.path.insert(2, str(source_root))
        import tests.helpers

        source_scripts = str(source_root / "skills" / "obsidian-agent-memory" / "scripts")
        sys.path[:] = [value for value in sys.path if value != source_scripts]
        suite = unittest.defaultTestLoader.loadTestsFromNames(_RESOLUTION_TESTS)
        _assert_module_origins("obsidian_agent_memory", runtime_root)
        _assert_module_origins("tests", source_root / "tests")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        _assert_module_origins("obsidian_agent_memory", runtime_root)
        _assert_module_origins("tests", source_root / "tests")
        if not result.wasSuccessful() or result.testsRun != 4:
            raise AssertionError("installed resolution behavior failed")
    print("INSTALLED FIXTURE PASS resolution-tests=4")
