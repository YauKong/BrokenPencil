import json
import subprocess
import sys
import unittest

from tests.helpers import REPO_ROOT, tree_hashes
from tests.unit.test_artifact_schemas import _applied_golden_migration

from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope
from obsidian_agent_memory.proposal_review import (
    ProposalReviewContext,
    bind_proposal_review,
    load_proposal_review,
)
from obsidian_agent_memory.runtime_identity import observe_runtime_identity


SCRIPT = "tools/vault_maintain.py"
GUIDANCE = REPO_ROOT / "skills" / "obsidian-agent-memory" / "references" / (
    "proposal-review.md"
)


def run_tool(*arguments):
    return subprocess.run(
        [sys.executable, SCRIPT, *arguments],
        cwd=str(REPO_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def start_tool(*arguments):
    return subprocess.Popen(
        [sys.executable, SCRIPT, *arguments],
        cwd=str(REPO_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class ProposalReviewCliWorkflowTests(unittest.TestCase):
    def _arguments(self, root, bundle, output, digest=None):
        return (
            "review-proposals",
            "--root", str(root),
            "--bundle", str(bundle.bundle_dir),
            "--bundle-sha256", digest or bundle.bundle_sha256,
            "--output", str(output),
            "--scope", "fixture",
            "--actor", "fixture-agent",
            "--observed-at", "2026-09-04T00:00:00Z",
            "--fixture-code-revision", "proposal-review-fixture-v1",
        )

    def test_review_proposals_cli_writes_one_redacted_report(self):
        root, bundle, _ = _applied_golden_migration(self)
        output = root.parent / "proposal-review.json"
        before_root = tree_hashes(root)
        before_bundle = tree_hashes(bundle.bundle_dir)

        result = run_tool(*self._arguments(root, bundle, output))

        self.assertEqual(0, result.returncode, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual("reviewed", document["status"])
        artifact = load_proposal_review(output)
        proof = observe_runtime_identity(
            OperationScope.FIXTURE, "proposal-review-fixture-v1"
        )
        rebound = bind_proposal_review(
            root,
            bundle.bundle_dir,
            bundle.bundle_sha256,
            ProposalReviewContext(
                actor="fixture-agent",
                observed_at="2026-09-04T00:00:00Z",
                fixture_code_revision="proposal-review-fixture-v1",
            ),
            AuthorizationGate(OperationScope.FIXTURE, None),
            proof,
            artifact,
        )
        self.assertEqual(artifact.raw, rebound.raw)
        self.assertEqual(before_root, tree_hashes(root))
        self.assertEqual(before_bundle, tree_hashes(bundle.bundle_dir))
        self.assertNotIn("The asset cache is enabled.", result.stdout)
        self.assertNotIn("The asset cache is enabled.", output.read_text("utf-8"))

    def test_guidance_keeps_legacy_decomposition_and_real_review_outside_fixture(self):
        guidance = GUIDANCE.read_text("utf-8")

        self.assertIn("Legacy mixed-content files remain proposals", guidance)
        self.assertIn("225-item real review set", guidance)
        self.assertIn("is not auto-resolved", guidance)

    def test_review_proposals_cli_uses_existing_exit_taxonomy(self):
        misuse = run_tool("review-proposals")
        self.assertEqual(2, misuse.returncode)

        root, bundle, _ = _applied_golden_migration(self)
        output = root.parent / "proposal-review.json"
        invalid = run_tool(*self._arguments(root, bundle, output, "0" * 64))
        self.assertEqual(3, invalid.returncode)
        self.assertFalse(output.exists())

        created = run_tool(*self._arguments(root, bundle, output))
        self.assertEqual(0, created.returncode, created.stderr)
        occupied = run_tool(*self._arguments(root, bundle, output))
        self.assertEqual(0, occupied.returncode)
        changed = list(self._arguments(root, bundle, output))
        changed[changed.index("--observed-at") + 1] = "2026-09-04T00:00:01Z"
        conflict = run_tool(*changed)
        self.assertEqual(4, conflict.returncode)

    def test_review_proposals_cli_is_strictly_idempotent(self):
        root, bundle, _ = _applied_golden_migration(self)
        output = root.parent / "proposal-review.json"
        first = run_tool(*self._arguments(root, bundle, output))
        original = output.read_bytes()

        second = run_tool(*self._arguments(root, bundle, output))

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(original, output.read_bytes())

    def test_concurrent_identical_publishers_converge(self):
        root, bundle, _ = _applied_golden_migration(self)
        output = root.parent / "proposal-review.json"
        arguments = self._arguments(root, bundle, output)
        processes = (start_tool(*arguments), start_tool(*arguments))
        results = [process.communicate(timeout=60) for process in processes]
        self.assertEqual([0, 0], [process.returncode for process in processes], results)
        self.assertEqual(results[0][0], results[1][0])
        load_proposal_review(output)
        self.assertEqual([], list(output.parent.glob(".proposal-review-*")))

    def test_concurrent_different_publishers_never_replace(self):
        root, bundle, _ = _applied_golden_migration(self)
        output = root.parent / "proposal-review.json"
        first = list(self._arguments(root, bundle, output))
        second = list(first)
        second[second.index("--observed-at") + 1] = "2026-09-04T00:00:01Z"
        processes = (start_tool(*first), start_tool(*second))
        results = [process.communicate(timeout=60) for process in processes]
        self.assertEqual([0, 4], sorted(process.returncode for process in processes), results)
        load_proposal_review(output)
        self.assertEqual([], list(output.parent.glob(".proposal-review-*")))


if __name__ == "__main__":
    unittest.main()
