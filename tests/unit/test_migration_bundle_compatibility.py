import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from tests.helpers import REPO_ROOT

from obsidian_agent_memory.migration import (
    apply_migration,
    load_migration_bundle,
    verify_migration,
)
from obsidian_agent_memory.models import TransactionContext
from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope


GOLDEN_ROOT = REPO_ROOT / "tests" / "fixtures" / "migration-bundles" / "proposal-review"
SOURCE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "vaults" / "v1-proposal-review-golden"
FIXTURE_GATE = AuthorizationGate(OperationScope.FIXTURE, None)


def _read_expected():
    return json.loads((GOLDEN_ROOT / "expected.json").read_text(encoding="utf-8"))


def _bundle_path(schema_name):
    return GOLDEN_ROOT / schema_name.replace("_", "-")


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _action_expectations(bundle):
    return [
        {
            "action_id": action.action_id,
            "kind": action.kind.value,
            "memory_id": action.memory_id,
            "owner_scope": action.owner_scope,
            "project_id": action.project_id,
            "projection_effects": list(action.projection_effects),
            "reason": action.reason,
            "record_type": action.record_type,
            "source_path": action.source_path,
            "source_sha256": action.source_sha256,
            "target_path": action.target_path,
            "unresolved_classification": (
                None
                if action.unresolved_classification is None
                else action.unresolved_classification.value
            ),
        }
        for action in bundle.plan.actions
    ]


def _restore_snapshot_as_v1_root(bundle, add_cleanup):
    temporary = tempfile.TemporaryDirectory()
    add_cleanup(temporary.cleanup)
    root = Path(temporary.name) / "v1-proposal-review-golden"
    root.mkdir()
    shutil.copyfile(
        SOURCE_FIXTURE / ".agent-memory-fixture.json",
        root / ".agent-memory-fixture.json",
    )
    for entry in bundle.snapshot.entries:
        source = bundle.bundle_dir.joinpath(*PurePosixPath(entry.snapshot_path).parts)
        target = root.joinpath(*PurePosixPath(entry.relative_path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


def _apply_context(schema_name):
    return TransactionContext(
        "proposal-review-golden-apply-" + schema_name.replace("_", "-"),
        "fixture-agent",
        "2026-09-04T01:00:00Z",
    )


class MigrationBundleCompatibilityTests(unittest.TestCase):
    def test_schema_one_and_two_golden_bundles_load_apply_and_verify(self):
        expected = _read_expected()
        self.assertEqual(
            "8cbd09b1005528c2acab4061273958e03d062dedfd01f0a5dd060e3718221f6a",
            expected["schema_1"]["bundle_sha256"],
        )
        self.assertEqual(
            "3d8c294b3c3386d579070cae42224d37625df48738bbf5c657241230d3f76ace",
            expected["schema_1"]["plan_sha256"],
        )
        self.assertEqual(
            "008aa441d5bb83a378351c9faeac2dba1e9db68abdbc4ec28c849186449431ce",
            expected["schema_2"]["bundle_sha256"],
        )
        self.assertEqual(
            "82e1a408fb453a21a0734509852db0556c97fa7db0a7b34246ad0ea3e28c8ef9",
            expected["schema_2"]["plan_sha256"],
        )
        self.assertEqual(
            "51095478fa3c9a9fbc9ce619c30ab780cd1c072712e0735b79f534a86ac9a967",
            expected["source_revision"],
        )
        self.assertEqual(
            "8509fca82f5ace8e35379fb4a8dface971ecbd70381f01fb394f5ea49f501901",
            expected["snapshot_sha256"],
        )
        self.assertEqual(
            "1baa88d5488c0b7e547ca465a30e1cf4ade4183f601b12cfaa394b69ac262a32",
            expected["detection_sha256"],
        )
        self.assertEqual(7, len(expected["actions"]))
        self.assertEqual(
            [
                "action-e8a2c5a487c380343d2e",
                "action-612f3330563f0e03ba70",
                "action-a6d2a9c1b7093f582ddf",
                "action-08abd43c55206132f42e",
                "action-e2cb78b206a7dbd62b74",
                "action-12d01a3e4adf5f867232",
                "action-a97e3b9d4e85a0660452",
            ],
            [action["action_id"] for action in expected["actions"]],
        )

        for schema_name in ("schema_1", "schema_2"):
            bundle = load_migration_bundle(_bundle_path(schema_name))
            self.assertEqual(expected[schema_name]["bundle_sha256"], bundle.bundle_sha256)
            self.assertEqual(
                expected[schema_name]["plan_sha256"],
                _sha256(bundle.bundle_dir / "plan.json"),
            )
            self.assertEqual(expected["source_revision"], bundle.plan.source_revision)
            self.assertEqual(
                expected["snapshot_sha256"],
                _sha256(bundle.bundle_dir / "snapshot.json"),
            )
            self.assertEqual(
                expected["detection_sha256"],
                _sha256(bundle.bundle_dir / "detection.json"),
            )
            self.assertEqual(expected["actions"], _action_expectations(bundle))
            root = _restore_snapshot_as_v1_root(bundle, self.addCleanup)
            result = apply_migration(
                root,
                bundle,
                expected[schema_name]["bundle_sha256"],
                _apply_context(schema_name),
                FIXTURE_GATE,
            )
            self.assertEqual("applied", result.status)
            verification = verify_migration(root, bundle, FIXTURE_GATE)
            self.assertTrue(verification.valid)
            self.assertEqual((), verification.findings)


if __name__ == "__main__":
    unittest.main()
