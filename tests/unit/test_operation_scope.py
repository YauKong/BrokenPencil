import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import helpers as _helpers

from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.migration import detect_vault
from obsidian_agent_memory.operation_scope import (
    AuthorizationGate,
    OperationScope,
    require_operation_gate,
)


FIXTURE_GATE = AuthorizationGate(OperationScope.FIXTURE, None)


def _write_marker(root: Path, value) -> None:
    root.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        (root / ".agent-memory-fixture.json").write_bytes(value)
    else:
        (root / ".agent-memory-fixture.json").write_text(
            json.dumps(value, sort_keys=True) + "\n", "utf-8"
        )


class OperationScopeTests(unittest.TestCase):
    def test_fixture_scope_requires_repository_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate = AuthorizationGate(OperationScope.FIXTURE, None)
            with self.assertRaisesRegex(ValidationError, "fixture marker"):
                require_operation_gate(root, gate, "migration-detect")

    def test_real_scope_requires_authorization_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate = AuthorizationGate(OperationScope.REAL, None)
            with self.assertRaisesRegex(ValidationError, "authorization reference"):
                require_operation_gate(root, gate, "migration-plan")

    def test_real_scope_accepts_explicit_reference_on_temporary_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate = AuthorizationGate(OperationScope.REAL, "approval-fixture-001")
            self.assertEqual(
                require_operation_gate(root, gate, "migration-plan"), root.resolve()
            )

    def test_invalid_fixture_markers_are_rejected(self):
        cases = (
            ("invalid-json", b"not json\n"),
            (
                "unknown-key",
                {"fixture_id": "fixture", "fixture_version": 1, "extra": True},
            ),
            ("invalid-id", {"fixture_id": "Invalid fixture", "fixture_version": 1}),
            ("invalid-version", {"fixture_id": "fixture", "fixture_version": 2}),
            (
                "duplicate-key",
                b'{"fixture_id":"fixture","fixture_id":"other","fixture_version":1}\n',
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for name, value in cases:
                with self.subTest(name=name):
                    root = Path(temporary) / name
                    _write_marker(root, value)
                    with self.assertRaisesRegex(ValidationError, "fixture marker"):
                        require_operation_gate(root, FIXTURE_GATE, "migration-detect")

    def test_unknown_scope_blank_reference_and_invalid_operation_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValidationError, "operation scope"):
                require_operation_gate(
                    root, AuthorizationGate("unknown", None), "migration-detect"
                )
            with self.assertRaisesRegex(ValidationError, "authorization reference"):
                require_operation_gate(
                    root, AuthorizationGate(OperationScope.REAL, "  "), "migration-plan"
                )
            with self.assertRaisesRegex(ValidationError, "operation"):
                require_operation_gate(
                    root,
                    AuthorizationGate(OperationScope.REAL, "approval-fixture-001"),
                    "Migration Detect",
                )

    def test_blank_real_authorization_rejects_before_inventory(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "obsidian_agent_memory.migration._inventory_vault",
            side_effect=AssertionError("inventory entered"),
        ):
            with self.assertRaisesRegex(ValidationError, "authorization reference"):
                detect_vault(
                    Path(temporary), AuthorizationGate(OperationScope.REAL, "")
                )


if __name__ == "__main__":
    unittest.main()
