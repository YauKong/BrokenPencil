import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.helpers import copy_vault_fixture, fixture_root, tree_hashes

import obsidian_agent_memory.migration as migration
from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.migration import (
    SourceCategory,
    VaultGeneration,
    detect_vault,
)
from obsidian_agent_memory.operation_scope import AuthorizationGate, OperationScope


FIXTURE_GATE = AuthorizationGate(OperationScope.FIXTURE, None)


class MigrationDetectionTests(unittest.TestCase):
    def test_fixture_generation_matrix_is_deterministic(self):
        expected = {
            "v1-minimal": VaultGeneration.V1,
            "v1-focus-drift": VaultGeneration.V1,
            "v1-duplicate-owners": VaultGeneration.V1,
            "v1-embedded-knowledge": VaultGeneration.V1,
            "v1-partially-migrated": VaultGeneration.PARTIAL,
            "v2-clean": VaultGeneration.V2,
        }
        for name, generation in expected.items():
            with self.subTest(name=name):
                first = detect_vault(fixture_root(name), FIXTURE_GATE)
                second = detect_vault(fixture_root(name), FIXTURE_GATE)
                self.assertEqual(first, second)
                self.assertEqual(generation, first.generation)
                paths = tuple(entry.relative_path for entry in first.entries)
                self.assertEqual(tuple(sorted(paths)), paths)
                self.assertTrue(all("\\" not in path for path in paths))

    def test_v1_minimal_revision_and_categories_match_the_fixture_contract(self):
        detection = detect_vault(fixture_root("v1-minimal"), FIXTURE_GATE)
        self.assertEqual(
            "72092dd5e0c7ac8c1121ad71c55fea9b0ce25b63c2ac290df5d06b64f5260b4a",
            detection.source_revision,
        )
        by_path = {entry.relative_path: entry for entry in detection.entries}
        self.assertEqual(
            by_path["_index/current-focus.md"].category,
            SourceCategory.LEGACY_FOCUS,
        )
        self.assertEqual(
            by_path["projects/demo/current-focus.md"].category,
            SourceCategory.LEGACY_FOCUS,
        )
        self.assertEqual(
            by_path["projects/demo/sessions/2026-01-01-bootstrap.md"].category,
            SourceCategory.SESSION,
        )
        self.assertEqual(
            by_path["projects/demo/decisions/cache-policy.md"].category,
            SourceCategory.DECISION,
        )
        self.assertEqual(
            by_path["projects/demo/raw/source.txt"].category,
            SourceCategory.RAW_SOURCE,
        )
        embedded = detect_vault(
            fixture_root("v1-embedded-knowledge"), FIXTURE_GATE
        )
        embedded_by_path = {
            entry.relative_path: entry for entry in embedded.entries
        }
        self.assertEqual(
            embedded_by_path["knowledge/modeling/retopology.md"].category,
            SourceCategory.EMBEDDED_KNOWLEDGE,
        )

    def test_one_source_byte_changes_only_its_entry_hash_and_aggregate_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v1-minimal", Path(temporary))
            before = detect_vault(root, FIXTURE_GATE)
            target = root / "projects" / "demo" / "raw" / "source.txt"
            target.write_bytes(target.read_bytes().replace(b"Fictional", b"Imaginary"))
            after = detect_vault(root, FIXTURE_GATE)

            self.assertNotEqual(before.source_revision, after.source_revision)
            before_entries = {entry.relative_path: entry for entry in before.entries}
            after_entries = {entry.relative_path: entry for entry in after.entries}
            changed_path = "projects/demo/raw/source.txt"
            self.assertEqual(set(before_entries), set(after_entries))
            self.assertEqual(
                [
                    path
                    for path in sorted(before_entries)
                    if before_entries[path] != after_entries[path]
                ],
                [changed_path],
            )
            self.assertNotEqual(
                before_entries[changed_path].sha256,
                after_entries[changed_path].sha256,
            )
            self.assertEqual(
                before_entries[changed_path].size,
                after_entries[changed_path].size,
            )
            self.assertEqual(before.findings, after.findings)

    def test_operational_files_are_excluded_from_v2_revision(self):
        detection = detect_vault(fixture_root("v2-clean"), FIXTURE_GATE)
        paths = {entry.relative_path for entry in detection.entries}
        self.assertEqual(14, len(paths))
        self.assertNotIn(".agent-memory-fixture.json", paths)
        self.assertNotIn(".agent-memory-root-write.anchor", paths)
        self.assertFalse(
            any(path.startswith(".agent-memory/transactions/") for path in paths)
        )

    def test_unknown_fixture_and_changed_anchor_return_stable_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            unknown = Path(temporary) / "unknown"
            unknown.mkdir()
            (unknown / ".agent-memory-fixture.json").write_text(
                '{"fixture_id":"unknown","fixture_version":1}\n', "utf-8"
            )
            first = detect_vault(unknown, FIXTURE_GATE)
            second = detect_vault(unknown, FIXTURE_GATE)
            self.assertEqual(first, second)
            self.assertEqual(VaultGeneration.UNKNOWN, first.generation)
            self.assertIn("unrecognized-vault", {item.code for item in first.findings})

            changed_anchor = copy_vault_fixture("v1-minimal", Path(temporary))
            (changed_anchor / ".agent-memory-root-write.anchor").write_bytes(
                b"changed-anchor\n"
            )
            detection = detect_vault(changed_anchor, FIXTURE_GATE)
            self.assertEqual(VaultGeneration.V1, detection.generation)
            self.assertIn(
                "invalid-root-anchor", {item.code for item in detection.findings}
            )

    def test_root_and_entry_symlinks_are_rejected_when_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            alias = Path(temporary) / "root-alias"
            try:
                os.symlink(fixture_root("v1-minimal"), alias, target_is_directory=True)
            except OSError as error:
                self.skipTest("directory symlinks unavailable: %s" % error)
            with self.assertRaisesRegex(ValidationError, "unsafe filesystem entry"):
                detect_vault(alias, FIXTURE_GATE)

        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v1-minimal", Path(temporary))
            outside = Path(temporary) / "outside.txt"
            outside.write_text("outside fixture bytes\n", "utf-8")
            linked = root / "linked.txt"
            try:
                os.symlink(outside, linked)
            except OSError as error:
                self.skipTest("file symlinks unavailable: %s" % error)
            with self.assertRaisesRegex(ValidationError, "unsafe filesystem entry"):
                detect_vault(root, FIXTURE_GATE)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "special files unavailable")
    def test_special_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v1-minimal", Path(temporary))
            os.mkfifo(root / "fixture.pipe")
            with self.assertRaisesRegex(ValidationError, "unsafe filesystem entry"):
                detect_vault(root, FIXTURE_GATE)

    def test_simulated_windows_reparse_directory_is_not_descended_or_mutated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v1-minimal", Path(temporary))
            blocked = root / "blocked"
            blocked.mkdir()
            (blocked / "unread.txt").write_text("must not be read\n", "utf-8")
            before = tree_hashes(Path(temporary))
            real_lstat = migration._lstat
            real_scandir = os.scandir
            scanned = []

            def simulated_lstat(path):
                value = real_lstat(path)
                if Path(path) == blocked:
                    return SimpleNamespace(
                        st_mode=value.st_mode,
                        st_size=value.st_size,
                        st_file_attributes=getattr(
                            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                        ),
                    )
                return value

            def tracked_scandir(path):
                scanned.append(Path(path))
                return real_scandir(path)

            with mock.patch(
                "obsidian_agent_memory.migration._lstat",
                side_effect=simulated_lstat,
            ), mock.patch(
                "obsidian_agent_memory.migration.os.scandir",
                side_effect=tracked_scandir,
            ):
                with self.assertRaisesRegex(ValidationError, "unsafe filesystem entry"):
                    detect_vault(root, FIXTURE_GATE)

            self.assertNotIn(blocked, scanned)
            self.assertEqual(before, tree_hashes(Path(temporary)))


if __name__ == "__main__":
    unittest.main()
