import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT

from obsidian_agent_memory import ConflictError, ValidationError
from obsidian_agent_memory import load_pack_manifest, validate_repository
from tools.agent_memory_pack import (
    collect_manifest_files,
    load_removal_profiles,
    refresh_pack_manifest,
    validate_release_metadata,
)
from tools.agent_memory_pack import io as pack_io


ACTIVE_MEMBERS = (
    "obsidian-agent-memory",
    "obsidian-agent-memory-init",
    "obsidian-agent-memory-route",
    "obsidian-agent-memory-collaboration",
    "obsidian-agent-memory-query",
    "obsidian-agent-memory-add",
    "obsidian-agent-memory-summary",
    "obsidian-agent-memory-maintain",
    "obsidian-agent-memory-upgrade",
)
REMOVED_MEMBERS = ("obsidian-agent-memory-writer",)
REQUIRED_PAYLOAD_PATHS = (
    ".gitattributes",
    ".gitignore",
    "docs/vault-migration-operations.md",
    "skills/obsidian-agent-memory/scripts/vault_migrate.py",
    "skills/obsidian-agent-memory/scripts/vault_maintain.py",
    "skills/obsidian-agent-memory/scripts/obsidian_agent_memory/cli_migrate.py",
    "skills/obsidian-agent-memory/scripts/obsidian_agent_memory/cli_maintain.py",
    "tools/vault_migrate.py",
    "tools/vault_maintain.py",
)


class ReleaseMetadataTests(unittest.TestCase):
    def test_fixed_release_header_and_version_are_exact(self):
        self.assertEqual(b"2.0.2\n", (REPO_ROOT / "VERSION").read_bytes())

        manifest = load_pack_manifest(REPO_ROOT / "pack.json")

        self.assertEqual("obsidian-agent-memory-skill-pack", manifest.name)
        self.assertEqual("2.0.2", manifest.version)
        self.assertEqual("3.9", manifest.minimum_python)
        self.assertEqual((1, 2), manifest.schema_versions)
        self.assertEqual(ACTIVE_MEMBERS, manifest.active_members)
        self.assertEqual(REMOVED_MEMBERS, manifest.removed_members)
        self.assertEqual((), manifest.required_capabilities)
        self.assertEqual(
            ("obsidian-cli", "obsidian-knowledge-base"),
            manifest.optional_capabilities,
        )
        self.assertEqual(
            "obsidian-agent-memory-skill-pack-2.0.2.zip",
            manifest.release_archive,
        )
        self.assertEqual(
            "obsidian-agent-memory-skill-pack-2.0.2.zip.sha256",
            manifest.release_checksum,
        )
        self.assertEqual(
            "obsidian-agent-memory-skill-pack-2.0.2-manifest.json",
            manifest.release_manifest,
        )

    def test_manifest_is_the_exact_current_payload(self):
        manifest = load_pack_manifest(REPO_ROOT / "pack.json")

        self.assertEqual(collect_manifest_files(REPO_ROOT), manifest.files)
        paths = tuple(item.path for item in manifest.files)
        for relative_path in REQUIRED_PAYLOAD_PATHS:
            with self.subTest(path=relative_path):
                self.assertIn(relative_path, paths)

    def test_payload_keeps_fixtures_tests_tools_and_skills_but_not_source_evidence(self):
        paths = frozenset(item.path for item in collect_manifest_files(REPO_ROOT))
        fixture_paths = frozenset(
            path.relative_to(REPO_ROOT).as_posix()
            for path in (REPO_ROOT / "tests" / "fixtures").rglob("*")
            if path.is_file()
        )

        self.assertTrue(fixture_paths)
        self.assertTrue(fixture_paths.issubset(paths))
        self.assertIn("tests/integration/test_vault_migration_workflow.py", paths)
        self.assertIn("tests/unit/test_release_metadata.py", paths)
        self.assertIn("tools/validate.py", paths)
        self.assertIn("skills/obsidian-agent-memory/SKILL.md", paths)
        self.assertNotIn("pack.json", paths)
        self.assertNotIn("tests/unit/test_evaluation_evidence.py", paths)
        self.assertFalse(any(path.startswith("tests/evaluations/") for path in paths))
        self.assertFalse(any(path.startswith("docs/superpowers/") for path in paths))

    def test_payload_collection_rejects_a_reparse_point(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            tools = root / "tools"
            tools.mkdir()
            outside = root / "outside.py"
            outside.write_text("outside\n", encoding="utf-8")
            link = tools / "linked.py"
            try:
                link.symlink_to(outside)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))

            with self.assertRaises(ValidationError):
                collect_manifest_files(root)

    def test_refresh_check_is_read_only_and_refresh_changes_only_files(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            document = json.loads((REPO_ROOT / "pack.json").read_text(encoding="utf-8"))
            document["files"] = []
            manifest_path = root / "pack.json"
            manifest_path.write_text(
                json.dumps(document, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            (root / "VERSION").write_bytes(b"2.0.2\n")
            before = manifest_path.read_bytes()

            with self.assertRaises(ConflictError):
                refresh_pack_manifest(root, check=True)
            self.assertEqual(before, manifest_path.read_bytes())
            self.assertEqual((), tuple(root.glob(".pack.json.pending-*")))

            refreshed = refresh_pack_manifest(root)
            refresh_pack_manifest(root, check=True)
            after = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected_header = dict(document)
            expected_header.pop("files")
            actual_header = dict(after)
            actual_header.pop("files")
            self.assertEqual(expected_header, actual_header)
            self.assertEqual(("VERSION",), tuple(item.path for item in refreshed.files))

    def test_repository_and_release_metadata_are_valid(self):
        manifest = load_pack_manifest(REPO_ROOT / "pack.json")

        errors = tuple(
            finding
            for finding in (
                validate_repository(REPO_ROOT, manifest)
                + validate_release_metadata(REPO_ROOT, manifest)
            )
            if finding.severity == "error"
        )
        self.assertEqual((), errors)


class RemovalProfileTests(unittest.TestCase):
    def profile_document(self):
        return json.loads(
            (REPO_ROOT / "removal-profiles.json").read_text(encoding="utf-8")
        )

    def write_document(self, root, document):
        path = Path(root) / "removal-profiles.json"
        path.write_text(
            json.dumps(document, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def assert_rejected(self, document):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = self.write_document(temporary_directory, document)
            with self.assertRaises(ValidationError):
                load_removal_profiles(path)

    def test_checked_in_profile_is_the_exact_whole_legacy_family(self):
        profile_set = load_removal_profiles(REPO_ROOT / "removal-profiles.json")

        self.assertEqual(1, profile_set.schema_version)
        self.assertEqual(1, len(profile_set.profiles))
        profile = profile_set.profiles[0]
        self.assertEqual("installed-unmanaged-v1-2026-08-30", profile.profile_id)
        self.assertEqual(16, len(profile.directories))
        self.assertEqual(20, len(profile.files))
        self.assertEqual(tuple(sorted(set(profile.directories))), profile.directories)
        self.assertEqual(
            tuple(sorted(set(item.path for item in profile.files))),
            tuple(item.path for item in profile.files),
        )
        for relative_path in profile.directories + tuple(
            item.path for item in profile.files
        ):
            with self.subTest(path=relative_path):
                self.assertFalse(Path(relative_path).is_absolute())
                self.assertNotIn("\\", relative_path)
                self.assertNotIn("..", Path(relative_path).parts)

    def test_duplicate_and_unknown_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "removal-profiles.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1,"profiles":[]}\n',
                encoding="utf-8",
            )
            with self.assertRaises(ValidationError):
                load_removal_profiles(path)

        document = self.profile_document()
        document["unknown"] = True
        self.assert_rejected(document)

        document = self.profile_document()
        document["profiles"][0]["unknown"] = True
        self.assert_rejected(document)

    def test_schema_profile_ids_and_complete_member_set_are_strict(self):
        document = self.profile_document()
        document["schema_version"] = 2
        self.assert_rejected(document)

        document = self.profile_document()
        document["profiles"].append(copy.deepcopy(document["profiles"][0]))
        self.assert_rejected(document)

        document = self.profile_document()
        document["profiles"][0]["files"].pop()
        self.assert_rejected(document)

        document = self.profile_document()
        document["profiles"][0]["directories"].insert(
            0, "obsidian-agent-memory-eleventh-member"
        )
        self.assert_rejected(document)

    def test_paths_and_hashes_are_strict_portable_sorted_values(self):
        mutations = []

        document = self.profile_document()
        document["profiles"][0]["directories"] = list(
            reversed(document["profiles"][0]["directories"])
        )
        mutations.append(document)

        document = self.profile_document()
        document["profiles"][0]["directories"].append(
            document["profiles"][0]["directories"][-1]
        )
        mutations.append(document)

        for value in (1, "../escape", "absolute\\path", "C:/absolute"):
            document = self.profile_document()
            document["profiles"][0]["directories"][0] = value
            mutations.append(document)

        document = self.profile_document()
        document["profiles"][0]["files"] = list(
            reversed(document["profiles"][0]["files"])
        )
        mutations.append(document)

        document = self.profile_document()
        document["profiles"][0]["files"][0]["path"] = "../SKILL.md"
        mutations.append(document)

        for sha256 in ("", "A" * 64, "g" * 64, "a" * 63):
            document = self.profile_document()
            document["profiles"][0]["files"][0]["sha256"] = sha256
            mutations.append(document)

        for document in mutations:
            with self.subTest(document=document):
                self.assert_rejected(document)

    def test_profile_file_symlink_or_reparse_point_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            real = self.write_document(root, self.profile_document())
            link = root / "linked-removal-profiles.json"
            try:
                link.symlink_to(real)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            with self.assertRaises(ValidationError):
                load_removal_profiles(link)


class AtomicPublicationTests(unittest.TestCase):
    def sha256(self, value):
        return hashlib.sha256(value).hexdigest()

    def fail_once_at(self, stage):
        seen = []

        def checkpoint(actual):
            seen.append(actual)
            if actual == stage:
                raise RuntimeError("injected crash at {0}".format(stage))

        return seen, checkpoint

    def test_canonical_json_bytes_are_stable(self):
        self.assertEqual(
            b'{\n  "a": 1,\n  "z": 2\n}\n',
            pack_io.canonical_json_bytes({"z": 2, "a": 1}),
        )

    def test_atomic_write_recovers_complete_before_and_after_replace(self):
        stages = (
            "before-replace",
            "after-replace",
            "before-directory-fsync",
            "after-directory-fsync",
        )
        for stage in stages:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary_directory:
                target = Path(temporary_directory) / "state.json"
                before = b"before\n"
                desired = b"desired\n"
                target.write_bytes(before)
                seen, checkpoint = self.fail_once_at(stage)
                with mock.patch.object(pack_io, "_checkpoint", checkpoint):
                    with self.assertRaises(RuntimeError):
                        pack_io.atomic_write(
                            target,
                            desired,
                            "operation-1",
                            "transition-1",
                            self.sha256(before),
                        )
                self.assertIn(stage, seen)

                expected_state = "not-run" if stage == "before-replace" else "ran"
                self.assertEqual(
                    expected_state,
                    pack_io._classify_atomic_write(
                        target,
                        desired,
                        "operation-1",
                        "transition-1",
                        self.sha256(before),
                    ),
                )
                pack_io.atomic_write(
                    target,
                    desired,
                    "operation-1",
                    "transition-1",
                    self.sha256(before),
                )
                self.assertEqual(desired, target.read_bytes())
                self.assertEqual((), tuple(target.parent.glob(".state.json.pending-*")))

    def test_atomic_write_recovers_candidate_fsync_interruptions(self):
        for stage in ("before-candidate-fsync", "after-candidate-fsync"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary_directory:
                target = Path(temporary_directory) / "state.json"
                before = b"before\n"
                desired = b"desired\n"
                target.write_bytes(before)
                seen, checkpoint = self.fail_once_at(stage)
                with mock.patch.object(pack_io, "_checkpoint", checkpoint):
                    with self.assertRaises(RuntimeError):
                        pack_io.atomic_write(
                            target,
                            desired,
                            "operation-fsync",
                            stage,
                            self.sha256(before),
                        )
                self.assertIn(stage, seen)
                self.assertEqual(before, target.read_bytes())
                self.assertEqual(
                    "not-run",
                    pack_io._classify_atomic_write(
                        target,
                        desired,
                        "operation-fsync",
                        stage,
                        self.sha256(before),
                    ),
                )
                pack_io.atomic_write(
                    target,
                    desired,
                    "operation-fsync",
                    stage,
                    self.sha256(before),
                )
                self.assertEqual(desired, target.read_bytes())

    def test_atomic_write_retains_partial_and_unknown_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "state.json"
            before = b"before\n"
            desired = b"desired\n"
            target.write_bytes(before)
            _, checkpoint = self.fail_once_at("after-candidate-open")
            with mock.patch.object(pack_io, "_checkpoint", checkpoint):
                with self.assertRaises(RuntimeError):
                    pack_io.atomic_write(
                        target,
                        desired,
                        "operation-2",
                        "transition-2",
                        self.sha256(before),
                    )

            pending = tuple(target.parent.glob(".state.json.pending-*"))
            self.assertEqual(1, len(pending))
            self.assertEqual(
                "incomplete-owned",
                pack_io._classify_atomic_write(
                    target,
                    desired,
                    "operation-2",
                    "transition-2",
                    self.sha256(before),
                ),
            )
            with self.assertRaises(ConflictError):
                pack_io.atomic_write(
                    target,
                    desired,
                    "operation-2",
                    "transition-2",
                    self.sha256(before),
                )
            self.assertTrue(pending[0].exists())

        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "state.json"
            before = b"before\n"
            target.write_bytes(before)
            unknown = target.parent / ".state.json.pending-unknown"
            unknown.write_bytes(b"unknown")
            self.assertEqual(
                "ambiguous",
                pack_io._classify_atomic_write(
                    target,
                    b"desired\n",
                    "operation-3",
                    "transition-3",
                    self.sha256(before),
                ),
            )
            self.assertTrue(unknown.exists())

    def test_atomic_write_rejects_target_drift_without_deleting_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "state.json"
            target.write_bytes(b"unexpected\n")
            with self.assertRaises(ConflictError):
                pack_io.atomic_write(
                    target,
                    b"desired\n",
                    "operation-4",
                    "transition-4",
                    self.sha256(b"before\n"),
                )
            self.assertEqual(b"unexpected\n", target.read_bytes())

    def test_exclusive_publish_recovers_after_link_and_cleans_candidate(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "journal.json"
            candidate = root / "journal.candidate-abc"
            desired = b"journal\n"
            _, checkpoint = self.fail_once_at("after-hardlink")
            with mock.patch.object(pack_io, "_checkpoint", checkpoint):
                with self.assertRaises(RuntimeError):
                    pack_io.atomic_publish_exclusive(target, desired, candidate)

            self.assertEqual(desired, target.read_bytes())
            self.assertEqual(desired, candidate.read_bytes())
            pack_io.atomic_publish_exclusive(target, desired, candidate)
            self.assertEqual(desired, target.read_bytes())
            self.assertFalse(candidate.exists())

    def test_exclusive_publish_recovers_each_durable_boundary(self):
        stages = (
            "before-candidate-fsync",
            "after-candidate-fsync",
            "before-hardlink",
            "after-hardlink",
            "before-directory-fsync",
            "after-directory-fsync",
            "before-candidate-unlink",
            "after-candidate-unlink",
        )
        before_link = frozenset(
            ("before-candidate-fsync", "after-candidate-fsync", "before-hardlink")
        )
        for stage in stages:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                target = root / "journal.json"
                candidate = root / "journal.candidate-boundary"
                desired = b"journal\n"
                seen, checkpoint = self.fail_once_at(stage)
                with mock.patch.object(pack_io, "_checkpoint", checkpoint):
                    with self.assertRaises(RuntimeError):
                        pack_io.atomic_publish_exclusive(target, desired, candidate)
                self.assertIn(stage, seen)
                if stage in before_link:
                    self.assertFalse(target.exists())
                else:
                    self.assertEqual(desired, target.read_bytes())

                pack_io.atomic_publish_exclusive(target, desired, candidate)
                self.assertEqual(desired, target.read_bytes())
                self.assertFalse(candidate.exists())

    def test_exclusive_publish_never_overwrites_an_occupied_target(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "journal.json"
            candidate = root / "journal.candidate-abc"
            target.write_bytes(b"other\n")

            with self.assertRaises(ConflictError):
                pack_io.atomic_publish_exclusive(target, b"desired\n", candidate)

            self.assertEqual(b"other\n", target.read_bytes())
            self.assertFalse(candidate.exists())


if __name__ == "__main__":
    unittest.main()
