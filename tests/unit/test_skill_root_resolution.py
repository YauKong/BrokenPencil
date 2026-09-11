import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT as _REPO_ROOT

from obsidian_agent_memory import ValidationError
from tools.agent_memory_pack import resolve_skill_roots


LOCK_DIRECTORY = ".obsidian-agent-memory-pack-target-locks"
STATE_DIRECTORY = ".obsidian-agent-memory-pack-state"


class SkillRootResolutionTests(unittest.TestCase):
    def test_explicit_roots_are_normalized_without_ambient_discovery(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            skills_root = (root / "skills").resolve()
            state_root = (root / "pack-state").resolve()
            expected_digest = hashlib.sha256(
                os.path.normcase(str(skills_root)).encode("utf-8")
            ).hexdigest()

            with mock.patch.object(
                Path, "home", side_effect=AssertionError("ambient home access")
            ), mock.patch.object(
                Path, "expanduser", side_effect=AssertionError("ambient expansion")
            ):
                selection = resolve_skill_roots(
                    explicit_skills_root=skills_root,
                    runtime=None,
                    env={},
                    explicit_state_root=state_root,
                )

            self.assertEqual(skills_root, selection.skills_root)
            self.assertEqual(state_root, selection.state_root)
            self.assertEqual(expected_digest, selection.target_digest)
            self.assertEqual(
                root / LOCK_DIRECTORY / (expected_digest + ".lock"),
                selection.target_lock_path,
            )
            self.assertIsNone(selection.runtime)
            self.assertFalse(skills_root.exists())
            self.assertFalse(state_root.exists())
            self.assertFalse(selection.target_lock_path.parent.exists())

    def test_codex_requires_only_an_explicit_absolute_codex_home(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            codex_home = (Path(temporary_directory) / "codex-home").resolve()
            selection = resolve_skill_roots(None, "codex", {"CODEX_HOME": str(codex_home)}, None)

            self.assertEqual(codex_home / "skills", selection.skills_root)
            self.assertEqual("codex", selection.runtime)
            self.assertEqual(
                codex_home / STATE_DIRECTORY / selection.target_digest,
                selection.state_root,
            )

            invalid_calls = (
                (None, None, {}, None),
                (codex_home / "skills", "codex", {"CODEX_HOME": str(codex_home)}, None),
                (None, "other", {"CODEX_HOME": str(codex_home)}, None),
                (None, "codex", {}, None),
                (None, "codex", {"CODEX_HOME": "relative-home"}, None),
            )
            for arguments in invalid_calls:
                with self.subTest(arguments=arguments), self.assertRaises(ValidationError):
                    resolve_skill_roots(*arguments)

    def test_relative_and_overlapping_roots_are_rejected_in_both_directions(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            skills = root / "skills"
            invalid_pairs = (
                (Path("relative-skills"), root / "state"),
                (skills, Path("relative-state")),
                (skills, skills),
                (skills, skills / "state"),
                (skills / "nested", skills),
            )
            for skills_root, state_root in invalid_pairs:
                with self.subTest(skills=skills_root, state=state_root), self.assertRaises(
                    ValidationError
                ):
                    resolve_skill_roots(skills_root, None, {}, state_root)

            digest = hashlib.sha256(
                os.path.normcase(str(skills)).encode("utf-8")
            ).hexdigest()
            lock_directory = root / LOCK_DIRECTORY
            lock_path = lock_directory / (digest + ".lock")
            for state_root in (
                lock_directory,
                lock_directory / "nested",
                root,
                lock_path,
            ):
                with self.subTest(state=state_root), self.assertRaises(ValidationError):
                    resolve_skill_roots(skills, None, {}, state_root)

    def test_target_lock_is_stable_across_state_roots_and_unique_per_target(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            first = resolve_skill_roots(root / "skills-a", None, {}, root / "state-a")
            same_target = resolve_skill_roots(
                root / "skills-a", None, {}, root / "state-b"
            )
            second = resolve_skill_roots(root / "skills-b", None, {}, root / "state-c")
            default_first = resolve_skill_roots(root / "skills-a", None, {}, None)
            default_second = resolve_skill_roots(root / "skills-b", None, {}, None)

            self.assertEqual(first.target_lock_path, same_target.target_lock_path)
            self.assertNotEqual(first.target_lock_path, second.target_lock_path)
            self.assertNotEqual(default_first.state_root, default_second.state_root)
            self.assertEqual(
                root / STATE_DIRECTORY / default_first.target_digest,
                default_first.state_root,
            )

    def test_existing_lock_directory_must_be_an_ordinary_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            lock_directory = root / LOCK_DIRECTORY
            lock_directory.mkdir()

            selection = resolve_skill_roots(
                root / "skills", None, {}, root / "state"
            )
            self.assertEqual(lock_directory, selection.target_lock_path.parent)
            self.assertTrue(lock_directory.is_dir())

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            (root / LOCK_DIRECTORY).write_text("not a directory", encoding="utf-8")
            with self.assertRaises(ValidationError):
                resolve_skill_roots(root / "skills", None, {}, root / "state")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            lock_directory = root / LOCK_DIRECTORY
            real_directory = root / "real-lock-directory"
            real_directory.mkdir()
            try:
                lock_directory.symlink_to(real_directory, target_is_directory=True)
            except OSError:
                pass
            else:
                with self.assertRaises(ValidationError):
                    resolve_skill_roots(root / "skills", None, {}, root / "state")

    @unittest.skipUnless(os.name == "nt", "Windows drive-anchor contract")
    def test_different_windows_drive_anchors_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            skills = (Path(temporary_directory) / "skills").resolve()
            current_drive = skills.drive.upper()
            other_drive = "D:" if current_drive != "D:" else "E:"
            with self.assertRaises(ValidationError):
                resolve_skill_roots(
                    skills,
                    None,
                    {},
                    Path(other_drive + "\\agent-memory-pack-state"),
                )


if __name__ == "__main__":
    unittest.main()
