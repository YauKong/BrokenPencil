import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT

from obsidian_agent_memory import ConflictError, ManifestFile, ValidationError
from obsidian_agent_memory import load_pack_manifest
from tools.agent_memory_pack import (
    RemovalProfile,
    RemovalProfileSet,
    apply_install,
    build_release,
    load_lifecycle_plan,
    plan_install,
    recover_lifecycle,
    resolve_skill_roots,
    rollback_lifecycle,
    write_lifecycle_plan,
)
from tools.agent_memory_pack.io import canonical_json_bytes
from tools.agent_memory_pack import lifecycle as pack_lifecycle


PACK_NAME = "obsidian-agent-memory-skill-pack"
PACK_VERSION = "2.0.1"
PLANNED_AT = "2026-08-30T05:00:00Z"


def _snapshot(root):
    root = Path(root)
    if not root.exists():
        return ()
    result = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result.append((relative, "link", os.readlink(path)))
        elif path.is_dir():
            result.append((relative, "directory", None))
        elif path.is_file():
            result.append((relative, "file", path.read_bytes()))
        else:
            result.append((relative, "special", None))
    return tuple(result)


def _selection(root, name="target"):
    root = Path(root).resolve()
    return resolve_skill_roots(
        root / (name + "-skills"),
        None,
        {},
        root / (name + "-state"),
    )


def _copy_active_family(skills_root):
    manifest = load_pack_manifest(REPO_ROOT / "pack.json")
    skills_root.mkdir(parents=True, exist_ok=True)
    for member in manifest.active_members:
        shutil.copytree(
            REPO_ROOT / "skills" / member,
            skills_root / member,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )


def _target_inventory(skills_root, member_names):
    directories = []
    files = []
    for member in member_names:
        member_root = Path(skills_root) / member
        if not member_root.exists():
            continue
        for path in sorted((member_root,) + tuple(member_root.rglob("*"))):
            relative = path.relative_to(skills_root).as_posix()
            if path.is_dir():
                directories.append(relative)
            elif path.is_file():
                files.append(
                    {
                        "path": relative,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
    return sorted(directories), sorted(files, key=lambda item: item["path"])


def _write_installed_state(selection, source_revision="0" * 64):
    manifest = load_pack_manifest(REPO_ROOT / "pack.json")
    directories, files = _target_inventory(
        selection.skills_root, manifest.active_members
    )
    document = {
        "actor": "previous-operator",
        "authorization_ref": "previous-install-approval",
        "directories": directories,
        "files": files,
        "occurred_at": "2026-08-29T05:00:00Z",
        "pack_name": PACK_NAME,
        "pack_version": PACK_VERSION,
        "schema_version": 1,
        "skills_root": str(selection.skills_root),
        "source_revision": source_revision,
        "target_digest": selection.target_digest,
        "transaction_id": "previous-install",
    }
    selection.state_root.mkdir(parents=True, exist_ok=True)
    path = selection.state_root / "installed.json"
    path.write_bytes(canonical_json_bytes(document))
    return path


def _synthetic_legacy_profile(skills_root):
    directory_names = (
        "obsidian-agent-memory",
        "obsidian-agent-memory-add",
        "obsidian-agent-memory-collaboration",
        "obsidian-agent-memory-init",
        "obsidian-agent-memory-maintain",
        "obsidian-agent-memory-query",
        "obsidian-agent-memory-route",
        "obsidian-agent-memory-summary",
        "obsidian-agent-memory-upgrade",
        "obsidian-agent-memory-writer",
        "obsidian-agent-memory-writer/agents",
        "obsidian-agent-memory-writer/scripts",
        "obsidian-agent-memory/designs",
        "obsidian-agent-memory/plans",
        "obsidian-agent-memory/references",
        "obsidian-agent-memory/scripts",
    )
    file_names = (
        "obsidian-agent-memory-add/SKILL.md",
        "obsidian-agent-memory-collaboration/SKILL.md",
        "obsidian-agent-memory-init/SKILL.md",
        "obsidian-agent-memory-maintain/SKILL.md",
        "obsidian-agent-memory-query/SKILL.md",
        "obsidian-agent-memory-route/SKILL.md",
        "obsidian-agent-memory-summary/SKILL.md",
        "obsidian-agent-memory-upgrade/SKILL.md",
        "obsidian-agent-memory-writer/SKILL.md",
        "obsidian-agent-memory-writer/agents/openai.yaml",
        "obsidian-agent-memory-writer/scripts/create_session_summary.py",
        "obsidian-agent-memory/SKILL.md",
        "obsidian-agent-memory/designs/2026-08-03-collaboration-skill-design.md",
        "obsidian-agent-memory/designs/2026-08-03-collaboration-skill-tdd.md",
        "obsidian-agent-memory/plans/2026-08-03-collaboration-skill.md",
        "obsidian-agent-memory/references/project-story-template.md",
        "obsidian-agent-memory/references/schema.md",
        "obsidian-agent-memory/references/session-template.md",
        "obsidian-agent-memory/references/source-priority.md",
        "obsidian-agent-memory/scripts/create_session_summary.py",
    )
    for directory in directory_names:
        (skills_root / Path(directory)).mkdir(parents=True, exist_ok=True)
    files = []
    for relative_path in file_names:
        path = skills_root / Path(relative_path)
        raw = ("legacy fixture " + relative_path + "\n").encode("utf-8")
        path.write_bytes(raw)
        files.append(ManifestFile(relative_path, hashlib.sha256(raw).hexdigest()))
    return RemovalProfile("synthetic-v1", directory_names, tuple(files))


def _plan(selection, source=REPO_ROOT, transaction_id="pack-plan-001", **kwargs):
    return plan_install(
        source=Path(source),
        selection=selection,
        transaction_id=transaction_id,
        actor="workstation-operator",
        occurred_at=PLANNED_AT,
        **kwargs
    )


def _review_plan(plan, root, name="reviewed-plan.json"):
    path = Path(root) / name
    write_lifecycle_plan(plan, path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return load_lifecycle_plan(path), digest


class InstallPlanningTests(unittest.TestCase):
    def test_fresh_directory_plan_is_exact_and_read_only(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            selection = _selection(root)
            before = _snapshot(root)

            plan = _plan(selection)

            self.assertEqual(before, _snapshot(root))
            self.assertEqual((), plan.blockers)
            self.assertEqual(11, len(plan.actions))
            self.assertEqual(
                ["create-skills-root"]
                + ["activate-member"] * 9
                + ["write-installed-state"],
                [action.kind for action in plan.actions],
            )
            self.assertEqual(
                load_pack_manifest(REPO_ROOT / "pack.json").active_members,
                tuple(
                    action.member
                    for action in plan.actions
                    if action.kind == "activate-member"
                ),
            )
            self.assertEqual(PACK_NAME, plan.pack_name)
            self.assertEqual(PACK_VERSION, plan.to_version)
            self.assertIsNone(plan.from_version)
            self.assertIsNone(plan.legacy_profile_id)
            self.assertEqual(str(REPO_ROOT.resolve()), plan.source)
            self.assertRegex(plan.source_revision, r"^[0-9a-f]{64}$")
            self.assertRegex(plan.target_revision, r"^[0-9a-f]{64}$")
            self.assertIsNone(plan.installed_state_sha256)

    def test_archive_plan_keeps_the_archive_locator_and_content_revision(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifacts = build_release(REPO_ROOT, root / "release")
            selection = _selection(root)
            before_target = _snapshot(selection.skills_root)
            before_state = _snapshot(selection.state_root)

            plan = _plan(
                selection,
                source=artifacts.archive_path,
                checksum_path=artifacts.checksum_path,
                release_manifest_path=artifacts.manifest_path,
            )

            self.assertEqual(str(artifacts.archive_path.resolve()), plan.source)
            self.assertEqual(artifacts.content_revision, plan.source_revision)
            self.assertEqual(11, len(plan.actions))
            self.assertEqual(before_target, _snapshot(selection.skills_root))
            self.assertEqual(before_state, _snapshot(selection.state_root))

    def test_managed_plan_matches_exact_installed_state_and_inventory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            selection = _selection(root)
            _copy_active_family(selection.skills_root)
            installed_path = _write_installed_state(selection)
            installed_bytes = installed_path.read_bytes()
            before = _snapshot(root)

            plan = _plan(selection)

            self.assertEqual(before, _snapshot(root))
            self.assertEqual((), plan.blockers)
            self.assertEqual(PACK_VERSION, plan.from_version)
            self.assertEqual(
                hashlib.sha256(installed_bytes).hexdigest(),
                plan.installed_state_sha256,
            )
            self.assertEqual(20, len(plan.actions))
            self.assertEqual(9, sum(action.kind == "archive-member" for action in plan.actions))
            self.assertEqual(1, sum(action.kind == "archive-installed-state" for action in plan.actions))
            self.assertEqual(9, sum(action.kind == "activate-member" for action in plan.actions))
            self.assertEqual("write-installed-state", plan.actions[-1].kind)

            manifest = load_pack_manifest(REPO_ROOT / "pack.json")
            _, installed_files = _target_inventory(
                selection.skills_root, manifest.active_members
            )
            changed = selection.skills_root / installed_files[0]["path"]
            original = changed.read_bytes()
            changed.write_bytes(b"changed managed byte\n")
            changed_plan = _plan(selection, transaction_id="pack-plan-002")
            self.assertTrue(changed_plan.blockers)
            self.assertEqual((), changed_plan.actions)
            changed.write_bytes(original)

            changed.unlink()
            missing_plan = _plan(selection, transaction_id="pack-plan-003")
            self.assertTrue(missing_plan.blockers)
            self.assertEqual((), missing_plan.actions)
            changed.parent.mkdir(parents=True, exist_ok=True)
            changed.write_bytes(original)

            empty = selection.skills_root / manifest.active_members[0] / "unexpected-empty"
            empty.mkdir()
            empty_plan = _plan(selection, transaction_id="pack-plan-004")
            self.assertTrue(empty_plan.blockers)
            self.assertEqual((), empty_plan.actions)
            empty.rmdir()

            removed = selection.skills_root / manifest.removed_members[0]
            removed.mkdir()
            removed_plan = _plan(selection, transaction_id="pack-plan-005")
            self.assertTrue(removed_plan.blockers)
            self.assertEqual((), removed_plan.actions)

    def test_exact_synthetic_unmanaged_family_is_all_or_nothing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            selection = _selection(root)
            selection.skills_root.mkdir(parents=True)
            profile = _synthetic_legacy_profile(selection.skills_root)
            profiles = RemovalProfileSet(1, (profile,))
            unrelated = selection.skills_root / "unrelated-skill" / "sentinel.txt"
            unrelated.parent.mkdir()
            unrelated.write_text("preserve", encoding="utf-8")
            before = _snapshot(root)

            with mock.patch(
                "tools.agent_memory_pack.lifecycle.load_removal_profiles",
                return_value=profiles,
            ):
                plan = _plan(selection)

            self.assertEqual(before, _snapshot(root))
            self.assertEqual((), plan.blockers)
            self.assertEqual("synthetic-v1", plan.legacy_profile_id)
            self.assertEqual(20, len(plan.actions))
            self.assertEqual(10, sum(action.kind == "archive-member" for action in plan.actions))
            writer_action = next(
                action
                for action in plan.actions
                if action.kind == "archive-member"
                and action.member == "obsidian-agent-memory-writer"
            )
            self.assertEqual(
                "transactions/pack-plan-001/rollback/previous/skills/obsidian-agent-memory-writer",
                writer_action.target_relative,
            )

            changed = selection.skills_root / profile.files[-1].path
            changed.write_bytes(b"changed\n")
            with mock.patch(
                "tools.agent_memory_pack.lifecycle.load_removal_profiles",
                return_value=profiles,
            ):
                blocked = _plan(selection, transaction_id="pack-plan-002")
            self.assertTrue(blocked.blockers)
            self.assertEqual((), blocked.actions)

            changed.write_bytes(
                ("legacy fixture " + profile.files[-1].path + "\n").encode("utf-8")
            )
            missing = selection.skills_root / profile.files[0].path
            missing_raw = missing.read_bytes()
            missing.unlink()
            with mock.patch(
                "tools.agent_memory_pack.lifecycle.load_removal_profiles",
                return_value=profiles,
            ):
                missing_plan = _plan(selection, transaction_id="pack-plan-003")
            self.assertTrue(missing_plan.blockers)
            self.assertEqual((), missing_plan.actions)
            missing.write_bytes(missing_raw)

            extra = selection.skills_root / "obsidian-agent-memory-writer" / "extra.txt"
            extra.write_text("extra", encoding="utf-8")
            with mock.patch(
                "tools.agent_memory_pack.lifecycle.load_removal_profiles",
                return_value=profiles,
            ):
                extra_plan = _plan(selection, transaction_id="pack-plan-004")
            self.assertTrue(extra_plan.blockers)
            self.assertEqual((), extra_plan.actions)
            extra.unlink()

            empty = selection.skills_root / "obsidian-agent-memory-writer" / "empty"
            empty.mkdir()
            with mock.patch(
                "tools.agent_memory_pack.lifecycle.load_removal_profiles",
                return_value=profiles,
            ):
                empty_plan = _plan(selection, transaction_id="pack-plan-005")
            self.assertTrue(empty_plan.blockers)
            self.assertEqual((), empty_plan.actions)
            empty.rmdir()

            link = selection.skills_root / "obsidian-agent-memory-writer" / "linked"
            try:
                link.symlink_to(selection.skills_root / profile.files[0].path)
            except OSError:
                pass
            else:
                with mock.patch(
                    "tools.agent_memory_pack.lifecycle.load_removal_profiles",
                    return_value=profiles,
                ):
                    link_plan = _plan(selection, transaction_id="pack-plan-006")
                self.assertTrue(link_plan.blockers)
                self.assertEqual((), link_plan.actions)
                link.unlink()
            self.assertEqual("preserve", unrelated.read_text(encoding="utf-8"))

    def test_partial_corrupt_and_extra_target_states_are_blocked_without_actions(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)

            partial = _selection(root, "partial")
            (partial.skills_root / "obsidian-agent-memory").mkdir(parents=True)
            (partial.skills_root / "obsidian-agent-memory" / "SKILL.md").write_text(
                "partial", encoding="utf-8"
            )
            partial_plan = _plan(partial)
            self.assertTrue(partial_plan.blockers)
            self.assertEqual((), partial_plan.actions)

            corrupt = _selection(root, "corrupt")
            _copy_active_family(corrupt.skills_root)
            corrupt.state_root.mkdir(parents=True)
            (corrupt.state_root / "installed.json").write_text("{", encoding="utf-8")
            corrupt_plan = _plan(corrupt, transaction_id="pack-plan-002")
            self.assertTrue(corrupt_plan.blockers)
            self.assertEqual((), corrupt_plan.actions)

            managed_extra = _selection(root, "managed-extra")
            _copy_active_family(managed_extra.skills_root)
            _write_installed_state(managed_extra)
            extra = managed_extra.skills_root / "obsidian-agent-memory" / "unexpected.txt"
            extra.write_text("unexpected", encoding="utf-8")
            extra_plan = _plan(managed_extra, transaction_id="pack-plan-003")
            self.assertTrue(extra_plan.blockers)
            self.assertEqual((), extra_plan.actions)

            removed = _selection(root, "removed")
            (removed.skills_root / "obsidian-agent-memory-writer").mkdir(parents=True)
            (removed.skills_root / "obsidian-agent-memory-writer" / "SKILL.md").write_text(
                "unknown writer", encoding="utf-8"
            )
            removed_plan = _plan(removed, transaction_id="pack-plan-004")
            self.assertTrue(removed_plan.blockers)
            self.assertEqual((), removed_plan.actions)

    def test_installed_state_bytes_and_root_binding_are_cas_inputs(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            selection = _selection(root, "managed")
            _copy_active_family(selection.skills_root)
            installed_path = _write_installed_state(selection)
            valid = _plan(selection)

            document = json.loads(installed_path.read_text(encoding="utf-8"))
            document["transaction_id"] = "other-prior-install"
            installed_path.write_bytes(canonical_json_bytes(document))
            changed = _plan(selection, transaction_id="pack-plan-002")

            self.assertNotEqual(valid.installed_state_sha256, changed.installed_state_sha256)
            self.assertEqual((), valid.blockers)
            self.assertEqual((), changed.blockers)
            self.assertNotEqual(valid.target_revision, changed.target_revision)

            other_target = resolve_skill_roots(
                root / "other-skills", None, {}, selection.state_root
            )
            _copy_active_family(other_target.skills_root)
            mismatch = _plan(other_target, transaction_id="pack-plan-003")
            self.assertTrue(mismatch.blockers)
            self.assertEqual((), mismatch.actions)

    def test_invalid_planning_provenance_and_source_root_overlap_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            selection = _selection(root)
            invalid = (
                {"transaction_id": "bad id"},
                {"actor": "bad actor"},
                {"occurred_at": "not-a-time"},
            )
            for changes in invalid:
                arguments = {
                    "source": REPO_ROOT,
                    "selection": selection,
                    "transaction_id": "pack-plan-001",
                    "actor": "workstation-operator",
                    "occurred_at": PLANNED_AT,
                }
                arguments.update(changes)
                with self.subTest(changes=changes), self.assertRaises(ValidationError):
                    plan_install(**arguments)

            overlap_selections = (
                resolve_skill_roots(REPO_ROOT, None, {}, root / "state-a"),
                resolve_skill_roots(REPO_ROOT / "skills", None, {}, root / "state-b"),
                resolve_skill_roots(root / "target-c", None, {}, REPO_ROOT),
            )
            for overlap in overlap_selections:
                with self.subTest(selection=overlap), self.assertRaises(ValidationError):
                    _plan(overlap)


class LifecyclePlanDocumentTests(unittest.TestCase):
    def test_plan_round_trip_is_canonical_exclusive_and_outside_managed_roots(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            selection = _selection(root)
            plan = _plan(selection)
            plan_path = root / "review" / "install-plan.json"

            written = write_lifecycle_plan(plan, plan_path)

            self.assertEqual(plan_path.resolve(), written)
            self.assertEqual(plan, load_lifecycle_plan(plan_path))
            self.assertEqual(
                canonical_json_bytes(json.loads(plan_path.read_text(encoding="utf-8"))),
                plan_path.read_bytes(),
            )
            occupied = root / "occupied.json"
            occupied.write_text("occupied", encoding="utf-8")
            with self.assertRaises(ConflictError):
                write_lifecycle_plan(plan, occupied)
            for unsafe in (
                selection.skills_root / "plan.json",
                selection.state_root / "plan.json",
                selection.target_lock_path.parent / "plan.json",
            ):
                with self.subTest(path=unsafe), self.assertRaises(ValidationError):
                    write_lifecycle_plan(plan, unsafe)

    def test_plan_loader_rejects_duplicate_unknown_unsafe_and_binding_drift(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            selection = _selection(root)
            plan_path = root / "plan.json"
            write_lifecycle_plan(_plan(selection), plan_path)
            original = json.loads(plan_path.read_text(encoding="utf-8"))

            variants = []
            unknown = dict(original)
            unknown["unknown"] = True
            variants.append(canonical_json_bytes(unknown))
            unsafe = json.loads(json.dumps(original))
            unsafe["actions"][0]["target_relative"] = "../escape"
            variants.append(canonical_json_bytes(unsafe))
            unsorted = json.loads(json.dumps(original))
            unsorted["actions"] = list(reversed(unsorted["actions"]))
            variants.append(canonical_json_bytes(unsorted))
            binding = dict(original)
            binding["target_digest"] = "0" * 64
            variants.append(canonical_json_bytes(binding))
            duplicate = plan_path.read_text(encoding="utf-8").replace(
                '{\n  "actions"', '{\n  "schema_version": 1,\n  "actions"', 1
            ).encode("utf-8")
            variants.append(duplicate)

            for index, raw in enumerate(variants):
                candidate = root / ("invalid-{0}.json".format(index))
                candidate.write_bytes(raw)
                with self.subTest(index=index), self.assertRaises(ValidationError):
                    load_lifecycle_plan(candidate)


class InstallApplyTests(unittest.TestCase):
    def test_fresh_apply_activates_the_exact_family_and_persists_provenance(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            plan, reviewed_sha256 = _review_plan(_plan(selection), root)
            source_before = _snapshot(REPO_ROOT)

            lock_events = []

            def record_lock(stage, path):
                lock_events.append((stage, Path(path).name))

            with mock.patch.object(
                pack_lifecycle, "_lock_checkpoint", side_effect=record_lock
            ):
                result = apply_install(
                    REPO_ROOT,
                    plan,
                    reviewed_sha256,
                    "apply-operator",
                    "2026-08-30T05:05:00Z",
                    "install-approval-001",
                )

            manifest = load_pack_manifest(REPO_ROOT / "pack.json")
            self.assertEqual("installed", result.status)
            self.assertEqual("pack-plan-001", result.transaction_id)
            self.assertEqual(PACK_VERSION, result.version)
            self.assertEqual("apply-operator", result.actor)
            self.assertEqual("2026-08-30T05:05:00Z", result.occurred_at)
            self.assertEqual("install-approval-001", result.authorization_ref)
            self.assertEqual(selection.target_digest, result.target_digest)
            self.assertEqual(source_before, _snapshot(REPO_ROOT))
            self.assertEqual(
                set(manifest.active_members),
                {path.name for path in selection.skills_root.iterdir() if path.is_dir()},
            )
            self.assertFalse(
                any((selection.skills_root / member).exists() for member in manifest.removed_members)
            )
            installed = json.loads(
                (selection.state_root / "installed.json").read_text(encoding="utf-8")
            )
            self.assertEqual("workstation-operator", json.loads(
                (selection.state_root / "transactions" / "pack-plan-001" / "journal.json").read_text(encoding="utf-8")
            )["planning_actor"])
            self.assertEqual("apply-operator", installed["actor"])
            self.assertEqual("install-approval-001", installed["authorization_ref"])
            self.assertEqual(str(selection.skills_root), installed["skills_root"])
            self.assertEqual(selection.target_digest, installed["target_digest"])
            self.assertTrue(
                (selection.state_root / "transactions" / "pack-plan-001" / "result.json").is_file()
            )
            self.assertFalse(selection.target_lock_path.exists())
            self.assertFalse((selection.state_root / "lifecycle.lock").exists())
            self.assertTrue(selection.target_lock_path.parent.is_dir())
            self.assertEqual(
                [selection.target_lock_path.name, "lifecycle.lock"],
                [name for stage, name in lock_events if stage == "canonical-linked"],
            )

    def test_prevalidation_failure_creates_no_lifecycle_byte(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            plan, reviewed_sha256 = _review_plan(_plan(selection), root)
            before = _snapshot(root)

            invalid_calls = (
                ("0" * 64, "apply-operator", "2026-08-30T05:05:00Z", "approval"),
                (reviewed_sha256, "bad actor", "2026-08-30T05:05:00Z", "approval"),
                (reviewed_sha256, "apply-operator", "invalid-time", "approval"),
                (reviewed_sha256, "apply-operator", "2026-08-30T05:05:00Z", ""),
            )
            for digest, actor, occurred_at, authorization in invalid_calls:
                with self.subTest(actor=actor, occurred_at=occurred_at, authorization=authorization), self.assertRaises(
                    ValidationError
                ):
                    apply_install(
                        REPO_ROOT,
                        plan,
                        digest,
                        actor,
                        occurred_at,
                        authorization,
                    )
                self.assertEqual(before, _snapshot(root))

    def test_reviewed_source_and_target_cas_refuse_before_lifecycle_bytes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            source = root / "source"
            shutil.copytree(
                REPO_ROOT,
                source,
                ignore=shutil.ignore_patterns(
                    ".git", ".worktrees", "__pycache__", "*.pyc", "dist"
                ),
            )
            source_selection = _selection(root, "source-drift")
            source_plan, source_digest = _review_plan(
                _plan(source_selection, source=source), root, "source-plan.json"
            )
            (source / "VERSION").write_text("9.0.0\n", encoding="utf-8")
            source_target_before = _snapshot(source_selection.skills_root)
            source_state_before = _snapshot(source_selection.state_root)

            with self.assertRaises(ValidationError):
                apply_install(
                    source,
                    source_plan,
                    source_digest,
                    "apply-operator",
                    "2026-08-30T05:05:00Z",
                    "source-cas-approval",
                )
            self.assertEqual(source_target_before, _snapshot(source_selection.skills_root))
            self.assertEqual(source_state_before, _snapshot(source_selection.state_root))

            target_selection = _selection(root, "target-drift")
            target_plan, target_digest = _review_plan(
                _plan(target_selection), root, "target-plan.json"
            )
            drift = target_selection.skills_root / "obsidian-agent-memory" / "SKILL.md"
            drift.parent.mkdir(parents=True)
            drift.write_text("unreviewed target\n", encoding="utf-8")
            target_before = _snapshot(target_selection.skills_root)

            with self.assertRaises(ConflictError):
                apply_install(
                    REPO_ROOT,
                    target_plan,
                    target_digest,
                    "apply-operator",
                    "2026-08-30T05:05:00Z",
                    "target-cas-approval",
                )
            self.assertEqual(target_before, _snapshot(target_selection.skills_root))
            self.assertFalse(target_selection.state_root.exists())
            self.assertFalse(target_selection.target_lock_path.exists())

    def test_managed_upgrade_archives_the_exact_prior_family_and_state(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            first_plan, first_digest = _review_plan(_plan(selection), root, "first.json")
            apply_install(
                REPO_ROOT,
                first_plan,
                first_digest,
                "first-operator",
                "2026-08-30T05:05:00Z",
                "install-approval-001",
            )
            prior_installed = (selection.state_root / "installed.json").read_bytes()
            second_plan = _plan(
                selection,
                transaction_id="pack-plan-002",
            )
            self.assertEqual((), second_plan.blockers)
            self.assertEqual(20, len(second_plan.actions))
            reviewed, digest = _review_plan(second_plan, root, "second.json")

            result = apply_install(
                REPO_ROOT,
                reviewed,
                digest,
                "second-operator",
                "2026-08-30T05:10:00Z",
                "install-approval-002",
            )

            rollback = selection.state_root / "transactions" / "pack-plan-002" / "rollback" / "previous"
            manifest = load_pack_manifest(REPO_ROOT / "pack.json")
            self.assertEqual("installed", result.status)
            self.assertEqual(
                set(manifest.active_members),
                {path.name for path in (rollback / "skills").iterdir()},
            )
            self.assertEqual(prior_installed, (rollback / "installed.json").read_bytes())
            self.assertEqual(
                "second-operator",
                json.loads((selection.state_root / "installed.json").read_text(encoding="utf-8"))["actor"],
            )

    def test_exact_unmanaged_upgrade_archives_the_removed_writer(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            selection.skills_root.mkdir(parents=True)
            profile = _synthetic_legacy_profile(selection.skills_root)
            profiles = RemovalProfileSet(1, (profile,))
            writer_before = _snapshot(selection.skills_root / "obsidian-agent-memory-writer")
            with mock.patch(
                "tools.agent_memory_pack.lifecycle.load_removal_profiles",
                return_value=profiles,
            ):
                plan = _plan(selection)
                reviewed, digest = _review_plan(plan, root)
                result = apply_install(
                    REPO_ROOT,
                    reviewed,
                    digest,
                    "upgrade-operator",
                    "2026-08-30T05:05:00Z",
                    "upgrade-approval-001",
                )

            writer_rollback = (
                selection.state_root
                / "transactions"
                / "pack-plan-001"
                / "rollback"
                / "previous"
                / "skills"
                / "obsidian-agent-memory-writer"
            )
            self.assertEqual("installed", result.status)
            self.assertFalse(
                (selection.skills_root / "obsidian-agent-memory-writer").exists()
            )
            self.assertEqual(writer_before, _snapshot(writer_rollback))


class LifecycleRecoveryRollbackTests(unittest.TestCase):
    def test_fresh_rollback_is_hash_safe_and_restores_reviewed_absence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            plan, digest = _review_plan(_plan(selection), root)
            apply_install(
                REPO_ROOT,
                plan,
                digest,
                "apply-operator",
                "2026-08-30T05:05:00Z",
                "install-approval-001",
            )

            result = rollback_lifecycle(
                selection,
                "pack-plan-001",
                "rollback-operator",
                "2026-08-30T05:10:00Z",
                "rollback-approval-001",
            )

            reverted = (
                selection.state_root
                / "transactions"
                / "pack-plan-001"
                / "rollback"
                / "reverted"
            )
            self.assertEqual("rolled-back", result.status)
            self.assertFalse(selection.skills_root.exists())
            self.assertFalse((selection.state_root / "installed.json").exists())
            self.assertTrue((reverted / "installed.json").is_file())
            self.assertEqual(
                set(load_pack_manifest(REPO_ROOT / "pack.json").active_members),
                {path.name for path in (reverted / "skills").iterdir()},
            )
            journal = json.loads(
                (
                    selection.state_root
                    / "transactions"
                    / "pack-plan-001"
                    / "journal.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual("rolled-back", journal["status"])
            self.assertEqual("install-approval-001", journal["authorization_ref"])
            self.assertEqual(
                "rollback-approval-001", journal["rollback_authorization_ref"]
            )
            self.assertFalse(selection.target_lock_path.exists())
            self.assertFalse((selection.state_root / "lifecycle.lock").exists())

    def test_unmanaged_rollback_restores_the_entire_legacy_family(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            selection.skills_root.mkdir(parents=True)
            profile = _synthetic_legacy_profile(selection.skills_root)
            profiles = RemovalProfileSet(1, (profile,))
            legacy_before = _snapshot(selection.skills_root)
            with mock.patch(
                "tools.agent_memory_pack.lifecycle.load_removal_profiles",
                return_value=profiles,
            ):
                plan = _plan(selection)
                reviewed, digest = _review_plan(plan, root)
                apply_install(
                    REPO_ROOT,
                    reviewed,
                    digest,
                    "upgrade-operator",
                    "2026-08-30T05:05:00Z",
                    "upgrade-approval-001",
                )

            result = rollback_lifecycle(
                selection,
                "pack-plan-001",
                "rollback-operator",
                "2026-08-30T05:10:00Z",
                "rollback-approval-001",
            )

            self.assertEqual("rolled-back", result.status)
            self.assertEqual(legacy_before, _snapshot(selection.skills_root))
            self.assertTrue(
                (selection.skills_root / "obsidian-agent-memory-writer").is_dir()
            )
            self.assertFalse((selection.state_root / "installed.json").exists())

    def test_rollback_refuses_active_drift_and_reused_authorization_before_lock(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            plan, digest = _review_plan(_plan(selection), root)
            apply_install(
                REPO_ROOT,
                plan,
                digest,
                "apply-operator",
                "2026-08-30T05:05:00Z",
                "install-approval-001",
            )
            with self.assertRaises(ConflictError):
                rollback_lifecycle(
                    selection,
                    "pack-plan-001",
                    "rollback-operator",
                    "2026-08-30T05:10:00Z",
                    "install-approval-001",
                )
            self.assertFalse(selection.target_lock_path.exists())

            changed = selection.skills_root / "obsidian-agent-memory" / "SKILL.md"
            changed.write_bytes(changed.read_bytes() + b"\nchanged\n")
            before = _snapshot(root)
            with self.assertRaises(ConflictError):
                rollback_lifecycle(
                    selection,
                    "pack-plan-001",
                    "rollback-operator",
                    "2026-08-30T05:10:00Z",
                    "rollback-approval-001",
                )
            self.assertEqual(before, _snapshot(root))
            self.assertFalse(selection.target_lock_path.exists())

    def test_terminal_recovery_adopts_dead_locks_and_tears_down_state_then_target(self):
        class SimulatedCrash(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            plan, digest = _review_plan(_plan(selection), root)

            def crash(stage):
                if stage == "before-state-lock-release":
                    raise SimulatedCrash()

            with mock.patch.object(
                pack_lifecycle, "_lifecycle_checkpoint", side_effect=crash
            ), self.assertRaises(SimulatedCrash):
                apply_install(
                    REPO_ROOT,
                    plan,
                    digest,
                    "apply-operator",
                    "2026-08-30T05:05:00Z",
                    "install-approval-001",
                )
            self.assertTrue(selection.target_lock_path.is_file())
            self.assertTrue((selection.state_root / "lifecycle.lock").is_file())
            events = []

            def record(stage, path):
                events.append((stage, Path(path).name))

            with mock.patch.object(pack_lifecycle, "_lock_checkpoint", side_effect=record):
                result = recover_lifecycle(
                    selection,
                    "pack-plan-001",
                    "recovery-operator",
                    "2026-08-30T05:15:00Z",
                    "recovery-approval-001",
                )

            self.assertEqual("recovered", result.status)
            self.assertFalse(selection.target_lock_path.exists())
            self.assertFalse((selection.state_root / "lifecycle.lock").exists())
            canonical_unlinks = [
                name for stage, name in events if stage == "canonical-unlinked"
            ]
            self.assertEqual(
                ["lifecycle.lock", selection.target_lock_path.name], canonical_unlinks
            )
            recoveries = (
                selection.state_root
                / "transactions"
                / "pack-plan-001"
                / "recoveries"
            )
            self.assertEqual(1, len(tuple(recoveries.glob("*.json"))))

    def test_rolled_back_terminal_recovery_accepts_reviewed_absence(self):
        class SimulatedCrash(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            plan, digest = _review_plan(_plan(selection), root)
            apply_install(
                REPO_ROOT,
                plan,
                digest,
                "apply-operator",
                "2026-08-30T05:05:00Z",
                "install-approval-001",
            )

            def crash(stage):
                if stage == "before-state-lock-release":
                    raise SimulatedCrash()

            with mock.patch.object(
                pack_lifecycle, "_lifecycle_checkpoint", side_effect=crash
            ), self.assertRaises(SimulatedCrash):
                rollback_lifecycle(
                    selection,
                    "pack-plan-001",
                    "rollback-operator",
                    "2026-08-30T05:10:00Z",
                    "rollback-approval-001",
                )

            result = recover_lifecycle(
                selection,
                "pack-plan-001",
                "recovery-operator",
                "2026-08-30T05:15:00Z",
                "recovery-approval-001",
            )

            self.assertEqual("recovered", result.status)
            self.assertFalse(selection.skills_root.exists())
            self.assertFalse((selection.state_root / "installed.json").exists())
            self.assertFalse(selection.target_lock_path.exists())
            self.assertFalse((selection.state_root / "lifecycle.lock").exists())


class InstallPlanCliTests(unittest.TestCase):
    def _run(self, *arguments):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "install_pack.py")] + list(arguments),
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def test_directory_and_archive_plan_forms_write_only_the_reviewed_plan(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            plan_path = root / "directory-plan.json"

            completed = self._run(
                "plan",
                "--source", str(REPO_ROOT),
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--transaction-id", "pack-plan-001",
                "--actor", "workstation-operator",
                "--occurred-at", PLANNED_AT,
                "--plan-out", str(plan_path),
            )

            self.assertEqual(0, completed.returncode, completed.stdout)
            self.assertRegex(
                completed.stdout,
                r"^PLAN install transaction=pack-plan-001 mode=fresh actions=11 blockers=0 sha256=[0-9a-f]{64}\n$",
            )
            self.assertTrue(plan_path.is_file())
            self.assertFalse(selection.skills_root.exists())
            self.assertFalse(selection.state_root.exists())

            artifacts = build_release(REPO_ROOT, root / "release")
            archive_plan = root / "archive-plan.json"
            archive_completed = self._run(
                "plan",
                "--source", str(artifacts.archive_path),
                "--checksum", str(artifacts.checksum_path),
                "--release-manifest", str(artifacts.manifest_path),
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--transaction-id", "pack-plan-archive",
                "--actor", "workstation-operator",
                "--occurred-at", PLANNED_AT,
                "--plan-out", str(archive_plan),
            )
            self.assertEqual(0, archive_completed.returncode, archive_completed.stdout)
            self.assertTrue(archive_plan.is_file())
            self.assertEqual(
                str(artifacts.archive_path.resolve()),
                load_lifecycle_plan(archive_plan).source,
            )

    def test_blocked_plan_prints_blockers_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root)
            (selection.skills_root / "obsidian-agent-memory").mkdir(parents=True)
            output = root / "blocked-plan.json"

            completed = self._run(
                "plan",
                "--source", str(REPO_ROOT),
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--transaction-id", "pack-plan-001",
                "--actor", "workstation-operator",
                "--occurred-at", PLANNED_AT,
                "--plan-out", str(output),
            )

            self.assertEqual(3, completed.returncode, completed.stdout)
            self.assertRegex(completed.stdout, r"^BLOCKED [a-z0-9-]+ .+: .+\n$")
            self.assertFalse(output.exists())

    def test_apply_rollback_and_terminal_recover_commands_are_thin(self):
        class SimulatedCrash(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            selection = _selection(root, "cli")
            plan_path = root / "apply-plan.json"
            reviewed_plan, reviewed_sha256 = _review_plan(
                _plan(selection), root, plan_path.name
            )

            applied = self._run(
                "apply",
                "--source", str(REPO_ROOT),
                "--plan", str(plan_path),
                "--plan-sha256", reviewed_sha256,
                "--actor", "apply-operator",
                "--occurred-at", "2026-08-30T05:05:00Z",
                "--authorization-ref", "install-approval-001",
            )
            self.assertEqual(0, applied.returncode, applied.stdout)
            self.assertEqual(
                "INSTALLED version=2.0.1 transaction=pack-plan-001 rollback-retained=true\n",
                applied.stdout,
            )

            rolled_back = self._run(
                "rollback",
                "--skills-root", str(selection.skills_root),
                "--state-root", str(selection.state_root),
                "--transaction-id", "pack-plan-001",
                "--actor", "rollback-operator",
                "--occurred-at", "2026-08-30T05:10:00Z",
                "--authorization-ref", "rollback-approval-001",
            )
            self.assertEqual(0, rolled_back.returncode, rolled_back.stdout)
            self.assertEqual(
                "ROLLED-BACK transaction=pack-plan-001 rollback-retained=true\n",
                rolled_back.stdout,
            )

            recovery_selection = _selection(root, "recover-cli")
            recovery_plan, recovery_digest = _review_plan(
                _plan(recovery_selection, transaction_id="pack-plan-recover"),
                root,
                "recover-plan.json",
            )

            def crash(stage):
                if stage == "before-state-lock-release":
                    raise SimulatedCrash()

            with mock.patch.object(
                pack_lifecycle, "_lifecycle_checkpoint", side_effect=crash
            ), self.assertRaises(SimulatedCrash):
                apply_install(
                    REPO_ROOT,
                    recovery_plan,
                    recovery_digest,
                    "apply-operator",
                    "2026-08-30T05:05:00Z",
                    "recover-install-approval",
                )

            recovered = self._run(
                "recover",
                "--skills-root", str(recovery_selection.skills_root),
                "--state-root", str(recovery_selection.state_root),
                "--transaction-id", "pack-plan-recover",
                "--actor", "recovery-operator",
                "--occurred-at", "2026-08-30T05:15:00Z",
                "--authorization-ref", "recovery-approval-001",
            )
            self.assertEqual(0, recovered.returncode, recovered.stdout)
            self.assertEqual(
                "RECOVERED transaction=pack-plan-recover target-state=unchanged\n",
                recovered.stdout,
            )


if __name__ == "__main__":
    unittest.main()
