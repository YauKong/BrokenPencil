import copy
import contextlib
import dataclasses
import hashlib
import inspect
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "skills" / "obsidian-agent-memory" / "scripts"
FIXTURE_MANIFEST = REPO_ROOT / "tests" / "fixtures" / "manifests" / "valid-pack.json"
FIXTURE_SKILL_TREE = REPO_ROOT / "tests" / "fixtures" / "skill-trees" / "valid"
sys.path.insert(0, str(SCRIPTS_DIR))

import obsidian_agent_memory as public_api  # noqa: E402
from obsidian_agent_memory.errors import ValidationError  # noqa: E402
from obsidian_agent_memory.manifest import load_pack_manifest  # noqa: E402
from obsidian_agent_memory.models import Finding, ManifestFile, PackManifest  # noqa: E402
from obsidian_agent_memory.validation import validate_repository, validate_skill_tree  # noqa: E402


ACTIVE_MEMBERS = [
    "obsidian-agent-memory",
    "obsidian-agent-memory-init",
    "obsidian-agent-memory-route",
    "obsidian-agent-memory-collaboration",
    "obsidian-agent-memory-query",
    "obsidian-agent-memory-add",
    "obsidian-agent-memory-summary",
    "obsidian-agent-memory-maintain",
    "obsidian-agent-memory-upgrade",
]
RELEASE_TEXT_PATHS = (
    ".gitattributes",
    "skills/obsidian-agent-memory/scripts/obsidian_agent_memory/__init__.py",
    "skills/obsidian-agent-memory/scripts/obsidian_agent_memory/manifest.py",
    "skills/obsidian-agent-memory/scripts/obsidian_agent_memory/validation.py",
    "tests/fixtures/manifests/valid-pack.json",
    "tests/fixtures/skill-trees/valid/skills/obsidian-agent-memory-add/SKILL.md",
    "tests/fixtures/skill-trees/valid/skills/obsidian-agent-memory-collaboration/SKILL.md",
    "tests/fixtures/skill-trees/valid/skills/obsidian-agent-memory-init/SKILL.md",
    "tests/fixtures/skill-trees/valid/skills/obsidian-agent-memory-maintain/SKILL.md",
    "tests/fixtures/skill-trees/valid/skills/obsidian-agent-memory-query/SKILL.md",
    "tests/fixtures/skill-trees/valid/skills/obsidian-agent-memory-route/SKILL.md",
    "tests/fixtures/skill-trees/valid/skills/obsidian-agent-memory-summary/SKILL.md",
    "tests/fixtures/skill-trees/valid/skills/obsidian-agent-memory-upgrade/SKILL.md",
    "tests/fixtures/skill-trees/valid/skills/obsidian-agent-memory/SKILL.md",
    "tests/unit/test_manifest_validation.py",
)


def valid_document():
    return json.loads(FIXTURE_MANIFEST.read_text(encoding="utf-8"))


class LineEndingContractTests(unittest.TestCase):
    def test_raw_fixture_hashes_and_line_endings_are_portable(self):
        self.assertEqual(
            b"* text=auto eol=lf\n",
            (REPO_ROOT / ".gitattributes").read_bytes(),
        )

        manifest = load_pack_manifest(FIXTURE_MANIFEST)
        fixture_paths = (FIXTURE_MANIFEST,) + tuple(
            FIXTURE_SKILL_TREE / item.path for item in manifest.files
        )
        for path in fixture_paths:
            raw = path.read_bytes()
            with self.subTest(raw_path=path.relative_to(REPO_ROOT).as_posix()):
                self.assertNotIn(b"\r", raw)
                self.assertTrue(raw.endswith(b"\n"))
                self.assertFalse(raw.endswith(b"\n\n"))
        for item in manifest.files:
            with self.subTest(hash_path=item.path):
                self.assertEqual(
                    item.sha256,
                    hashlib.sha256((FIXTURE_SKILL_TREE / item.path).read_bytes()).hexdigest(),
                )

    @unittest.skipUnless((REPO_ROOT / ".git").exists(), "archive has no Git attribute context")
    def test_git_release_text_attributes_are_portable(self):
        git_executable = shutil.which("git")
        self.assertIsNotNone(git_executable)
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        for name in ("SYSTEMROOT", "SystemRoot", "WINDIR"):
            if name in os.environ:
                environment[name] = os.environ[name]
        completed = subprocess.run(
            [
                git_executable,
                "-c",
                "safe.directory={0}".format(REPO_ROOT),
                "check-attr",
                "text",
                "eol",
                "--",
            ]
            + list(RELEASE_TEXT_PATHS),
            cwd=str(REPO_ROOT),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5.0,
            check=False,
        )
        self.assertEqual(0, completed.returncode)
        self.assertEqual(b"", completed.stderr)
        expected_lines = []
        for relative in RELEASE_TEXT_PATHS:
            expected_lines.extend(
                (
                    "{0}: text: auto".format(relative),
                    "{0}: eol: lf".format(relative),
                )
            )
        self.assertEqual(expected_lines, completed.stdout.decode("utf-8").splitlines())


class ManifestLoadingTests(unittest.TestCase):
    def load_document(self, document):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "pack.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return load_pack_manifest(path)

    def reject_document(self, document):
        with self.assertRaises(ValidationError):
            self.load_document(document)

    def load_raw(self, content):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "pack.json"
            path.write_bytes(content)
            return load_pack_manifest(path)

    def test_loads_the_exact_valid_fixture_into_locked_models(self):
        fixture_bytes = FIXTURE_MANIFEST.read_bytes()
        self.assertTrue(fixture_bytes.endswith(b"\n"))
        self.assertNotIn(b"\r", fixture_bytes)
        self.assertEqual(
            (json.dumps(valid_document(), indent=2) + "\n").encode("utf-8"),
            fixture_bytes,
        )

        manifest = load_pack_manifest(FIXTURE_MANIFEST)

        self.assertEqual(
            PackManifest(
                name="obsidian-agent-memory-skill-pack",
                version="2.0.0",
                minimum_python="3.9",
                schema_versions=(1, 2),
                active_members=tuple(ACTIVE_MEMBERS),
                removed_members=("obsidian-agent-memory-writer",),
                required_capabilities=(),
                optional_capabilities=("obsidian-cli", "obsidian-knowledge-base"),
                release_archive="obsidian-agent-memory-skill-pack-2.0.0.zip",
                release_checksum="obsidian-agent-memory-skill-pack-2.0.0.zip.sha256",
                release_manifest="obsidian-agent-memory-skill-pack-2.0.0-manifest.json",
                files=(
                    ManifestFile(
                        "skills/obsidian-agent-memory-add/SKILL.md",
                        "81333f5de0bccbb575834679ca0e5367fb5f29451cc42b2621566a5c82783114",
                    ),
                    ManifestFile(
                        "skills/obsidian-agent-memory-collaboration/SKILL.md",
                        "7d3f18becb524533c7dfc2c653f15dd8a60c8bbd63ca7b03eff3cdede78fb85c",
                    ),
                    ManifestFile(
                        "skills/obsidian-agent-memory-init/SKILL.md",
                        "282f78fcc7adc8d22fbbb91112c1195769ca45772747fa5d44b482af3d433df8",
                    ),
                    ManifestFile(
                        "skills/obsidian-agent-memory-maintain/SKILL.md",
                        "9c49b268aa130afe872a3926b33698aeaacfafda13f323dd2101f00536858d81",
                    ),
                    ManifestFile(
                        "skills/obsidian-agent-memory-query/SKILL.md",
                        "afb59c49ad0d4fd68aa32ea359e162fe12c4a207a2e638079c54b5b8600920f0",
                    ),
                    ManifestFile(
                        "skills/obsidian-agent-memory-route/SKILL.md",
                        "ea4ba9657168a8395ade81743bb54d5e8631793858ee42b2f1a13b5d2f964acd",
                    ),
                    ManifestFile(
                        "skills/obsidian-agent-memory-summary/SKILL.md",
                        "0fdf04d380d83ae65311459c9fa5abe6780f6c3ce803a089e3689605b50ac1b8",
                    ),
                    ManifestFile(
                        "skills/obsidian-agent-memory-upgrade/SKILL.md",
                        "37130629fa78016232de0f323cbd8c59f60cedad81c827a35668894762c9eb0f",
                    ),
                    ManifestFile(
                        "skills/obsidian-agent-memory/SKILL.md",
                        "9e1631e664eac5c94072f30d46675796398ddd2a084b3546b942d2f49e5613eb",
                    ),
                ),
            ),
            manifest,
        )

    def test_rejects_invalid_utf8_json_nonobjects_and_duplicate_keys_at_every_level(self):
        invalid_bytes = (
            b"\xff",
            b"{",
            b"[]",
            b'{"name":"one","name":"two"}',
        )
        for content in invalid_bytes:
            with self.subTest(content=content[:32]):
                with self.assertRaises(ValidationError):
                    self.load_raw(content)

        document = valid_document()
        raw = json.dumps(document)
        duplicate_file_key = raw.replace(
            '"sha256": "81333f5de0bccbb575834679ca0e5367fb5f29451cc42b2621566a5c82783114"',
            '"sha256": "' + ("a" * 64) + '", "sha256": "' + ("b" * 64) + '"',
            1,
        ).encode("utf-8")
        with self.assertRaises(ValidationError):
            self.load_raw(duplicate_file_key)

    def test_requires_exact_top_level_and_file_keys_with_json_types(self):
        required_keys = tuple(valid_document())
        for key in required_keys:
            document = valid_document()
            del document[key]
            with self.subTest(missing=key):
                self.reject_document(document)

        document = valid_document()
        document["unknown"] = "value"
        self.reject_document(document)

        scalar_fields = (
            "name",
            "version",
            "minimum_python",
            "release_archive",
            "release_checksum",
            "release_manifest",
        )
        for field in scalar_fields:
            for value in (None, True, 1, [], {}):
                document = valid_document()
                document[field] = value
                with self.subTest(field=field, value=type(value).__name__):
                    self.reject_document(document)


def skill_document(member, description="Portable test member.", body=""):
    return (
        "---\n"
        "name: {0}\n"
        "description: {1}\n"
        "---\n\n"
        "# {0}\n\n"
        "{2}".format(member, description, body)
    )


def write_runtime(root, relative_path, content):
    path = Path(root) / Path(relative_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def manifest_for_tree(root, extra_paths=()):
    manifest = load_pack_manifest(FIXTURE_MANIFEST)
    declared_paths = [item.path for item in manifest.files]
    declared_paths.extend(extra_paths)
    files = []
    for relative_path in sorted(declared_paths):
        raw = (Path(root) / Path(relative_path)).read_bytes()
        files.append(ManifestFile(relative_path, hashlib.sha256(raw).hexdigest()))
    return dataclasses.replace(manifest, files=tuple(files))


class SkillTreeValidationTests(unittest.TestCase):
    def make_tree(self, temporary_directory):
        root = Path(temporary_directory) / "repo"
        shutil.copytree(str(FIXTURE_SKILL_TREE), str(root))
        return root

    def manifest(self):
        return load_pack_manifest(FIXTURE_MANIFEST)

    def skill_path(self, root, member):
        return root / "skills" / member / "SKILL.md"

    def test_valid_fixture_has_no_skill_tree_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)

            self.assertEqual((), validate_skill_tree(root, self.manifest()))

    def test_missing_active_skill_returns_member_and_umbrella_route_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            missing = self.skill_path(root, "obsidian-agent-memory-query")
            missing.unlink()

            self.assertEqual(
                (
                    Finding(
                        "member-missing",
                        "error",
                        "skills/obsidian-agent-memory-query/SKILL.md",
                        "active member SKILL.md is missing",
                    ),
                    Finding(
                        "route-missing",
                        "error",
                        "skills/obsidian-agent-memory/SKILL.md",
                        "route target obsidian-agent-memory-query is missing or inactive",
                    ),
                ),
                validate_skill_tree(root, self.manifest()),
            )

    def test_frontmatter_rejects_mismatch_duplicate_unknown_and_unsafe_scalars(self):
        member = "obsidian-agent-memory-init"
        invalid_headers = (
            "---\nname: wrong-member\ndescription: valid\n---\n",
            "---\nname: {0}\nname: {0}\ndescription: valid\n---\n".format(member),
            "---\nname: {0}\ndescription: valid\nunknown: value\n---\n".format(member),
            "---\nname: {0}\n---\n".format(member),
            "---\nname: {0}\ndescription: \"quoted\"\n---\n".format(member),
            "---\nname: {0}\ndescription: [list]\n---\n".format(member),
            "---\nname: {0}\ndescription: {{mapping}}\n---\n".format(member),
            "---\nname: {0}\ndescription: !tagged\n---\n".format(member),
            "---\nname: {0}\ndescription: &anchor\n---\n".format(member),
            "---\nname: {0}\ndescription: *alias\n---\n".format(member),
            "---\nname: {0}\ndescription: |\n---\n".format(member),
            "---\nname: {0}\ndescription: valid # comment\n---\n".format(member),
            "---\nname: {0}\ndescription:  leading\n---\n".format(member),
            "---\nname: {0}\ndescription: trailing \n---\n".format(member),
            "---\nname: {0}\ndescription: control\x07\n---\n".format(member),
            "name: {0}\ndescription: no delimiter\n---\n".format(member),
            "---\nname {0}\ndescription: malformed\n---\n".format(member),
        )
        expected = (
            Finding(
                "frontmatter-invalid",
                "error",
                "skills/{0}/SKILL.md".format(member),
                "invalid SKILL.md frontmatter",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            path = self.skill_path(root, member)
            for header in invalid_headers:
                with self.subTest(header=repr(header[:80])):
                    path.write_text(header, encoding="utf-8")
                    self.assertEqual(expected, validate_skill_tree(root, self.manifest()))

            path.write_bytes(b"---\nname: " + member.encode("ascii") + b"\ndescription: \xff\n---\n")
            self.assertEqual(expected, validate_skill_tree(root, self.manifest()))

    def test_frontmatter_description_and_header_bounds_are_exact(self):
        member = "obsidian-agent-memory-init"
        path_text = "skills/{0}/SKILL.md".format(member)
        expected = (
            Finding(
                "frontmatter-invalid",
                "error",
                path_text,
                "invalid SKILL.md frontmatter",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            path = self.skill_path(root, member)

            path.write_text(skill_document(member, "é" * 256), encoding="utf-8")
            self.assertEqual((), validate_skill_tree(root, self.manifest()))
            path.write_text(skill_document(member, "é" * 257), encoding="utf-8")
            self.assertEqual(expected, validate_skill_tree(root, self.manifest()))

            line_32 = ["---", "name: " + member, "description: bounded"] + ([""] * 28) + ["---"]
            self.assertEqual(32, len(line_32))
            path.write_text("\n".join(line_32) + "\n", encoding="utf-8")
            self.assertEqual((), validate_skill_tree(root, self.manifest()))
            line_33 = line_32[:-1] + [""] + ["---"]
            path.write_text("\n".join(line_33) + "\n", encoding="utf-8")
            self.assertEqual(expected, validate_skill_tree(root, self.manifest()))

            prefix = (
                "---\nname: {0}\ndescription: bounded\n".format(member).encode("utf-8")
            )
            closing = b"---\n"
            padding_size = 4096 - len(prefix) - len(closing)
            at_limit = prefix + (b" " * (padding_size - 1)) + b"\n" + closing
            self.assertEqual(4096, len(at_limit))
            path.write_bytes(at_limit)
            self.assertEqual((), validate_skill_tree(root, self.manifest()))
            path.write_bytes(prefix + (b" " * (padding_size + 1)) + b"\n" + closing)
            self.assertEqual(expected, validate_skill_tree(root, self.manifest()))

    def test_cross_member_duplicate_names_mark_each_involved_skill(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            first = "obsidian-agent-memory-init"
            second = "obsidian-agent-memory-route"
            self.skill_path(root, first).write_text(skill_document(second), encoding="utf-8")

            self.assertEqual(
                (
                    Finding(
                        "frontmatter-invalid",
                        "error",
                        "skills/{0}/SKILL.md".format(first),
                        "invalid SKILL.md frontmatter",
                    ),
                    Finding(
                        "frontmatter-invalid",
                        "error",
                        "skills/{0}/SKILL.md".format(second),
                        "invalid SKILL.md frontmatter",
                    ),
                ),
                validate_skill_tree(root, self.manifest()),
            )

    def test_local_links_are_referrer_relative_fragment_aware_and_contained(self):
        member = "obsidian-agent-memory-init"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            reference = root / "skills" / "obsidian-agent-memory" / "references" / "guide.md"
            reference.parent.mkdir(parents=True)
            reference.write_text("# Guide\n", encoding="utf-8")
            self.skill_path(root, member).write_text(
                skill_document(
                    member,
                    body=(
                        "[Sibling guide](../obsidian-agent-memory/references/guide.md#section)\n"
                        "[This document](#initialize-agent-memory)\n"
                    ),
                ),
                encoding="utf-8",
            )

            self.assertEqual((), validate_skill_tree(root, self.manifest()))

    def test_missing_external_absolute_and_escaping_links_are_reference_broken(self):
        member = "obsidian-agent-memory-init"
        path_text = "skills/{0}/SKILL.md".format(member)
        expected = (
            Finding(
                "reference-broken",
                "error",
                path_text,
                "local reference is missing or outside repository",
            ),
        )
        targets = (
            "missing.md",
            "../../../../outside.md",
            "/absolute.md",
            "C:/absolute.md",
            "\\\\server\\share\\file.md",
            "https://example.invalid/file.md",
            "mailto:test@example.invalid",
            "#" + ("a" * 1025),
            ("a" * 1025) + ".md",
            ("b" * 3000) + ".md",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            path = self.skill_path(root, member)
            for target in targets:
                with self.subTest(target=target[:40]):
                    path.write_text(
                        skill_document(member, body="[Broken]({0})\n".format(target)),
                        encoding="utf-8",
                    )
                    self.assertEqual(expected, validate_skill_tree(root, self.manifest()))

    def test_reference_schemes_are_rejected_before_path_resolution(self):
        member = "obsidian-agent-memory-init"
        relative = "skills/{0}/SKILL.md".format(member)
        expected = (
            Finding(
                "reference-broken",
                "error",
                relative,
                "local reference is missing or outside repository",
            ),
        )
        original_resolve = Path.resolve

        def reject_scheme_resolution(path, strict=False):
            if any(
                marker in str(path)
                for marker in ("https:", "mailto:", "urn:", "file:")
            ):
                raise AssertionError("URI scheme reached Path.resolve")
            return original_resolve(path, strict=strict)

        for target in (
            "https://example.invalid/file.md",
            "mailto:portable@example.invalid",
            "urn:portable:test",
            "file:///C:/Users/portable/file.md",
        ):
            with self.subTest(target=target):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = self.make_tree(temporary_directory)
                    self.skill_path(root, member).write_text(
                        skill_document(member, body="[External]({0})\n".format(target)),
                        encoding="utf-8",
                    )
                    with mock.patch.object(Path, "resolve", new=reject_scheme_resolution):
                        self.assertEqual(expected, validate_skill_tree(root, self.manifest()))

    def test_reference_resolution_failures_are_content_safe_findings(self):
        member = "obsidian-agent-memory-init"
        relative = "skills/{0}/SKILL.md".format(member)
        expected = (
            Finding(
                "reference-broken",
                "error",
                relative,
                "local reference is missing or outside repository",
            ),
        )
        original_resolve = Path.resolve
        for error_type in (OSError, RuntimeError, ValueError):
            secret = "resolution-secret-{0}".format(error_type.__name__)

            def fail_reference_resolution(
                path, strict=False, error_type=error_type, secret=secret
            ):
                if path.name == "faulty.md":
                    raise error_type(secret)
                return original_resolve(path, strict=strict)

            with self.subTest(error_type=error_type.__name__):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = self.make_tree(temporary_directory)
                    self.skill_path(root, member).write_text(
                        skill_document(member, body="[Faulty](faulty.md)\n"),
                        encoding="utf-8",
                    )
                    with mock.patch.object(Path, "resolve", new=fail_reference_resolution):
                        findings = validate_skill_tree(root, self.manifest())
                    self.assertEqual(expected, findings)
                    self.assertNotIn(secret, repr(findings))

    def test_link_scan_stops_after_128_matches(self):
        member = "obsidian-agent-memory-init"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            guide = self.skill_path(root, member).with_name("guide.md")
            guide.write_text("# Guide\n", encoding="utf-8")
            body = "".join("[Guide {0}](guide.md)\n".format(index) for index in range(128))
            body += "[Ignored broken](missing.md)\n"
            self.skill_path(root, member).write_text(
                skill_document(member, body=body), encoding="utf-8"
            )

            self.assertEqual((), validate_skill_tree(root, self.manifest()))

    def test_reference_symlink_outside_root_is_broken_when_supported(self):
        member = "obsidian-agent-memory-init"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            outside = Path(temporary_directory) / "outside.md"
            outside.write_text("outside\n", encoding="utf-8")
            link = self.skill_path(root, member).with_name("linked.md")
            try:
                link.symlink_to(outside)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            self.skill_path(root, member).write_text(
                skill_document(member, body="[Outside](linked.md)\n"), encoding="utf-8"
            )

            self.assertEqual(
                (
                    Finding(
                        "reference-broken",
                        "error",
                        "skills/{0}/SKILL.md".format(member),
                        "local reference is missing or outside repository",
                    ),
                ),
                validate_skill_tree(root, self.manifest()),
            )

    def test_active_member_directory_reparse_is_containment_without_following_it(self):
        member = "obsidian-agent-memory-query"
        relative = "skills/{0}/SKILL.md".format(member)
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            member_root = root / "skills" / member
            outside = Path(temporary_directory) / "outside-member"
            member_root.replace(outside)
            try:
                member_root.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest("directory symlinks unavailable: {0}".format(error))

            self.assertEqual(
                (
                    Finding(
                        "path-containment",
                        "error",
                        relative,
                        "path escapes repository or is a reparse point",
                    ),
                    Finding(
                        "route-missing",
                        "error",
                        "skills/obsidian-agent-memory/SKILL.md",
                        "route target {0} is missing or inactive".format(member),
                    ),
                ),
                validate_skill_tree(root, self.manifest()),
            )

    def test_routes_are_only_interpreted_inside_the_umbrella_routes_section(self):
        umbrella = "obsidian-agent-memory"
        umbrella_path = "skills/obsidian-agent-memory/SKILL.md"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            path = self.skill_path(root, umbrella)
            text = path.read_text(encoding="utf-8")
            text = text.replace(
                "# Obsidian Agent Memory\n\n## Routes",
                "# Obsidian Agent Memory\n\n"
                "- Prose route: `inactive-outside`.\n\n## Routes",
                1,
            )
            text += (
                "- Missing route: `inactive-member`.\n\n"
                "## Notes\n\n"
                "- More prose: `another-inactive`.\n"
            )
            path.write_text(text, encoding="utf-8")

            self.assertEqual(
                (
                    Finding(
                        "route-missing",
                        "error",
                        umbrella_path,
                        "route target inactive-member is missing or inactive",
                    ),
                ),
                validate_skill_tree(root, self.manifest()),
            )

    def test_missing_expected_route_is_reported_even_when_member_exists(self):
        umbrella = "obsidian-agent-memory"
        umbrella_path = "skills/obsidian-agent-memory/SKILL.md"
        missing = "obsidian-agent-memory-query"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            path = self.skill_path(root, umbrella)
            text = path.read_text(encoding="utf-8").replace(
                "- Query durable facts: `{0}`.\n".format(missing), "", 1
            )
            path.write_text(text, encoding="utf-8")

            self.assertEqual(
                (
                    Finding(
                        "route-missing",
                        "error",
                        umbrella_path,
                        "route target {0} is missing or inactive".format(missing),
                    ),
                ),
                validate_skill_tree(root, self.manifest()),
            )

    def test_duplicate_active_and_self_routes_are_route_invalid(self):
        umbrella = "obsidian-agent-memory"
        umbrella_path = "skills/obsidian-agent-memory/SKILL.md"
        additions = (
            "- Duplicate query: `obsidian-agent-memory-query`.\n",
            "- Self route: `obsidian-agent-memory`.\n",
        )
        expected = (
            Finding(
                "route-invalid",
                "error",
                umbrella_path,
                "invalid route declaration",
            ),
        )
        for addition in additions:
            with self.subTest(addition=addition.strip()):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = self.make_tree(temporary_directory)
                    path = self.skill_path(root, umbrella)
                    path.write_text(
                        path.read_text(encoding="utf-8") + addition,
                        encoding="utf-8",
                    )

                    self.assertEqual(expected, validate_skill_tree(root, self.manifest()))

    def test_malformed_route_and_replaced_expected_route_have_exact_findings(self):
        umbrella = "obsidian-agent-memory"
        umbrella_path = "skills/obsidian-agent-memory/SKILL.md"
        missing = "obsidian-agent-memory-query"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            path = self.skill_path(root, umbrella)
            text = path.read_text(encoding="utf-8").replace(
                "- Query durable facts: `{0}`.\n".format(missing),
                "- Query durable facts without code: {0}.\n".format(missing),
                1,
            )
            path.write_text(text, encoding="utf-8")

            self.assertEqual(
                (
                    Finding(
                        "route-invalid",
                        "error",
                        umbrella_path,
                        "invalid route declaration",
                    ),
                    Finding(
                        "route-missing",
                        "error",
                        umbrella_path,
                        "route target {0} is missing or inactive".format(missing),
                    ),
                ),
                validate_skill_tree(root, self.manifest()),
            )

    def test_findings_are_unique_sorted_and_never_expose_the_host_root(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            umbrella = self.skill_path(root, "obsidian-agent-memory")
            text = umbrella.read_text(encoding="utf-8")
            umbrella.write_text(
                text
                + "- Missing once: `inactive-member`.\n"
                + "- Missing twice: `inactive-member`.\n",
                encoding="utf-8",
            )
            self.skill_path(root, "obsidian-agent-memory-query").unlink()

            findings = validate_skill_tree(root, self.manifest())

            self.assertEqual(tuple(sorted(set(findings), key=lambda item: (
                item.severity, item.code, item.path, item.message
            ))), findings)
            self.assertEqual(3, len(findings))
            self.assertNotIn(str(root), repr(findings))


class RepositoryValidationTests(unittest.TestCase):
    def make_tree(self, temporary_directory):
        root = Path(temporary_directory) / "repo"
        shutil.copytree(str(FIXTURE_SKILL_TREE), str(root))
        return root

    def test_valid_fixture_repository_has_no_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            before = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                findings = validate_repository(root, load_pack_manifest(FIXTURE_MANIFEST))

            after = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            self.assertEqual((), findings)
            self.assertEqual(before, after)
            self.assertEqual("", stdout.getvalue())
            self.assertEqual("", stderr.getvalue())

    def test_hash_drift_and_missing_declared_files_use_exact_hash_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            drifted = root / "skills" / "obsidian-agent-memory-query" / "SKILL.md"
            drifted.write_text(drifted.read_text(encoding="utf-8") + "\nDrift.\n", encoding="utf-8")

            self.assertEqual(
                (
                    Finding(
                        "hash-mismatch",
                        "error",
                        "skills/obsidian-agent-memory-query/SKILL.md",
                        "manifest file is missing or its SHA-256 differs",
                    ),
                ),
                validate_repository(root, load_pack_manifest(FIXTURE_MANIFEST)),
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            manifest = load_pack_manifest(FIXTURE_MANIFEST)
            missing = ManifestFile("docs/missing.txt", "0" * 64)
            manifest = dataclasses.replace(
                manifest,
                files=tuple(sorted(manifest.files + (missing,), key=lambda item: item.path)),
            )

            self.assertEqual(
                (
                    Finding(
                        "hash-mismatch",
                        "error",
                        "docs/missing.txt",
                        "manifest file is missing or its SHA-256 differs",
                    ),
                ),
                validate_repository(root, manifest),
            )

    def test_direct_extra_skill_member_directory_is_rejected_even_when_manifested(self):
        relative = "skills/unexpected-memory-member/SKILL.md"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            write_runtime(
                root,
                relative,
                skill_document("unexpected-memory-member"),
            )
            manifest = manifest_for_tree(root, (relative,))

            self.assertEqual(
                (
                    Finding(
                        "member-unexpected",
                        "error",
                        "skills/unexpected-memory-member",
                        "skill member directory is not declared active",
                    ),
                ),
                validate_repository(root, manifest),
            )

    def test_removed_member_directory_is_rejected_independent_of_content(self):
        writer = "obsidian-agent-memory-writer"
        cases = (
            (writer, (writer,)),
            ("legacy-member", ("legacy-member", writer)),
        )
        for member, removed_members in cases:
            with self.subTest(member=member):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = self.make_tree(temporary_directory)
                    member_root = "skills/{0}".format(member)
                    relative = member_root + "/README.md"
                    write_runtime(root, relative, "Portable placeholder.\n")
                    manifest = dataclasses.replace(
                        manifest_for_tree(root, (relative,)),
                        removed_members=removed_members,
                    )

                    self.assertEqual(
                        (
                            Finding(
                                "removed-member-present",
                                "error",
                                member_root,
                                "removed member is exposed by active source",
                            ),
                        ),
                        validate_repository(root, manifest),
                    )

    def test_reparse_skills_root_is_rejected_before_member_inventory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            skills_root = root / "skills"
            original_lstat = Path.lstat
            original_scandir = os.scandir

            def fake_lstat(path):
                if Path(path) == skills_root:
                    return mock.Mock(
                        st_mode=stat.S_IFDIR,
                        st_file_attributes=0x400,
                    )
                return original_lstat(path)

            def reject_skills_scandir(path):
                if Path(path) == skills_root:
                    raise AssertionError("reparse Skill root was enumerated")
                return original_scandir(path)

            with mock.patch.object(Path, "lstat", new=fake_lstat), mock.patch(
                "obsidian_agent_memory.validation.os.scandir",
                new=reject_skills_scandir,
            ):
                findings = validate_repository(root, load_pack_manifest(FIXTURE_MANIFEST))

            self.assertTrue(findings)
            self.assertTrue(all(finding.code == "path-containment" for finding in findings))

    def test_every_regular_runtime_file_must_be_manifested_and_only_text_is_scanned(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            unmanifested = (
                "skills/extra/blob.bin",
                "skills/extra/unlisted.md",
                "skills/obsidian-agent-memory/assets/icon.png",
                "tools/unlisted.json",
                "tools/unlisted.py",
                "tools/unlisted.txt",
            )
            for relative_path in unmanifested:
                content = (
                    'password = "must-not-be-scanned"\n'
                    if relative_path.endswith(".bin")
                    else "portable\n"
                )
                write_runtime(root, relative_path, content)
            ignored = (
                "skills/.agent-memory/secret.py",
                "skills/.superpowers/ignored.py",
                "skills/dist/ignored.json",
                "skills/tests/ignored.md",
                "tools/__pycache__/ignored.py",
                "tools/ignored.pyc",
            )
            for relative_path in ignored:
                write_runtime(root, relative_path, 'password = "must-not-be-scanned"\n')

            findings = validate_repository(root, load_pack_manifest(FIXTURE_MANIFEST))

            self.assertEqual(
                (
                    Finding(
                        "member-unexpected",
                        "error",
                        "skills/extra",
                        "skill member directory is not declared active",
                    ),
                )
                + tuple(
                    Finding(
                        "runtime-file-unmanifested",
                        "error",
                        relative_path,
                        "runtime file is not listed in manifest",
                    )
                    for relative_path in unmanifested
                ),
                findings,
            )

    def test_detects_each_machine_path_default_binding_and_ambient_home_category(self):
        contents = (
            'root = "C:\\Users\\alice\\memory"\n',
            'root = "\\\\server\\share\\memory"\n',
            'root = "/Users/alice/memory"\n',
            'root = "/home/alice/memory"\n',
            'OBSIDIAN_VAULT = "portable-demo"\n',
            'DEFAULT_MEMORY_ROOT = "memory"\n',
            'DEFAULT_PROJECT = "demo"\n',
            'DEFAULT_RUNTIME_HOME = "runtime"\n',
            'root = Path.home() / "memory"\n',
            'root = os.path.expanduser("~/memory")\n',
        )
        expected = (
            Finding(
                "path-hardcoded",
                "error",
                "tools/source.txt",
                "machine-specific path or default binding detected",
            ),
        )
        for content in contents:
            with self.subTest(content=content.strip()):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = self.make_tree(temporary_directory)
                    write_runtime(root, "tools/source.txt", content)
                    manifest = manifest_for_tree(root, ("tools/source.txt",))

                    self.assertEqual(expected, validate_repository(root, manifest))

    def test_portable_urls_are_not_drive_or_posix_home_literals(self):
        content = (
            "https://example.invalid/docs\n"
            "https://example.invalid/home/alice\n"
            "https://example.invalid/Users/alice\n"
            "https://example.invalid/C:/Users/alice?next=/home/alice\n"
            "http://example.invalid/search?root=C:/portable&next=/Users/alice\n"
            "https://[2001:db8::1]/C:/Users/alice?next=/home/alice\n"
            "https://example.invalid/(C:/Users/alice)\n"
            "https://example.invalid/a_(b)/C:/Users/alice?next=/home/alice\n"
            "https://example.invalid/wiki/Foo_(bar)?next=/home/alice\n"
            "mailto:portable@example.invalid\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            write_runtime(root, "tools/source.txt", content)
            manifest = manifest_for_tree(root, ("tools/source.txt",))

            self.assertEqual((), validate_repository(root, manifest))

    def test_file_uris_remain_machine_specific_path_findings(self):
        expected = (
            Finding(
                "path-hardcoded",
                "error",
                "tools/source.txt",
                "machine-specific path or default binding detected",
            ),
        )
        for content in (
            "file:///home/alice/memory.md\n",
            "file:///C:/Users/alice/memory.md\n",
        ):
            with self.subTest(content=content.strip()):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = self.make_tree(temporary_directory)
                    write_runtime(root, "tools/source.txt", content)
                    manifest = manifest_for_tree(root, ("tools/source.txt",))

                    self.assertEqual(expected, validate_repository(root, manifest))

    def test_http_mask_does_not_hide_a_path_after_markdown_link_delimiter(self):
        content = (
            "[Portable](https://example.invalid/wiki/Foo_(bar))"
            "C:/Users/alice/memory\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            write_runtime(root, "tools/source.txt", content)
            manifest = manifest_for_tree(root, ("tools/source.txt",))

            self.assertEqual(
                (
                    Finding(
                        "path-hardcoded",
                        "error",
                        "tools/source.txt",
                        "machine-specific path or default binding detected",
                    ),
                ),
                validate_repository(root, manifest),
            )

    def test_secret_detection_requires_a_nonempty_quoted_assignment(self):
        secret_assignments = (
            'password = "hunter2"\n',
            "secret='value'\n",
            'API_KEY = "value"\n',
            'apikey = "value"\n',
            'authorization = "Bearer value"\n',
            'credential = "value"\n',
            'token = "value"\n',
        )
        expected = (
            Finding(
                "secret-present",
                "error",
                "tools/source.py",
                "credential-like literal assignment detected",
            ),
        )
        for content in secret_assignments:
            with self.subTest(content=content.strip()):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = self.make_tree(temporary_directory)
                    write_runtime(root, "tools/source.py", content)
                    manifest = manifest_for_tree(root, ("tools/source.py",))
                    self.assertEqual(expected, validate_repository(root, manifest))

        safe_content = (
            'password = ""\n'
            "token = compute_transaction_token()\n"
            'environment = {"TOKEN": "caller-supplied"}\n'
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            write_runtime(root, "tools/source.py", safe_content)
            manifest = manifest_for_tree(root, ("tools/source.py",))
            self.assertEqual((), validate_repository(root, manifest))

    def test_nested_json_sensitive_keys_are_detected_without_echoing_values(self):
        secret_literal = "unique-nested-json-value-must-not-echo"
        document = {
            "portable": [
                {"metadata": {"TOKEN": secret_literal}},
            ]
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            write_runtime(root, "tools/source.json", json.dumps(document) + "\n")
            manifest = manifest_for_tree(root, ("tools/source.json",))

            findings = validate_repository(root, manifest)

            self.assertEqual(
                (
                    Finding(
                        "secret-present",
                        "error",
                        "tools/source.json",
                        "credential-like literal assignment detected",
                    ),
                ),
                findings,
            )
            self.assertNotIn(secret_literal, repr(findings))

        safe_document = {
            "token": "",
            "api_key": None,
            "secret": False,
            "credential": 0,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            write_runtime(root, "tools/source.json", json.dumps(safe_document) + "\n")
            manifest = manifest_for_tree(root, ("tools/source.json",))

            self.assertEqual((), validate_repository(root, manifest))

    def test_removed_writer_is_rejected_from_active_and_runtime_source(self):
        expected_paths = (
            "skills/obsidian-agent-memory-query/SKILL.md",
            "tools/discovery.json",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            query = root / expected_paths[0]
            query.write_text(
                query.read_text(encoding="utf-8") + "\nobsidian-agent-memory-writer\n",
                encoding="utf-8",
            )
            write_runtime(root, expected_paths[1], '"obsidian-agent-memory-writer"\n')
            manifest = manifest_for_tree(root, (expected_paths[1],))

            self.assertEqual(
                tuple(
                    Finding(
                        "removed-member-present",
                        "error",
                        path,
                        "removed member is exposed by active source",
                    )
                    for path in expected_paths
                ),
                validate_repository(root, manifest),
            )

    def test_removed_writer_directory_route_and_discovery_metadata_are_rejected(self):
        writer = "obsidian-agent-memory-writer"
        writer_relative = "skills/{0}/SKILL.md".format(writer)
        umbrella_relative = "skills/obsidian-agent-memory/SKILL.md"
        discovery_relative = "tools/discovery.json"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            write_runtime(root, writer_relative, skill_document(writer))
            umbrella = root / umbrella_relative
            umbrella.write_text(
                umbrella.read_text(encoding="utf-8")
                + "\n- Legacy writer: `{0}`.\n".format(writer),
                encoding="utf-8",
            )
            write_runtime(
                root,
                discovery_relative,
                json.dumps({"removed_members": [writer]}) + "\n",
            )
            manifest = manifest_for_tree(root, (writer_relative, discovery_relative))

            self.assertEqual(
                (
                    Finding(
                        "removed-member-present",
                        "error",
                        "skills/{0}".format(writer),
                        "removed member is exposed by active source",
                    ),
                    Finding(
                        "removed-member-present",
                        "error",
                        umbrella_relative,
                        "removed member is exposed by active source",
                    ),
                    Finding(
                        "removed-member-present",
                        "error",
                        discovery_relative,
                        "removed member is exposed by active source",
                    ),
                    Finding(
                        "route-missing",
                        "error",
                        umbrella_relative,
                        "route target {0} is missing or inactive".format(writer),
                    ),
                ),
                validate_repository(root, manifest),
            )

    def test_removed_writer_profile_allowance_is_root_file_only(self):
        relative = "skills/obsidian-agent-memory/removal-profiles.json"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            write_runtime(root, relative, '"obsidian-agent-memory-writer"\n')
            manifest = manifest_for_tree(root, (relative,))

            self.assertEqual(
                (
                    Finding(
                        "removed-member-present",
                        "error",
                        relative,
                        "removed member is exposed by active source",
                    ),
                ),
                validate_repository(root, manifest),
            )

    def test_task_seven_runtime_modules_do_not_expose_removed_writer_literal(self):
        module_root = SCRIPTS_DIR / "obsidian_agent_memory"
        relative_paths = ("tools/manifest.py", "tools/validation.py")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            for relative, module_name in zip(
                relative_paths, ("manifest.py", "validation.py")
            ):
                write_runtime(
                    root,
                    relative,
                    (module_root / module_name).read_text(encoding="utf-8"),
                )
            manifest = manifest_for_tree(root, relative_paths)

            self.assertEqual((), validate_repository(root, manifest))

    def test_removed_writer_is_allowed_only_in_locked_migration_and_metadata_contexts(self):
        allowed = (
            "removal-profiles.json",
            "skills/obsidian-agent-memory/references/v1-to-v2-migration.md",
            "docs/release-and-authorization.md",
            "tests/evidence.txt",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            for relative_path in allowed:
                write_runtime(root, relative_path, "obsidian-agent-memory-writer\n")
            metadata = write_runtime(
                root,
                "pack-metadata.json",
                json.dumps({"removed_members": ["obsidian-agent-memory-writer"]}) + "\n",
            )
            self.assertTrue(metadata.exists())
            manifest = manifest_for_tree(root, allowed + ("pack-metadata.json",))

            self.assertEqual((), validate_repository(root, manifest))

    def test_runtime_and_manifest_reparse_points_are_path_containment_errors(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            outside = Path(temporary_directory) / "outside.py"
            outside.write_text('password = "outside-secret"\n', encoding="utf-8")
            link = root / "tools" / "linked.py"
            link.parent.mkdir(parents=True)
            try:
                link.symlink_to(outside)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            manifest = load_pack_manifest(FIXTURE_MANIFEST)
            declared = tuple(manifest.files) + (ManifestFile("tools/linked.py", "0" * 64),)
            manifest = dataclasses.replace(
                manifest, files=tuple(sorted(declared, key=lambda item: item.path))
            )

            self.assertEqual(
                (
                    Finding(
                        "path-containment",
                        "error",
                        "tools/linked.py",
                        "path escapes repository or is a reparse point",
                    ),
                ),
                validate_repository(root, manifest),
            )

    def test_active_skill_reparse_is_reported_without_following_it(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            member = "obsidian-agent-memory-query"
            skill = root / "skills" / member / "SKILL.md"
            real = Path(temporary_directory) / "real.md"
            skill.replace(real)
            try:
                skill.symlink_to(real)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))

            findings = validate_repository(root, load_pack_manifest(FIXTURE_MANIFEST))

            self.assertIn(
                Finding(
                    "path-containment",
                    "error",
                    "skills/{0}/SKILL.md".format(member),
                    "path escapes repository or is a reparse point",
                ),
                findings,
            )
            self.assertNotIn("real.md", repr(findings))

    def test_combined_findings_are_closed_sorted_errors_without_content_leakage(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.make_tree(temporary_directory)
            secret_literal = "unique-do-not-echo-value"
            write_runtime(
                root,
                "tools/source.py",
                'password = "{0}"\nDEFAULT_PROJECT = "demo"\n'.format(secret_literal),
            )
            manifest = manifest_for_tree(root, ("tools/source.py",))
            findings = validate_repository(root, manifest)

            self.assertEqual(
                tuple(
                    sorted(
                        findings,
                        key=lambda item: (item.severity, item.code, item.path, item.message),
                    )
                ),
                findings,
            )
            self.assertEqual(2, len(findings))
            self.assertTrue(all(item.severity == "error" for item in findings))
            self.assertNotIn(str(root), repr(findings))
            self.assertNotIn(secret_literal, repr(findings))


class ManifestConstraintTests(unittest.TestCase):
    def load_document(self, document):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "pack.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return load_pack_manifest(path)

    def reject_document(self, document):
        with self.assertRaises(ValidationError):
            self.load_document(document)

    def test_requires_collection_and_file_json_types(self):
        collection_fields = (
            "schema_versions",
            "active_members",
            "removed_members",
            "required_capabilities",
            "optional_capabilities",
            "files",
        )
        for field in collection_fields:
            for value in (None, True, 1, "value", {}):
                document = valid_document()
                document[field] = value
                with self.subTest(field=field, value=type(value).__name__):
                    self.reject_document(document)

        for files in (
            ["not-an-object"],
            [{"path": "skills/member/SKILL.md"}],
            [{"sha256": "a" * 64}],
            [{"path": 1, "sha256": "a" * 64}],
            [{"path": "skills/member/SKILL.md", "sha256": "a" * 64, "extra": 1}],
        ):
            document = valid_document()
            document["files"] = files
            with self.subTest(files=files):
                self.reject_document(document)

    def test_rejects_noncanonical_versions_and_python_below_three_nine(self):
        for version in (
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-alpha",
            "1.2.3+build",
        ):
            document = valid_document()
            document["version"] = version
            with self.subTest(version=version):
                self.reject_document(document)

        for minimum_python in (
            "",
            "3",
            "3.8",
            "2.99",
            "03.9",
            "3.09",
            "3.9.0",
            "python3.9",
        ):
            document = valid_document()
            document["minimum_python"] = minimum_python
            with self.subTest(minimum_python=minimum_python):
                self.reject_document(document)

        for minimum_python in ("3.9", "3.10", "4.0", "10.1"):
            document = valid_document()
            document["minimum_python"] = minimum_python
            with self.subTest(valid_minimum=minimum_python):
                self.assertEqual(minimum_python, self.load_document(document).minimum_python)

    def test_rejects_noncanonical_schema_versions(self):
        invalid_values = (
            [],
            [1],
            [2, 1],
            [1, 2, 2],
            [0, 2],
            [-1, 2],
            [True, 2],
            [1.0, 2],
            ["1", 2],
        )
        for value in invalid_values:
            document = valid_document()
            document["schema_versions"] = value
            with self.subTest(value=value):
                self.reject_document(document)

    def test_requires_the_exact_active_family_and_valid_removed_members(self):
        active_mutations = (
            ACTIVE_MEMBERS[:-1],
            list(reversed(ACTIVE_MEMBERS)),
            ACTIVE_MEMBERS + ["extra-member"],
            ACTIVE_MEMBERS + ["obsidian-agent-memory-writer"],
            ACTIVE_MEMBERS[:-1] + [ACTIVE_MEMBERS[-2]],
        )
        for active_members in active_mutations:
            document = valid_document()
            document["active_members"] = active_members
            with self.subTest(active_members=active_members):
                self.reject_document(document)

        removed_mutations = (
            [],
            ["obsidian-agent-memory-writer", "alpha"],
            ["obsidian-agent-memory-writer", "obsidian-agent-memory-writer"],
            ["obsidian-agent-memory", "obsidian-agent-memory-writer"],
            ["INVALID", "obsidian-agent-memory-writer"],
        )
        for removed_members in removed_mutations:
            document = valid_document()
            document["removed_members"] = removed_members
            with self.subTest(removed_members=removed_members):
                self.reject_document(document)

        document = valid_document()
        document["removed_members"] = ["legacy-member", "obsidian-agent-memory-writer"]
        self.assertEqual(
            ("legacy-member", "obsidian-agent-memory-writer"),
            self.load_document(document).removed_members,
        )

    def test_requires_sorted_unique_disjoint_portable_capabilities(self):
        mutations = (
            ("required_capabilities", ["zeta", "alpha"]),
            ("required_capabilities", ["alpha", "alpha"]),
            ("required_capabilities", ["INVALID"]),
            ("optional_capabilities", ["obsidian-knowledge-base", "obsidian-cli"]),
            ("optional_capabilities", ["obsidian-cli", "obsidian-cli"]),
            ("optional_capabilities", ["../escape"]),
        )
        for field, value in mutations:
            document = valid_document()
            document[field] = value
            with self.subTest(field=field, value=value):
                self.reject_document(document)

        document = valid_document()
        document["required_capabilities"] = ["obsidian-cli"]
        with self.assertRaises(ValidationError):
            self.load_document(document)

    def test_rejects_unsafe_unsorted_duplicate_file_paths_and_malformed_hashes(self):
        unsafe_paths = (
            "",
            ".",
            "../escape.md",
            "skills/../escape.md",
            "skills/./member.md",
            "skills//member.md",
            "/absolute.md",
            "C:/absolute.md",
            "C:\\absolute.md",
            "skills\\member.md",
            "skills/member\x00.md",
            "skills/member:name.md",
        )
        for unsafe_path in unsafe_paths:
            document = valid_document()
            document["files"] = [{"path": unsafe_path, "sha256": "a" * 64}]
            with self.subTest(path=repr(unsafe_path)):
                self.reject_document(document)

        for sha256 in ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64, 1, None):
            document = valid_document()
            document["files"] = [
                {"path": "skills/member/SKILL.md", "sha256": sha256}
            ]
            with self.subTest(sha256=sha256):
                self.reject_document(document)

        first = {"path": "skills/a/SKILL.md", "sha256": "a" * 64}
        second = {"path": "skills/b/SKILL.md", "sha256": "b" * 64}
        for files in ([second, first], [first, copy.deepcopy(first)]):
            document = valid_document()
            document["files"] = files
            with self.subTest(files=files):
                self.reject_document(document)

    def test_rejects_nonportable_windows_components_in_paths_and_release_names(self):
        invalid_components = (
            "CON",
            "con.txt",
            "PRN.md",
            "AUX",
            "NUL.bin",
            "COM1.log",
            "com9",
            "LPT1.txt",
            "lpt9",
            "trailing.",
            "trailing ",
            "bad<name",
            "bad>name",
            'bad"name',
            "bad|name",
            "bad?name",
            "bad*name",
        )
        for component in invalid_components:
            document = valid_document()
            document["files"] = [
                {
                    "path": "skills/{0}/SKILL.md".format(component),
                    "sha256": "a" * 64,
                }
            ]
            with self.subTest(kind="path", component=repr(component)):
                self.reject_document(document)

        for field in ("release_archive", "release_checksum", "release_manifest"):
            for component in invalid_components:
                document = valid_document()
                document[field] = component
                with self.subTest(
                    kind="release", field=field, component=repr(component)
                ):
                    self.reject_document(document)

    def test_rejects_unsafe_release_basenames(self):
        invalid_basenames = (
            "",
            ".",
            "..",
            "../release.zip",
            "dist/release.zip",
            "dist\\release.zip",
            "C:release.zip",
            "C:\\release.zip",
            "/release.zip",
            " release.zip",
            "release.zip ",
            "release\x00.zip",
        )
        for field in ("release_archive", "release_checksum", "release_manifest"):
            for basename in invalid_basenames:
                document = valid_document()
                document[field] = basename
                with self.subTest(field=field, basename=repr(basename)):
                    self.reject_document(document)

    def test_release_names_are_exactly_derived_from_pack_name_and_version(self):
        alternate_names = {
            "release_archive": "portable-but-wrong.zip",
            "release_checksum": "portable-but-wrong.zip.sha256",
            "release_manifest": "portable-but-wrong-manifest.json",
        }
        for field, alternate in alternate_names.items():
            document = valid_document()
            document[field] = alternate
            with self.subTest(field=field):
                self.reject_document(document)

        document = valid_document()
        document["name"] = "portable-memory-pack"
        document["version"] = "3.4.5"
        document["release_archive"] = "portable-memory-pack-3.4.5.zip"
        document["release_checksum"] = "portable-memory-pack-3.4.5.zip.sha256"
        document["release_manifest"] = "portable-memory-pack-3.4.5-manifest.json"

        manifest = self.load_document(document)

        self.assertEqual(document["release_archive"], manifest.release_archive)
        self.assertEqual(document["release_checksum"], manifest.release_checksum)
        self.assertEqual(document["release_manifest"], manifest.release_manifest)


class PublicTaskSevenApiTests(unittest.TestCase):
    def test_exports_proposal_resolution_surface_and_locked_signatures(self):
        expected = {
            "ProposalDecisionEnvelope", "RewriteCandidateArtifact",
            "SemanticReviewArtifact", "RewritePacket", "ResolutionPlan",
            "ResolutionResult", "ResolutionVerification",
            "bind_proposal_decisions", "load_proposal_decisions",
            "load_rewrite_candidate", "load_semantic_review",
            "bind_rewrite_packet", "load_rewrite_packet", "seal_rewrite_packet",
            "bind_resolution_plan", "load_resolution_plan",
            "plan_proposal_resolution", "apply_proposal_resolution",
            "recover_proposal_resolution", "verify_proposal_resolution",
        }
        self.assertTrue(expected.issubset(set(public_api.__all__)))
        self.assertEqual(
            ("root", "gate", "transaction_id", "context"),
            tuple(inspect.signature(public_api.recover_proposal_resolution).parameters),
        )
        self.assertEqual(
            ("root", "gate", "plan", "result"),
            tuple(inspect.signature(public_api.verify_proposal_resolution).parameters),
        )

    def test_exports_exact_proposal_review_surface(self):
        expected = {
            "CodeIdentity", "CodeIdentityProof", "MigrationReviewProposal",
            "ProposalArtifact", "ProposalFamily", "ProposalReviewArtifact",
            "ProposalReviewContext", "TransactionConflictProposal",
            "bind_proposal_review", "build_proposal_review",
            "load_proposal_review", "observe_runtime_identity",
            "parse_proposal_artifact",
        }
        self.assertTrue(expected.issubset(set(public_api.__all__)))
        for name in expected:
            self.assertIsNotNone(getattr(public_api, name))

    def test_proposal_review_public_signatures_match_the_locked_contract(self):
        self.assertEqual(
            (
                "root", "bundle_path", "reviewed_bundle_sha256", "context",
                "gate", "code_identity_proof",
            ),
            tuple(inspect.signature(public_api.build_proposal_review).parameters),
        )
        self.assertEqual(
            (
                "root", "bundle_path", "reviewed_bundle_sha256", "context",
                "gate", "code_identity_proof", "report",
            ),
            tuple(inspect.signature(public_api.bind_proposal_review).parameters),
        )

    def test_exports_the_locked_manifest_and_validation_entry_points(self):
        self.assertIs(load_pack_manifest, public_api.load_pack_manifest)
        self.assertIs(validate_repository, public_api.validate_repository)
        self.assertIs(validate_skill_tree, public_api.validate_skill_tree)
        self.assertTrue(
            {
                "load_pack_manifest",
                "validate_repository",
                "validate_skill_tree",
            }.issubset(set(public_api.__all__))
        )


if __name__ == "__main__":
    unittest.main()
