import ast
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from tests.helpers import REPO_ROOT

from obsidian_agent_memory import ConflictError, ValidationError
from tools.agent_memory_pack.io import canonical_json_bytes
from tools.agent_memory_pack.models import ReleaseArtifacts
from tools.agent_memory_pack.release import (
    build_release,
    verified_release_source,
    verify_release,
)


def _copied_artifacts(artifacts, destination):
    destination.mkdir()
    archive = destination / artifacts.archive_path.name
    checksum = destination / artifacts.checksum_path.name
    manifest = destination / artifacts.manifest_path.name
    shutil.copyfile(artifacts.archive_path, archive)
    shutil.copyfile(artifacts.checksum_path, checksum)
    shutil.copyfile(artifacts.manifest_path, manifest)
    return ReleaseArtifacts(
        archive,
        checksum,
        manifest,
        artifacts.archive_sha256,
        artifacts.content_revision,
    )


def _refresh_artifact_hashes(artifacts):
    archive_sha256 = hashlib.sha256(artifacts.archive_path.read_bytes()).hexdigest()
    document = json.loads(artifacts.manifest_path.read_text(encoding="utf-8"))
    document["archive_sha256"] = archive_sha256
    artifacts.manifest_path.write_bytes(canonical_json_bytes(document))
    artifacts.checksum_path.write_bytes(
        (
            archive_sha256 + "  " + artifacts.archive_path.name + "\n"
        ).encode("ascii")
    )


def _clone_info(info, name=None):
    clone = zipfile.ZipInfo(name or info.filename, info.date_time)
    clone.compress_type = info.compress_type
    clone.create_system = info.create_system
    clone.external_attr = info.external_attr
    clone.flag_bits = info.flag_bits
    clone.internal_attr = info.internal_attr
    clone.extra = info.extra
    clone.comment = info.comment
    return clone


def _rewrite_archive(artifacts, transform):
    with zipfile.ZipFile(artifacts.archive_path, "r") as archive:
        entries = [(info, archive.read(info)) for info in archive.infolist()]
    transformed = transform(entries)
    temporary = artifacts.archive_path.with_suffix(".rewrite")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for info, raw in transformed:
                archive.writestr(info, raw, compress_type=info.compress_type)
    os.replace(temporary, artifacts.archive_path)
    _refresh_artifact_hashes(artifacts)


class ReleaseTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls._root = Path(cls._temporary.name)
        cls.artifacts = build_release(REPO_ROOT, cls._root / "valid")

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def artifact_copy(self, name):
        return _copied_artifacts(self.artifacts, self._root / name)

    def assert_verification_rejected(self, artifacts):
        with self.assertRaises(ValidationError):
            verify_release(
                artifacts.archive_path,
                artifacts.checksum_path,
                artifacts.manifest_path,
            )


class ReleaseReproducibilityTests(unittest.TestCase):
    def test_two_builds_are_byte_identical_with_canonical_zip_metadata(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = build_release(REPO_ROOT, root / "first")
            second = build_release(REPO_ROOT, root / "second")

            self.assertEqual(
                first.archive_path.read_bytes(), second.archive_path.read_bytes()
            )
            self.assertEqual(
                first.checksum_path.read_bytes(), second.checksum_path.read_bytes()
            )
            self.assertEqual(
                first.manifest_path.read_bytes(), second.manifest_path.read_bytes()
            )
            with zipfile.ZipFile(first.archive_path, "r") as archive:
                infos = tuple(archive.infolist())
                names = tuple(info.filename for info in infos)
                self.assertEqual(tuple(sorted(names)), names)
                self.assertEqual(len(names), len(set(names)))
                self.assertFalse(
                    any("/tests/evaluations/" in name for name in names)
                )
                self.assertTrue(
                    any(
                        name.endswith(
                            "/tests/fixtures/vaults/v1-minimal/.agent-memory-fixture.json"
                        )
                        for name in names
                    )
                )
                for info in infos:
                    self.assertEqual((1980, 1, 1, 0, 0, 0), info.date_time)
                    self.assertEqual(zipfile.ZIP_STORED, info.compress_type)
                    self.assertEqual(3, info.create_system)
                    self.assertEqual(0o100644, info.external_attr >> 16)

    def test_source_mtimes_do_not_change_any_artifact_byte(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)

            def ignore(directory, names):
                del directory
                return tuple(
                    name
                    for name in names
                    if name in (".git", "dist", "__pycache__")
                    or name.endswith(".pyc")
                )

            source = root / "source"
            shutil.copytree(REPO_ROOT, source, ignore=ignore)
            first = build_release(source, root / "first")
            for path in source.rglob("*"):
                if path.is_file():
                    os.utime(path, (946684800, 946684800))
            second = build_release(source, root / "second")

            self.assertEqual(first.archive_path.read_bytes(), second.archive_path.read_bytes())
            self.assertEqual(first.checksum_path.read_bytes(), second.checksum_path.read_bytes())
            self.assertEqual(first.manifest_path.read_bytes(), second.manifest_path.read_bytes())

            pack_before = (source / "pack.json").read_bytes()
            (source / "VERSION").write_bytes(b"9.0.0\n")
            stale_output = root / "stale-output"
            with self.assertRaises(ConflictError):
                build_release(source, stale_output)
            self.assertEqual(pack_before, (source / "pack.json").read_bytes())
            self.assertFalse(stale_output.exists())


class ReleaseVerificationTests(ReleaseTestBase):
    def test_valid_release_verifies_without_exposing_or_creating_a_source_root(self):
        before = frozenset(path.relative_to(self._root) for path in self._root.rglob("*"))

        result = verify_release(
            self.artifacts.archive_path,
            self.artifacts.checksum_path,
            self.artifacts.manifest_path,
        )

        after = frozenset(path.relative_to(self._root) for path in self._root.rglob("*"))
        self.assertEqual(before, after)
        self.assertEqual(self.artifacts.archive_sha256, result.archive_sha256)
        self.assertFalse(hasattr(result, "source_root"))

    def test_changed_archive_byte_is_rejected(self):
        artifacts = self.artifact_copy("changed-archive")
        raw = bytearray(artifacts.archive_path.read_bytes())
        raw[-1] ^= 1
        artifacts.archive_path.write_bytes(raw)
        self.assert_verification_rejected(artifacts)

    def test_checksum_sidecar_is_exact_lowercase_two_space_form(self):
        valid = self.artifacts.checksum_path.read_text(encoding="ascii")
        digest, name = valid.rstrip("\n").split("  ", 1)
        mutations = (
            digest.upper() + "  " + name + "\n",
            digest[:-1] + "  " + name + "\n",
            digest + "  wrong.zip\n",
            digest + "  " + name + "  extra\n",
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                artifacts = self.artifact_copy("checksum-{0}".format(index))
                artifacts.checksum_path.write_text(mutation, encoding="ascii")
                self.assert_verification_rejected(artifacts)

    def test_changed_duplicate_or_unknown_external_manifest_is_rejected(self):
        mutations = []
        document = json.loads(self.artifacts.manifest_path.read_text(encoding="utf-8"))
        changed = dict(document)
        changed["pack_version"] = "9.0.0"
        mutations.append(canonical_json_bytes(changed))
        unknown = dict(document)
        unknown["unknown"] = True
        mutations.append(canonical_json_bytes(unknown))
        raw = self.artifacts.manifest_path.read_text(encoding="utf-8")
        mutations.append(raw.replace('{\n  "archive":', '{\n  "archive": "duplicate",\n  "archive":', 1).encode("utf-8"))

        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                artifacts = self.artifact_copy("manifest-{0}".format(index))
                artifacts.manifest_path.write_bytes(mutation)
                self.assert_verification_rejected(artifacts)

    def test_duplicate_pack_manifest_json_is_rejected_after_member_hashes_match(self):
        artifacts = self.artifact_copy("duplicate-pack-manifest")
        mutated_pack = []

        def transform(entries):
            result = []
            for info, raw in entries:
                if info.filename.endswith("/pack.json"):
                    raw = raw.replace(
                        b'{\n  "active_members":',
                        b'{\n  "active_members": [],\n  "active_members":',
                        1,
                    )
                    mutated_pack.append(raw)
                result.append((_clone_info(info), raw))
            return result

        _rewrite_archive(artifacts, transform)
        self.assertEqual(1, len(mutated_pack))
        document = json.loads(artifacts.manifest_path.read_text(encoding="utf-8"))
        pack_record = next(item for item in document["files"] if item["path"] == "pack.json")
        pack_record["sha256"] = hashlib.sha256(mutated_pack[0]).hexdigest()
        pack_record["size"] = len(mutated_pack[0])
        document["content_revision"] = hashlib.sha256(
            canonical_json_bytes(document["files"])
        ).hexdigest()
        artifacts.manifest_path.write_bytes(canonical_json_bytes(document))

        self.assert_verification_rejected(artifacts)

    def test_duplicate_unlisted_and_unsafe_member_names_are_rejected(self):
        cases = (
            ("duplicate", lambda entries: entries + [entries[0]]),
            (
                "unlisted",
                lambda entries: entries
                + [(_clone_info(entries[0][0], entries[0][0].filename + ".extra"), b"extra")],
            ),
            (
                "absolute",
                lambda entries: [(_clone_info(entries[0][0], "/absolute"), entries[0][1])]
                + entries[1:],
            ),
            (
                "traversal",
                lambda entries: [(_clone_info(entries[0][0], "prefix/../escape"), entries[0][1])]
                + entries[1:],
            ),
            (
                "backslash",
                lambda entries: [(_clone_info(entries[0][0], "prefix\\escape"), entries[0][1])]
                + entries[1:],
            ),
            (
                "drive",
                lambda entries: [(_clone_info(entries[0][0], "C:/escape"), entries[0][1])]
                + entries[1:],
            ),
        )
        for name, transform in cases:
            with self.subTest(name=name):
                artifacts = self.artifact_copy("member-" + name)
                _rewrite_archive(artifacts, transform)
                self.assert_verification_rejected(artifacts)

    def test_symlink_encrypted_order_and_member_metadata_are_rejected(self):
        def mutate_first(entries, **values):
            info, raw = entries[0]
            clone = _clone_info(info)
            for key, value in values.items():
                setattr(clone, key, value)
            return [(clone, raw)] + entries[1:]

        cases = (
            ("order", lambda entries: list(reversed(entries))),
            ("timestamp", lambda entries: mutate_first(entries, date_time=(1980, 1, 2, 0, 0, 0))),
            ("mode", lambda entries: mutate_first(entries, external_attr=0o120777 << 16)),
            ("compression", lambda entries: mutate_first(entries, compress_type=zipfile.ZIP_DEFLATED)),
        )
        for name, transform in cases:
            with self.subTest(name=name):
                artifacts = self.artifact_copy("metadata-" + name)
                _rewrite_archive(artifacts, transform)
                self.assert_verification_rejected(artifacts)

        artifacts = self.artifact_copy("metadata-encrypted")
        raw = bytearray(artifacts.archive_path.read_bytes())
        local = raw.find(b"PK\x03\x04")
        central = raw.find(b"PK\x01\x02")
        self.assertGreaterEqual(local, 0)
        self.assertGreaterEqual(central, 0)
        local_flags = struct.unpack_from("<H", raw, local + 6)[0] | 1
        central_flags = struct.unpack_from("<H", raw, central + 8)[0] | 1
        struct.pack_into("<H", raw, local + 6, local_flags)
        struct.pack_into("<H", raw, central + 8, central_flags)
        artifacts.archive_path.write_bytes(raw)
        _refresh_artifact_hashes(artifacts)
        self.assert_verification_rejected(artifacts)

    def test_declared_hash_size_content_revision_and_file_order_are_rejected(self):
        mutations = []
        base = json.loads(self.artifacts.manifest_path.read_text(encoding="utf-8"))

        changed_hash = json.loads(json.dumps(base))
        changed_hash["files"][0]["sha256"] = "0" * 64
        mutations.append(changed_hash)

        changed_size = json.loads(json.dumps(base))
        changed_size["files"][0]["size"] += 1
        mutations.append(changed_size)

        changed_revision = json.loads(json.dumps(base))
        changed_revision["content_revision"] = "0" * 64
        mutations.append(changed_revision)

        changed_order = json.loads(json.dumps(base))
        changed_order["files"] = list(reversed(changed_order["files"]))
        mutations.append(changed_order)

        for index, document in enumerate(mutations):
            if index < 2:
                document["content_revision"] = hashlib.sha256(
                    canonical_json_bytes(document["files"])
                ).hexdigest()
            with self.subTest(index=index):
                artifacts = self.artifact_copy("record-{0}".format(index))
                artifacts.manifest_path.write_bytes(canonical_json_bytes(document))
                self.assert_verification_rejected(artifacts)


class VerifiedReleaseSourceTests(ReleaseTestBase):
    def test_verified_source_lives_for_the_context_and_contains_the_exact_pack(self):
        with verified_release_source(
            self.artifacts.archive_path,
            self.artifacts.checksum_path,
            self.artifacts.manifest_path,
        ) as source:
            source_root = source.source_root
            self.assertTrue((source_root / "pack.json").is_file())
            document = json.loads((source_root / "pack.json").read_text(encoding="utf-8"))
            expected = {"pack.json"}
            expected.update(item["path"] for item in document["files"])
            actual = {
                path.relative_to(source_root).as_posix()
                for path in source_root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(expected, actual)
            self.assertTrue(source_root.exists())

        self.assertFalse(source_root.exists())

    def test_overlapping_verified_sources_are_distinct_and_nested_safe(self):
        with verified_release_source(
            self.artifacts.archive_path,
            self.artifacts.checksum_path,
            self.artifacts.manifest_path,
        ) as first:
            first_root = first.source_root
            with verified_release_source(
                self.artifacts.archive_path,
                self.artifacts.checksum_path,
                self.artifacts.manifest_path,
            ) as second:
                second_root = second.source_root
                self.assertNotEqual(first_root, second_root)
                self.assertTrue(first_root.exists())
                self.assertTrue(second_root.exists())
            self.assertTrue(first_root.exists())
            self.assertFalse(second_root.exists())
        self.assertFalse(first_root.exists())

    def test_extracted_deterministic_tests_are_self_contained_and_static_gate_runs(self):
        forbidden = (
            "tests.evaluations",
            "tests.unit.test_evaluation_evidence",
        )
        with verified_release_source(
            self.artifacts.archive_path,
            self.artifacts.checksum_path,
            self.artifacts.manifest_path,
        ) as source:
            self.assertTrue((source.source_root / ".gitignore").is_file())
            self.assertTrue((source.source_root / "docs/vault-migration-operations.md").is_file())
            for path in sorted((source.source_root / "tests").rglob("*.py")):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                imported = []
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported.extend(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported.append(node.module)
                with self.subTest(path=path.relative_to(source.source_root).as_posix()):
                    self.assertFalse(
                        any(
                            name == blocked or name.startswith(blocked + ".")
                            for name in imported
                            for blocked in forbidden
                        )
                    )

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "unittest",
                    "tests.unit.test_skill_family_static",
                    "tests.unit.test_models",
                    "tests.unit.test_release_documentation",
                    "tests.unit.test_manifest_validation",
                    "-v",
                ],
                cwd=str(source.source_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(0, completed.returncode, completed.stdout)


class ReleaseCliTests(unittest.TestCase):
    def run_command(self, arguments):
        return subprocess.run(
            [sys.executable] + arguments,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )

    def test_build_and_verify_cli_outputs_and_exit_codes_are_stable(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "release"
            built = self.run_command(
                [
                    "tools/build_release.py",
                    "--repo-root",
                    ".",
                    "--dist-dir",
                    str(output),
                ]
            )
            self.assertEqual(0, built.returncode, built.stdout)
            self.assertRegex(
                built.stdout,
                r"^BUILT obsidian-agent-memory-skill-pack-2\.0\.1\.zip "
                r"obsidian-agent-memory-skill-pack-2\.0\.1\.zip\.sha256 "
                r"obsidian-agent-memory-skill-pack-2\.0\.1-manifest\.json "
                r"sha256=[0-9a-f]{64}\n$",
            )
            archive = output / "obsidian-agent-memory-skill-pack-2.0.1.zip"
            checksum = output / "obsidian-agent-memory-skill-pack-2.0.1.zip.sha256"
            manifest = output / "obsidian-agent-memory-skill-pack-2.0.1-manifest.json"
            verified = self.run_command(
                [
                    "tools/verify_release.py",
                    "--archive",
                    str(archive),
                    "--checksum",
                    str(checksum),
                    "--manifest",
                    str(manifest),
                ]
            )
            self.assertEqual(0, verified.returncode, verified.stdout)
            self.assertRegex(
                verified.stdout,
                r"^VERIFIED obsidian-agent-memory-skill-pack 2\.0\.1 "
                r"sha256=[0-9a-f]{64}\n$",
            )

            checksum.write_text(
                checksum.read_text(encoding="ascii").upper(), encoding="ascii"
            )
            tampered = self.run_command(
                [
                    "tools/verify_release.py",
                    "--archive",
                    str(archive),
                    "--checksum",
                    str(checksum),
                    "--manifest",
                    str(manifest),
                ]
            )
            self.assertEqual(5, tampered.returncode, tampered.stdout)

            missing = self.run_command(
                [
                    "tools/verify_release.py",
                    "--archive",
                    str(output / "missing.zip"),
                    "--checksum",
                    str(checksum),
                    "--manifest",
                    str(manifest),
                ]
            )
            self.assertEqual(2, missing.returncode, missing.stdout)


if __name__ == "__main__":
    unittest.main()
