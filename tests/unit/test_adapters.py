import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory.adapters import select_read_adapter  # noqa: E402
import obsidian_agent_memory.adapters as adapters_module  # noqa: E402
from obsidian_agent_memory.catalog import (  # noqa: E402
    load_catalog,
    read_accepted_record,
    search_accepted_records,
)
from obsidian_agent_memory.errors import ValidationError  # noqa: E402
from obsidian_agent_memory.models import CatalogEntry, RootBinding, SearchHit  # noqa: E402
from obsidian_agent_memory.records import record_relative_path, render_record  # noqa: E402
from obsidian_agent_memory.transactions import commit_record  # noqa: E402
import obsidian_agent_memory as public_api  # noqa: E402
from tests.helpers import candidate, context, initialize  # noqa: E402


class FakeRunner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, arguments, timeout):
        self.calls.append((tuple(arguments), timeout))
        if not self.responses:
            raise AssertionError("unexpected command")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class CatalogOnlyAdapter:
    def __init__(self, documents):
        self.documents = dict(documents)
        self.read_calls = []

    def read(self, relative_path):
        self.read_calls.append(relative_path)
        return self.documents[relative_path]

    def search(self, query, limit=20):
        raise AssertionError("accepted search must not call raw adapter search")

    def files(self, prefix, limit=200):
        raise AssertionError("accepted search must not enumerate adapter files")


class CountingScandir:
    def __init__(self, entries):
        self.entries = tuple(entries)
        self.index = 0
        self.next_calls = 0
        self.successful_inspections = 0
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __iter__(self):
        return self

    def __next__(self):
        self.next_calls += 1
        if self.index == len(self.entries):
            raise StopIteration
        entry = self.entries[self.index]
        self.index += 1
        self.successful_inspections += 1
        return entry

    def close(self):
        self.closed = True


class FakeDirEntry:
    def __init__(self, path):
        self.path = os.fspath(path)


class MetadataOverride:
    def __init__(self, metadata, **overrides):
        self._metadata = metadata
        self._overrides = overrides

    def __getattr__(self, name):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._metadata, name)


def simulated_metadata(path, **overrides):
    original_lstat = Path.lstat
    target = os.path.normcase(os.path.abspath(os.fspath(path)))

    def lstat(candidate):
        metadata = original_lstat(candidate)
        absolute = os.path.normcase(os.path.abspath(os.fspath(candidate)))
        if absolute == target:
            return MetadataOverride(metadata, **overrides)
        return metadata

    return mock.patch.object(Path, "lstat", new=lstat)


def simulated_reparse(path):
    metadata = Path(path).lstat()
    attributes = getattr(metadata, "st_file_attributes", 0) | 0x400
    return simulated_metadata(path, st_file_attributes=attributes)


def forbid_resolution_at_or_below(path):
    original_resolve = Path.resolve
    target = os.path.normcase(os.path.abspath(os.fspath(path)))
    prefix = target + os.sep

    def resolve(candidate, *args, **kwargs):
        absolute = os.path.normcase(os.path.abspath(os.fspath(candidate)))
        if absolute == target or absolute.startswith(prefix):
            raise AssertionError("reparse component reached the resolver")
        return original_resolve(candidate, *args, **kwargs)

    return mock.patch.object(Path, "resolve", new=resolve)


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess((), returncode, stdout=stdout, stderr=stderr)


def filesystem_adapter(root):
    with mock.patch("obsidian_agent_memory.adapters.shutil.which", return_value=None):
        return select_read_adapter(
            RootBinding(Path(root), "demo", "demo-vault"), FakeRunner()
        ).adapter


def catalog_row(record_candidate):
    envelope = record_candidate.envelope
    return {
        "memory_id": envelope.memory_id,
        "revision": envelope.revision,
        "relative_path": record_relative_path(envelope).as_posix(),
        "record_type": envelope.record_type,
        "owner_scope": envelope.owner_scope,
        "project": envelope.project,
    }


def write_catalog(root, rows, revision=1):
    path = Path(root) / ".agent-memory/state/catalog.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"schema_version": 2, "revision": revision, "records": rows},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    return path


class AdapterSelectionTests(unittest.TestCase):
    def binding(self, root, vault="demo-vault"):
        return RootBinding(Path(root), "demo", vault)

    def healthy_runner(self):
        return FakeRunner(completed(stdout="read\nsearch\nfiles\n"), completed())

    def test_explicit_executable_requires_exact_capabilities_and_bounded_vault_probe(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "must-not-be-scanned"
            runner = self.healthy_runner()

            with mock.patch(
                "obsidian_agent_memory.adapters.shutil.which",
                side_effect=AssertionError("explicit executable must bypass discovery"),
            ):
                selection = select_read_adapter(
                    self.binding(root), runner, Path("portable-obsidian")
                )

            self.assertEqual("obsidian-cli", selection.mode)
            self.assertEqual("cli-healthy", selection.reason)
            self.assertEqual(
                [
                    (("portable-obsidian", "help"), 2.0),
                    (
                        (
                            "portable-obsidian",
                            "vault=demo-vault",
                            "search",
                            "query=__agent_memory_health_probe__",
                            "limit=1",
                        ),
                        2.0,
                    ),
                ],
                runner.calls,
            )
            self.assertFalse(root.exists())

    def test_discovers_only_obsidian_when_no_executable_is_supplied(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = self.healthy_runner()
            discovered = Path(temporary_directory) / "obsidian"

            with mock.patch(
                "obsidian_agent_memory.adapters.shutil.which", return_value=str(discovered)
            ) as which:
                selection = select_read_adapter(
                    self.binding(Path(temporary_directory) / "memory"), runner
                )

            self.assertEqual("obsidian-cli", selection.mode)
            which.assert_called_once_with("obsidian")
            self.assertEqual(str(discovered), runner.calls[0][0][0])

    def test_missing_executable_falls_back_without_running_or_scanning(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "not-created"
            runner = FakeRunner()

            with mock.patch("obsidian_agent_memory.adapters.shutil.which", return_value=None):
                selection = select_read_adapter(self.binding(root), runner)

            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-executable-missing", selection.reason)
            self.assertEqual([], runner.calls)
            self.assertFalse(root.exists())

    def test_missing_vault_falls_back_before_health_checks(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            for vault in (None, "", "   "):
                with self.subTest(vault=vault):
                    runner = FakeRunner()

                    selection = select_read_adapter(
                        self.binding(root, vault=vault), runner, Path("obsidian")
                    )

                    self.assertEqual("filesystem", selection.mode)
                    self.assertEqual("cli-vault-missing", selection.reason)
                    self.assertEqual([], runner.calls)

    def test_timeout_and_not_running_fail_closed_with_the_same_reason(self):
        failures = (
            subprocess.TimeoutExpired(("obsidian", "help"), 2.0),
            FileNotFoundError("closed application"),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            for failure in failures:
                with self.subTest(failure=type(failure).__name__):
                    runner = FakeRunner(failure)

                    selection = select_read_adapter(
                        self.binding(root), runner, Path("obsidian")
                    )

                    self.assertEqual("filesystem", selection.mode)
                    self.assertEqual("cli-health-timeout", selection.reason)
                    self.assertEqual(1, len(runner.calls))

    def test_nonzero_help_does_not_run_the_probe(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = FakeRunner(completed(returncode=9, stderr="unbounded external detail"))

            selection = select_read_adapter(
                self.binding(Path(temporary_directory) / "memory"),
                runner,
                Path("obsidian"),
            )

            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-help-nonzero", selection.reason)
            self.assertEqual(1, len(runner.calls))

    def test_help_capabilities_are_exact_tokens_not_substrings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = FakeRunner(completed(stdout="bread\nresearch\nprofile-files\n"))

            selection = select_read_adapter(
                self.binding(Path(temporary_directory) / "memory"),
                runner,
                Path("obsidian"),
            )

            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-operation-unsupported", selection.reason)
            self.assertEqual(1, len(runner.calls))

    def test_help_capabilities_must_appear_in_command_position(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deceptive = FakeRunner(
                completed(
                    stdout=(
                        "search  Search notes\n"
                        "read and files are discussed in prose\n"
                        "files are unavailable in this mode\n"
                        "Options: --read --files\n"
                        "bread is prose, not a command\n"
                    )
                ),
                completed(),
            )

            selection = select_read_adapter(
                self.binding(Path(temporary_directory) / "memory"),
                deceptive,
                Path("obsidian"),
            )

            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-operation-unsupported", selection.reason)
            self.assertEqual(1, len(deceptive.calls))

    def test_help_command_lines_may_include_descriptions(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = FakeRunner(
                completed(
                    stdout=(
                        "read\n"
                        "search: Search notes\n"
                        "files  List files\n"
                    )
                ),
                completed(),
            )

            selection = select_read_adapter(
                self.binding(Path(temporary_directory) / "memory"),
                runner,
                Path("obsidian"),
            )

            self.assertEqual("obsidian-cli", selection.mode)
            self.assertEqual(2, len(runner.calls))

    def test_help_description_form_rejects_a_flag(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = FakeRunner(
                completed(stdout="read  --help\nsearch\nfiles\n"), completed()
            )

            selection = select_read_adapter(
                self.binding(Path(temporary_directory) / "memory"),
                runner,
                Path("obsidian"),
            )

            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-operation-unsupported", selection.reason)
            self.assertEqual(1, len(runner.calls))

    def test_help_exact_form_rejects_a_whitespace_only_suffix(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = FakeRunner(
                completed(stdout="read   \nsearch\nfiles\n"), completed()
            )

            selection = select_read_adapter(
                self.binding(Path(temporary_directory) / "memory"),
                runner,
                Path("obsidian"),
            )

            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-operation-unsupported", selection.reason)
            self.assertEqual(1, len(runner.calls))

    def test_oversized_help_output_is_not_parsed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = FakeRunner(
                completed(stdout="read search files " + ("x" * (1024 * 1024)))
            )

            selection = select_read_adapter(
                self.binding(Path(temporary_directory) / "memory"),
                runner,
                Path("obsidian"),
            )

            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-operation-unsupported", selection.reason)
            self.assertEqual(1, len(runner.calls))

    def test_nonzero_probe_has_a_distinct_fallback_reason(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = FakeRunner(
                completed(stdout="read\nsearch\nfiles\n"),
                completed(returncode=3, stderr="vault unavailable"),
            )

            selection = select_read_adapter(
                self.binding(Path(temporary_directory) / "memory"),
                runner,
                Path("obsidian"),
            )

            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-health-nonzero", selection.reason)
            self.assertEqual(2, len(runner.calls))


class FilesystemAdapterTests(unittest.TestCase):
    def test_discovery_ignores_code_and_binary_attachments_without_reading_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "projects" / "demo"
            examples = project / "examples"
            examples.mkdir(parents=True)
            (project / "overview.md").write_text("accepted overview", encoding="utf-8")
            (examples / "GhostDepthRendererFeature_example.cs").write_text("private attachment", encoding="utf-8")
            (examples / "Screenshot 2026.png").write_bytes(b"\x89PNG\xff" * 300000)
            (examples / "Ghostly Shader.md").write_text("legacy reference", encoding="utf-8")
            legacy = root / "projects" / "LegacyProject"
            legacy.mkdir()
            (legacy / "overview.md").write_text("old project reference", encoding="utf-8")
            dotted = root / "projects" / "demo.tools"
            dotted.mkdir()
            (dotted / "overview.md").write_text("another project", encoding="utf-8")
            adapter = filesystem_adapter(root)
            self.assertEqual(("projects/demo.tools/overview.md", "projects/demo/overview.md"), adapter.files("projects"))
            self.assertEqual((SearchHit("projects/demo/overview.md", "accepted overview"),), adapter.search("accepted"))
            self.assertEqual((), adapter.search("private attachment"))
            self.assertTrue((examples / "Screenshot 2026.png").exists())

    def test_attachment_reparse_points_are_rejected_before_skipping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "projects" / "demo"
            project.mkdir(parents=True)
            image = project / "asset.png"
            image.write_bytes(b"image")
            with simulated_reparse(image), forbid_resolution_at_or_below(image):
                with self.assertRaises(ValidationError):
                    filesystem_adapter(root).files("projects")

    def test_reads_lists_and_searches_only_the_three_allowed_roots(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            documents = {
                "_records/a.md": "Alpha accepted\nsecond line\n",
                "_index/b.md": "beta ALPHA\n",
                "projects/demo/c.md": "no match\n",
            }
            for relative_path, content in documents.items():
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content.encode("utf-8"))
            adapter = filesystem_adapter(root)

            for relative_path, content in documents.items():
                with self.subTest(relative_path=relative_path):
                    self.assertEqual(content, adapter.read(relative_path))
            self.assertEqual(("_records/a.md",), adapter.files("_records", limit=10))
            self.assertEqual(
                ("projects/demo/c.md",), adapter.files("projects", limit=10)
            )
            self.assertEqual(
                (
                    SearchHit("_index/b.md", "beta ALPHA"),
                    SearchHit("_records/a.md", "Alpha accepted"),
                ),
                adapter.search("alpha", limit=10),
            )

    def test_rejects_forbidden_absolute_and_traversing_paths(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            (root / "_records").mkdir(parents=True)
            adapter = filesystem_adapter(root)
            invalid_paths = (
                "_sources/private.md",
                ".agent-memory/state/catalog.json",
                "README.md",
                "../outside.md",
                "_records/../../outside.md",
                str((root / "_records/absolute.md").resolve()),
            )

            for invalid_path in invalid_paths:
                with self.subTest(invalid_path=invalid_path):
                    with self.assertRaises(ValidationError):
                        adapter.read(invalid_path)
                    with self.assertRaises(ValidationError):
                        adapter.files(invalid_path, limit=1)

    def test_read_and_files_reject_nonportable_paths_before_lstat(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            (root / "_records").mkdir(parents=True)
            adapter = filesystem_adapter(root)
            invalid_paths = (
                "_records/bad\x00.md",
                "_records/bad\x1f.md",
                "_records\\bad.md",
                "_records/../../outside.md",
                str((root / "_records/absolute.md").resolve()),
            )

            for invalid_path in invalid_paths:
                for operation in (
                    lambda value: adapter.read(value),
                    lambda value: adapter.files(value, limit=1),
                ):
                    with self.subTest(
                        invalid_path=repr(invalid_path),
                        operation=operation.__code__.co_firstlineno,
                    ):
                        with mock.patch.object(
                            Path,
                            "lstat",
                            side_effect=AssertionError(
                                "invalid adapter path reached filesystem inspection"
                            ),
                        ) as lstat:
                            with self.assertRaises(ValidationError) as raised:
                                operation(invalid_path)

                        self.assertNotIn(invalid_path, str(raised.exception))
                        self.assertEqual(0, lstat.call_count)

    def test_search_rejects_a_nul_entry_before_candidate_lstat_or_read(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            index = root / "_index"
            index.mkdir(parents=True)
            invalid_entry = index / "bad\x00.md"
            adapter = filesystem_adapter(root)
            counting = CountingScandir((FakeDirEntry(invalid_entry),))
            original_plain = adapters_module._plain_contained_metadata

            def plain(memory_root, target, *args, **kwargs):
                if "\x00" in os.fspath(target):
                    raise AssertionError(
                        "invalid adapter entry reached filesystem inspection"
                    )
                return original_plain(memory_root, target, *args, **kwargs)

            with mock.patch(
                "obsidian_agent_memory.adapters.os.scandir",
                return_value=counting,
            ), mock.patch(
                "obsidian_agent_memory.adapters._plain_contained_metadata",
                side_effect=plain,
            ), mock.patch.object(adapter, "read", wraps=adapter.read) as read:
                with self.assertRaises(ValidationError) as raised:
                    adapter.search("needle", limit=1)

            self.assertNotIn("bad", str(raised.exception))
            self.assertEqual(0, read.call_count)
            self.assertTrue(counting.closed)

    def test_rejects_empty_queries_prefixes_and_nonpositive_limits(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            adapter = filesystem_adapter(Path(temporary_directory) / "memory")

            for query in ("", "  \t\n"):
                with self.subTest(query=query):
                    with self.assertRaises(ValidationError):
                        adapter.search(query)
            with self.assertRaises(ValidationError):
                adapter.files("", limit=1)
            for limit in (0, -1, True):
                with self.subTest(limit=limit):
                    with self.assertRaises(ValidationError):
                        adapter.search("term", limit=limit)
                    with self.assertRaises(ValidationError):
                        adapter.files("_records", limit=limit)

    def test_rejects_missing_directories_invalid_utf8_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            records = root / "_records"
            records.mkdir(parents=True)
            (records / "bad.md").write_bytes(b"\xff")
            (records / "large.md").write_bytes(b"x" * (1024 * 1024 + 1))
            adapter = filesystem_adapter(root)

            for relative_path in (
                "_records/missing.md",
                "_records",
                "_records/bad.md",
                "_records/large.md",
            ):
                with self.subTest(relative_path=relative_path):
                    with self.assertRaises(ValidationError):
                        adapter.read(relative_path)

    def test_rejects_a_symlink_that_resolves_outside_the_memory_root(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "memory"
            records = root / "_records"
            records.mkdir(parents=True)
            external = base / "external.md"
            external.write_text("outside", encoding="utf-8")
            try:
                (records / "escape.md").symlink_to(external)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            adapter = filesystem_adapter(root)

            with self.assertRaises(ValidationError):
                adapter.read("_records/escape.md")

    def test_search_reads_the_lexical_inventory_until_the_result_limit_matches(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            index = root / "_index"
            index.mkdir(parents=True)
            documents = {
                "a.md": "first has no match\n",
                "b.md": "second has no match\n",
                "c.md": "first needle match\n",
                "d.md": "second NEEDLE match\n",
                "e.md": "later needle match\n",
            }
            for name, text in documents.items():
                (index / name).write_text(text, encoding="utf-8")
            adapter = filesystem_adapter(root)

            with mock.patch.object(adapter, "read", wraps=adapter.read) as read:
                results = adapter.search("needle", limit=2)

            self.assertEqual(
                (
                    SearchHit("_index/c.md", "first needle match"),
                    SearchHit("_index/d.md", "second NEEDLE match"),
                ),
                results,
            )
            self.assertEqual(
                [
                    mock.call("_index/a.md"),
                    mock.call("_index/b.md"),
                    mock.call("_index/c.md"),
                    mock.call("_index/d.md"),
                ],
                read.call_args_list,
            )

    def test_search_skips_missing_optional_read_roots(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            record = root / "_records/record.md"
            record.parent.mkdir(parents=True)
            record.write_bytes(b"needle")
            adapter = filesystem_adapter(root)

            self.assertEqual((), adapter.files("_index", limit=5))
            self.assertEqual(
                (SearchHit("_records/record.md", "needle"),),
                adapter.search("needle", limit=5),
            )

    def test_files_are_globally_lexical_across_files_and_subdirectories(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            relative_paths = (
                "_records/a/inside.md",
                "_records/a-early.md",
                "_records/a.md",
                "_records/a0.md",
            )
            for relative_path in relative_paths:
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"content")
            adapter = filesystem_adapter(root)

            expected = tuple(sorted(relative_paths))
            self.assertEqual(expected, adapter.files("_records", limit=10))
            self.assertEqual(expected[:2], adapter.files("_records", limit=2))

    def test_files_and_search_are_identical_for_forward_and_reverse_scandir(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            records = root / "_records"
            relative_paths = (
                "_records/a/inside.md",
                "_records/a-early.md",
                "_records/a.md",
                "_records/a0.md",
            )
            for relative_path in relative_paths:
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("needle " + relative_path, encoding="utf-8")
            adapter = filesystem_adapter(root)
            original_scandir = os.scandir
            entries_by_directory = {}
            for directory in (records, records / "a"):
                with original_scandir(str(directory)) as iterator:
                    entries_by_directory[
                        os.path.normcase(os.path.abspath(os.fspath(directory)))
                    ] = tuple(iterator)

            def scanner(reverse):
                def scanned(path):
                    key = os.path.normcase(os.path.abspath(os.fspath(path)))
                    entries = sorted(
                        entries_by_directory[key],
                        key=lambda entry: entry.name,
                        reverse=reverse,
                    )
                    return CountingScandir(entries)

                return scanned

            observed = []
            for reverse in (False, True):
                with mock.patch(
                    "obsidian_agent_memory.adapters.os.scandir",
                    side_effect=scanner(reverse),
                ):
                    observed.append(
                        (
                            adapter.files("_records", limit=2),
                            adapter.search("needle", limit=2),
                        )
                    )

            expected_paths = tuple(sorted(relative_paths))[:2]
            expected_hits = tuple(
                SearchHit(path, "needle " + path) for path in expected_paths
            )
            self.assertEqual((expected_paths, expected_hits), observed[0])
            self.assertEqual(observed[0], observed[1])

    def test_empty_directory_tree_fails_at_the_fixed_inspection_ceiling(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            records = root / "_records"
            records.mkdir(parents=True)
            fake_directory = records / "empty"
            root_scan = CountingScandir(
                (FakeDirEntry(fake_directory),) * 10001
            )
            directory_metadata = records.lstat()
            entry_checks = [0]
            child_scans = [0]
            original_validated = adapters_module._validated_relative_path
            original_plain = adapters_module._plain_contained_metadata

            def validated(memory_root, value):
                if value == "_records/empty":
                    entry_checks[0] += 1
                    return fake_directory, value
                return original_validated(memory_root, value)

            def plain(memory_root, target, *args, **kwargs):
                if os.path.normcase(os.path.abspath(os.fspath(target))) == os.path.normcase(
                    os.path.abspath(os.fspath(fake_directory))
                ):
                    return fake_directory, directory_metadata
                return original_plain(memory_root, target, *args, **kwargs)

            def scanned(path):
                normalized = os.path.normcase(os.path.abspath(os.fspath(path)))
                if normalized == os.path.normcase(
                    os.path.abspath(os.fspath(records))
                ):
                    return root_scan
                child_scans[0] += 1
                return CountingScandir(())

            adapter = filesystem_adapter(root)
            with mock.patch(
                "obsidian_agent_memory.adapters.os.scandir", side_effect=scanned
            ), mock.patch(
                "obsidian_agent_memory.adapters._validated_relative_path",
                side_effect=validated,
            ), mock.patch(
                "obsidian_agent_memory.adapters._plain_contained_metadata",
                side_effect=plain,
            ):
                with self.assertRaises(ValidationError) as raised:
                    adapter.files("_records", limit=1)

            self.assertEqual("filesystem inspection limit exceeded", str(raised.exception))
            self.assertEqual(10001, root_scan.successful_inspections)
            self.assertEqual(10001, root_scan.next_calls)
            self.assertEqual(10000, entry_checks[0])
            self.assertLessEqual(child_scans[0], 10000)
            self.assertTrue(root_scan.closed)

    def test_files_and_search_fail_at_the_fixed_special_entry_ceiling(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            records = root / "_records"
            records.mkdir(parents=True)
            fake_special = records / "special"
            fake_reparse = records / "reparse-loop"
            special_metadata = MetadataOverride(
                records.lstat(), st_mode=stat.S_IFIFO | 0o600
            )
            adapter = filesystem_adapter(root)
            original_validated = adapters_module._validated_relative_path
            original_plain = adapters_module._plain_contained_metadata

            for operation in (
                lambda: adapter.files("_records", limit=1),
                lambda: adapter.search("needle", limit=1),
            ):
                with self.subTest(operation=operation.__code__.co_firstlineno):
                    counting = CountingScandir(
                        (FakeDirEntry(fake_special),) * 10000
                        + (FakeDirEntry(fake_reparse),)
                    )
                    entry_checks = [0]

                    def validated(memory_root, value):
                        if value == "_records/special":
                            entry_checks[0] += 1
                            return fake_special, value
                        if value == "_records/reparse-loop":
                            raise AssertionError("entry 10,001 reached path validation")
                        return original_validated(memory_root, value)

                    def plain(memory_root, target, *args, **kwargs):
                        if os.path.normcase(
                            os.path.abspath(os.fspath(target))
                        ) == os.path.normcase(os.path.abspath(os.fspath(fake_special))):
                            return fake_special, special_metadata
                        return original_plain(memory_root, target, *args, **kwargs)

                    with mock.patch(
                        "obsidian_agent_memory.adapters.os.scandir",
                        return_value=counting,
                    ), mock.patch(
                        "obsidian_agent_memory.adapters._validated_relative_path",
                        side_effect=validated,
                    ), mock.patch(
                        "obsidian_agent_memory.adapters._plain_contained_metadata",
                        side_effect=plain,
                    ), mock.patch.object(
                        adapter,
                        "read",
                        side_effect=AssertionError("incomplete inventory was read"),
                    ):
                        with self.assertRaises(ValidationError) as raised:
                            operation()

                    self.assertEqual(
                        "filesystem inspection limit exceeded", str(raised.exception)
                    )
                    self.assertNotIn("special", str(raised.exception))
                    self.assertEqual(10001, counting.successful_inspections)
                    self.assertEqual(10001, counting.next_calls)
                    self.assertEqual(10000, entry_checks[0])
                    self.assertTrue(counting.closed)

    def test_exact_ceiling_succeeds_but_one_more_regular_entry_returns_no_partial(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            records = root / "_records"
            records.mkdir(parents=True)
            fake_regular = records / "regular.md"
            regular_metadata = MetadataOverride(
                records.lstat(), st_mode=stat.S_IFREG | 0o600
            )
            adapter = filesystem_adapter(root)
            original_validated = adapters_module._validated_relative_path
            original_plain = adapters_module._plain_contained_metadata
            cases = (
                ("exact-files", 10000, lambda: adapter.files("_records", limit=1)),
                ("overflow-files", 10001, lambda: adapter.files("_records", limit=1)),
                (
                    "overflow-search",
                    10001,
                    lambda: adapter.search("needle", limit=1),
                ),
            )

            for name, entry_count, operation in cases:
                with self.subTest(name=name):
                    counting = CountingScandir(
                        (FakeDirEntry(fake_regular),) * entry_count
                    )
                    entry_checks = [0]

                    def validated(memory_root, value):
                        if value == "_records/regular.md":
                            entry_checks[0] += 1
                            return fake_regular, value
                        return original_validated(memory_root, value)

                    def plain(memory_root, target, *args, **kwargs):
                        if os.path.normcase(
                            os.path.abspath(os.fspath(target))
                        ) == os.path.normcase(os.path.abspath(os.fspath(fake_regular))):
                            return fake_regular, regular_metadata
                        return original_plain(memory_root, target, *args, **kwargs)

                    with mock.patch(
                        "obsidian_agent_memory.adapters.os.scandir",
                        return_value=counting,
                    ), mock.patch(
                        "obsidian_agent_memory.adapters._validated_relative_path",
                        side_effect=validated,
                    ), mock.patch(
                        "obsidian_agent_memory.adapters._plain_contained_metadata",
                        side_effect=plain,
                    ), mock.patch.object(
                        adapter, "read", return_value="needle"
                    ) as read:
                        if entry_count == 10000:
                            self.assertEqual(
                                ("_records/regular.md",), operation()
                            )
                        else:
                            with self.assertRaises(ValidationError) as raised:
                                operation()
                            self.assertEqual(
                                "filesystem inspection limit exceeded",
                                str(raised.exception),
                            )

                    self.assertEqual(10000, entry_checks[0])
                    self.assertEqual(10001, counting.next_calls)
                    self.assertEqual(entry_count, counting.successful_inspections)
                    self.assertEqual(0, read.call_count)
                    self.assertTrue(counting.closed)

    def test_regular_allowed_root_is_the_shared_inspection_10001_and_reads_nothing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            index = root / "_index"
            index.mkdir(parents=True)
            records = root / "_records"
            records.write_text("needle\n", encoding="utf-8")
            fake_special = index / "special"
            special_metadata = MetadataOverride(
                index.lstat(), st_mode=stat.S_IFIFO | 0o600
            )
            adapter = filesystem_adapter(root)
            original_validated = adapters_module._validated_relative_path
            original_plain = adapters_module._plain_contained_metadata
            counting = CountingScandir((FakeDirEntry(fake_special),) * 10000)
            entry_checks = [0]

            def validated(memory_root, value):
                if value == "_index/special":
                    entry_checks[0] += 1
                    return fake_special, value
                return original_validated(memory_root, value)

            def plain(memory_root, target, *args, **kwargs):
                target_absolute = os.path.normcase(
                    os.path.abspath(os.fspath(target))
                )
                fake_absolute = os.path.normcase(
                    os.path.abspath(os.fspath(fake_special))
                )
                if target_absolute == fake_absolute:
                    return fake_special, special_metadata
                return original_plain(memory_root, target, *args, **kwargs)

            with mock.patch(
                "obsidian_agent_memory.adapters.os.scandir",
                return_value=counting,
            ), mock.patch(
                "obsidian_agent_memory.adapters._validated_relative_path",
                side_effect=validated,
            ), mock.patch(
                "obsidian_agent_memory.adapters._plain_contained_metadata",
                side_effect=plain,
            ), mock.patch.object(adapter, "read", wraps=adapter.read) as read:
                with self.assertRaises(ValidationError) as raised:
                    adapter.search("needle", limit=1)

            self.assertEqual(
                "filesystem inspection limit exceeded", str(raised.exception)
            )
            self.assertEqual(10000, counting.successful_inspections)
            self.assertEqual(10001, counting.next_calls)
            self.assertEqual(10000, entry_checks[0])
            self.assertEqual(0, read.call_count)
            self.assertTrue(counting.closed)

    def test_special_entries_do_not_consume_result_limit_and_reparse_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            records = root / "_records"
            records.mkdir(parents=True)
            for number in range(5):
                (records / "item-{0}.md".format(number)).write_bytes(b"content")
            with os.scandir(str(records)) as iterator:
                entries = tuple(iterator)
            target = Path(entries[0].path)
            adapter = filesystem_adapter(root)

            special_scan = CountingScandir(entries)
            special_mode = stat.S_IFIFO | 0o600
            expected = tuple(
                sorted(
                    Path(entry.path).relative_to(root).as_posix()
                    for entry in entries
                    if Path(entry.path) != target
                )
            )[:1]
            with mock.patch(
                "obsidian_agent_memory.adapters.os.scandir",
                return_value=special_scan,
            ), simulated_metadata(target, st_mode=special_mode):
                self.assertEqual(expected, adapter.files("_records", limit=1))
            self.assertEqual(len(entries) + 1, special_scan.next_calls)

            reparse_scan = CountingScandir(entries)
            with mock.patch(
                "obsidian_agent_memory.adapters.os.scandir",
                return_value=reparse_scan,
            ), simulated_reparse(target):
                with self.assertRaises(ValidationError):
                    adapter.files("_records", limit=1)
            self.assertEqual(1, reparse_scan.next_calls)

    def test_simulated_self_loop_is_rejected_before_resolution(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            loop = root / "_records/self-loop.md"
            loop.parent.mkdir(parents=True)
            loop.write_bytes(b"content")
            adapter = filesystem_adapter(root)

            with simulated_reparse(loop), forbid_resolution_at_or_below(loop):
                with self.assertRaises(ValidationError):
                    adapter.read("_records/self-loop.md")

    def test_simulated_allowed_root_and_nested_junctions_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            records = root / "_records"
            junction = records / "nested"
            junction.mkdir(parents=True)
            record = junction / "record.md"
            record.write_bytes(b"content")
            adapter = filesystem_adapter(root)
            cases = (
                (records, lambda: adapter.files("_records", limit=5)),
                (junction, lambda: adapter.read("_records/nested/record.md")),
            )

            for target, operation in cases:
                with self.subTest(target=target.relative_to(root).as_posix()):
                    with simulated_reparse(target), forbid_resolution_at_or_below(
                        target
                    ):
                        with self.assertRaises(ValidationError):
                            operation()

    def test_rejects_an_in_root_file_alias_when_symlinks_are_available(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            records = root / "_records"
            records.mkdir(parents=True)
            real = records / "real.md"
            real.write_bytes(b"content")
            alias = records / "alias.md"
            try:
                alias.symlink_to(real)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            adapter = filesystem_adapter(root)

            with self.assertRaises(ValidationError):
                adapter.read("_records/alias.md")

    def test_rejects_an_allowed_root_alias_when_directory_symlinks_are_available(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            allowed_root = Path(temporary_directory) / "memory"
            actual_records = allowed_root / "actual-records"
            actual_records.mkdir(parents=True)
            (actual_records / "record.md").write_bytes(b"content")
            try:
                (allowed_root / "_records").symlink_to(
                    actual_records, target_is_directory=True
                )
            except OSError as error:
                self.skipTest("directory symlinks unavailable: {0}".format(error))

            with self.assertRaises(ValidationError):
                filesystem_adapter(allowed_root).read("_records/record.md")

    def test_rejects_a_nested_directory_alias_when_symlinks_are_available(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            records = root / "_records"
            actual_nested = records / "actual-nested"
            records.mkdir(parents=True)
            actual_nested.mkdir()
            (actual_nested / "record.md").write_bytes(b"content")
            try:
                (records / "nested").symlink_to(
                    actual_nested, target_is_directory=True
                )
            except OSError as error:
                self.skipTest("directory symlinks unavailable: {0}".format(error))

            with self.assertRaises(ValidationError):
                filesystem_adapter(root).read("_records/nested/record.md")

    def test_rejects_file_identity_change_between_lstat_and_open_handle(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            record = root / "_records/record.md"
            record.parent.mkdir(parents=True)
            record.write_bytes(b"content")
            adapter = filesystem_adapter(root)
            original_fstat = os.fstat

            def mismatched_identity(descriptor):
                metadata = original_fstat(descriptor)
                return MetadataOverride(metadata, st_ino=metadata.st_ino + 1)

            with mock.patch(
                "obsidian_agent_memory.adapters.os.fstat",
                side_effect=mismatched_identity,
            ):
                with self.assertRaises(ValidationError):
                    adapter.read("_records/record.md")

    def test_resolver_os_and_loop_failures_are_normalized(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            (root / "_records").mkdir(parents=True)
            adapter = filesystem_adapter(root)

            for failure in (OSError("resolver unavailable"), RuntimeError("loop")):
                with self.subTest(failure=type(failure).__name__):
                    with mock.patch(
                        "obsidian_agent_memory.adapters.resolve_inside",
                        side_effect=failure,
                    ):
                        with self.assertRaises(ValidationError):
                            adapter.files("_records", limit=1)

    def test_lstat_value_and_runtime_failures_are_content_safe_validation_errors(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            (root / "_records").mkdir(parents=True)
            adapter = filesystem_adapter(root)

            for failure in (
                RuntimeError("sensitive-runtime-detail"),
                ValueError("sensitive-value-detail"),
            ):
                with self.subTest(failure=type(failure).__name__):
                    with mock.patch.object(
                        Path,
                        "lstat",
                        side_effect=failure,
                    ):
                        with self.assertRaises(ValidationError) as raised:
                            adapter.files("_records", limit=1)

                    self.assertNotIn("sensitive", str(raised.exception))


class CliAdapterOperationTests(unittest.TestCase):
    def test_saturated_cli_search_cannot_report_legacy_filtered_results_as_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "projects/demo"
            project.mkdir(parents=True)
            (project / "Ghostly Shader.md").write_text("needle", encoding="utf-8")
            (project / "overview.md").write_text("needle", encoding="utf-8")
            runner = FakeRunner(completed(stdout="read\nsearch\nfiles\n"), completed(),
                                completed(stdout="No matches found.\n"), completed(stdout="No matches found.\n"),
                                completed(stdout="projects/demo/Ghostly Shader.md\n"))
            adapter = select_read_adapter(RootBinding(root, None, "AgentMemory"), runner, Path("obsidian")).adapter
            with self.assertRaisesRegex(ValidationError, "incomplete"):
                adapter.search("needle", limit=1)

    def test_cli_project_discovery_skips_noncanonical_legacy_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            examples = root / "projects/demo/examples"
            examples.mkdir(parents=True)
            (examples / "Ghostly Shader.md").write_text("legacy reference", encoding="utf-8")
            (root / "projects/demo/overview.md").write_text("current view", encoding="utf-8")
            runner = FakeRunner(completed(stdout="read\nsearch\nfiles\n"), completed(),
                                completed(stdout="projects/demo/examples/Ghostly Shader.md\nprojects/demo/overview.md\n"))
            adapter = select_read_adapter(RootBinding(root, None, "AgentMemory"), runner, Path("obsidian")).adapter
            self.assertEqual(("projects/demo/overview.md",), adapter.files("projects"))

    def test_empty_cli_search_is_not_parsed_as_a_file_path(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "_index").mkdir()
            runner = FakeRunner(completed(stdout="read\nsearch\nfiles\n"), completed(),
                                *[completed(stdout="No matches found.\n") for _ in range(3)])
            adapter = select_read_adapter(RootBinding(Path(directory), None, "AgentMemory"), runner, Path("obsidian")).adapter
            self.assertEqual((), adapter.search("absent"))
            self.assertEqual({"path=_index", "path=_records", "path=projects"},
                             {arg for command, _ in runner.calls[2:] for arg in command if arg.startswith("path=")})

    def test_operations_target_vault_and_use_supported_folder_and_search_limits(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = FakeRunner(
                completed(stdout="read\nsearch\nfiles\n"),
                completed(),
                completed(stdout="record text\n"),
                completed(stdout="No matches found.\n"),
                completed(stdout="_records/a.md\tmatching excerpt\n"),
                completed(stdout="No matches found.\n"),
                completed(stdout="_records/a.md\n"),
            )
            selection = select_read_adapter(
                RootBinding(Path(temporary_directory) / "memory", "demo", "named-vault"),
                runner,
                Path("obsidian"),
            )

            self.assertEqual("record text\n", selection.adapter.read("_records/a.md"))
            self.assertEqual(
                (SearchHit("_records/a.md", "matching excerpt"),),
                selection.adapter.search("matching", limit=3),
            )
            self.assertEqual(
                ("_records/a.md",), selection.adapter.files("_records", limit=4)
            )
            self.assertEqual(
                [
                    (
                        (
                            "obsidian",
                            "vault=named-vault",
                            "read",
                            "path=_records/a.md",
                            "limit=1",
                        ),
                        2.0,
                    ),
                    (
                        ("obsidian", "vault=named-vault", "search", "query=matching", "path=_index", "limit=3"),
                        2.0,
                    ),
                    (
                        (
                            "obsidian",
                            "vault=named-vault",
                            "search",
                            "query=matching",
                            "path=_records",
                            "limit=3",
                        ),
                        2.0,
                    ),
                    (
                        ("obsidian", "vault=named-vault", "search", "query=matching", "path=projects", "limit=3"),
                        2.0,
                    ),
                    (
                        (
                            "obsidian",
                            "vault=named-vault",
                            "files",
                            "folder=_records",
                            "ext=md",
                        ),
                        2.0,
                    ),
                ],
                runner.calls[2:],
            )

    def test_operation_failures_are_content_safe_validation_errors(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner = FakeRunner(
            completed(stdout="read\nsearch\nfiles\n"),
                completed(),
                completed(returncode=7, stderr="secret workstation output"),
            )
            adapter = select_read_adapter(
                RootBinding(
                    Path(temporary_directory) / "memory", "demo", "named-vault"
                ),
                runner,
                Path("obsidian"),
            ).adapter

            with self.assertRaises(ValidationError) as raised:
                adapter.read("_records/a.md")

            self.assertNotIn("secret workstation output", str(raised.exception))


class CatalogLoadTests(unittest.TestCase):
    def test_reads_only_the_canonical_catalog_and_sorts_entries_by_memory_id(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            first = candidate(memory_id="memory-a")
            second = candidate(memory_id="memory-b")
            catalog_path = write_catalog(
                root,
                {
                    "memory-b": catalog_row(second),
                    "memory-a": catalog_row(first),
                },
                revision=7,
            )
            orphan = root / "_records/poison.md"
            orphan.parent.mkdir(parents=True)
            orphan.write_bytes(b"\xff")
            opened = []
            original_open = os.open

            def tracking_open(path, flags, *args, **kwargs):
                opened.append(Path(path).resolve())
                return original_open(path, flags, *args, **kwargs)

            with mock.patch(
                "obsidian_agent_memory.adapters.os.open", side_effect=tracking_open
            ):
                snapshot = load_catalog(root)

            self.assertEqual(7, snapshot.revision)
            self.assertEqual(
                (
                    CatalogEntry(
                        "memory-a",
                        1,
                        "_records/projects/demo/decisions/memory-a--r0001.md",
                        "decision",
                        "project.demo.decision",
                        "demo",
                    ),
                    CatalogEntry(
                        "memory-b",
                        1,
                        "_records/projects/demo/decisions/memory-b--r0001.md",
                        "decision",
                        "project.demo.decision",
                        "demo",
                    ),
                ),
                snapshot.entries,
            )
            self.assertEqual([catalog_path.resolve()], opened)

    def test_rejects_malformed_duplicate_and_oversized_catalog_documents(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            catalog_path = write_catalog(root, {})
            row = catalog_row(candidate(memory_id="memory-a"))
            valid = json.dumps(
                {
                    "schema_version": 2,
                    "revision": 1,
                    "records": {"memory-a": row},
                }
            )
            duplicate_nested = valid.replace(
                '"revision": 1, "relative_path"',
                '"revision": 1, "revision": 1, "relative_path"',
                1,
            )
            invalid_documents = (
                b"",
                b"{not-json}",
                b'{"schema_version":2,"schema_version":2,"revision":0,"records":{}}',
                duplicate_nested.encode("utf-8"),
                b"\xff",
                b"x" * (1024 * 1024 + 1),
            )

            for document in invalid_documents:
                with self.subTest(size=len(document), prefix=document[:20]):
                    catalog_path.write_bytes(document)
                    with self.assertRaises(ValidationError):
                        load_catalog(root)

    def test_rejects_invalid_catalog_top_level_shapes_and_entry_counts(self):
        invalid_catalogs = (
            {"schema_version": 1, "revision": 0, "records": {}},
            {"schema_version": 2.0, "revision": 0, "records": {}},
            {"schema_version": 2, "revision": True, "records": {}},
            {"schema_version": 2, "revision": -1, "records": {}},
            {"schema_version": 2, "revision": 0, "records": []},
            {"schema_version": 2, "revision": 0, "records": {}, "unknown": 1},
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            catalog_path = write_catalog(root, {})

            for document in invalid_catalogs:
                with self.subTest(document=document):
                    catalog_path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(ValidationError):
                        load_catalog(root)

            too_many = {"memory-{0:05d}".format(index): {} for index in range(10001)}
            catalog_path.write_text(
                json.dumps(
                    {"schema_version": 2, "revision": 0, "records": too_many},
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValidationError, "10000"):
                load_catalog(root)

    def test_rejects_invalid_entry_shapes_identities_and_selected_paths(self):
        base_candidate = candidate(memory_id="memory-a")
        base = catalog_row(base_candidate)
        invalid_rows = (
            {},
            dict(base, unknown="value"),
            dict(base, memory_id="memory-b"),
            dict(base, revision=True),
            dict(base, revision=0),
            dict(base, record_type="unknown"),
            dict(base, owner_scope="project.demo.story"),
            dict(base, project=None),
            dict(base, relative_path="../outside.md"),
            dict(base, relative_path="_index/generated.md"),
            dict(base, relative_path="_records/../../outside.md"),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"

            for row in invalid_rows:
                with self.subTest(row=row):
                    write_catalog(root, {"memory-a": row})
                    with self.assertRaises(ValidationError):
                        load_catalog(root)

    def test_rejects_a_nul_selected_path_before_filesystem_inspection(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            row = catalog_row(candidate(memory_id="memory-a"))
            invalid_path = "_records/bad\x00.md"
            row["relative_path"] = invalid_path
            write_catalog(root, {"memory-a": row})

            with mock.patch(
                "obsidian_agent_memory.catalog._plain_contained_metadata",
                side_effect=AssertionError(
                    "invalid catalog path reached filesystem inspection"
                ),
            ):
                with self.assertRaises(ValidationError) as raised:
                    load_catalog(root)

            self.assertNotIn(invalid_path, str(raised.exception))

    def test_rejects_a_simulated_catalog_reparse_point(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            catalog_path = write_catalog(root, {})

            with simulated_reparse(catalog_path), forbid_resolution_at_or_below(
                catalog_path
            ):
                with self.assertRaises(ValidationError):
                    load_catalog(root)

    def test_rejects_an_in_root_catalog_alias_when_symlinks_are_available(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            catalog_path = write_catalog(root, {})
            real_catalog = catalog_path.with_name("catalog-real.json")
            catalog_path.replace(real_catalog)
            try:
                catalog_path.symlink_to(real_catalog)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))

            with self.assertRaises(ValidationError):
                load_catalog(root)


class AcceptedRecordReadTests(unittest.TestCase):
    def test_returns_only_the_catalog_selected_record_with_catalog_revision(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            accepted = candidate(memory_id="memory-a", body="accepted body")
            outcome = commit_record(root, accepted, 0, None, context("tx-memory-a"))

            result = read_accepted_record(root, "memory-a")

            self.assertEqual(accepted.envelope, result.envelope)
            self.assertEqual("accepted body\n", result.body)
            self.assertEqual(outcome.record_path.relative_to(root).as_posix(), result.relative_path)
            self.assertEqual(1, result.catalog_revision)

    def test_does_not_substitute_an_orphan_or_prior_revision_for_a_corrupt_selection(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            first = candidate(memory_id="memory-a", body="revision one")
            first_outcome = commit_record(root, first, 0, None, context("tx-memory-a-r1"))
            second = candidate(
                memory_id="memory-a",
                revision=2,
                supersedes="memory-a@1",
                body="revision two",
            )
            second_outcome = commit_record(root, second, 1, 1, context("tx-memory-a-r2"))
            orphan = candidate(
                memory_id="memory-a",
                revision=3,
                supersedes="memory-a@2",
                body="orphan replacement",
            )
            orphan_path = root / record_relative_path(orphan.envelope)
            orphan_path.parent.mkdir(parents=True, exist_ok=True)
            orphan_path.write_text(
                render_record(orphan.envelope, orphan.body), encoding="utf-8"
            )
            second_outcome.record_path.write_bytes(b"corrupt selected bytes")

            with self.assertRaises(ValidationError):
                read_accepted_record(root, "memory-a")

            self.assertTrue(first_outcome.record_path.exists())
            self.assertTrue(orphan_path.exists())

    def test_rejects_missing_ids_invalid_ids_and_oversized_selected_records(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            large_body = "x" * (1024 * 1024)
            large = candidate(memory_id="memory-large", body=large_body)
            relative = record_relative_path(large.envelope)
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(render_record(large.envelope, large.body), encoding="utf-8")
            write_catalog(root, {"memory-large": catalog_row(large)})

            for memory_id in ("missing", "../escape", "INVALID"):
                with self.subTest(memory_id=memory_id):
                    with self.assertRaises(ValidationError):
                        read_accepted_record(root, memory_id)
            with self.assertRaises(ValidationError):
                read_accepted_record(root, "memory-large")

    def test_requires_catalog_and_envelope_identity_to_match(self):
        mutations = (
            {"revision": 2},
            {"record_type": "story"},
            {"owner_scope": "project.demo.story"},
            {"project": "other"},
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            selected = candidate(memory_id="memory-a")
            path = root / record_relative_path(selected.envelope)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(render_record(selected.envelope, selected.body), encoding="utf-8")

            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    write_catalog(root, {"memory-a": dict(catalog_row(selected), **mutation)})
                    with self.assertRaises(ValidationError):
                        read_accepted_record(root, "memory-a")

    def test_rejects_a_simulated_selected_record_reparse_point(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            selected = candidate(memory_id="memory-a")
            path = root / record_relative_path(selected.envelope)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(render_record(selected.envelope, selected.body), encoding="utf-8")
            write_catalog(root, {"memory-a": catalog_row(selected)})

            with simulated_reparse(path), forbid_resolution_at_or_below(path):
                with self.assertRaises(ValidationError):
                    read_accepted_record(root, "memory-a")

    def test_rejects_an_in_root_selected_record_alias_when_symlinks_are_available(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            selected = candidate(memory_id="memory-a")
            selected_path = root / record_relative_path(selected.envelope)
            selected_path.parent.mkdir(parents=True, exist_ok=True)
            duplicate = selected_path.with_name("duplicate.md")
            duplicate.write_text(
                render_record(selected.envelope, selected.body), encoding="utf-8"
            )
            try:
                selected_path.symlink_to(duplicate)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            write_catalog(root, {"memory-a": catalog_row(selected)})

            with self.assertRaises(ValidationError):
                read_accepted_record(root, "memory-a")


class AcceptedRecordSearchTests(unittest.TestCase):
    def test_accepted_limit_cannot_be_starved_by_raw_or_nonmatching_files(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            first = candidate(memory_id="memory-a", body="needle in superseded revision")
            first_outcome = commit_record(root, first, 0, None, context("tx-a-r1"))
            current = candidate(
                memory_id="memory-a",
                revision=2,
                supersedes="memory-a@1",
                body="current body without the query",
            )
            current_outcome = commit_record(root, current, 1, 1, context("tx-a-r2"))
            later = candidate(memory_id="memory-z", body="later NEEDLE accepted")
            later_outcome = commit_record(root, later, 2, None, context("tx-z-r1"))

            orphan_candidates = [
                candidate(memory_id="orphan-{0}".format(index), body="needle orphan")
                for index in range(3)
            ]
            losing = candidate(
                memory_id="memory-z",
                revision=2,
                supersedes="memory-z@1",
                body="needle losing revision",
            )
            for record_candidate in tuple(orphan_candidates) + (losing,):
                path = root / record_relative_path(record_candidate.envelope)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    render_record(record_candidate.envelope, record_candidate.body),
                    encoding="utf-8",
                )
            generated = root / "_index/current-focus.md"
            generated.parent.mkdir(parents=True, exist_ok=True)
            generated.write_text("needle generated projection", encoding="utf-8")

            adapter = CatalogOnlyAdapter(
                {
                    current_outcome.record_path.relative_to(root).as_posix(): current_outcome.record_path.read_text(
                        encoding="utf-8"
                    ),
                    later_outcome.record_path.relative_to(root).as_posix(): later_outcome.record_path.read_text(
                        encoding="utf-8"
                    ),
                }
            )

            with mock.patch(
                "obsidian_agent_memory.catalog.load_catalog", wraps=load_catalog
            ) as catalog_loader:
                results = search_accepted_records(root, adapter, "  needle ", limit=1)

            self.assertEqual(("memory-z",), tuple(result.envelope.memory_id for result in results))
            self.assertEqual("later NEEDLE accepted\n", results[0].body)
            self.assertEqual(
                [
                    current_outcome.record_path.relative_to(root).as_posix(),
                    later_outcome.record_path.relative_to(root).as_posix(),
                ],
                adapter.read_calls,
            )
            catalog_loader.assert_called_once_with(root)
            self.assertTrue(first_outcome.record_path.exists())
            self.assertTrue(generated.exists())

    def test_stops_after_the_requested_number_of_accepted_matches(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            first = candidate(memory_id="memory-a", body="needle first")
            first_outcome = commit_record(root, first, 0, None, context("tx-a"))
            second = candidate(memory_id="memory-b", body="needle second")
            second_outcome = commit_record(root, second, 1, None, context("tx-b"))
            first_relative = first_outcome.record_path.relative_to(root).as_posix()
            second_relative = second_outcome.record_path.relative_to(root).as_posix()
            adapter = CatalogOnlyAdapter(
                {
                    first_relative: first_outcome.record_path.read_text(encoding="utf-8"),
                    second_relative: "corrupt unread successor",
                }
            )

            results = search_accepted_records(root, adapter, "needle", limit=1)

            self.assertEqual(("memory-a",), tuple(result.envelope.memory_id for result in results))
            self.assertEqual([first_relative], adapter.read_calls)

    def test_rejects_a_corrupt_selected_record_instead_of_skipping_it(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            first = candidate(memory_id="memory-a", body="no query")
            first_outcome = commit_record(root, first, 0, None, context("tx-a"))
            later = candidate(memory_id="memory-z", body="needle later")
            later_outcome = commit_record(root, later, 1, None, context("tx-z"))
            first_relative = first_outcome.record_path.relative_to(root).as_posix()
            later_relative = later_outcome.record_path.relative_to(root).as_posix()
            adapter = CatalogOnlyAdapter(
                {
                    first_relative: "corrupt selected record",
                    later_relative: later_outcome.record_path.read_text(encoding="utf-8"),
                }
            )

            with self.assertRaises(ValidationError):
                search_accepted_records(root, adapter, "needle", limit=1)

            self.assertEqual([first_relative], adapter.read_calls)

    def test_validates_query_and_limit_before_loading_any_catalog(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            adapter = CatalogOnlyAdapter({})
            invalid_calls = (
                ("", 1),
                (" \t ", 1),
                ("needle", 0),
                ("needle", -1),
                ("needle", True),
            )

            for query, limit in invalid_calls:
                with self.subTest(query=query, limit=limit):
                    with self.assertRaises(ValidationError):
                        search_accepted_records(
                            Path(temporary_directory) / "memory",
                            adapter,
                            query,
                            limit=limit,
                        )

            self.assertEqual([], adapter.read_calls)


class PublicAdapterApiTests(unittest.TestCase):
    def test_reexports_only_the_four_locked_task_six_calls(self):
        locked_calls = {
            "select_read_adapter": select_read_adapter,
            "load_catalog": load_catalog,
            "read_accepted_record": read_accepted_record,
            "search_accepted_records": search_accepted_records,
        }

        for name, implementation in locked_calls.items():
            with self.subTest(name=name):
                self.assertIs(implementation, getattr(public_api, name))
                self.assertIn(name, public_api.__all__)


if __name__ == "__main__":
    unittest.main()
