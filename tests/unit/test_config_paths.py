import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory import (  # noqa: E402
    ConfigurationError,
    ContainmentError,
    RootBinding,
    ValidationError,
    load_local_config,
    resolve_binding,
    resolve_inside,
    select_local_config_path,
    validate_identifier,
)


class PathValidationTests(unittest.TestCase):
    def test_identifier_returns_unchanged_portable_value(self):
        self.assertEqual("demo.project_1-2", validate_identifier("demo.project_1-2", "project_id"))

    def test_identifier_rejects_nonportable_values(self):
        invalid_values = (
            "",
            "..",
            "a/b",
            "a\\b",
            "C:drive",
            "line\nbreak",
            ".hidden",
            "terminal.",
            "CON",
            "prn.txt",
            "aux.data",
            "nul",
            "com1.log",
            "com9",
            "lpt1.txt",
            "lpt9",
            "Uppercase",
            "space value",
            "a" * 129,
        )

        for value in invalid_values:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValidationError):
                    validate_identifier(value, "project_id")

    def test_resolve_inside_rejects_escape_absolute_and_invalid_components(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "root"
            root.mkdir()

            for component in ("..", str(Path(temporary_directory).resolve()), "not/valid"):
                with self.subTest(component=component):
                    with self.assertRaises(ContainmentError):
                        resolve_inside(root, component)

    def test_resolve_inside_rejects_symlink_that_resolves_outside_root(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            link = root / "linked"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest("symlinks are unavailable: {0}".format(error))

            with self.assertRaises(ContainmentError):
                resolve_inside(root, "linked", "record")

    def test_resolve_inside_returns_resolved_contained_path(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "root"
            root.mkdir()

            self.assertEqual((root / "records" / "demo").resolve(), resolve_inside(root, "records", "demo"))


class ConfigurationTests(unittest.TestCase):
    def _write_config(self, directory, bindings):
        path = Path(directory) / "config.json"
        path.write_text(
            json.dumps({"schema_version": 1, "bindings": bindings}),
            encoding="utf-8",
        )
        return path

    def _binding(self, workspace, memory_root, project_id="demo", obsidian_vault="portable-demo"):
        return {
            "workspace": str(workspace),
            "memory_root": str(memory_root),
            "project_id": project_id,
            "obsidian_vault": obsidian_vault,
        }

    def test_load_local_config_rejects_invalid_shapes_and_credentials(self):
        cases = (
            '{"schema_version": 1, "schema_version": 1, "bindings": []}',
            '{"schema_version": 1, "bindings": [], "unknown": true}',
            '{"schema_version": 2, "bindings": []}',
            '{"schema_version": 1, "bindings": [{"workspace": "relative", "memory_root": "/tmp/memory", "project_id": "demo"}]}',
            '{"schema_version": 1, "bindings": [{"workspace": "/tmp/work", "memory_root": "/tmp/memory", "project_id": "demo", "api_token": "secret"}]}',
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            for index, content in enumerate(cases):
                path = Path(temporary_directory) / "invalid-{0}.json".format(index)
                path.write_text(content, encoding="utf-8")
                with self.subTest(content=content):
                    with self.assertRaises(ConfigurationError):
                        load_local_config(path)

    def test_load_local_config_rejects_duplicate_bindings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            workspace = base / "workspace"
            memory_root = base / "memory"
            config_path = self._write_config(
                base,
                [self._binding(workspace, memory_root), self._binding(workspace, memory_root)],
            )

            with self.assertRaises(ConfigurationError):
                load_local_config(config_path)

    def test_explicit_root_wins_over_environment_and_config(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            explicit_root = base / "explicit-memory"
            environment_root = base / "environment-memory"
            config_root = base / "config-memory"
            workspace = base / "workspace"
            cwd = workspace / "nested"
            cwd.mkdir(parents=True)
            config_path = self._write_config(base, [self._binding(workspace, config_root)])

            binding = resolve_binding(
                explicit_root,
                "chosen-project",
                {"OBSIDIAN_AGENT_MEMORY_ROOT": str(environment_root)},
                config_path,
                cwd,
            )

            self.assertEqual(RootBinding(explicit_root.resolve(), "chosen-project", None), binding)

    def test_environment_root_wins_over_config(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            environment_root = base / "environment-memory"
            config_root = base / "config-memory"
            workspace = base / "workspace"
            cwd = workspace / "nested"
            cwd.mkdir(parents=True)
            config_path = self._write_config(base, [self._binding(workspace, config_root)])

            binding = resolve_binding(
                None,
                "chosen-project",
                {"OBSIDIAN_AGENT_MEMORY_ROOT": str(environment_root)},
                config_path,
                cwd,
            )

            self.assertEqual(RootBinding(environment_root.resolve(), "chosen-project", None), binding)

    def test_config_selects_longest_workspace_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            outer_workspace = base / "workspace"
            inner_workspace = outer_workspace / "component"
            cwd = inner_workspace / "src"
            cwd.mkdir(parents=True)
            outer_memory = base / "outer-memory"
            inner_memory = base / "inner-memory"
            config_path = self._write_config(
                base,
                [
                    self._binding(outer_workspace, outer_memory, "outer", "outer-vault"),
                    self._binding(inner_workspace, inner_memory, "inner", "inner-vault"),
                ],
            )

            binding = resolve_binding(None, None, {}, config_path, cwd)

            self.assertEqual(RootBinding(inner_memory.resolve(), "inner", "inner-vault"), binding)

    def test_explicit_project_only_changes_project_selection(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            workspace = base / "workspace"
            cwd = workspace / "nested"
            cwd.mkdir(parents=True)
            memory_root = base / "memory"
            config_path = self._write_config(base, [self._binding(workspace, memory_root, "config-project")])

            binding = resolve_binding(None, "explicit-project", {}, config_path, cwd)

            self.assertEqual(
                RootBinding(memory_root.resolve(), "explicit-project", "portable-demo"), binding
            )

    def test_basename_project_hint_requires_exactly_one_binding(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            cwd = base / "demo"
            cwd.mkdir()
            memory_root = base / "memory"
            config_path = self._write_config(
                base,
                [self._binding(base / "unrelated-workspace", memory_root, "demo")],
            )

            self.assertEqual(
                RootBinding(memory_root.resolve(), "demo", "portable-demo"),
                resolve_binding(None, None, {}, config_path, cwd),
            )

            ambiguous_config = self._write_config(
                base,
                [
                    self._binding(base / "first-workspace", memory_root, "demo"),
                    self._binding(base / "second-workspace", base / "other-memory", "demo"),
                ],
            )
            with self.assertRaises(ConfigurationError):
                resolve_binding(None, None, {}, ambiguous_config, cwd)

    def test_missing_or_ambiguous_binding_raises_without_home_discovery(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            cwd = base / "cwd"
            cwd.mkdir()

            with self.assertRaises(ConfigurationError):
                resolve_binding(None, None, {}, None, cwd)

            config_path = self._write_config(
                base,
                [
                    self._binding(base / "one", base / "memory-one", "one"),
                    self._binding(base / "two", base / "memory-two", "two"),
                ],
            )
            with self.assertRaises(ConfigurationError):
                resolve_binding(None, None, {}, config_path, cwd)

    def test_select_local_config_path_uses_only_supplied_platform_and_environment(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            explicit = (base / "explicit.json").resolve()
            appdata = (base / "appdata").resolve()
            home = (base / "home").resolve()
            xdg = (base / "xdg").resolve()

            self.assertEqual(explicit, select_local_config_path(explicit, "linux", {}))
            self.assertEqual(
                appdata / "obsidian-agent-memory" / "config.json",
                select_local_config_path(None, "win32", {"APPDATA": str(appdata), "HOME": str(home)}),
            )
            self.assertEqual(
                home / "Library" / "Application Support" / "obsidian-agent-memory" / "config.json",
                select_local_config_path(None, "darwin", {"HOME": str(home), "APPDATA": str(appdata)}),
            )
            self.assertEqual(
                xdg / "obsidian-agent-memory" / "config.json",
                select_local_config_path(None, "linux", {"XDG_CONFIG_HOME": str(xdg), "HOME": str(home)}),
            )
            self.assertEqual(
                home / ".config" / "obsidian-agent-memory" / "config.json",
                select_local_config_path(None, "linux", {"HOME": str(home)}),
            )
            self.assertIsNone(select_local_config_path(None, "win32", {"APPDATA": "relative"}))
            self.assertIsNone(select_local_config_path(None, "darwin", {"HOME": "relative"}))
            self.assertIsNone(select_local_config_path(None, "linux", {"XDG_CONFIG_HOME": "relative", "HOME": "relative"}))
            with self.assertRaises(ConfigurationError):
                select_local_config_path(Path("relative.json"), "linux", {})


if __name__ == "__main__":
    unittest.main()
