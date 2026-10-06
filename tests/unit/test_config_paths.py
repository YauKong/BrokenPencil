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
    select_read_adapter,
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

    def test_known_root_still_resolves_same_root_workspace_project(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            workspace = base / "workspace"
            config = self._write_config(base, [self._binding(workspace, root)])
            for source in ("explicit", "environment"):
                with self.subTest(source=source):
                    binding = resolve_binding(
                        root if source == "explicit" else None, None,
                        {"OBSIDIAN_AGENT_MEMORY_ROOT": str(root)}, config,
                        workspace / "src",
                    )
                    self.assertEqual(RootBinding(root.resolve(), "demo", "portable-demo"), binding)

    def test_known_root_filters_other_roots_before_longest_workspace_match(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            workspace = base / "workspace"
            config = self._write_config(base, [
                self._binding(workspace, root, "outer"),
                self._binding(workspace / "component", root, "inner"),
                self._binding(workspace / "component" / "src", base / "other", "wrong"),
            ])
            binding = resolve_binding(root, None, {}, config, workspace / "component" / "src")
            self.assertEqual("inner", binding.project_id)
            self.assertEqual(root.resolve(), binding.memory_root)

    def test_known_root_uses_unique_same_root_configured_basename_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [
                self._binding(base / "one", root),
                self._binding(base / "two", base / "other"),
            ])
            self.assertEqual("demo", resolve_binding(root, None, {}, config, base / "demo").project_id)

    def test_known_root_rejects_ambiguous_same_root_basename_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [
                self._binding(base / "one", root),
                self._binding(base / "two", root),
            ])
            with self.assertRaisesRegex(ConfigurationError, "ambiguous"):
                resolve_binding(root, None, {}, config, base / "demo")

    def test_known_root_does_not_adopt_another_roots_project_or_vault(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [self._binding(base, base / "other")])
            self.assertEqual(RootBinding(root.resolve(), None, None), resolve_binding(root, None, {}, config, base))

    def test_known_root_without_matching_config_remains_available_for_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [self._binding(base / "unrelated", root)])
            for path in (None, base / "absent.json", config):
                with self.subTest(config=path):
                    self.assertEqual(
                        RootBinding(root.resolve(), None, "portable-demo" if path == config else None),
                        resolve_binding(None, None, {"OBSIDIAN_AGENT_MEMORY_ROOT": str(root)}, path, base / "chat"),
                    )

    def test_known_root_rejects_malformed_selected_config_when_resolving_project(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config = base / "invalid.json"
            config.write_text("{", encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                resolve_binding(base / "memory", None, {}, config, base)

    def test_complete_explicit_binding_rejects_malformed_selected_config(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config = base / "invalid.json"
            config.write_text("{", encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                resolve_binding(base / "memory", "chosen", {}, config, base)

    def test_vault_names_preserve_display_text_instead_of_using_project_id_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for vault in ("AgentMemory", "My Vault", "项目记忆"):
                with self.subTest(vault=vault):
                    config = self._write_config(base, [self._binding(base, base / "memory", obsidian_vault=vault)])
                    self.assertEqual(vault, load_local_config(config)["bindings"][0]["obsidian_vault"])
            for vault in ("", "  ", "a\nb", "a\x00b", "a\x7fb", 12):
                with self.subTest(invalid=vault):
                    config = self._write_config(base, [self._binding(base, base / "memory", obsidian_vault=vault)])
                    with self.assertRaises(ConfigurationError):
                        load_local_config(config)

    def test_explicit_rebinding_retains_unique_same_root_vault(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [
                self._binding(base / "work", root, "demo", "named-vault"),
                self._binding(base / "other", base / "other-root", "elsewhere", "other-vault"),
            ])
            for explicit, env in ((root, {}), (None, {"OBSIDIAN_AGENT_MEMORY_ROOT": str(root)})):
                with self.subTest(explicit=explicit):
                    result = resolve_binding(explicit, "chosen", env, config, base / "new-chat")
                    self.assertEqual(RootBinding(root.resolve(), "chosen", "named-vault"), result)

    def test_root_only_discovery_retains_vault_without_inventing_project(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [self._binding(base / "unrelated", root)])
            result = resolve_binding(root, None, {}, config, base / "new-chat")
            self.assertEqual(RootBinding(root.resolve(), None, "portable-demo"), result)

    def test_root_only_config_can_bind_vault_without_assigning_a_project(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [self._binding(base, root, None, "AgentMemory")])
            self.assertEqual(RootBinding(root.resolve(), None, "AgentMemory"), resolve_binding(None, None, {}, config, base))
            self.assertEqual(RootBinding(root.resolve(), "chosen", "AgentMemory"), resolve_binding(root, "chosen", {}, config, base))

    def test_explicit_rebinding_refuses_conflicting_same_root_vaults(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [
                self._binding(base / "one", root, "one", "first"),
                self._binding(base / "two", root, "two", "second"),
            ])
            with self.assertRaises(ConfigurationError):
                resolve_binding(root, "chosen", {}, config, base)

    def test_inferred_project_inherits_unique_vault_from_root_only_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [
                self._binding(base, root, None, "AgentMemory"),
                self._binding(base / "work", root, "demo", None),
            ])
            for explicit_root in (None, root):
                with self.subTest(root=explicit_root):
                    self.assertEqual(RootBinding(root.resolve(), "demo", "AgentMemory"), resolve_binding(explicit_root, None, {}, config, base / "work"))

    def test_environment_root_and_platform_registry_select_project_in_fresh_context(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            workspace = base / "workspace"
            registry_directory = base / "appdata" / "obsidian-agent-memory"
            registry_directory.mkdir(parents=True)
            self._write_config(registry_directory, [self._binding(workspace, root)])
            env = {"OBSIDIAN_AGENT_MEMORY_ROOT": str(root), "APPDATA": str(base / "appdata")}
            selected_config = select_local_config_path(None, "win32", env)
            self.assertEqual(
                RootBinding(root.resolve(), "demo", "portable-demo"),
                resolve_binding(None, None, env, selected_config, workspace / "src"),
            )

    def test_root_only_adapter_discovery_can_be_rebound_without_writes(self):
        fixture = Path(__file__).resolve().parents[1] / "fixtures" / "vaults" / "v2-clean"
        before = {path.relative_to(fixture): path.read_bytes() for path in fixture.rglob("*") if path.is_file()}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            env = {"OBSIDIAN_AGENT_MEMORY_ROOT": str(fixture)}
            binding = resolve_binding(None, None, env, base / "absent.json", base / "chat")

            def unexpected_cli(arguments, timeout):
                raise AssertionError("a root without a vault must not launch a CLI")

            selection = select_read_adapter(binding, unexpected_cli, executable=base / "optional-cli")
            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-vault-missing", selection.reason)
            paths = selection.adapter.files("projects", limit=200)
            self.assertIn("projects/demo/overview.md", paths)
            self.assertTrue(selection.adapter.read("projects/demo/overview.md"))
            # The caller supplies its reviewed choice, not a runtime default.
            chosen = resolve_binding(binding.memory_root, "demo", {}, None, base / "chat")
            self.assertEqual("demo", chosen.project_id)
            self.assertEqual(fixture.resolve(), chosen.memory_root)
        after = {path.relative_to(fixture): path.read_bytes() for path in fixture.rglob("*") if path.is_file()}
        self.assertEqual(before, after)

    def test_explicit_root_project_resolution_ignores_conflicting_environment_root(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "chosen-memory"
            config = self._write_config(base, [self._binding(base, root, "chosen")])
            binding = resolve_binding(root, None, {"OBSIDIAN_AGENT_MEMORY_ROOT": str(base / "other")}, config, base)
            self.assertEqual(RootBinding(root.resolve(), "chosen", "portable-demo"), binding)

    def test_known_root_matching_normalizes_lexical_path_components(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "memory"
            config = self._write_config(base, [self._binding(base, root / "nested" / "..")])
            binding = resolve_binding(root, None, {}, config, base)
            self.assertEqual("demo", binding.project_id)

    def test_unreadable_selected_config_is_not_treated_as_absent_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with self.assertRaises(ConfigurationError):
                resolve_binding(base / "memory", None, {}, base, base)

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
