import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.fixture_builders import build_v2_clean
from tests.helpers import copy_vault_fixture, fixture_root, tree_hashes


FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "vaults"

EXPECTED = {
    "v1-minimal": (
        "AGENTS.md",
        "projects/demo/sessions/2026-01-01-bootstrap.md",
        "projects/demo/decisions/cache-policy.md",
    ),
    "v1-focus-drift": (
        "_index/current-focus.md",
        "projects/demo/current-focus.md",
    ),
    "v1-duplicate-owners": (
        "projects/demo/sessions/2026-01-01-cache.md",
        "projects/demo/stories/cache.md",
    ),
    "v1-embedded-knowledge": ("knowledge/modeling/retopology.md",),
    "v1-partially-migrated": (
        ".agent-memory/schema.json",
        "projects/demo/current-focus.md",
    ),
    "v1-proposal-review-golden": (
        "projects/demo/sessions/2026-01-01-cache.md",
        "projects/demo/stories/cache.md",
        "preferences/review-style.md",
        "skills/rebuild-index.md",
    ),
    "v2-clean": (
        ".agent-memory/state/catalog.json",
        "_index/home.md",
        "_index/current-focus.md",
        "projects/demo/current-focus.md",
    ),
    "v2-proposal-resolution": ("AGENTS.md",),
    "v2-story-session-coordination": (
        "AGENTS.md",
        "projects/demo/sessions/2026-09-01-legacy.md",
    ),
}

EXPECTED_FILES = {
    "v1-minimal": (
        ".agent-memory-fixture.json",
        "AGENTS.md",
        "_index/home.md",
        "_index/current-focus.md",
        "projects/demo/overview.md",
        "projects/demo/current-focus.md",
        "projects/demo/sessions/2026-01-01-bootstrap.md",
        "projects/demo/stories/cache-failure.md",
        "projects/demo/decisions/cache-policy.md",
        "projects/demo/raw/source.txt",
        "preferences/review-style.md",
        "skills/rebuild-index.md",
    ),
    "v1-focus-drift": (
        ".agent-memory-fixture.json",
        "AGENTS.md",
        "_index/current-focus.md",
        "projects/demo/current-focus.md",
        "projects/demo/stories/current-work.md",
    ),
    "v1-duplicate-owners": (
        ".agent-memory-fixture.json",
        "AGENTS.md",
        "projects/demo/sessions/2026-01-01-cache.md",
        "projects/demo/stories/cache.md",
        "preferences/cache.md",
    ),
    "v1-embedded-knowledge": (
        ".agent-memory-fixture.json",
        "AGENTS.md",
        "knowledge/modeling/retopology.md",
        "projects/demo/sessions/2026-01-01-source.md",
    ),
    "v1-partially-migrated": (
        ".agent-memory-fixture.json",
        "AGENTS.md",
        ".agent-memory/schema.json",
        ".agent-memory/state/catalog.json",
        "_records/projects/demo/stories/story-demo-cache--r0001.md",
        "projects/demo/current-focus.md",
    ),
    "v1-proposal-review-golden": (
        ".agent-memory-fixture.json",
        "AGENTS.md",
        "preferences/review-style.md",
        "projects/demo/sessions/2026-01-01-cache.md",
        "projects/demo/stories/cache.md",
        "skills/rebuild-index.md",
    ),
    "v2-clean": (
        ".agent-memory-fixture.json",
        "AGENTS.md",
        "README.md",
        ".agent-memory-root-write.anchor",
        ".agent-memory/config.json",
        ".agent-memory/schema.json",
        ".agent-memory/state/catalog.json",
        ".agent-memory/state/focus/demo.json",
        ".agent-memory/transactions/fixture-v2-focus.json",
        ".agent-memory/transactions/fixture-v2-init.json",
        ".agent-memory/transactions/fixture-v2-story.json",
        "_records/projects/demo/stories/story-demo-cache--r0001.md",
        "_index/home.md",
        "_index/current-focus.md",
        "_index/memory-map.md",
        "_index/stale-or-uncertain.md",
        "projects/demo/overview.md",
        "projects/demo/current-focus.md",
        "projects/demo/stories/story-demo-cache.md",
    ),
    "v2-proposal-resolution": (
        ".agent-memory-fixture.json",
        "AGENTS.md",
    ),
    "v2-story-session-coordination": (
        ".agent-memory-fixture.json",
        "AGENTS.md",
        "projects/demo/sessions/2026-09-01-legacy.md",
    ),
}


def assert_portable_fixture_bytes(testcase, root):
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        raw = path.read_bytes()
        raw.decode("utf-8", errors="strict")
        testcase.assertNotIn(b"\r", raw, str(path))
        testcase.assertTrue(raw.endswith(b"\n"), str(path))
        testcase.assertFalse(raw.endswith(b"\n\n"), str(path))


class VaultFixtureTests(unittest.TestCase):
    def test_fixture_matrix_is_exact_and_marked(self):
        actual = {path.name for path in FIXTURE_ROOT.iterdir() if path.is_dir()}
        self.assertEqual(set(EXPECTED), actual)
        for name, sentinels in EXPECTED.items():
            root = FIXTURE_ROOT / name
            relative_files = {
                path.relative_to(root).as_posix()
                for path in root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(set(EXPECTED_FILES[name]), relative_files)
            marker = json.loads(
                (root / ".agent-memory-fixture.json").read_text("utf-8")
            )
            self.assertEqual({"fixture_id": name, "fixture_version": 1}, marker)
            for relative_path in sentinels:
                self.assertTrue((root / relative_path).is_file(), (name, relative_path))
            assert_portable_fixture_bytes(self, root)

    def test_fixture_byte_gate_rejects_crlf_and_double_final_newline(self):
        for name, invalid_suffix in (
            ("crlf", b"\r\n"),
            ("double-final-newline", b"\n\n"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                copied = Path(temporary) / "fixture"
                shutil.copytree(FIXTURE_ROOT / "v1-minimal", copied)
                target = copied / "AGENTS.md"
                target.write_bytes(target.read_bytes().rstrip(b"\r\n") + invalid_suffix)
                with self.assertRaises(AssertionError):
                    assert_portable_fixture_bytes(self, copied)

    def test_v2_clean_builder_matches_checked_in_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            built = build_v2_clean(Path(temporary) / "v2-clean")
            checked_in = fixture_root("v2-clean")
            self.assertEqual(tree_hashes(checked_in), tree_hashes(built))
            for relative_path, _ in tree_hashes(checked_in):
                self.assertEqual(
                    (checked_in / relative_path).read_bytes(),
                    (built / relative_path).read_bytes(),
                    relative_path,
                )

    def test_fixture_copy_is_isolated_from_checked_in_source(self):
        source = fixture_root("v1-minimal")
        before = tree_hashes(source)
        with tempfile.TemporaryDirectory() as temporary:
            copied = copy_vault_fixture("v1-minimal", Path(temporary))
            target = copied / "projects" / "demo" / "overview.md"
            target.write_bytes(target.read_bytes() + b"Copied fixture change.\n")
            self.assertNotEqual(before, tree_hashes(copied))
        self.assertEqual(before, tree_hashes(source))


if __name__ == "__main__":
    unittest.main()
