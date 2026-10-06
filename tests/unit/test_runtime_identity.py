import os
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from tests.helpers import REPO_ROOT

from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.operation_scope import OperationScope
from obsidian_agent_memory.runtime_identity import _observe_runtime_identity


class RuntimeIdentityTests(unittest.TestCase):
    def test_fixture_identity_is_explicit(self):
        proof = _observe_runtime_identity(
            OperationScope.FIXTURE,
            "proposal-review-fixture-v1",
            Path("ignored"),
            {},
            None,
            False,
            None,
            (),
        )
        self.assertEqual(
            {"kind": "fixture", "revision": "proposal-review-fixture-v1"},
            proof.identity.document,
        )
        self.assertEqual((), proof.protected_roots)
        for value in (None, "", "Invalid Revision"):
            with self.assertRaises(ValidationError):
                _observe_runtime_identity(
                    OperationScope.FIXTURE, value, Path("ignored"), {}, None,
                    False, None, (),
                )

    def test_clean_git_identity_is_module_bound_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / ".git").mkdir()
            module = root / "skills/obsidian-agent-memory/scripts/obsidian_agent_memory/runtime_identity.py"
            module.parent.mkdir(parents=True)
            module.write_text("# fixture\n", encoding="utf-8")
            cache = root.parent / (root.name + "-cache")
            calls = []

            def runner(arguments, env):
                calls.append((tuple(arguments), dict(env)))
                if "--show-toplevel" in arguments:
                    return SimpleNamespace(returncode=0, stdout=(str(root) + "\n").encode(), stderr=b"")
                if "--verify" in arguments:
                    return SimpleNamespace(returncode=0, stdout=("a" * 40 + "\n").encode(), stderr=b"")
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            proof = _observe_runtime_identity(
                OperationScope.REAL, None, module, {}, runner, True, cache, (cache / "runtime_identity.pyc",),
            )
            self.assertEqual(
                {"kind": "git-commit", "revision": "a" * 40, "tree_state": "clean"},
                proof.identity.document,
            )
            self.assertEqual((root,), proof.protected_roots)
            self.assertEqual(3, len(calls))
            self.assertTrue(all(call[1]["GIT_OPTIONAL_LOCKS"] == "0" for call in calls))

            def dirty(arguments, env):
                result = runner(arguments, env)
                if "status" in arguments:
                    result.stdout = b"?? untracked\0"
                return result

            with self.assertRaises(ValidationError):
                _observe_runtime_identity(
                    OperationScope.REAL, None, module, {}, dirty, True, cache, (cache / "x.pyc",),
                )
            with self.assertRaises(ValidationError):
                _observe_runtime_identity(
                    OperationScope.REAL, "fixture", module, {}, runner, True, cache, (cache / "x.pyc",),
                )

    def test_default_installed_identity_binds_manifest_and_managed_bytes(self):
        for version in ("2.0.0", "2.0.2"):
            with self.subTest(version=version):
                self._check_installed_identity(version)

    def _check_installed_identity(self, version):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            skills_root = parent / "skills"
            module = skills_root / "obsidian-agent-memory/scripts/obsidian_agent_memory/runtime_identity.py"
            module.parent.mkdir(parents=True)
            module.write_text("# installed fixture\n", encoding="utf-8")
            directories = []
            current = module.parent
            while current != skills_root:
                directories.append(current.relative_to(skills_root).as_posix())
                current = current.parent
            directories.sort()
            target = hashlib.sha256(os.path.normcase(str(skills_root)).encode()).hexdigest()
            state_root = parent / ".obsidian-agent-memory-pack-state" / target
            state_root.mkdir(parents=True)
            document = {
                "actor": "fixture-agent",
                "authorization_ref": "fixture-authorization",
                "directories": directories,
                "files": [{
                    "path": module.relative_to(skills_root).as_posix(),
                    "sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
                }],
                "occurred_at": "2026-09-04T00:00:00Z",
                "pack_name": "obsidian-agent-memory-skill-pack",
                "pack_version": version,
                "schema_version": 1,
                "skills_root": str(skills_root),
                "source_revision": "1" * 64,
                "target_digest": target,
                "transaction_id": "fixture-install",
            }
            raw = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
            (state_root / "installed.json").write_bytes(raw)
            cache = parent / "fresh-cache"

            proof = _observe_runtime_identity(
                OperationScope.REAL, None, module, {}, None, True, cache, (cache / "x.pyc",),
            )

            self.assertEqual(
                {
                    "kind": "pack-manifest",
                    "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                    "verification_status": "managed-valid",
                    "version": version,
                },
                proof.identity.document,
            )
            self.assertEqual((skills_root, state_root), proof.protected_roots)
            document["pack_version"] = "9.0.0"
            invalid = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
            (state_root / "installed.json").write_bytes(invalid)
            with self.assertRaisesRegex(ValidationError, "invalid installed pack identity"):
                _observe_runtime_identity(
                    OperationScope.REAL, None, module, {}, None, True, cache, (cache / "x.pyc",),
                )
            (state_root / "installed.json").write_bytes(raw)
            module.write_text("# tampered\n", encoding="utf-8")
            with self.assertRaises(ValidationError):
                _observe_runtime_identity(
                    OperationScope.REAL, None, module, {}, None, True, cache, (cache / "x.pyc",),
                )


if __name__ == "__main__":
    unittest.main()
