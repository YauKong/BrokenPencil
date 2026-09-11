import dataclasses
import inspect
import subprocess
import sys
import typing
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory import (  # noqa: E402
    AcceptedRecord,
    AdapterSelection,
    AgentMemoryError,
    CatalogEntry,
    CatalogSnapshot,
    CommandRunner,
    CommitOutcome,
    ConfigurationError,
    ConflictError,
    ContainmentError,
    Finding,
    FocusState,
    FocusUpdateOutcome,
    LockBusyError,
    ManifestFile,
    PackManifest,
    PlanInvalidatedError,
    ProjectionDocument,
    ProjectionDriftError,
    PromotionCandidate,
    RecordCandidate,
    RecordEnvelope,
    ReadAdapter,
    RootBinding,
    RootGuardRecovery,
    RootWriteGuard,
    SearchHit,
    SessionRelationship,
    StoryDelta,
    StoryProfile,
    TransactionContext,
    ValidationError,
)


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.envelope = RecordEnvelope(
            memory_id="memory-1",
            record_type="decision",
            schema_version=2,
            owner_scope="project",
            project="demo",
            revision=1,
            supersedes=None,
            created_at="2026-08-30T00:00:00Z",
            observed_at="2026-08-30T00:00:00Z",
            source="test",
            source_revision="1",
            body_sha256="a" * 64,
        )
        self.context = TransactionContext(
            transaction_id="tx-1", actor="tester", occurred_at="2026-08-30T00:00:00Z"
        )
        self.guard = RootWriteGuard(
            root=Path("root"),
            lock_path=Path("root/.agent-memory/lock"),
            token="token-1",
            transaction_id="tx-1",
        )

    def test_exceptions_have_the_locked_hierarchy(self):
        for exception_class in (
            AgentMemoryError,
            ConfigurationError,
            ValidationError,
            ContainmentError,
            ConflictError,
            LockBusyError,
            ProjectionDriftError,
            PlanInvalidatedError,
        ):
            self.assertIsInstance(exception_class("problem"), AgentMemoryError)

    def test_repository_gitignore_preserves_worktree_and_python_cache_rules(self):
        self.assertEqual(
            (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines(),
            [
                ".worktrees/",
                "dist/",
                ".artifacts/",
                "__pycache__/",
                "*.py[cod]",
            ],
        )

    def test_read_adapter_and_command_runner_match_the_locked_static_contract(self):
        self.assertEqual(
            {name for name in ReadAdapter.__dict__ if not name.startswith("_")},
            {"read", "search", "files"},
        )

        read_signature = inspect.signature(ReadAdapter.read)
        self.assertEqual(
            tuple(
                (parameter.name, parameter.default)
                for parameter in read_signature.parameters.values()
            ),
            (("self", inspect.Parameter.empty), ("relative_path", inspect.Parameter.empty)),
        )
        self.assertEqual(
            typing.get_type_hints(ReadAdapter.read),
            {"relative_path": str, "return": str},
        )

        search_signature = inspect.signature(ReadAdapter.search)
        self.assertEqual(
            tuple(
                (parameter.name, parameter.default)
                for parameter in search_signature.parameters.values()
            ),
            (
                ("self", inspect.Parameter.empty),
                ("query", inspect.Parameter.empty),
                ("limit", 20),
            ),
        )
        self.assertEqual(
            typing.get_type_hints(ReadAdapter.search),
            {
                "query": str,
                "limit": int,
                "return": typing.Tuple[SearchHit, ...],
            },
        )

        files_signature = inspect.signature(ReadAdapter.files)
        self.assertEqual(
            tuple(
                (parameter.name, parameter.default)
                for parameter in files_signature.parameters.values()
            ),
            (
                ("self", inspect.Parameter.empty),
                ("prefix", inspect.Parameter.empty),
                ("limit", 200),
            ),
        )
        self.assertEqual(
            typing.get_type_hints(ReadAdapter.files),
            {"prefix": str, "limit": int, "return": typing.Tuple[str, ...]},
        )

        self.assertIs(typing.get_origin(CommandRunner), typing.get_origin(typing.Callable))
        self.assertEqual(
            typing.get_args(CommandRunner),
            ([typing.Sequence[str], float], subprocess.CompletedProcess),
        )

    def test_locked_models_are_immutable(self):
        models = (
            RootBinding(Path("root"), "demo", "vault"),
            self.envelope,
            RecordCandidate(self.envelope, "body"),
            self.context,
            self.guard,
            RootGuardRecovery(self.guard, Path("evidence"), "canonical-lock", "b" * 64),
            CommitOutcome("accepted", "tx-1", 1, Path("record"), None, None),
            FocusUpdateOutcome("proposed", "tx-1", 2, Path("proposal"), "conflict"),
            FocusState("demo", 1, ("memory-1",), "2026-08-30T00:00:00Z"),
            ProjectionDocument("current-focus.md", "content", "1", "2026-08-30T00:00:00Z", None),
            CatalogEntry("memory-1", 1, "records/memory-1.md", "decision", "project", "demo"),
            CatalogSnapshot(1, ()),
            AcceptedRecord(self.envelope, "body", "records/memory-1.md", 1),
            PromotionCandidate("candidate-1", ("memory-1",), "global", "useful"),
            SearchHit("records/memory-1.md", "excerpt"),
            SessionRelationship("completed", None, ()),
            StoryProfile("Readable story title", "situation", "state", (), None, None, (), ()),
            StoryDelta("story-1", 1, "session-1", None, (), None, None, (), ()),
            AdapterSelection(object(), "filesystem", "test adapter"),
            Finding("test", "warning", "path", "message"),
            ManifestFile("skill.md", "c" * 64),
            PackManifest(
                "agent-memory",
                "1.0.0",
                "3.9",
                (2,),
                ("member",),
                (),
                ("filesystem",),
                (),
                "release.zip",
                "d" * 64,
                "manifest.json",
                (),
            ),
        )

        for model in models:
            field_name = dataclasses.fields(model)[0].name
            with self.subTest(model=type(model).__name__):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(model, field_name, None)


if __name__ == "__main__":
    unittest.main()
