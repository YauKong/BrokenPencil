import sys
import tempfile
import unittest
import json
import multiprocessing
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory.errors import (  # noqa: E402
    AgentMemoryError,
    ConflictError,
    LockBusyError,
    ValidationError,
)
from obsidian_agent_memory.coordination import build_unbound_session_candidate  # noqa: E402
from obsidian_agent_memory.models import PromotionCandidate, RootWriteGuard, TransactionContext  # noqa: E402
from obsidian_agent_memory.session_relationships import (  # noqa: E402
    SessionRelationship,
    render_session_relationship,
)
from obsidian_agent_memory.transactions import (  # noqa: E402
    commit_record,
    initialize_memory_root,
    preserve_promotion_candidate,
    preserve_unbound_session_candidate,
    recover_root_write_guard,
    root_write_guard,
)
import obsidian_agent_memory.transactions as transaction_module  # noqa: E402
from tests.helpers import (  # noqa: E402
    candidate,
    context,
    crash_during_anchor_bootstrap,
    crash_during_recovery,
    crash_with_root_guard,
    hold_one_byte_lease,
    initialize,
    sha256,
)


def session_body(status="completed", primary_story_id=None, related_story_ids=()):
    relationship = render_session_relationship(
        SessionRelationship(status, primary_story_id, tuple(related_story_ids))
    )
    return "# Session: Demo\n\n{0}\n## User Goal\n\nExercise the commit boundary.\n".format(
        relationship
    )


class InitializationTests(unittest.TestCase):
    def test_initializes_only_schema_two_canonical_files(self):
        context = TransactionContext("tx-init", "test-agent", "2026-08-30T00:00:00Z")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"

            created = initialize_memory_root(root, "demo", context)

            relative_created = tuple(path.relative_to(root).as_posix() for path in created)
            self.assertEqual(
                (
                    ".agent-memory-root-write.anchor",
                    "AGENTS.md",
                    "README.md",
                    ".agent-memory/config.json",
                    ".agent-memory/schema.json",
                    ".agent-memory/state/catalog.json",
                    ".agent-memory/state/focus/demo.json",
                    ".agent-memory/transactions/tx-init.json",
                ),
                relative_created,
            )
            self.assertEqual(
                b'{"purpose":"root-write-namespace","schema_version":1}\n',
                (root / ".agent-memory-root-write.anchor").read_bytes(),
            )
            self.assertFalse(any(path.name == "current-focus.md" for path in root.rglob("*")))

    def test_refuses_nonempty_and_initialized_roots_without_mutation(self):
        context_value = context("tx-init-refused")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            root.mkdir()
            marker = root / "existing.txt"
            marker.write_bytes(b"unchanged")
            before = tuple((path.relative_to(root).as_posix(), path.read_bytes()) for path in root.rglob("*") if path.is_file())
            with self.assertRaises(ConflictError):
                initialize_memory_root(root, "demo", context_value)
            after = tuple((path.relative_to(root).as_posix(), path.read_bytes()) for path in root.rglob("*") if path.is_file())
            self.assertEqual(before, after)

            clean_root = Path(temporary_directory) / "initialized"
            initialize(clean_root)
            snapshot = tuple((path.relative_to(clean_root).as_posix(), path.read_bytes()) for path in clean_root.rglob("*") if path.is_file())
            with self.assertRaises(ConflictError):
                initialize_memory_root(clean_root, "demo", context_value)
            self.assertEqual(snapshot, tuple((path.relative_to(clean_root).as_posix(), path.read_bytes()) for path in clean_root.rglob("*") if path.is_file()))

    def test_value_equal_guard_clone_is_not_live_ownership(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            with root_write_guard(root, context("tx-guard")) as guard:
                clone = RootWriteGuard(guard.root, guard.lock_path, guard.token, guard.transaction_id)
                with self.assertRaises(LockBusyError):
                    initialize_memory_root(root, "demo", context("tx-guard"), guard=clone)
                self.assertFalse((root / ".agent-memory").exists())

    def test_supplied_guard_requires_actor_and_occurred_at_identity(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            owner_context = context("tx-guard-identity")
            mismatches = (
                TransactionContext(owner_context.transaction_id, "other-agent", owner_context.occurred_at),
                TransactionContext(owner_context.transaction_id, owner_context.actor, "2026-08-30T00:00:01Z"),
            )
            with root_write_guard(root, owner_context) as guard:
                for mismatch in mismatches:
                    with self.subTest(mismatch=mismatch):
                        with self.assertRaises(LockBusyError):
                            commit_record(root, candidate(), 0, None, mismatch, guard=guard)
                        self.assertFalse(
                            (root / ".agent-memory/transactions/tx-guard-identity.json").exists()
                        )

    def test_anchor_bootstrap_resumes_exact_prefix_and_publication_crashes(self):
        anchor_bytes = b'{"purpose":"root-write-namespace","schema_version":1}\n'
        stages = (
            "candidate-created",
            "candidate-leased",
        ) + tuple("prefix-{0}".format(offset) for offset in range(1, len(anchor_bytes) + 1)) + (
            "canonical-linked",
            "canonical-directory-synced",
            "before-candidate-unlink",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            for index, stage in enumerate(stages):
                with self.subTest(stage=stage):
                    root = Path(temporary_directory) / ("anchor-" + str(index))
                    root.mkdir()
                    process = multiprocessing.Process(
                        target=crash_during_anchor_bootstrap,
                        args=(str(root), "tx-anchor-crash", stage),
                    )
                    process.start()
                    process.join(10)
                    self.assertEqual(41, process.exitcode)

                    with root_write_guard(root, context("tx-anchor-resume")):
                        pass

                    self.assertEqual(
                        anchor_bytes,
                        (root / ".agent-memory-root-write.anchor").read_bytes(),
                    )
                    self.assertFalse((root / ".agent-memory-root-write.anchor.candidate").exists())


class ContainmentTests(unittest.TestCase):
    def test_reparse_attribute_is_rejected_without_optional_symlink_capability(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            reparse = Path(temporary_directory) / "reparse"
            reparse.mkdir()
            original_lstat = Path.lstat

            def lstat_with_reparse(path):
                metadata = original_lstat(path)
                if path == reparse:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_file_attributes=getattr(metadata, "st_file_attributes", 0) | 0x400,
                    )
                return metadata

            with mock.patch.object(Path, "lstat", autospec=True, side_effect=lstat_with_reparse):
                with self.assertRaises(ValidationError):
                    transaction_module._assert_plain_path(reparse / "child", allow_missing=True)

    def test_transaction_parent_symlink_cannot_redirect_bytes_outside_root(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "memory"
            external = base / "external"
            external.mkdir()
            initialize(root)
            transactions_directory = root / ".agent-memory/transactions"
            (transactions_directory / "tx-init.json").unlink()
            transactions_directory.rmdir()
            try:
                os.symlink(external, transactions_directory, target_is_directory=True)
            except OSError as error:
                self.skipTest("directory symlinks unavailable: {0}".format(error))

            with self.assertRaises(ValidationError):
                commit_record(root, candidate(), 0, None, context("tx-redirect"))

            self.assertEqual([], list(external.iterdir()))
            self.assertEqual(0, json.loads((root / ".agent-memory/state/catalog.json").read_text("utf-8"))["revision"])

    def test_proposal_and_lock_parent_symlinks_never_receive_bytes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            for parent_kind in ("proposals", "locks"):
                with self.subTest(parent_kind=parent_kind):
                    root = base / ("memory-" + parent_kind)
                    external = base / ("external-" + parent_kind)
                    external.mkdir()
                    initialize(root, "tx-init-" + parent_kind)
                    if parent_kind == "proposals":
                        redirected = root / ".agent-memory/state/proposals"
                        with root_write_guard(root, context("tx-holder")):
                            try:
                                os.symlink(external, redirected, target_is_directory=True)
                            except OSError as error:
                                self.skipTest("directory symlinks unavailable: {0}".format(error))
                            with self.assertRaises(ValidationError):
                                commit_record(root, candidate(), 0, None, context("tx-proposal-redirect"))
                    else:
                        redirected = root / ".agent-memory/locks"
                        try:
                            os.symlink(external, redirected, target_is_directory=True)
                        except OSError as error:
                            self.skipTest("directory symlinks unavailable: {0}".format(error))
                        with self.assertRaises(ValidationError):
                            commit_record(root, candidate(), 0, None, context("tx-lock-redirect"))
                    self.assertEqual([], list(external.iterdir()))
                    self.assertEqual(0, json.loads((root / ".agent-memory/state/catalog.json").read_text("utf-8"))["revision"])

    def test_recovery_parent_symlink_cannot_redirect_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "memory"
            external = base / "external"
            external.mkdir()
            initialize(root)
            token = __import__("hashlib").sha256(
                (str(root.resolve()) + "\0tx-partial").encode("utf-8")
            ).hexdigest()
            (root / (".agent-memory-root-write.candidate-" + token)).write_bytes(b"partial")
            try:
                os.symlink(
                    external,
                    root / ".agent-memory-root-write-recoveries",
                    target_is_directory=True,
                )
            except OSError as error:
                self.skipTest("directory symlinks unavailable: {0}".format(error))

            with self.assertRaises(ValidationError):
                with recover_root_write_guard(
                    root,
                    "tx-partial",
                    None,
                    context("tx-recovery-redirect"),
                    "incident-redirect",
                ):
                    pass

            self.assertEqual([], list(external.iterdir()))


class CommitRecordTests(unittest.TestCase):
    def test_session_commit_requires_profile_and_same_project_accepted_stories(self):
        cases = (
            ("accepted body", None, "session-relationship-required"),
            (session_body(primary_story_id="story-missing"), None, "session-story-missing"),
            (
                session_body(primary_story_id="story-other"),
                candidate(
                    memory_id="story-other",
                    record_type="story",
                    project="other",
                    owner_scope="project.other.story",
                ),
                "session-story-project-mismatch",
            ),
            (
                session_body(primary_story_id="decision-demo"),
                candidate(memory_id="decision-demo"),
                "session-story-type-mismatch",
            ),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            for index, (body, prerequisite, expected_code) in enumerate(cases):
                with self.subTest(expected_code=expected_code):
                    root = Path(temporary_directory) / ("memory-session-invalid-" + str(index))
                    initialize(root, "tx-init-session-invalid-" + str(index))
                    catalog_revision = 0
                    if prerequisite is not None:
                        accepted = commit_record(
                            root,
                            prerequisite,
                            catalog_revision,
                            None,
                            context("tx-prerequisite-" + str(index)),
                        )
                        self.assertEqual("accepted", accepted.status)
                        catalog_revision = accepted.catalog_revision

                    outcome = commit_record(
                        root,
                        candidate(
                            memory_id="session-invalid-" + str(index),
                            body=body,
                            record_type="session",
                            project="demo",
                            owner_scope="project.demo.session",
                        ),
                        catalog_revision,
                        None,
                        context("tx-session-invalid-" + str(index)),
                    )

                    self.assertEqual("proposed", outcome.status)
                    self.assertEqual(expected_code, outcome.conflict_code)
                    self.assertEqual(catalog_revision, outcome.catalog_revision)

    def test_two_unique_sessions_can_link_to_one_accepted_story(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            story = commit_record(
                root,
                candidate(
                    memory_id="story-demo",
                    record_type="story",
                    owner_scope="project.demo.story",
                ),
                0,
                None,
                context("tx-story"),
            )
            self.assertEqual("accepted", story.status)

            first = commit_record(
                root,
                candidate(
                    memory_id="session-one",
                    body=session_body(primary_story_id="story-demo"),
                    record_type="session",
                    owner_scope="project.demo.session",
                ),
                story.catalog_revision,
                None,
                context("tx-session-one"),
            )
            second = commit_record(
                root,
                candidate(
                    memory_id="session-two",
                    body=session_body("failed", "story-demo"),
                    record_type="session",
                    owner_scope="project.demo.session",
                ),
                first.catalog_revision,
                None,
                context("tx-session-two"),
            )

            self.assertEqual(("accepted", "accepted"), (first.status, second.status))

    def test_accepts_new_record_with_catalog_compare_and_swap(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)

            outcome = commit_record(root, candidate(), 0, None, context("tx-record-1"))

            self.assertEqual("accepted", outcome.status)
            self.assertEqual(1, outcome.catalog_revision)
            self.assertIsNotNone(outcome.record_path)
            self.assertIsNone(outcome.proposal_path)
            catalog = json.loads((root / ".agent-memory/state/catalog.json").read_text("utf-8"))
            self.assertEqual(1, catalog["revision"])
            self.assertEqual(1, catalog["records"]["memory-1"]["revision"])
            transaction = json.loads(
                (root / ".agent-memory/transactions/tx-record-1.json").read_text("utf-8")
            )
            self.assertEqual("accepted", transaction["status"])

    def test_updates_exact_revision_chain_and_switches_catalog_pointer_only(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            first = commit_record(root, candidate(), 0, None, context("tx-record-1"))
            second_candidate = candidate(revision=2, supersedes="memory-1@1", body="revision two")

            second = commit_record(root, second_candidate, 1, 1, context("tx-record-2"))

            self.assertEqual("accepted", second.status)
            self.assertTrue(first.record_path.exists())
            self.assertTrue(second.record_path.exists())
            catalog = json.loads((root / ".agent-memory/state/catalog.json").read_text("utf-8"))
            self.assertEqual(2, catalog["revision"])
            self.assertEqual("_records/projects/demo/decisions/memory-1--r0002.md", catalog["records"]["memory-1"]["relative_path"])

    def test_preserves_revision_and_owner_conflicts_as_append_only_proposals(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            commit_record(root, candidate(), 0, None, context("tx-record-1"))
            catalog_before = (root / ".agent-memory/state/catalog.json").read_bytes()
            accepted_before = tuple(path.read_bytes() for path in (root / "_records").rglob("*.md"))
            cases = (
                (candidate(revision=3, supersedes="memory-1@1", body="jump"), 1, 1, "revision-chain-mismatch"),
                (candidate(revision=2, supersedes="other-memory@1", body="wrong id"), 1, 1, "revision-chain-mismatch"),
                (candidate(revision=2, supersedes="memory-1@1", body="owner", record_type="story", owner_scope="project.demo.story"), 1, 1, "owner-identity-mismatch"),
                (candidate(revision=1, supersedes=None, body="duplicate"), 1, None, "duplicate-memory-id"),
                (candidate(revision=2, supersedes="memory-1@1", body="stale"), 0, 1, "stale-catalog-revision"),
                (candidate(revision=2, supersedes="memory-1@1", body="stale record"), 1, 9, "stale-record-revision"),
            )
            for index, (record_candidate, catalog_revision, record_revision, code) in enumerate(cases):
                with self.subTest(code=code):
                    tx = "tx-conflict-{0}".format(index)
                    outcome = commit_record(root, record_candidate, catalog_revision, record_revision, context(tx))
                    self.assertEqual("proposed", outcome.status)
                    self.assertEqual(code, outcome.conflict_code)
                    proposal = json.loads(outcome.proposal_path.read_text("utf-8"))
                    self.assertEqual(
                        {"actor", "conflict_code", "desired", "expected_base", "observed_base", "occurred_at", "operation", "schema_version", "target", "transaction_id"},
                        set(proposal),
                    )
                    self.assertEqual(record_candidate.body.rstrip("\n") + "\n", proposal["desired"]["record_candidate"]["body"])
                    self.assertEqual(
                        record_candidate.envelope.memory_id,
                        proposal["desired"]["record_candidate"]["envelope"]["memory_id"],
                    )
            self.assertEqual(catalog_before, (root / ".agent-memory/state/catalog.json").read_bytes())
            self.assertEqual(accepted_before, tuple(path.read_bytes() for path in (root / "_records").rglob("*.md")))

    def test_reused_transaction_id_never_overwrites_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            commit_record(root, candidate(), 0, None, context("tx-record"))
            transaction_path = root / ".agent-memory/transactions/tx-record.json"
            before = transaction_path.read_bytes()

            with self.assertRaises(ConflictError):
                commit_record(root, candidate(memory_id="memory-2"), 1, None, context("tx-record"))

            self.assertEqual(before, transaction_path.read_bytes())

    def test_busy_root_preserves_intent_and_one_proposal_without_canonical_change(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            catalog_before = (root / ".agent-memory/state/catalog.json").read_bytes()
            with root_write_guard(root, context("tx-holder")):
                outcome = commit_record(root, candidate(), 0, None, context("tx-busy"))

            self.assertEqual("proposed", outcome.status)
            self.assertEqual("root-write-busy", outcome.conflict_code)
            self.assertEqual(catalog_before, (root / ".agent-memory/state/catalog.json").read_bytes())
            self.assertEqual(1, len(list((root / ".agent-memory/state/proposals").glob("tx-busy.json"))))

    def test_failure_after_catalog_cas_retains_advanced_catalog_and_intent(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            original_finalize = transaction_module._finalize_transaction

            def fail_accepted_result(transaction_path, expected, final, transaction_id):
                if json.loads(final.decode("utf-8")).get("status") == "accepted":
                    raise OSError("injected finalization failure")
                return original_finalize(transaction_path, expected, final, transaction_id)

            with mock.patch.object(
                transaction_module,
                "_finalize_transaction",
                side_effect=fail_accepted_result,
            ):
                with self.assertRaises(OSError):
                    commit_record(root, candidate(), 0, None, context("tx-finalize-failure"))

            catalog = json.loads((root / ".agent-memory/state/catalog.json").read_text("utf-8"))
            transaction = json.loads(
                (root / ".agent-memory/transactions/tx-finalize-failure.json").read_text("utf-8")
            )
            self.assertEqual(1, catalog["revision"])
            self.assertEqual("in-progress", transaction["status"])
            self.assertTrue((root / catalog["records"]["memory-1"]["relative_path"]).exists())

    def test_catalog_cas_failure_retains_immutable_orphan_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            original_replace = transaction_module._replace_cas

            def fail_catalog(target, expected, desired, token, root=None):
                if target.name == "catalog.json":
                    raise OSError("injected catalog failure")
                return original_replace(target, expected, desired, token, root=root)

            with mock.patch.object(transaction_module, "_replace_cas", side_effect=fail_catalog):
                with self.assertRaises(AgentMemoryError):
                    commit_record(root, candidate(), 0, None, context("tx-catalog-failure"))

            transaction = json.loads(
                (root / ".agent-memory/transactions/tx-catalog-failure.json").read_text("utf-8")
            )
            self.assertEqual("_records/projects/demo/decisions/memory-1--r0001.md", transaction["orphan_record_path"])
            self.assertTrue((root / transaction["orphan_record_path"]).exists())
            self.assertEqual(0, json.loads((root / ".agent-memory/state/catalog.json").read_text("utf-8"))["revision"])

    def test_post_link_directory_failure_marks_exact_record_orphan(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)

            def fail_after_record_link(stage, target):
                if stage == "canonical-linked" and target.suffix == ".md":
                    raise OSError("injected post-link failure")

            with mock.patch.object(
                transaction_module,
                "_publication_checkpoint",
                side_effect=fail_after_record_link,
            ):
                with self.assertRaises(AgentMemoryError):
                    commit_record(root, candidate(), 0, None, context("tx-post-link-failure"))

            transaction = json.loads(
                (root / ".agent-memory/transactions/tx-post-link-failure.json").read_text("utf-8")
            )
            orphan_path = root / transaction["orphan_record_path"]
            self.assertEqual("published-before-catalog", transaction["orphan_status"])
            self.assertEqual(__import__("hashlib").sha256(orphan_path.read_bytes()).hexdigest(), transaction["orphan_record_sha256"])
            self.assertEqual("in-progress", transaction["status"])
            self.assertEqual(0, json.loads((root / ".agent-memory/state/catalog.json").read_text("utf-8"))["revision"])


class UnboundSessionCandidateTests(unittest.TestCase):
    def test_preserves_append_only_proposal_without_accepting_session(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            session = candidate(
                memory_id="session-unbound",
                body=session_body(),
                record_type="session",
                project="demo",
                owner_scope="project.demo.session",
            )
            unbound = build_unbound_session_candidate(
                session,
                origin_task_id="task-direct",
            )

            proposal_path = preserve_unbound_session_candidate(
                root,
                unbound,
                context("tx-unbound"),
            )

            self.assertEqual(
                root / ".agent-memory/state/proposals/tx-unbound.json",
                proposal_path,
            )
            proposal = json.loads(proposal_path.read_text("utf-8"))
            self.assertEqual("unbound-session", proposal["operation"])
            self.assertEqual("proposed", proposal["status"])
            transaction = json.loads(
                (root / ".agent-memory/transactions/tx-unbound.json").read_text("utf-8")
            )
            self.assertEqual("proposed", transaction["status"])
            catalog = json.loads(
                (root / ".agent-memory/state/catalog.json").read_text("utf-8")
            )
            self.assertEqual({}, catalog["records"])

    def test_rejects_project_mismatch_before_writing_any_artifact(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            session = candidate(
                memory_id="session-unbound",
                body=session_body(),
                record_type="session",
                project="demo",
                owner_scope="project.demo.session",
            )
            unbound = replace(
                build_unbound_session_candidate(session, origin_task_id="task-direct"),
                project_id="other",
            )

            with self.assertRaises(ValidationError):
                preserve_unbound_session_candidate(
                    root,
                    unbound,
                    context("tx-unbound-mismatch"),
                )

            self.assertFalse(
                (root / ".agent-memory/transactions/tx-unbound-mismatch.json").exists()
            )
            self.assertFalse(
                (root / ".agent-memory/state/proposals/tx-unbound-mismatch.json").exists()
            )


class PromotionCandidateTests(unittest.TestCase):
    def test_preserves_typed_candidate_without_cross_root_write(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            commit_record(root, candidate(), 0, None, context("tx-record"))
            promotion = PromotionCandidate(
                "promotion-1",
                ("memory-1",),
                "knowledge/topics/portable-memory.md",
                "Reusable invariant",
            )

            proposal_path = preserve_promotion_candidate(root, promotion, context("tx-promotion"))

            self.assertEqual(root / ".agent-memory/state/proposals/promotion-1.json", proposal_path)
            proposal = json.loads(proposal_path.read_text("utf-8"))
            self.assertEqual("knowledge-promotion", proposal["operation"])
            self.assertEqual(1, proposal["observed_base"]["catalog_revision"])
            self.assertEqual("accepted", json.loads((root / ".agent-memory/transactions/tx-promotion.json").read_text("utf-8"))["status"])
            self.assertEqual([], list(Path(temporary_directory).glob("knowledge")))


class RootGuardRecoveryTests(unittest.TestCase):
    def _assert_valid_removed_transition(self, root):
        operation_directory = next(
            (root / ".agent-memory-root-write-recoveries").iterdir()
        )
        published_path = operation_directory / "010-new-guard-published.json"
        published_bytes = published_path.read_bytes()
        published = json.loads(published_bytes.decode("utf-8"))
        removed = json.loads(
            (operation_directory / "020-old-artifact-removed.json").read_text("utf-8")
        )
        expected_endpoints = dict(published["endpoints"])
        expected_endpoints["old_candidate_present"] = False
        self.assertEqual(
            {
                "endpoints": expected_endpoints,
                "operation_id": published["operation_id"],
                "previous_transition_sha256": __import__("hashlib").sha256(
                    published_bytes
                ).hexdigest(),
                "schema_version": 1,
                "step": "old-artifact-removed",
            },
            removed,
        )

    def _candidate_only_crash_at(self, root, crash_stage):
        token = __import__("hashlib").sha256(
            (str(root.resolve()) + "\0tx-partial").encode("utf-8")
        ).hexdigest()
        old_candidate = root / (".agent-memory-root-write.candidate-" + token)
        old_candidate.write_bytes(b"partial crash bytes")
        process = multiprocessing.Process(
            target=crash_during_recovery,
            args=(
                str(root),
                "tx-partial",
                None,
                "tx-replay-validate",
                "incident-replay-validate",
                crash_stage,
            ),
        )
        process.start()
        process.join(10)
        self.assertEqual(31, process.exitcode)
        operation_directory = next((root / ".agent-memory-root-write-recoveries").iterdir())
        return old_candidate, operation_directory

    def _file_snapshot(self, root):
        return tuple(
            sorted(
                (path.relative_to(root).as_posix(), path.read_bytes())
                for path in root.rglob("*")
                if path.is_file()
            )
        )

    def test_tampered_published_transition_refuses_before_endpoint_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            _, operation_directory = self._candidate_only_crash_at(
                root, "published-transition-published"
            )
            transition_path = operation_directory / "010-new-guard-published.json"
            transition = json.loads(transition_path.read_text("utf-8"))
            transition["previous_transition_sha256"] = "f" * 64
            transition_path.write_text(
                json.dumps(transition, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            (root / ".agent-memory-root-write.lock").unlink()
            before = self._file_snapshot(root)

            with self.assertRaises(ConflictError):
                with recover_root_write_guard(
                    root,
                    "tx-partial",
                    None,
                    context("tx-replay-validate"),
                    "incident-replay-validate",
                ):
                    pass

            self.assertEqual(before, self._file_snapshot(root))

    def test_recorded_old_candidate_presence_must_match_before_replay(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            old_candidate, _ = self._candidate_only_crash_at(
                root, "prepared-transition-published"
            )
            old_candidate.unlink()
            before = self._file_snapshot(root)

            with self.assertRaises(ConflictError):
                with recover_root_write_guard(
                    root,
                    "tx-partial",
                    None,
                    context("tx-replay-validate"),
                    "incident-replay-validate",
                ):
                    pass

            self.assertEqual(before, self._file_snapshot(root))

    def test_recorded_old_canonical_presence_must_match_recovery_kind(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            token = __import__("hashlib").sha256(
                (str(root.resolve()) + "\0tx-partial").encode("utf-8")
            ).hexdigest()
            (root / (".agent-memory-root-write.candidate-" + token)).write_bytes(
                b"partial crash bytes"
            )
            process = multiprocessing.Process(
                target=crash_during_recovery,
                args=(
                    str(root),
                    "tx-partial",
                    None,
                    "tx-replay-validate",
                    "incident-replay-validate",
                    "prepared-transition-published",
                ),
            )
            process.start()
            process.join(10)
            self.assertEqual(31, process.exitcode)
            operation_directory = next(
                (root / ".agent-memory-root-write-recoveries").iterdir()
            )
            transition_path = operation_directory / "000-prepared.json"
            transition = json.loads(transition_path.read_text("utf-8"))
            transition["old_artifact"]["canonical_present"] = True
            transition_path.write_text(
                json.dumps(transition, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            before = self._file_snapshot(root)

            with self.assertRaises(ConflictError):
                with recover_root_write_guard(
                    root,
                    "tx-partial",
                    None,
                    context("tx-replay-validate"),
                    "incident-replay-validate",
                ):
                    pass

            self.assertEqual(before, self._file_snapshot(root))

    def test_recovers_dead_canonical_guard_and_authorizes_real_commit(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            process = multiprocessing.Process(
                target=crash_with_root_guard,
                args=(str(root), "tx-dead"),
            )
            process.start()
            process.join(10)
            self.assertFalse(process.is_alive())
            self.assertEqual(23, process.exitcode)
            stale_path = root / ".agent-memory-root-write.lock"
            stale_bytes = stale_path.read_bytes()
            expected_hash = sha256(stale_path)

            with recover_root_write_guard(
                root,
                "tx-dead",
                expected_hash,
                context("tx-recovery"),
                "incident-42",
            ) as recovery:
                self.assertEqual("canonical-lock", recovery.recovered_kind)
                self.assertEqual(expected_hash, recovery.recovered_artifact_sha256)
                self.assertEqual(stale_bytes, recovery.evidence_path.read_bytes())
                outcome = commit_record(
                    root,
                    candidate(),
                    0,
                    None,
                    context("tx-recovery"),
                    guard=recovery.guard,
                )
                self.assertEqual("accepted", outcome.status)

            self.assertFalse(stale_path.exists())

    def test_recovers_exact_partial_candidate_only_artifact(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            token = __import__("hashlib").sha256(
                (str(root.resolve()) + "\0tx-partial").encode("utf-8")
            ).hexdigest()
            old_candidate = root / (".agent-memory-root-write.candidate-" + token)
            old_bytes = b'{"actor":"crashed"'
            old_candidate.write_bytes(old_bytes)
            expected_hash = __import__("hashlib").sha256(old_bytes).hexdigest()

            with recover_root_write_guard(
                root,
                "tx-partial",
                None,
                context("tx-recovery-partial"),
                "incident-43",
            ) as recovery:
                self.assertEqual("candidate-only", recovery.recovered_kind)
                self.assertEqual(expected_hash, recovery.recovered_artifact_sha256)
                self.assertEqual(old_bytes, recovery.evidence_path.read_bytes())

            self.assertFalse(old_candidate.exists())

    def test_wrong_hash_or_blank_authorization_refuses_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            process = multiprocessing.Process(target=crash_with_root_guard, args=(str(root), "tx-dead"))
            process.start()
            process.join(10)
            snapshot = tuple((path.relative_to(root).as_posix(), path.read_bytes()) for path in root.rglob("*") if path.is_file())
            with self.assertRaises(ValidationError):
                with recover_root_write_guard(root, "tx-dead", "f" * 64, context("tx-recovery"), ""):
                    pass
            with self.assertRaises(ConflictError):
                with recover_root_write_guard(root, "tx-dead", "f" * 64, context("tx-recovery"), "incident"):
                    pass
            self.assertEqual(snapshot, tuple((path.relative_to(root).as_posix(), path.read_bytes()) for path in root.rglob("*") if path.is_file()))

    def test_exact_candidate_only_replay_finishes_new_guard_publication(self):
        stages = (
            "evidence-published",
            "prepared-transition-published",
            "new-candidate-leased",
            "new-canonical-published",
            "published-transition-published",
            "before-removed-transition",
            "old-candidate-unlinked",
            "removed-transition-published",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            for index, stage in enumerate(stages):
                with self.subTest(stage=stage):
                    root = Path(temporary_directory) / ("memory-" + str(index))
                    initialize(root, "tx-init-replay-" + str(index))
                    token = __import__("hashlib").sha256(
                        (str(root.resolve()) + "\0tx-partial").encode("utf-8")
                    ).hexdigest()
                    old_candidate = root / (".agent-memory-root-write.candidate-" + token)
                    old_bytes = b"partial crash bytes"
                    old_candidate.write_bytes(old_bytes)
                    process = multiprocessing.Process(
                        target=crash_during_recovery,
                        args=(
                            str(root),
                            "tx-partial",
                            None,
                            "tx-replay",
                            "incident-replay",
                            stage,
                        ),
                    )
                    process.start()
                    process.join(10)
                    self.assertEqual(31, process.exitcode)

                    with recover_root_write_guard(
                        root,
                        "tx-partial",
                        None,
                        context("tx-replay"),
                        "incident-replay",
                    ) as recovery:
                        self.assertEqual(__import__("hashlib").sha256(old_bytes).hexdigest(), recovery.recovered_artifact_sha256)
                        self.assertEqual(old_bytes, recovery.evidence_path.read_bytes())
                        self.assertTrue(recovery.guard.lock_path.exists())
                        self.assertFalse(old_candidate.exists())

                    self.assertFalse((root / ".agent-memory-root-write.lock").exists())
                    self.assertEqual([], list(root.glob(".agent-memory-root-write.candidate-*")))
                    self._assert_valid_removed_transition(root)

    def test_exact_canonical_replay_resumes_every_rotation_checkpoint(self):
        stages = (
            "evidence-published",
            "prepared-transition-published",
            "new-candidate-leased",
            "old-canonical-unlinked",
            "new-canonical-published",
            "published-transition-published",
            "before-removed-transition",
            "old-candidate-unlinked",
            "removed-transition-published",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            for index, stage in enumerate(stages):
                with self.subTest(stage=stage):
                    root = Path(temporary_directory) / ("canonical-" + str(index))
                    initialize(root, "tx-init-canonical-" + str(index))
                    stale = multiprocessing.Process(
                        target=crash_with_root_guard,
                        args=(str(root), "tx-dead"),
                    )
                    stale.start()
                    stale.join(10)
                    self.assertEqual(23, stale.exitcode)
                    expected_hash = sha256(root / ".agent-memory-root-write.lock")
                    recovering = multiprocessing.Process(
                        target=crash_during_recovery,
                        args=(
                            str(root),
                            "tx-dead",
                            expected_hash,
                            "tx-replay-canonical",
                            "incident-canonical",
                            stage,
                        ),
                    )
                    recovering.start()
                    recovering.join(10)
                    self.assertEqual(31, recovering.exitcode)

                    with recover_root_write_guard(
                        root,
                        "tx-dead",
                        expected_hash,
                        context("tx-replay-canonical"),
                        "incident-canonical",
                    ) as recovery:
                        self.assertEqual("canonical-lock", recovery.recovered_kind)
                        self.assertEqual(expected_hash, recovery.recovered_artifact_sha256)
                        self.assertEqual(
                            expected_hash,
                            __import__("hashlib").sha256(recovery.evidence_path.read_bytes()).hexdigest(),
                        )
                        self.assertTrue(recovery.guard.lock_path.exists())

                    self.assertFalse((root / ".agent-memory-root-write.lock").exists())
                    self.assertEqual([], list(root.glob(".agent-memory-root-write.candidate-*")))
                    self._assert_valid_removed_transition(root)


@unittest.skipUnless(os.name == "nt", "Windows byte-range release gate")
class WindowsLeaseTests(unittest.TestCase):
    def test_root_and_narrow_locks_probe_live_unlink_before_visibility(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            original_probe = transaction_module._prove_live_unlink
            probed_names = []

            def record_probe(memory_root, candidate_path, lease, expected_bytes):
                probed_names.append(candidate_path.name)
                return original_probe(memory_root, candidate_path, lease, expected_bytes)

            with mock.patch.object(
                transaction_module,
                "_prove_live_unlink",
                side_effect=record_probe,
            ):
                commit_record(root, candidate(), 0, None, context("tx-live-unlink"))

            self.assertTrue(any(name.startswith(".agent-memory-root-write.candidate-") for name in probed_names))
            self.assertTrue(any(name.startswith("catalog.lock.candidate-") for name in probed_names))

    def test_live_unlink_probe_failure_precedes_canonical_lock_visibility(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            root.mkdir()
            with mock.patch.object(
                transaction_module,
                "_prove_live_unlink",
                side_effect=AgentMemoryError("injected unsupported live unlink"),
            ):
                with self.assertRaises(AgentMemoryError):
                    with root_write_guard(root, context("tx-probe-failure")):
                        pass
            self.assertFalse((root / ".agent-memory-root-write.lock").exists())

    def test_failed_probe_unlink_retains_classifiable_candidate_alias_pair(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            original_unlink = Path.unlink

            def fail_catalog_probe_unlink(path, *arguments, **keywords):
                if path.name.startswith("catalog.lock.candidate-") and path.name.endswith(
                    ".live-unlink-probe"
                ):
                    raise PermissionError("injected live-unlink failure")
                return original_unlink(path, *arguments, **keywords)

            with mock.patch.object(
                Path,
                "unlink",
                autospec=True,
                side_effect=fail_catalog_probe_unlink,
            ):
                with self.assertRaises(AgentMemoryError):
                    commit_record(root, candidate(), 0, None, context("tx-narrow-probe-failure"))

            lock_directory = root / ".agent-memory/locks"
            probe = next(lock_directory.glob("catalog.lock.candidate-*.live-unlink-probe"))
            candidate_path = probe.with_name(probe.name[: -len(".live-unlink-probe")])
            self.assertTrue(candidate_path.exists())
            self.assertTrue(os.path.samefile(str(candidate_path), str(probe)))
            self.assertFalse((lock_directory / "catalog.lock").exists())

    def test_failure_after_probe_unlink_retains_classifiable_candidate(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            original_unlink = Path.unlink

            def fail_after_catalog_probe_unlink(path, *arguments, **keywords):
                if path.name.startswith("catalog.lock.candidate-") and path.name.endswith(
                    ".live-unlink-probe"
                ):
                    original_unlink(path, *arguments, **keywords)
                    raise OSError("injected post-unlink durability failure")
                return original_unlink(path, *arguments, **keywords)

            with mock.patch.object(
                Path,
                "unlink",
                autospec=True,
                side_effect=fail_after_catalog_probe_unlink,
            ):
                with self.assertRaises(AgentMemoryError):
                    commit_record(root, candidate(), 0, None, context("tx-probe-fsync-failure"))

            lock_directory = root / ".agent-memory/locks"
            retained = list(lock_directory.glob("catalog.lock.candidate-*"))
            self.assertEqual(1, len(retained))
            self.assertFalse(retained[0].name.endswith(".live-unlink-probe"))
            self.assertFalse((lock_directory / "catalog.lock").exists())

    def test_directory_flush_uses_write_access_and_fails_closed(self):
        class FakeFunction:
            def __init__(self, implementation):
                self.implementation = implementation

            def __call__(self, *arguments):
                return self.implementation(*arguments)

        class FakeKernel32:
            def __init__(self, create_result, flush_result, accesses):
                self.CreateFileW = FakeFunction(
                    lambda path, access, sharing, security, disposition, flags, template: (
                        accesses.append(access) or create_result
                    )
                )
                self.FlushFileBuffers = FakeFunction(lambda handle: flush_result)
                self.CloseHandle = FakeFunction(lambda handle: 1)

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            transaction_module._fsync_directory(directory)

            accesses = []
            successful_kernel = FakeKernel32(123, 1, accesses)
            with mock.patch.object(transaction_module.ctypes, "WinDLL", return_value=successful_kernel):
                transaction_module._fsync_directory(directory)
            self.assertEqual([0x40000000], accesses)

            invalid_handle = transaction_module.ctypes.c_void_p(-1).value
            for create_result, flush_result in ((invalid_handle, 1), (123, 0)):
                with self.subTest(create_result=create_result, flush_result=flush_result):
                    failing_kernel = FakeKernel32(create_result, flush_result, [])
                    with mock.patch.object(transaction_module.ctypes, "WinDLL", return_value=failing_kernel), mock.patch.object(
                        transaction_module.ctypes,
                        "get_last_error",
                        return_value=5,
                    ):
                        with self.assertRaises(OSError):
                            transaction_module._fsync_directory(directory)

    def test_complete_empty_and_partial_files_contend_at_byte_zero(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            for index, content in enumerate((b"", b"{", b'{"complete":true}\n')):
                with self.subTest(content=content):
                    path = Path(temporary_directory) / ("lease-" + str(index))
                    path.write_bytes(content)
                    ready = multiprocessing.Event()
                    release = multiprocessing.Event()
                    process = multiprocessing.Process(
                        target=hold_one_byte_lease,
                        args=(str(path), ready, release),
                    )
                    process.start()
                    self.assertTrue(ready.wait(10))
                    probe = transaction_module._Lease.open(path)
                    try:
                        self.assertFalse(probe.acquire())
                    finally:
                        probe.close()
                    if index == 2:
                        path.unlink()
                        self.assertFalse(path.exists())
                    release.set()
                    process.join(10)
                    self.assertEqual(0, process.exitcode)


if __name__ == "__main__":
    unittest.main()
