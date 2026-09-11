import copy
import json
import hashlib
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory.errors import (  # noqa: E402
    AgentMemoryError,
    ConflictError,
    LockBusyError,
    ProjectionDriftError,
    ValidationError,
)
from obsidian_agent_memory.models import (  # noqa: E402
    ProjectionDocument,
    PromotionCandidate,
    RootWriteGuard,
    TransactionContext,
)
from obsidian_agent_memory.projections import (  # noqa: E402
    build_global_focus,
    build_project_focus,
    build_project_views,
    build_root_views,
    publish_projection,
)
import obsidian_agent_memory.projections as projection_module  # noqa: E402
from obsidian_agent_memory.transactions import (  # noqa: E402
    _narrow_lock,
    commit_record,
    initialize_memory_root,
    preserve_promotion_candidate,
    root_write_guard,
    update_focus,
)
import obsidian_agent_memory.transactions as transaction_module  # noqa: E402
from tests.helpers import candidate, context, initialize  # noqa: E402


_ROOT_VIEW_PATHS_FOR_TEST = (
    "_index/current-focus.md",
    "_index/home.md",
    "_index/memory-map.md",
    "_index/stale-or-uncertain.md",
)


def _session_candidate(
    memory_id,
    observed_at,
    status="completed",
    primary_story_id="story-demo",
    related_story_ids=(),
):
    related_lines = related_story_ids or ("none",)
    body = "".join(
        (
            "# Session: " + memory_id + " work\n\n",
            "## Session Relationship\n",
            "session_status: " + status + "\n",
            "primary_story_id: " + (primary_story_id or "none") + "\n",
            "".join("related_story_id: " + item + "\n" for item in related_lines),
            "\n## Outcome\n\nRecorded outcome.\n",
        )
    )
    value = candidate(
        memory_id=memory_id,
        body=body,
        record_type="session",
        project="demo",
        owner_scope="project.demo.session",
    )
    return replace(value, envelope=replace(value.envelope, observed_at=observed_at))


def _read_json(path):
    return json.loads(Path(path).read_text("utf-8"))


def _noncooperating_write(path, content):
    path = Path(path)
    if os.name != "nt":
        path.write_bytes(content)
        return
    descriptor = transaction_module._windows_open(path, 3)
    try:
        os.ftruncate(descriptor, 0)
        os.write(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _projection_transaction_path(root, transaction_id, relative_target):
    return (
        Path(root)
        / ".agent-memory/transactions/projections"
        / hashlib.sha256(transaction_id.encode("utf-8")).hexdigest()
        / (hashlib.sha256(relative_target.encode("utf-8")).hexdigest() + ".json")
    )


def _unexpected_terminal_manifest(
    root,
    recovery_directory,
    transaction_id,
    document,
    prior,
    **overrides
):
    relative_target = document.relative_path
    quarantine = Path(recovery_directory) / "displaced.bin"
    evidence_paths = [
        (Path(recovery_directory) / "intent.json").relative_to(root).as_posix(),
        quarantine.relative_to(root).as_posix(),
    ]
    if prior is not None:
        evidence_paths.append(
            (
                Path(recovery_directory)
                / ("prior-" + hashlib.sha256(prior).hexdigest() + ".bin")
            ).relative_to(root).as_posix()
        )
    manifest = {
        "endpoints": {
            "quarantine": {
                "file_type": stat.S_IFREG,
                "kind": "regular",
                "path": quarantine.relative_to(root).as_posix(),
            },
            "target": {
                "kind": "absent",
                "path": relative_target,
            },
        },
        "error_type": "OSError",
        "evidence_paths": sorted(evidence_paths),
        "invalid_terminals": [],
        "outcome": "unexpected-exception",
        "prior_sha256": hashlib.sha256(prior).hexdigest() if prior is not None else None,
        "projection_evidence": {
            "context_sha256": hashlib.sha256(transaction_id.encode("utf-8")).hexdigest(),
            "target_path_sha256": hashlib.sha256(relative_target.encode("utf-8")).hexdigest(),
        },
        "published_sha256": hashlib.sha256(document.content.encode("utf-8")).hexdigest(),
        "schema_version": 2,
        "status": "terminal",
        "target": relative_target,
        "transaction_id": transaction_id,
    }
    manifest.update(overrides)
    return manifest


def _write_content_addressed_terminal(directory, manifest):
    raw = transaction_module._json_bytes(manifest)
    path = Path(directory) / ("terminal-" + hashlib.sha256(raw).hexdigest() + ".json")
    path.write_bytes(raw)
    return path, raw


def _strict_terminal_schema_fixtures():
    target = "_index/stale-or-uncertain.md"
    published_hash = "b04e5ea201bb040cae53f693f6a38a3e00b62da6039ca248fecd59b7fc842894"
    prior_hash = "e5bade0e979cb8cf6e53303dae696c6631a5c82ce60386d7a602f85fb249fcc0"
    other_hash = "bcf7690127d5b0c019c22e0472b2bb4e8d98784c6e7414f29436513a1c60853f"
    context_hash = "d71913a108257cb24f847e58c061d434d5e1e1ee4f5f41a9e58b49b40630ae97"
    target_hash = "c76b67042e49563f7217776bcc4e93e81c228b142711ec33b1ab8cee6eeb93dd"
    recovery = ".agent-memory/transactions/projection-recovery/{0}/{1}".format(
        context_hash,
        target_hash,
    )
    quarantine = recovery + "/displaced.bin"
    intent = recovery + "/intent.json"
    prior_path = recovery + "/prior-" + prior_hash + ".bin"
    regular_quarantine = {"file_type": stat.S_IFREG, "kind": "regular", "path": quarantine}
    regular_target = {"file_type": stat.S_IFREG, "kind": "regular", "path": target}

    def common(captured_prior=prior_hash):
        return {
            "prior_sha256": captured_prior,
            "projection_evidence": {
                "context_sha256": context_hash,
                "target_path_sha256": target_hash,
            },
            "published_sha256": published_hash,
            "schema_version": 2,
            "status": "terminal",
            "target": target,
            "transaction_id": "tx-schema",
        }

    def byte_terminal(outcome, observed, observed_hash, captured_prior=prior_hash):
        evidence = [intent]
        if captured_prior is not None:
            evidence.append(prior_path)
        if observed_hash is not None:
            evidence.append(recovery + "/observed-" + observed_hash + ".bin")
        return {
            **common(captured_prior),
            "displaced": dict(regular_quarantine),
            "displaced_path": quarantine,
            "displaced_sha256": published_hash,
            "evidence_paths": sorted(evidence),
            "observed": observed,
            "observed_sha256": observed_hash,
            "outcome": outcome,
        }

    restored = byte_terminal("restored", dict(regular_target), prior_hash)
    restored_absence = byte_terminal(
        "restored",
        {"kind": "absent", "path": target},
        None,
        None,
    )
    conflict_regular = byte_terminal("conflict-preserved", dict(regular_target), other_hash)
    conflict_matching_prior = byte_terminal(
        "conflict-preserved",
        dict(regular_target),
        prior_hash,
    )
    conflict_namespace = {
        **common(),
        "displaced": {"file_type": stat.S_IFDIR, "kind": "directory", "path": quarantine},
        "evidence_paths": [intent, prior_path, target],
        "observed": {"file_type": stat.S_IFDIR, "kind": "directory", "path": target},
        "outcome": "conflict-preserved",
    }
    namespace_absent = copy.deepcopy(conflict_namespace)
    namespace_absent["displaced"] = {"kind": "absent", "path": quarantine}
    namespace_absent["observed"] = {"kind": "absent", "path": target}
    namespace_absent["evidence_paths"] = [intent, prior_path]
    namespace_reparse_regular = copy.deepcopy(conflict_namespace)
    namespace_reparse_regular["displaced"] = {
        "file_type": stat.S_IFREG,
        "kind": "reparse",
        "path": quarantine,
    }
    namespace_reparse_regular["observed"] = dict(regular_target)
    namespace_reparse_regular["evidence_paths"] = [intent, prior_path, target]
    namespace_reparse_absent = copy.deepcopy(namespace_reparse_regular)
    namespace_reparse_absent["observed"] = {"kind": "absent", "path": target}
    namespace_reparse_absent["evidence_paths"] = [intent, prior_path]
    quarantine_failed = {
        **common(),
        "endpoint_hashes": {"quarantine": None, "target": published_hash},
        "evidence_paths": [intent, prior_path, recovery + "/target-" + published_hash + ".bin"],
        "outcome": "quarantine-failed-closed",
    }
    quarantine_target_absent = copy.deepcopy(quarantine_failed)
    quarantine_target_absent["endpoint_hashes"]["target"] = None
    quarantine_target_absent["evidence_paths"].remove(
        recovery + "/target-" + published_hash + ".bin"
    )
    quarantine_target_other = copy.deepcopy(quarantine_failed)
    quarantine_target_other["endpoint_hashes"]["target"] = other_hash
    quarantine_target_other["evidence_paths"][-1] = recovery + "/target-" + other_hash + ".bin"
    unexpected = {
        **common(),
        "endpoints": {
            "quarantine": dict(regular_quarantine),
            "target": {"kind": "absent", "path": target},
        },
        "error_type": "OSError",
        "evidence_paths": sorted([intent, prior_path, quarantine]),
        "invalid_terminals": [],
        "outcome": "unexpected-exception",
    }
    fake_terminal = recovery + "/terminal-fake.json"
    unexpected_invalid = copy.deepcopy(unexpected)
    unexpected_invalid["evidence_paths"] = sorted(
        unexpected_invalid["evidence_paths"] + [fake_terminal]
    )
    unexpected_invalid["invalid_terminals"] = [
        {"file_type": stat.S_IFDIR, "kind": "directory", "path": fake_terminal}
    ]
    unexpected_overflow = copy.deepcopy(unexpected)
    unexpected_overflow["terminal_inventory"] = {
        "count_at_least": 10001,
        "limit": 10000,
    }
    return {
        "restored-existing": (b"prior", restored),
        "restored-absence": (None, restored_absence),
        "conflict-regular": (b"prior", conflict_regular),
        "conflict-matching-prior": (b"prior", conflict_matching_prior),
        "conflict-namespace": (b"prior", conflict_namespace),
        "namespace-absent": (b"prior", namespace_absent),
        "namespace-reparse-regular": (b"prior", namespace_reparse_regular),
        "namespace-reparse-absent": (b"prior", namespace_reparse_absent),
        "quarantine-failed": (b"prior", quarantine_failed),
        "quarantine-target-absent": (b"prior", quarantine_target_absent),
        "quarantine-target-other": (b"prior", quarantine_target_other),
        "unexpected": (b"prior", unexpected),
        "unexpected-invalid": (b"prior", unexpected_invalid),
        "unexpected-overflow": (b"prior", unexpected_overflow),
    }


def _write_focus(root, project_id, observed_at="2026-08-30T00:00:00Z"):
    path = Path(root) / ".agent-memory/state/focus" / (project_id + ".json")
    path.write_text(
        json.dumps(
            {
                "observed_at": observed_at,
                "project_id": project_id,
                "record_ids": [],
                "revision": 0,
                "schema_version": 2,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        "utf-8",
    )
    return path


class FocusUpdateTests(unittest.TestCase):
    def _accepted_root(self, temporary_directory):
        root = Path(temporary_directory) / "memory"
        initialize(root)
        first = commit_record(root, candidate(memory_id="memory-b"), 0, None, context("tx-record-b"))
        second = commit_record(
            root,
            candidate(memory_id="memory-a", body="second accepted body"),
            1,
            None,
            context("tx-record-a"),
        )
        self.assertEqual(("accepted", "accepted"), (first.status, second.status))
        return root

    def test_accepts_only_catalog_ids_and_writes_sorted_deduplicated_focus_once(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._accepted_root(temporary_directory)

            outcome = update_focus(
                root,
                "demo",
                0,
                ("memory-b", "memory-a", "memory-b"),
                "2026-08-30T01:02:03+08:00",
                context("tx-focus"),
            )

            self.assertEqual(("accepted", 1, None, None), (
                outcome.status,
                outcome.focus_revision,
                outcome.proposal_path,
                outcome.conflict_code,
            ))
            focus = _read_json(root / ".agent-memory/state/focus/demo.json")
            self.assertEqual(
                {
                    "observed_at": "2026-08-30T01:02:03+08:00",
                    "project_id": "demo",
                    "record_ids": ["memory-a", "memory-b"],
                    "revision": 1,
                    "schema_version": 2,
                },
                focus,
            )
            transaction = _read_json(root / ".agent-memory/transactions/tx-focus.json")
            self.assertEqual("update_focus", transaction["operation"])
            self.assertEqual("accepted", transaction["status"])
            self.assertEqual(1, transaction["focus_revision"])
            self.assertFalse(any(root.rglob("current-focus.md")))

    def test_invalid_timestamp_fails_before_any_byte_changes(self):
        invalid_values = (
            "2026-08-30T01:02:03",
            "2026-02-30T01:02:03Z",
            123,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._accepted_root(temporary_directory)
            for index, value in enumerate(invalid_values):
                with self.subTest(value=value):
                    before = tuple(
                        (path.relative_to(root).as_posix(), path.read_bytes())
                        for path in sorted(root.rglob("*"))
                        if path.is_file()
                    )
                    with self.assertRaises(ValidationError):
                        update_focus(
                            root,
                            "demo",
                            0,
                            ("memory-a",),
                            value,
                            context("tx-invalid-time-" + str(index)),
                        )
                    after = tuple(
                        (path.relative_to(root).as_posix(), path.read_bytes())
                        for path in sorted(root.rglob("*"))
                        if path.is_file()
                    )
                    self.assertEqual(before, after)

    def test_invalid_identifier_fails_before_mutation_and_missing_catalog_id_is_proposed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._accepted_root(temporary_directory)
            before = (root / ".agent-memory/state/focus/demo.json").read_bytes()

            for transaction_id, project_id, record_ids in (
                ("tx-bad-project", "../demo", ("memory-a",)),
                ("tx-bad-record", "demo", ("../memory",)),
            ):
                with self.subTest(transaction_id=transaction_id):
                    with self.assertRaises(ValidationError):
                        update_focus(
                            root,
                            project_id,
                            0,
                            record_ids,
                            "2026-08-30T00:00:00Z",
                            context(transaction_id),
                        )
                    self.assertFalse(
                        (root / ".agent-memory/transactions" / (transaction_id + ".json")).exists()
                    )

            outcome = update_focus(
                root,
                "demo",
                0,
                ("memory-missing",),
                "2026-08-30T00:00:00Z",
                context("tx-missing-record"),
            )
            self.assertEqual(("proposed", "missing-record-id", 0), (
                outcome.status,
                outcome.conflict_code,
                outcome.focus_revision,
            ))
            self.assertEqual(before, (root / ".agent-memory/state/focus/demo.json").read_bytes())
            proposal = _read_json(outcome.proposal_path)
            self.assertEqual("update_focus", proposal["operation"])
            self.assertEqual(["memory-missing"], proposal["desired"]["record_ids"])

    def test_stale_revision_and_project_lock_busy_preserve_proposals_without_markdown(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._accepted_root(temporary_directory)
            focus_path = root / ".agent-memory/state/focus/demo.json"
            before = focus_path.read_bytes()

            stale = update_focus(
                root,
                "demo",
                7,
                ("memory-a",),
                "2026-08-30T00:00:00Z",
                context("tx-focus-stale"),
            )
            self.assertEqual(("proposed", "stale-focus-revision", 0), (
                stale.status,
                stale.conflict_code,
                stale.focus_revision,
            ))

            lock_context = context("tx-focus-lock-holder")
            with root_write_guard(root, lock_context) as guard:
                with _narrow_lock(
                    root,
                    "focus--demo",
                    lock_context,
                    Path(".agent-memory/state/locks"),
                ):
                    busy = update_focus(
                        root,
                        "demo",
                        0,
                        ("memory-a",),
                        "2026-08-30T00:00:00Z",
                        lock_context,
                        guard=guard,
                    )
            self.assertEqual(("proposed", "occupied-lock", 0), (
                busy.status,
                busy.conflict_code,
                busy.focus_revision,
            ))
            self.assertEqual(
                {"focus_revision": 0},
                _read_json(busy.proposal_path)["observed_base"],
            )
            self.assertEqual(before, focus_path.read_bytes())
            self.assertFalse(any(root.rglob("*.md")) and any(root.rglob("current-focus.md")))
            self.assertFalse((root / ".agent-memory/locks/focus--demo.lock").exists())

    def test_other_project_focus_lock_does_not_block_demo_focus(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._accepted_root(temporary_directory)
            _write_focus(root, "other")
            owner = context("tx-other-lock")
            with root_write_guard(root, owner) as guard:
                with _narrow_lock(
                    root,
                    "focus--other",
                    owner,
                    Path(".agent-memory/state/locks"),
                ):
                    outcome = update_focus(
                        root,
                        "demo",
                        0,
                        ("memory-a",),
                        "2026-08-30T00:00:00Z",
                        owner,
                        guard=guard,
                    )
            self.assertEqual("accepted", outcome.status)

    def test_value_equal_guard_clone_is_rejected_by_every_task_five_writer_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._accepted_root(temporary_directory)
            owner = context("tx-cloned-writer")
            focus_before = (root / ".agent-memory/state/focus/demo.json").read_bytes()
            with root_write_guard(root, owner) as guard:
                clone = RootWriteGuard(guard.root, guard.lock_path, guard.token, guard.transaction_id)
                with self.assertRaises(LockBusyError):
                    commit_record(
                        root,
                        candidate(memory_id="clone-record"),
                        2,
                        None,
                        owner,
                        guard=clone,
                    )
                with self.assertRaises(LockBusyError):
                    update_focus(
                        root,
                        "demo",
                        0,
                        ("memory-a",),
                        "2026-08-30T00:00:00Z",
                        owner,
                        guard=clone,
                    )
                with self.assertRaises(LockBusyError):
                    preserve_promotion_candidate(
                        root,
                        PromotionCandidate(
                            "clone-promotion",
                            ("memory-a",),
                            "knowledge/demo",
                            "clone must not publish",
                        ),
                        owner,
                        guard=clone,
                    )
                document = build_project_focus(root, "demo", "generator-1")
                with self.assertRaises(LockBusyError):
                    publish_projection(root, document, owner, guard=clone)

            self.assertFalse(
                (root / ".agent-memory/transactions/tx-cloned-writer.json").exists()
            )
            self.assertFalse(
                (root / ".agent-memory/state/proposals/clone-promotion.json").exists()
            )
            self.assertEqual(focus_before, (root / ".agent-memory/state/focus/demo.json").read_bytes())
            self.assertFalse((root / "projects/demo/current-focus.md").exists())

    def test_root_guard_busy_preserves_root_write_busy_proposal(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._accepted_root(temporary_directory)
            before = (root / ".agent-memory/state/focus/demo.json").read_bytes()
            with root_write_guard(root, context("tx-root-holder")):
                outcome = update_focus(
                    root,
                    "demo",
                    0,
                    ("memory-a",),
                    "2026-08-30T00:00:00Z",
                    context("tx-root-contender"),
                )
            self.assertEqual(("proposed", "root-write-busy", 0), (
                outcome.status,
                outcome.conflict_code,
                outcome.focus_revision,
            ))
            self.assertEqual(before, (root / ".agent-memory/state/focus/demo.json").read_bytes())
            self.assertTrue(outcome.proposal_path.exists())
            self.assertEqual(
                {"focus_revision": 0},
                _read_json(outcome.proposal_path)["observed_base"],
            )

    def test_failure_after_focus_cas_retains_advanced_state_and_incomplete_intent(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._accepted_root(temporary_directory)
            original_finalize = transaction_module._finalize_transaction

            def fail_accepted_finalization(path, expected, final, transaction_id):
                document = json.loads(final.decode("utf-8"))
                if document.get("operation") == "update_focus" and document.get("status") == "accepted":
                    raise OSError("injected result finalization failure")
                return original_finalize(path, expected, final, transaction_id)

            with mock.patch.object(
                transaction_module,
                "_finalize_transaction",
                side_effect=fail_accepted_finalization,
            ):
                with self.assertRaises(OSError):
                    update_focus(
                        root,
                        "demo",
                        0,
                        ("memory-a",),
                        "2026-08-30T00:00:00Z",
                        context("tx-focus-crash"),
                    )

            self.assertEqual(1, _read_json(root / ".agent-memory/state/focus/demo.json")["revision"])
            intent = _read_json(root / ".agent-memory/transactions/tx-focus-crash.json")
            self.assertEqual("in-progress", intent["status"])
            self.assertEqual(1, intent["focus_cas"]["desired_revision"])
            self.assertFalse(any(root.rglob("current-focus.md")))


def _frontmatter(content):
    header, body = content.split("---\n", 2)[1:]
    fields = {}
    for line in header.splitlines():
        key, value = line.split(": ", 1)
        fields[key] = value
    return fields, body


def _append_operational_proposal(root, name="proposal-race", secret="do-not-echo"):
    path = Path(root) / ".agent-memory/state/proposals" / (name + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "actor": "test-agent",
                "conflict_code": "stale-focus-revision",
                "desired": {"secret": secret},
                "expected_base": {"focus_revision": 0},
                "observed_base": {"focus_revision": 1},
                "occurred_at": "2026-08-30T02:00:00Z",
                "operation": "update_focus",
                "schema_version": 2,
                "target": ".agent-memory/state/focus/demo.json",
                "transaction_id": name,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        "utf-8",
    )
    return path


class ProjectionTests(unittest.TestCase):
    def _projection_root(self, temporary_directory):
        root = Path(temporary_directory) / "memory"
        initialize(root)
        commits = (
            candidate(
                memory_id="story-demo",
                body="# Demo story\nDurable demo summary.",
                record_type="story",
                project="demo",
                owner_scope="project.demo.story",
            ),
            candidate(
                memory_id="decision-demo",
                body="# Demo decision\nUse canonical state.",
                record_type="decision",
                project="demo",
                owner_scope="project.demo.decision",
            ),
            candidate(
                memory_id="story-other",
                body="# Other story\nOther project summary.",
                record_type="story",
                project="other",
                owner_scope="project.other.story",
            ),
            candidate(
                memory_id="preference-global",
                body="# Preference\nPrefer deterministic bytes.",
                record_type="preference",
                project=None,
                owner_scope="user.preference",
            ),
        )
        for index, record_candidate in enumerate(commits):
            outcome = commit_record(
                root,
                record_candidate,
                index,
                None,
                context("tx-projection-record-" + str(index)),
            )
            self.assertEqual("accepted", outcome.status)
        update_focus(
            root,
            "demo",
            0,
            ("story-demo", "decision-demo"),
            "2026-08-30T01:00:00Z",
            context("tx-projection-focus-demo"),
        )
        _write_focus(root, "other", "2026-08-30T00:30:00Z")
        update_focus(
            root,
            "other",
            0,
            ("story-other",),
            "2026-08-30T01:30:00Z",
            context("tx-projection-focus-other"),
        )
        return root

    def _exercise_terminal_inventory_failure(
        self,
        temporary_directory,
        transaction_id,
        inject_terminal,
    ):
        root = self._projection_root(temporary_directory)
        initial = next(
            item
            for item in build_root_views(root, "generator-1")
            if item.relative_path == "_index/stale-or-uncertain.md"
        )
        publish_projection(root, initial, context(transaction_id + "-base"))
        document = next(
            item
            for item in build_root_views(root, "generator-1")
            if item.relative_path == "_index/stale-or-uncertain.md"
        )
        target = root / document.relative_path
        prior = target.read_bytes()
        recovery_directory = (
            root
            / ".agent-memory/transactions/projection-recovery"
            / hashlib.sha256(transaction_id.encode("utf-8")).hexdigest()
            / hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
        )
        original_description = projection_module._namespace_description
        inject_failure = False

        def projection_checkpoint(stage, memory_root, projection_target):
            if stage == "after-input-recheck":
                _append_operational_proposal(
                    memory_root,
                    "proposal-" + transaction_id,
                )

        def cas_checkpoint(stage, cas_target):
            nonlocal inject_failure
            if stage == "after-projection-quarantine":
                inject_terminal(
                    root,
                    recovery_directory,
                    document,
                    prior,
                )
                inject_failure = True

        def namespace_description(memory_root, path):
            nonlocal inject_failure
            if inject_failure and Path(path) == recovery_directory / "displaced.bin":
                inject_failure = False
                raise OSError("original rollback classification failure")
            return original_description(memory_root, path)

        with mock.patch.object(
            projection_module,
            "_projection_checkpoint",
            side_effect=projection_checkpoint,
        ), mock.patch.object(
            transaction_module,
            "_cas_checkpoint",
            side_effect=cas_checkpoint,
        ), mock.patch.object(
            projection_module,
            "_namespace_description",
            side_effect=namespace_description,
        ):
            with self.assertRaises(ConflictError):
                publish_projection(root, document, context(transaction_id))

        transaction = _read_json(
            _projection_transaction_path(
                root,
                transaction_id,
                document.relative_path,
            )
        )
        self.assertIn("projection_recovery", transaction)
        return root, document, prior, recovery_directory

    def _exercise_synthetic_terminal_inventory(
        self,
        temporary_directory,
        transaction_id,
        inventory,
    ):
        root = Path(temporary_directory) / "memory"
        root.mkdir()
        target = root / "_index/stale-or-uncertain.md"
        target.parent.mkdir()
        published = b"published"
        target.write_bytes(published)
        recovery_directory = (
            root
            / ".agent-memory/transactions/projection-recovery"
            / hashlib.sha256(transaction_id.encode("utf-8")).hexdigest()
            / hashlib.sha256(b"_index/stale-or-uncertain.md").hexdigest()
        )
        recovery_directory.mkdir(parents=True)
        (recovery_directory / "intent.json").write_bytes(b"{}\n")
        inventory_calls = []

        def terminal_inventory(*args, **kwargs):
            inventory_calls.append(True)
            return inventory

        with mock.patch.object(
            projection_module,
            "_rollback_projection_once",
            side_effect=OSError("synthetic rollback failure"),
        ), mock.patch.object(
            projection_module,
            "_terminal_inventory",
            side_effect=terminal_inventory,
        ):
            with self.assertRaises(ConflictError):
                projection_module._rollback_projection(
                    root,
                    target,
                    published,
                    None,
                    transaction_id,
                )
        terminals = sorted(recovery_directory.glob("terminal-*.json"))
        self.assertEqual(1, len(terminals))
        return root, target, recovery_directory, terminals[0], inventory_calls

    def test_projectless_initialized_root_builds_exact_four_deterministic_views(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize_memory_root(root, None, context("tx-init-projectless"))

            first = build_root_views(root, "generator-1")
            second = build_root_views(root, "generator-1")

            self.assertEqual(first, second)
            self.assertEqual(_ROOT_VIEW_PATHS_FOR_TEST, tuple(item.relative_path for item in first))
            self.assertTrue(
                all(item.observed_at == "2026-08-30T00:00:00Z" for item in first)
            )
            self.assertFalse((root / ".agent-memory/state/focus").exists())

            (root / ".agent-memory/state/focus").write_text("not a directory\n", "utf-8")
            with self.assertRaises(ValidationError):
                build_root_views(root, "generator-1")

    def test_builders_return_only_declared_views_in_lexical_order_from_accepted_owners(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)

            root_views = build_root_views(root, "generator-1")
            project_views = build_project_views(root, "demo", "generator-1")

            self.assertEqual(
                (
                    "_index/current-focus.md",
                    "_index/home.md",
                    "_index/memory-map.md",
                    "_index/stale-or-uncertain.md",
                ),
                tuple(document.relative_path for document in root_views),
            )
            self.assertEqual(
                (
                    "projects/demo/current-focus.md",
                    "projects/demo/overview.md",
                    "projects/demo/stories/story-demo.md",
                ),
                tuple(document.relative_path for document in project_views),
            )
            story = project_views[-1].content
            self.assertIn("story-demo", story)
            self.assertIn("Durable demo summary.", story)
            self.assertNotIn("story-other", story)
            global_focus = root_views[0].content
            self.assertLess(global_focus.index("demo"), global_focus.index("other"))
            self.assertIn("decision-demo", global_focus)
            self.assertIn("story-other", global_focus)

    def test_story_view_reverses_explicit_session_links_and_derives_time_range(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            before = next(
                item
                for item in build_project_views(root, "demo", "generator-1")
                if item.relative_path.endswith("story-demo.md")
            )
            commits = (
                _session_candidate("session-primary", "2026-09-01T10:00:00Z"),
                _session_candidate(
                    "session-date-only",
                    "2026-09-02T10:30:00Z",
                    primary_story_id=None,
                ),
                _session_candidate(
                    "session-related",
                    "2026-09-03T11:00:00Z",
                    status="failed",
                    primary_story_id=None,
                    related_story_ids=("story-demo",),
                ),
            )
            for offset, record_candidate in enumerate(commits, start=4):
                self.assertEqual(
                    "accepted",
                    commit_record(
                        root,
                        record_candidate,
                        offset,
                        None,
                        context("tx-" + record_candidate.envelope.memory_id),
                    ).status,
                )

            story = next(
                item
                for item in build_project_views(root, "demo", "generator-1")
                if item.relative_path.endswith("story-demo.md")
            )

            self.assertIn("## Session timeline", story.content)
            self.assertIn(
                "2026-09-01T10:00:00Z to 2026-09-03T11:00:00Z",
                story.content,
            )
            self.assertIn("session-primary` (completed, primary)", story.content)
            self.assertIn("session-related` (failed, related)", story.content)
            self.assertNotIn("session-date-only", story.content)
            self.assertNotEqual(before.source_revision, story.source_revision)

    def test_legacy_session_is_reported_unbound_without_inferred_story_membership(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            legacy = candidate(
                memory_id="session-legacy",
                body="# Session: Legacy work\n\n## Outcome\n\nNo explicit Story link.\n",
                record_type="session",
                project="demo",
                owner_scope="project.demo.session",
            )
            outcome = transaction_module._commit_record(
                root,
                legacy,
                4,
                None,
                context("tx-legacy-session"),
                allow_legacy_migration_session=True,
            )
            self.assertEqual("accepted", outcome.status)

            story = next(
                item
                for item in build_project_views(root, "demo", "generator-1")
                if item.relative_path.endswith("story-demo.md")
            )
            stale = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )

            self.assertNotIn("session-legacy", story.content)
            self.assertIn("session-legacy", stale.content)
            self.assertIn("legacy-session-unbound", stale.content)

    def test_pending_story_revision_proposal_is_shown_without_changing_session_membership(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            linked = _session_candidate("session-linked", "2026-09-01T10:00:00Z")
            self.assertEqual(
                "accepted",
                commit_record(
                    root,
                    linked,
                    4,
                    None,
                    context("tx-session-linked"),
                ).status,
            )
            winning = candidate(
                memory_id="story-demo",
                revision=2,
                supersedes="story-demo@1",
                body="# Demo story\nAccepted revision.",
                record_type="story",
                project="demo",
                owner_scope="project.demo.story",
            )
            self.assertEqual(
                "accepted",
                commit_record(
                    root,
                    winning,
                    5,
                    1,
                    context("tx-story-winner-for-delta"),
                ).status,
            )
            before_proposal = next(
                item
                for item in build_project_views(root, "demo", "generator-1")
                if item.relative_path.endswith("story-demo.md")
            )
            losing = candidate(
                memory_id="story-demo",
                revision=2,
                supersedes="story-demo@1",
                body="# Demo story\nConflicting Session delta.",
                record_type="story",
                project="demo",
                owner_scope="project.demo.story",
            )
            proposal = commit_record(
                root,
                losing,
                6,
                1,
                context("tx-story-delta-conflict"),
            )
            self.assertEqual("proposed", proposal.status)

            story = next(
                item
                for item in build_project_views(root, "demo", "generator-1")
                if item.relative_path.endswith("story-demo.md")
            )

            self.assertIn("session-linked` (completed, primary)", story.content)
            self.assertIn("## Pending Story updates", story.content)
            self.assertIn("tx-story-delta-conflict", story.content)
            self.assertIn("stale-record-revision", story.content)
            self.assertNotIn("Conflicting Session delta.", story.content)
            self.assertNotEqual(before_proposal.source_revision, story.source_revision)
            published = publish_projection(
                root,
                story,
                context("tx-publish-story-with-pending-delta"),
            )
            self.assertEqual(story.content, published.read_text("utf-8"))

    def test_story_browse_follows_catalog_winner_not_losing_immutable_revision(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            winner = candidate(
                memory_id="story-demo",
                revision=2,
                supersedes="story-demo@1",
                body="# Demo story\nWinning revision summary.",
                record_type="story",
                project="demo",
                owner_scope="project.demo.story",
            )
            outcome = commit_record(
                root,
                winner,
                4,
                1,
                context("tx-story-winner"),
            )
            self.assertEqual("accepted", outcome.status)

            story = next(
                document
                for document in build_project_views(root, "demo", "generator-1")
                if document.relative_path == "projects/demo/stories/story-demo.md"
            )
            self.assertIn("Winning revision summary.", story.content)
            self.assertIn("- Revision: 2", story.content)
            self.assertNotIn("Durable demo summary.", story.content)

    def test_catalog_selected_record_must_use_its_canonical_envelope_path(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            catalog_path = root / ".agent-memory/state/catalog.json"
            catalog = _read_json(catalog_path)
            canonical = root / catalog["records"]["story-demo"]["relative_path"]
            rogue_relative = "_records/rogue/story-demo-copy.md"
            rogue = root / rogue_relative
            rogue.parent.mkdir(parents=True)
            rogue.write_bytes(canonical.read_bytes())
            catalog["records"]["story-demo"]["relative_path"] = rogue_relative
            catalog_path.write_text(
                json.dumps(catalog, sort_keys=True, indent=2) + "\n",
                "utf-8",
            )

            with self.assertRaises(AgentMemoryError):
                build_project_views(root, "demo", "generator-1")
            self.assertFalse((root / "projects/demo/overview.md").exists())

    def test_frontmatter_body_hash_and_repeated_builds_are_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            first = build_project_focus(root, "demo", "generator-1")
            second = build_project_focus(root, "demo", "generator-1")

            self.assertEqual(first, second)
            self.assertEqual(
                "---\n"
                "generated: true\n"
                "projection_version: 2\n"
                "source_revision: 40c815d8b70675b472dc24ab489b48690d92e44d5ea5bda0cb38fb560a55e217\n"
                "observed_at: 2026-08-30T01:00:00Z\n"
                "generator_version: generator-1\n"
                "projection_body_sha256: ef865ef0d9955c3606a2a27dfe1976bc92387b19000e98e725d2d6f39dc4e7bc\n"
                "---\n"
                "# Current focus: demo\n"
                "\n"
                "- `decision-demo` (decision): Use canonical state.\n"
                "- `story-demo` (story): Durable demo summary.\n",
                first.content,
            )
            fields, body = _frontmatter(first.content)
            self.assertEqual("true", fields["generated"])
            self.assertEqual("2", fields["projection_version"])
            self.assertEqual(first.source_revision, fields["source_revision"])
            self.assertEqual("2026-08-30T01:00:00Z", fields["observed_at"])
            self.assertEqual("generator-1", fields["generator_version"])
            normalized_body = body.rstrip("\n") + "\n"
            self.assertEqual(
                hashlib.sha256(normalized_body.encode("utf-8")).hexdigest(),
                fields["projection_body_sha256"],
            )
            self.assertEqual(fields["observed_at"], first.observed_at)

    def test_builder_captures_target_hash_before_inputs_and_input_change_changes_bytes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            target = root / "_index/current-focus.md"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"existing projection bytes\n")

            before = build_global_focus(root, "generator-1")
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), before.expected_target_sha256)

            outcome = update_focus(
                root,
                "demo",
                1,
                ("decision-demo",),
                "2026-08-30T03:00:00Z",
                context("tx-projection-focus-change"),
            )
            self.assertEqual("accepted", outcome.status)
            after = build_global_focus(root, "generator-1")
            self.assertNotEqual(before.source_revision, after.source_revision)
            self.assertNotEqual(before.content, after.content)
            self.assertNotIn("story-demo", after.content)

    def test_home_tracks_every_accepted_owner_even_when_not_in_focus(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            before = next(
                document
                for document in build_root_views(root, "generator-1")
                if document.relative_path == "_index/home.md"
            )
            outcome = commit_record(
                root,
                candidate(
                    memory_id="decision-unfocused",
                    body="# Unfocused decision\nStill a durable owner.",
                    record_type="decision",
                    project="demo",
                    owner_scope="project.demo.decision",
                ),
                4,
                None,
                context("tx-unfocused-owner"),
            )
            self.assertEqual("accepted", outcome.status)

            after = next(
                document
                for document in build_root_views(root, "generator-1")
                if document.relative_path == "_index/home.md"
            )
            self.assertNotEqual(before.source_revision, after.source_revision)
            self.assertIn("decision-unfocused", after.content)
            self.assertIn("Still a durable owner.", after.content)

    def test_stale_uncertain_inventory_is_bounded_metadata_without_payload_echo(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            proposal = _append_operational_proposal(root)
            incomplete = root / ".agent-memory/transactions/incomplete-op.json"
            incomplete.write_text(
                json.dumps(
                    {
                        "actor": "test-agent",
                        "desired": {"secret": "transaction-secret"},
                        "expected_base": {},
                        "occurred_at": "2026-08-30T02:30:00Z",
                        "operation": "publish_projection",
                        "schema_version": 2,
                        "status": "in-progress",
                        "target": "_index/home.md",
                        "transaction_id": "incomplete-op",
                    },
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                "utf-8",
            )

            stale = next(
                document
                for document in build_root_views(root, "generator-1")
                if document.relative_path == "_index/stale-or-uncertain.md"
            )

            self.assertIn(proposal.relative_to(root).as_posix(), stale.content)
            self.assertIn("stale-focus-revision", stale.content)
            self.assertIn(incomplete.relative_to(root).as_posix(), stale.content)
            self.assertIn("in-progress", stale.content)
            self.assertNotIn("do-not-echo", stale.content)
            self.assertNotIn("transaction-secret", stale.content)

            malformed = root / ".agent-memory/state/proposals/malformed.json"
            malformed.write_bytes(b"{")
            with self.assertRaises(ValidationError):
                build_root_views(root, "generator-1")

    def test_operational_inventory_rejects_more_than_ten_thousand_entries(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            directory = root / ".agent-memory/state/proposals"
            directory.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                {
                    "actor": "test-agent",
                    "conflict_code": "bounded-test",
                    "desired": {},
                    "expected_base": {},
                    "observed_base": {},
                    "occurred_at": "2026-08-30T02:00:00Z",
                    "operation": "update_focus",
                    "schema_version": 2,
                    "target": ".agent-memory/state/focus/demo.json",
                    "transaction_id": "bounded-test",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            for index in range(10001):
                (directory / ("bounded-{0:05d}.json".format(index))).write_bytes(payload)

            with self.assertRaisesRegex(ValidationError, "exceeds 10000"):
                build_root_views(root, "generator-1")

    def test_operational_inputs_reject_oversize_before_open_and_use_bounded_reads(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            oversized = root / ".agent-memory/state/proposals/oversized.json"
            oversized.parent.mkdir(parents=True, exist_ok=True)
            oversized.write_bytes(b"{" + b" " * (1024 * 1024))
            original_open = Path.open

            def reject_oversized_open(path, *args, **kwargs):
                if Path(path) == oversized:
                    raise AssertionError("oversized operational input was opened")
                return original_open(path, *args, **kwargs)

            with mock.patch.object(Path, "open", autospec=True, side_effect=reject_oversized_open):
                with self.assertRaisesRegex(ValidationError, "exceeds 1048576 bytes"):
                    build_root_views(root, "generator-1")

            oversized.unlink()
            proposal = _append_operational_proposal(root, "bounded-reader")
            read_sizes = []

            class ReaderSpy:
                def __init__(self, stream):
                    self.stream = stream

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.stream.__exit__(*args)

                def read(self, size=-1):
                    read_sizes.append(size)
                    return self.stream.read(size)

            def spy_proposal_open(path, *args, **kwargs):
                stream = original_open(path, *args, **kwargs)
                if Path(path) == proposal:
                    return ReaderSpy(stream)
                return stream

            with mock.patch.object(Path, "open", autospec=True, side_effect=spy_proposal_open):
                raw = projection_module._read_operational_bytes(proposal)
            self.assertEqual(proposal.read_bytes(), raw)
            self.assertEqual([1024 * 1024 + 1], read_sizes)

    def test_normal_write_builder_reads_targets_and_generated_siblings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            target = root / "projects/demo/current-focus.md"
            sibling = root / "projects/demo/stories/generated-sibling.md"
            target.parent.mkdir(parents=True, exist_ok=True)
            sibling.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"existing target\n")
            sibling.write_bytes(b"existing generated sibling\n")
            observed = []
            original_read = projection_module._read_plain_bytes

            def observe_generated_reads(path):
                path = Path(path)
                if path in (target, sibling):
                    observed.append(path)
                return original_read(path)

            with mock.patch.object(
                projection_module,
                "_read_plain_bytes",
                side_effect=observe_generated_reads,
            ):
                build_project_views(root, "demo", "generator-1")

            self.assertEqual({target, sibling}, set(observed))

    def test_doctor_snapshot_builder_matches_every_healthy_target_class(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            target_paths = _ROOT_VIEW_PATHS_FOR_TEST + (
                "projects/demo/current-focus.md",
                "projects/demo/overview.md",
                "projects/demo/stories/story-demo.md",
            )
            observed_bytes = b"doctor-observed-target\n"
            observed_sha256 = hashlib.sha256(observed_bytes).hexdigest()
            for relative_path in target_paths:
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(observed_bytes)

            normal_documents = {
                document.relative_path: document
                for document in build_root_views(root, "generator-1")
                + build_project_views(root, "demo", "generator-1")
            }
            builder = projection_module.build_projection_from_observed_target

            for relative_path in target_paths:
                with self.subTest(relative_path=relative_path):
                    observed = builder(
                        root,
                        relative_path,
                        "generator-1",
                        observed_sha256,
                    )
                    self.assertEqual(normal_documents[relative_path], observed)

    def test_doctor_snapshot_builder_never_opens_target_or_generated_sibling(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            target = root / "projects/demo/stories/story-demo.md"
            sibling = root / "projects/demo/stories/generated-sibling.md"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"observed target\n")
            sibling.write_bytes(b"generated sibling must remain opaque\n")
            target_bytes = target.read_bytes()
            sibling_bytes = sibling.read_bytes()
            observed_sha256 = hashlib.sha256(target_bytes).hexdigest()
            generated_paths = {target, sibling}
            opened = []
            locks_before = tuple(
                sorted((root / ".agent-memory/state/locks").glob("*.lock"))
            )
            original_descriptor_open = projection_module._open_projection_snapshot_descriptor
            original_read_bytes = Path.read_bytes

            def observe_descriptor_open(path):
                path = Path(path)
                if path in generated_paths:
                    raise AssertionError("doctor opened a generated page")
                opened.append(path)
                return original_descriptor_open(path)

            def reject_generated_read_bytes(path):
                if Path(path) in generated_paths:
                    raise AssertionError("doctor bypassed its snapshot reader")
                return original_read_bytes(path)

            with mock.patch.object(
                projection_module,
                "_open_projection_snapshot_descriptor",
                side_effect=observe_descriptor_open,
            ), mock.patch.object(
                Path,
                "read_bytes",
                autospec=True,
                side_effect=reject_generated_read_bytes,
            ):
                document = projection_module.build_projection_from_observed_target(
                    root,
                    "projects/demo/stories/story-demo.md",
                    "generator-1",
                    observed_sha256,
                )

            self.assertEqual(observed_sha256, document.expected_target_sha256)
            self.assertTrue(opened)
            self.assertTrue(generated_paths.isdisjoint(opened))
            self.assertEqual(target_bytes, target.read_bytes())
            self.assertEqual(sibling_bytes, sibling.read_bytes())
            self.assertEqual(
                locks_before,
                tuple(sorted((root / ".agent-memory/state/locks").glob("*.lock"))),
            )

    def test_doctor_snapshot_builder_validates_target_generator_and_observed_hash(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            valid_hash = "a" * 64
            invalid_calls = (
                ("../current-focus.md", "generator-1", valid_hash),
                ("_index/current-focus.md", "../generator", valid_hash),
                ("_index/current-focus.md", "generator-1", "A" * 64),
                ("_index/current-focus.md", "generator-1", "a" * 63),
            )
            for relative_path, generator_version, observed_hash in invalid_calls:
                with self.subTest(
                    relative_path=relative_path,
                    generator_version=generator_version,
                    observed_hash=observed_hash,
                ):
                    with self.assertRaises(ValidationError):
                        projection_module.build_projection_from_observed_target(
                            root,
                            relative_path,
                            generator_version,
                            observed_hash,
                        )

    def test_doctor_snapshot_builder_rejects_oversize_sources_before_decode(self):
        cases = (
            "catalog",
            "record",
            "focus",
            "initialization",
            "operational",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary_directory:
                root = self._projection_root(temporary_directory)
                target_path = "_index/home.md"
                if case == "catalog":
                    source = root / ".agent-memory/state/catalog.json"
                elif case == "record":
                    catalog = _read_json(root / ".agent-memory/state/catalog.json")
                    source = root / catalog["records"]["story-demo"]["relative_path"]
                elif case == "focus":
                    source = root / ".agent-memory/state/focus/demo.json"
                elif case == "initialization":
                    source = next(
                        path
                        for path in (root / ".agent-memory/transactions").glob("*.json")
                        if _read_json(path).get("operation") == "initialize"
                    )
                else:
                    source = _append_operational_proposal(root, "doctor-oversize")
                    target_path = "_index/stale-or-uncertain.md"
                source.write_bytes(b"{" + b" " * (1024 * 1024))

                with self.assertRaisesRegex(
                    ValidationError,
                    "snapshot input exceeds 1048576 bytes",
                ):
                    projection_module.build_projection_from_observed_target(
                        root,
                        target_path,
                        "generator-1",
                        "a" * 64,
                    )

    def test_doctor_snapshot_builder_rejects_reparse_and_identity_race(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            catalog_path = root / ".agent-memory/state/catalog.json"
            catalog = _read_json(catalog_path)
            record_path = root / catalog["records"]["story-demo"]["relative_path"]
            original_lstat = projection_module._projection_snapshot_lstat

            class ReparseMetadata:
                def __init__(self, source):
                    self.st_mode = source.st_mode
                    self.st_dev = source.st_dev
                    self.st_ino = source.st_ino
                    self.st_size = source.st_size
                    self.st_file_attributes = getattr(
                        source,
                        "st_file_attributes",
                        0,
                    ) | getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

            def report_record_as_reparse(path):
                metadata = original_lstat(path)
                if Path(path) == record_path:
                    return ReparseMetadata(metadata)
                return metadata

            with mock.patch.object(
                projection_module,
                "_projection_snapshot_lstat",
                side_effect=report_record_as_reparse,
            ):
                with self.assertRaisesRegex(ValidationError, "reparse"):
                    projection_module.build_projection_from_observed_target(
                        root,
                        "_index/home.md",
                        "generator-1",
                        "a" * 64,
                    )

            original_open = projection_module._open_projection_snapshot_descriptor
            original_catalog = catalog_path.read_bytes()
            replaced = []

            def replace_catalog_before_open(path):
                path = Path(path)
                if path == catalog_path and not replaced:
                    path.replace(path.with_name(path.name + ".race-original"))
                    path.write_bytes(original_catalog)
                    replaced.append(True)
                return original_open(path)

            with mock.patch.object(
                projection_module,
                "_open_projection_snapshot_descriptor",
                side_effect=replace_catalog_before_open,
            ):
                with self.assertRaisesRegex(ValidationError, "identity changed"):
                    projection_module.build_projection_from_observed_target(
                        root,
                        "_index/home.md",
                        "generator-1",
                        "a" * 64,
                    )

    def test_doctor_snapshot_builder_opens_each_unique_source_once(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initialization_path = next(
                path
                for path in (root / ".agent-memory/transactions").glob("*.json")
                if _read_json(path).get("operation") == "initialize"
            )
            opened = []
            original_open = projection_module._open_projection_snapshot_descriptor

            def observe_open(path):
                opened.append(Path(path))
                return original_open(path)

            with mock.patch.object(
                projection_module,
                "_open_projection_snapshot_descriptor",
                side_effect=observe_open,
            ):
                projection_module.build_projection_from_observed_target(
                    root,
                    "_index/stale-or-uncertain.md",
                    "generator-1",
                    "a" * 64,
                )

            self.assertEqual(1, opened.count(initialization_path))
            self.assertEqual(len(opened), len(set(opened)))

    def test_snapshot_reader_preserves_primary_failure_when_close_also_fails(self):
        cases = (
            ("read", "unable to read projection snapshot input"),
            ("oversize", "projection snapshot input exceeds 1048576 bytes"),
        )
        for case, expected_message in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary_directory:
                root = self._projection_root(temporary_directory)
                catalog_path = root / ".agent-memory/state/catalog.json"
                if case == "oversize":
                    catalog_path.write_bytes(b"{" + b" " * (1024 * 1024))
                close_calls = []
                original_close = os.close

                def close_then_fail(descriptor):
                    close_calls.append(descriptor)
                    original_close(descriptor)
                    raise OSError("injected close failure")

                read_patch = (
                    mock.patch.object(
                        projection_module.os,
                        "read",
                        side_effect=OSError("injected read failure"),
                    )
                    if case == "read"
                    else mock.patch.object(
                        projection_module.os,
                        "read",
                        wraps=projection_module.os.read,
                    )
                )
                with read_patch, mock.patch.object(
                    projection_module.os,
                    "close",
                    side_effect=close_then_fail,
                ):
                    with self.assertRaisesRegex(ValidationError, expected_message):
                        projection_module._ProjectionSnapshotReader(root).read(
                            ".agent-memory/state/catalog.json"
                        )

                self.assertEqual(1, len(close_calls))

    def test_snapshot_reader_reports_close_failure_after_success_and_closes_once(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            close_calls = []
            original_close = os.close

            def close_then_fail(descriptor):
                close_calls.append(descriptor)
                original_close(descriptor)
                raise OSError("injected host detail")

            with mock.patch.object(
                projection_module.os,
                "close",
                side_effect=close_then_fail,
            ):
                with self.assertRaisesRegex(
                    ValidationError,
                    "unable to close projection snapshot input",
                ) as captured:
                    projection_module._ProjectionSnapshotReader(root).read(
                        ".agent-memory/state/catalog.json"
                    )

            self.assertNotIn("injected host detail", str(captured.exception))
            self.assertEqual(1, len(close_calls))

    def test_snapshot_reader_does_not_confuse_ambient_exception_with_primary_failure(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            reader = projection_module._ProjectionSnapshotReader(root)
            relative_path = ".agent-memory/state/catalog.json"
            close_calls = []
            original_close = os.close

            def close_then_fail(descriptor):
                close_calls.append(descriptor)
                original_close(descriptor)
                raise OSError("injected ambient close failure")

            try:
                raise RuntimeError("unrelated outer exception")
            except RuntimeError:
                with mock.patch.object(
                    projection_module.os,
                    "close",
                    side_effect=close_then_fail,
                ):
                    with self.assertRaisesRegex(
                        ValidationError,
                        "unable to close projection snapshot input",
                    ) as captured:
                        reader.read(relative_path)

            self.assertNotIn("injected ambient close failure", str(captured.exception))
            self.assertNotIn(relative_path, reader._cache)
            self.assertEqual(1, len(close_calls))

    def test_doctor_snapshot_builder_bounds_catalog_inventory_before_record_reads(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            catalog_path = root / ".agent-memory/state/catalog.json"
            catalog_path.write_text(
                json.dumps(
                    {
                        "records": {
                            "inventory-{0:05d}".format(index): {}
                            for index in range(10001)
                        },
                        "revision": 1,
                        "schema_version": 2,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                "utf-8",
            )
            opened = []
            original_open = projection_module._open_projection_snapshot_descriptor

            def observe_open(path):
                opened.append(Path(path))
                return original_open(path)

            with mock.patch.object(
                projection_module,
                "_open_projection_snapshot_descriptor",
                side_effect=observe_open,
            ):
                with self.assertRaisesRegex(ValidationError, "catalog inventory exceeds 10000"):
                    projection_module.build_projection_from_observed_target(
                        root,
                        "_index/home.md",
                        "generator-1",
                        "a" * 64,
                    )

            self.assertEqual([catalog_path], opened)

    def test_doctor_snapshot_builder_bounds_focus_init_and_operational_inventories(self):
        cases = ("focus", "initialization", "operational")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary_directory:
                root = self._projection_root(temporary_directory)
                if case == "focus":
                    directory = root / ".agent-memory/state/focus"
                    existing = len(tuple(directory.glob("*.json")))
                    for index in range(10001 - existing):
                        (directory / ("overflow-{0:05d}.json".format(index))).touch()
                    namespace = directory
                    target_path = "_index/home.md"
                    message = "focus inventory exceeds 10000"
                elif case == "initialization":
                    directory = root / ".agent-memory/transactions"
                    existing = len(tuple(directory.glob("*.json")))
                    for index in range(10001 - existing):
                        (directory / ("overflow-{0:05d}.json".format(index))).touch()
                    namespace = directory
                    target_path = "_index/home.md"
                    message = "initialization inventory exceeds 10000"
                else:
                    directory = root / ".agent-memory/state/proposals"
                    directory.mkdir(parents=True, exist_ok=True)
                    for index in range(10001):
                        (directory / ("overflow-{0:05d}.json".format(index))).touch()
                    namespace = directory
                    target_path = "_index/stale-or-uncertain.md"
                    message = "operational inventory exceeds 10000"
                opened = []
                original_open = projection_module._open_projection_snapshot_descriptor

                def observe_open(path):
                    opened.append(Path(path))
                    return original_open(path)

                with mock.patch.object(
                    projection_module,
                    "_open_projection_snapshot_descriptor",
                    side_effect=observe_open,
                ):
                    with self.assertRaisesRegex(ValidationError, message):
                        projection_module.build_projection_from_observed_target(
                            root,
                            target_path,
                            "generator-1",
                            "a" * 64,
                        )

                self.assertFalse(any(path.parent == namespace for path in opened))

    def test_publish_absent_target_uses_no_replace_and_finalizes_transaction(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            document = build_project_focus(root, "demo", "generator-1")
            self.assertIsNone(document.expected_target_sha256)
            original_replace = transaction_module._replace_cas
            observed_projection_locks = []

            def reject_absent_projection_replace(target, expected, content, token, root=None):
                if Path(target).as_posix().endswith("projects/demo/current-focus.md"):
                    raise AssertionError("absent projection went through replace CAS")
                return original_replace(target, expected, content, token, root=root)

            def capture_lock(stage, memory_root, projection_target):
                if stage == "after-target-replace":
                    observed_projection_locks.extend(
                        path.name
                        for path in (Path(memory_root) / ".agent-memory/state/locks").glob(
                            "projection--*.lock"
                        )
                    )

            with mock.patch.object(
                transaction_module,
                "_replace_cas",
                side_effect=reject_absent_projection_replace,
            ), mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=capture_lock,
            ):
                published = publish_projection(
                    root,
                    document,
                    context("tx-publish-absent"),
                )

            self.assertEqual(document.content.encode("utf-8"), published.read_bytes())
            self.assertEqual(
                [
                    "projection--{0}.lock".format(
                        hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
                    )
                ],
                observed_projection_locks,
            )
            transaction = _read_json(
                _projection_transaction_path(
                    root,
                    "tx-publish-absent",
                    document.relative_path,
                )
            )
            self.assertEqual("publish_projection", transaction["operation"])
            self.assertEqual("accepted", transaction["status"])
            self.assertEqual(document.source_revision, transaction["desired"]["source_revision"])
            self.assertIsNone(transaction["expected_base"]["target_sha256"])
            self.assertEqual(
                hashlib.sha256(document.content.encode("utf-8")).hexdigest(),
                transaction["desired"]["target_sha256"],
            )

    def test_manual_drift_requires_authorization_and_is_backed_up_before_replacement(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = build_project_focus(root, "demo", "generator-1")
            target = publish_projection(root, initial, context("tx-publish-initial"))
            stale_document = build_project_focus(root, "demo", "generator-1")
            target.write_text(target.read_text("utf-8") + "manual edit\n", "utf-8")
            manual_bytes = target.read_bytes()
            backup = root / ".agent-memory/transactions/projection-drift" / (
                hashlib.sha256(manual_bytes).hexdigest() + ".md"
            )

            with self.assertRaises(ConflictError):
                publish_projection(root, stale_document, context("tx-publish-drift-stale"))
            with self.assertRaises(ConflictError):
                publish_projection(
                    root,
                    stale_document,
                    context("tx-publish-drift-stale-approved"),
                    replace_drift=True,
                )
            self.assertEqual(manual_bytes, target.read_bytes())
            self.assertFalse(backup.exists())

            document = build_project_focus(root, "demo", "generator-1")
            with self.assertRaises(ProjectionDriftError):
                publish_projection(root, document, context("tx-publish-drift-refused"))
            self.assertEqual(manual_bytes, target.read_bytes())
            self.assertFalse(backup.exists())

            published = publish_projection(
                root,
                document,
                context("tx-publish-drift-approved"),
                replace_drift=True,
            )
            self.assertEqual(manual_bytes, backup.read_bytes())
            self.assertEqual(document.content, published.read_text("utf-8"))

    def test_intact_target_hash_conflict_and_stale_input_never_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = build_project_focus(root, "demo", "generator-1")
            target = publish_projection(root, initial, context("tx-publish-base"))
            document = build_project_focus(root, "demo", "generator-1")
            intact_changed = target.read_text("utf-8").replace(
                "generator_version: generator-1",
                "generator_version: generator-x",
            )
            target.write_text(intact_changed, "utf-8")
            with self.assertRaises(ConflictError):
                publish_projection(root, document, context("tx-publish-target-stale"))
            self.assertEqual(intact_changed, target.read_text("utf-8"))

            target.write_text(initial.content, "utf-8")
            stale_document = build_project_focus(root, "demo", "generator-1")
            update_focus(
                root,
                "demo",
                1,
                ("decision-demo",),
                "2026-08-30T03:00:00Z",
                context("tx-input-change"),
            )
            unchanged_target = target.read_bytes()
            with self.assertRaises(ConflictError):
                publish_projection(root, stale_document, context("tx-publish-input-stale"))
            self.assertEqual(unchanged_target, target.read_bytes())

    def test_publish_rejects_non_view_targets_and_tampered_document_before_target_mutation(self):
        invalid_paths = (
            "/absolute.md",
            "../escape.md",
            "_records/record.md",
            "_sources/source.md",
            ".agent-memory/state/catalog.json",
            "_index/unknown.md",
            "projects/demo/unknown.md",
            "projects/demo/stories/../escape.md",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            document = build_project_focus(root, "demo", "generator-1")
            before = tuple(
                (path.relative_to(root).as_posix(), path.read_bytes())
                for path in sorted(root.rglob("*"))
                if path.is_file()
            )
            for index, invalid_path in enumerate(invalid_paths):
                with self.subTest(invalid_path=invalid_path):
                    with self.assertRaises(ValidationError):
                        publish_projection(
                            root,
                            replace(document, relative_path=invalid_path),
                            context("tx-invalid-target-" + str(index)),
                        )
            fields, body = _frontmatter(document.content)
            tampered_body = body.replace("Durable demo summary.", "Different valid summary.")
            tampered_hash = hashlib.sha256(
                (tampered_body.rstrip("\n") + "\n").encode("utf-8")
            ).hexdigest()
            tampered_content = document.content.replace(
                "projection_body_sha256: " + fields["projection_body_sha256"],
                "projection_body_sha256: " + tampered_hash,
            ).replace(body, tampered_body)
            with self.assertRaises(ConflictError):
                publish_projection(
                    root,
                    replace(document, content=tampered_content),
                    context("tx-tampered-document"),
                )
            rejected_transaction = _projection_transaction_path(
                root,
                "tx-tampered-document",
                document.relative_path,
            )
            after_targets = tuple(
                (path.relative_to(root).as_posix(), path.read_bytes())
                for path in sorted(root.rglob("*"))
                if path.is_file() and path != rejected_transaction
            )
            self.assertEqual(before, after_targets)

    def test_supplied_guard_requires_exact_live_object_actor_and_occurrence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            document = build_project_focus(root, "demo", "generator-1")
            owner = context("tx-projection-guard")
            with root_write_guard(root, owner) as guard:
                clone = RootWriteGuard(guard.root, guard.lock_path, guard.token, guard.transaction_id)
                for supplied_guard, supplied_context in (
                    (clone, owner),
                    (guard, TransactionContext(owner.transaction_id, "other-agent", owner.occurred_at)),
                    (guard, TransactionContext(owner.transaction_id, owner.actor, "2026-08-30T00:00:01Z")),
                ):
                    with self.subTest(supplied_guard=supplied_guard, supplied_context=supplied_context):
                        with self.assertRaises(LockBusyError):
                            publish_projection(
                                root,
                                document,
                                supplied_context,
                                guard=supplied_guard,
                            )
                        self.assertFalse(
                            _projection_transaction_path(
                                root,
                                owner.transaction_id,
                                document.relative_path,
                            ).exists()
                        )

                published = publish_projection(root, document, owner, guard=guard)
                self.assertEqual(document.content, published.read_text("utf-8"))

    def test_one_guard_context_publishes_distinct_targets_and_replays_exact_target(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            documents = build_project_views(root, "demo", "generator-1")[:2]
            owner = context("tx-projection-batch")
            with root_write_guard(root, owner) as guard:
                published = tuple(
                    publish_projection(root, document, owner, guard=guard)
                    for document in documents
                )
                transaction_bytes = tuple(
                    _projection_transaction_path(
                        root,
                        owner.transaction_id,
                        document.relative_path,
                    ).read_bytes()
                    for document in documents
                )
                replayed = publish_projection(root, documents[0], owner, guard=guard)

            self.assertEqual(tuple(root / item.relative_path for item in documents), published)
            self.assertEqual(published[0], replayed)
            self.assertEqual(
                transaction_bytes,
                tuple(
                    _projection_transaction_path(
                        root,
                        owner.transaction_id,
                        document.relative_path,
                    ).read_bytes()
                    for document in documents
                ),
            )
            for document in documents:
                evidence = _read_json(
                    _projection_transaction_path(
                        root,
                        owner.transaction_id,
                        document.relative_path,
                    )
                )
                self.assertEqual("accepted", evidence["status"])
                self.assertEqual(document.relative_path, evidence["target"])
                self.assertEqual(
                    hashlib.sha256(document.content.encode("utf-8")).hexdigest(),
                    evidence["desired"]["target_sha256"],
                )

    def test_unguarded_context_is_bound_to_one_target_before_second_intent_or_target(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            documents = build_project_views(root, "demo", "generator-1")[:2]
            owner = context("tx-unguarded-context")
            first_target = publish_projection(root, documents[0], owner)
            first_transaction = _projection_transaction_path(
                root,
                owner.transaction_id,
                documents[0].relative_path,
            )
            second_target = root / documents[1].relative_path
            second_transaction = _projection_transaction_path(
                root,
                owner.transaction_id,
                documents[1].relative_path,
            )
            first_transaction_bytes = first_transaction.read_bytes()

            with self.assertRaises(ConflictError):
                publish_projection(root, documents[1], owner)

            self.assertEqual(documents[0].content.encode("utf-8"), first_target.read_bytes())
            self.assertEqual(first_transaction_bytes, first_transaction.read_bytes())
            self.assertFalse(second_target.exists())
            self.assertFalse(second_transaction.exists())

    def test_accepted_projection_replay_rejects_oversize_before_open_or_target_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            document = build_project_focus(root, "demo", "generator-1")
            owner = context("tx-oversized-replay")
            target = publish_projection(root, document, owner)
            target_bytes = target.read_bytes()
            transaction_path = _projection_transaction_path(
                root,
                owner.transaction_id,
                document.relative_path,
            )
            transaction_path.write_bytes(b"{" + b" " * (1024 * 1024))
            original_open = Path.open

            def reject_transaction_open(path, *args, **kwargs):
                if Path(path) == transaction_path:
                    raise AssertionError("oversized accepted transaction was opened")
                return original_open(path, *args, **kwargs)

            with mock.patch.object(
                Path,
                "open",
                autospec=True,
                side_effect=reject_transaction_open,
            ):
                with self.assertRaisesRegex(ValidationError, "exceeds 1048576 bytes"):
                    publish_projection(root, document, owner)

            self.assertEqual(target_bytes, target.read_bytes())
            self.assertEqual(1024 * 1024 + 1, transaction_path.stat().st_size)

    def test_busy_root_rejects_before_target_lock_or_drift_backup(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = build_project_focus(root, "demo", "generator-1")
            target = publish_projection(root, initial, context("tx-busy-base"))
            target.write_text(target.read_text("utf-8") + "manual\n", "utf-8")
            document = build_project_focus(root, "demo", "generator-1")
            lock_directory = root / ".agent-memory/state/locks"
            drift_directory = root / ".agent-memory/transactions/projection-drift"
            with root_write_guard(root, context("tx-busy-holder")):
                with self.assertRaises(LockBusyError):
                    publish_projection(
                        root,
                        document,
                        context("tx-busy-publisher"),
                        replace_drift=True,
                    )
                self.assertEqual([], list(lock_directory.glob("projection--*.lock")))
                self.assertFalse(drift_directory.exists())

    def test_operational_race_rolls_back_prior_target_without_removing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = next(
                document
                for document in build_root_views(root, "generator-1")
                if document.relative_path == "_index/stale-or-uncertain.md"
            )
            target = publish_projection(root, initial, context("tx-stale-base"))
            prior_bytes = target.read_bytes()
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )

            def checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-after-recheck")

            with mock.patch.object(projection_module, "_projection_checkpoint", side_effect=checkpoint):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-stale-race"))

            self.assertEqual(prior_bytes, target.read_bytes())
            self.assertTrue(
                (root / ".agent-memory/state/proposals/proposal-after-recheck.json").exists()
            )

    def test_operational_race_restores_prior_absence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            target = root / document.relative_path
            self.assertFalse(target.exists())

            def checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-absence-race")

            with mock.patch.object(projection_module, "_projection_checkpoint", side_effect=checkpoint):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-absence-race"))

            self.assertFalse(target.exists())
            self.assertTrue(
                (root / ".agent-memory/state/proposals/proposal-absence-race.json").exists()
            )

    def test_noncooperating_edit_inside_restore_existing_is_preserved_with_recovery(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            target = publish_projection(root, initial, context("tx-rollback-existing-base"))
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            prior_bytes = target.read_bytes()
            noncooperating_bytes = b"non-cooperating restore-existing edit\n"

            def projection_checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-restore-existing-race")

            def cas_checkpoint(stage, cas_target):
                if stage == "before-projection-quarantine" and Path(cas_target) == target:
                    _noncooperating_write(target, noncooperating_bytes)

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=projection_checkpoint,
            ), mock.patch.object(
                transaction_module,
                "_cas_checkpoint",
                side_effect=cas_checkpoint,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-restore-existing-window"))

            self.assertEqual(noncooperating_bytes, target.read_bytes())
            transaction = _read_json(
                _projection_transaction_path(
                    root,
                    "tx-restore-existing-window",
                    document.relative_path,
                )
            )
            recovery = transaction["projection_recovery"]
            self.assertEqual("rollback-target-drift", recovery["failure_code"])
            self.assertEqual(hashlib.sha256(prior_bytes).hexdigest(), recovery["prior_sha256"])
            self.assertEqual(hashlib.sha256(noncooperating_bytes).hexdigest(), recovery["observed_sha256"])
            self.assertTrue(recovery["evidence_paths"])

    def test_noncooperating_edit_inside_restore_absence_is_preserved_with_recovery(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            target = root / document.relative_path
            noncooperating_bytes = b"non-cooperating restore-absence edit\n"

            def projection_checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-restore-absence-race")

            def cas_checkpoint(stage, cas_target):
                if stage == "before-projection-quarantine" and Path(cas_target) == target:
                    _noncooperating_write(target, noncooperating_bytes)

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=projection_checkpoint,
            ), mock.patch.object(
                transaction_module,
                "_cas_checkpoint",
                side_effect=cas_checkpoint,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-restore-absence-window"))

            self.assertEqual(noncooperating_bytes, target.read_bytes())
            transaction = _read_json(
                _projection_transaction_path(
                    root,
                    "tx-restore-absence-window",
                    document.relative_path,
                )
            )
            recovery = transaction["projection_recovery"]
            self.assertEqual("rollback-target-drift", recovery["failure_code"])
            self.assertEqual(document.relative_path, recovery["target"])
            self.assertIsNone(recovery["prior_sha256"])
            self.assertEqual(hashlib.sha256(noncooperating_bytes).hexdigest(), recovery["observed_sha256"])
            self.assertTrue(recovery["evidence_paths"])
            self.assertNotIn("content", recovery)

    def test_noncooperating_edit_after_quarantine_is_never_replaced_by_rollback(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            publish_projection(root, initial, context("tx-quarantine-race-base"))
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            target = root / document.relative_path
            noncooperating_bytes = b"non-cooperating post-quarantine edit\n"

            def projection_checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-post-quarantine-race")

            def cas_checkpoint(stage, cas_target):
                if stage == "after-projection-quarantine" and Path(cas_target) == target:
                    target.write_bytes(noncooperating_bytes)

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=projection_checkpoint,
            ), mock.patch.object(
                transaction_module,
                "_cas_checkpoint",
                side_effect=cas_checkpoint,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-post-quarantine-race"))

            self.assertEqual(noncooperating_bytes, target.read_bytes())
            recovery_directory = (
                root
                / ".agent-memory/transactions/projection-recovery"
                / hashlib.sha256(b"tx-post-quarantine-race").hexdigest()
                / hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
            )
            self.assertEqual(document.content.encode("utf-8"), (recovery_directory / "displaced.bin").read_bytes())
            transaction = _read_json(
                _projection_transaction_path(
                    root,
                    "tx-post-quarantine-race",
                    document.relative_path,
                )
            )
            self.assertTrue(transaction["projection_recovery"]["evidence_paths"])

    def test_nonregular_entry_before_quarantine_is_restored_and_terminalized(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            publish_projection(root, initial, context("tx-nonregular-before-base"))
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            target = root / document.relative_path

            def projection_checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-nonregular-before")

            def cas_checkpoint(stage, cas_target):
                if stage == "before-projection-quarantine" and Path(cas_target) == target:
                    target.unlink()
                    target.mkdir()
                    (target / "sentinel.txt").write_text("directory entry survives\n", "utf-8")

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=projection_checkpoint,
            ), mock.patch.object(
                transaction_module,
                "_cas_checkpoint",
                side_effect=cas_checkpoint,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-nonregular-before"))

            self.assertTrue(target.is_dir())
            self.assertEqual("directory entry survives\n", (target / "sentinel.txt").read_text("utf-8"))
            recovery_directory = (
                root
                / ".agent-memory/transactions/projection-recovery"
                / hashlib.sha256(b"tx-nonregular-before").hexdigest()
                / hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
            )
            terminals = tuple(recovery_directory.glob("terminal-*.json"))
            self.assertEqual(1, len(terminals))
            terminal = _read_json(terminals[0])
            self.assertEqual("directory", terminal["displaced"]["kind"])
            self.assertEqual("conflict-preserved", terminal["outcome"])
            transaction = _read_json(
                _projection_transaction_path(
                    root,
                    "tx-nonregular-before",
                    document.relative_path,
                )
            )
            self.assertTrue(transaction["projection_recovery"]["evidence_paths"])

    def test_nonregular_entry_after_quarantine_is_retained_and_terminalized(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            publish_projection(root, initial, context("tx-nonregular-after-base"))
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            target = root / document.relative_path

            def projection_checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-nonregular-after")

            def cas_checkpoint(stage, cas_target):
                if stage == "after-projection-quarantine" and Path(cas_target) == target:
                    target.mkdir()
                    (target / "sentinel.txt").write_text("late directory survives\n", "utf-8")

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=projection_checkpoint,
            ), mock.patch.object(
                transaction_module,
                "_cas_checkpoint",
                side_effect=cas_checkpoint,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-nonregular-after"))

            self.assertTrue(target.is_dir())
            self.assertEqual("late directory survives\n", (target / "sentinel.txt").read_text("utf-8"))
            recovery_directory = (
                root
                / ".agent-memory/transactions/projection-recovery"
                / hashlib.sha256(b"tx-nonregular-after").hexdigest()
                / hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
            )
            terminal = _read_json(next(recovery_directory.glob("terminal-*.json")))
            self.assertEqual("directory", terminal["observed"]["kind"])
            self.assertEqual("conflict-preserved", terminal["outcome"])
            self.assertTrue((recovery_directory / "displaced.bin").is_file())

    def test_simulated_reparse_attribute_is_classified_without_content_read(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            publish_projection(root, initial, context("tx-simulated-reparse-base"))
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            target = root / document.relative_path
            simulated_bytes = b"simulated reparse payload must not be read\n"
            context_hash = hashlib.sha256(b"tx-simulated-reparse").hexdigest()
            target_hash = hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
            recovery_directory = (
                root
                / ".agent-memory/transactions/projection-recovery"
                / context_hash
                / target_hash
            )
            original_lstat = Path.lstat
            original_read = projection_module._read_plain_bytes
            simulate_reparse = False

            class ReparseMetadata:
                def __init__(self, metadata):
                    self._metadata = metadata
                    self.st_mode = metadata.st_mode
                    self.st_file_attributes = getattr(metadata, "st_file_attributes", 0) | 0x400

                def __getattr__(self, name):
                    return getattr(self._metadata, name)

            def lstat(path, *args, **kwargs):
                metadata = original_lstat(path, *args, **kwargs)
                if simulate_reparse and Path(path) == target:
                    return ReparseMetadata(metadata)
                return metadata

            def read_plain(path):
                if simulate_reparse and Path(path) == target:
                    raise AssertionError("simulated reparse content was read")
                return original_read(path)

            def projection_checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-simulated-reparse")

            def cas_checkpoint(stage, cas_target):
                nonlocal simulate_reparse
                if stage == "after-projection-quarantine" and Path(cas_target) == target:
                    target.write_bytes(simulated_bytes)
                    simulate_reparse = True

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=projection_checkpoint,
            ), mock.patch.object(
                transaction_module,
                "_cas_checkpoint",
                side_effect=cas_checkpoint,
            ), mock.patch.object(
                Path,
                "lstat",
                autospec=True,
                side_effect=lstat,
            ), mock.patch.object(
                projection_module,
                "_read_plain_bytes",
                side_effect=read_plain,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-simulated-reparse"))

            self.assertEqual(simulated_bytes, target.read_bytes())
            terminal = _read_json(next(recovery_directory.glob("terminal-*.json")))
            self.assertEqual("reparse", terminal["observed"]["kind"])

    def test_real_reparse_is_restored_exactly_when_platform_allows_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            publish_projection(root, initial, context("tx-real-reparse-base"))
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            target = root / document.relative_path
            external = Path(temporary_directory) / "external.txt"
            external.write_text("external bytes stay untouched\n", "utf-8")
            probe = Path(temporary_directory) / "symlink-probe"
            try:
                probe.symlink_to(external)
                probe.unlink()
            except OSError as error:
                self.skipTest("real symlink creation unavailable: {0}".format(error))

            def projection_checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-real-reparse")

            def cas_checkpoint(stage, cas_target):
                if stage == "before-projection-quarantine" and Path(cas_target) == target:
                    target.unlink()
                    target.symlink_to(external)

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=projection_checkpoint,
            ), mock.patch.object(
                transaction_module,
                "_cas_checkpoint",
                side_effect=cas_checkpoint,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-real-reparse"))

            self.assertTrue(target.is_symlink())
            self.assertEqual("external bytes stay untouched\n", external.read_text("utf-8"))
            recovery_directory = (
                root
                / ".agent-memory/transactions/projection-recovery"
                / hashlib.sha256(b"tx-real-reparse").hexdigest()
                / hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
            )
            terminal = _read_json(next(recovery_directory.glob("terminal-*.json")))
            self.assertEqual("reparse", terminal["displaced"]["kind"])

    def test_unexpected_post_intent_exception_writes_bounded_terminal_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            publish_projection(root, initial, context("tx-terminal-fallback-base"))
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            target = root / document.relative_path
            recovery_directory = (
                root
                / ".agent-memory/transactions/projection-recovery"
                / hashlib.sha256(b"tx-terminal-fallback").hexdigest()
                / hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
            )
            original_description = projection_module._namespace_description
            inject_failure = False

            def projection_checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-terminal-fallback")

            def cas_checkpoint(stage, cas_target):
                nonlocal inject_failure
                if stage == "after-projection-quarantine" and Path(cas_target) == target:
                    inject_failure = True

            def namespace_description(memory_root, path):
                nonlocal inject_failure
                if inject_failure and Path(path) == recovery_directory / "displaced.bin":
                    inject_failure = False
                    raise OSError("deterministic classification failure")
                return original_description(memory_root, path)

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=projection_checkpoint,
            ), mock.patch.object(
                transaction_module,
                "_cas_checkpoint",
                side_effect=cas_checkpoint,
            ), mock.patch.object(
                projection_module,
                "_namespace_description",
                side_effect=namespace_description,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-terminal-fallback"))

            self.assertTrue((recovery_directory / "displaced.bin").is_file())
            terminal = _read_json(next(recovery_directory.glob("terminal-*.json")))
            self.assertEqual("unexpected-exception", terminal["outcome"])
            self.assertEqual("regular", terminal["endpoints"]["quarantine"]["kind"])

    def test_terminal_directory_never_suppresses_fallback_classification(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self._projection_root(temporary_directory)
            initial = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            publish_projection(root, initial, context("tx-terminal-directory-base"))
            document = next(
                item
                for item in build_root_views(root, "generator-1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            recovery_directory = (
                root
                / ".agent-memory/transactions/projection-recovery"
                / hashlib.sha256(b"tx-terminal-directory").hexdigest()
                / hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
            )
            fake_terminal = recovery_directory / "terminal-fake.json"
            original_description = projection_module._namespace_description
            inject_failure = False

            def projection_checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    _append_operational_proposal(memory_root, "proposal-terminal-directory")

            def cas_checkpoint(stage, cas_target):
                nonlocal inject_failure
                if stage == "after-projection-quarantine":
                    fake_terminal.mkdir()
                    (fake_terminal / "sentinel.txt").write_text(
                        "terminal directory survives\n",
                        "utf-8",
                    )
                    inject_failure = True

            def namespace_description(memory_root, path):
                nonlocal inject_failure
                if inject_failure and Path(path) == recovery_directory / "displaced.bin":
                    inject_failure = False
                    raise OSError("original rollback classification failure")
                return original_description(memory_root, path)

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=projection_checkpoint,
            ), mock.patch.object(
                transaction_module,
                "_cas_checkpoint",
                side_effect=cas_checkpoint,
            ), mock.patch.object(
                projection_module,
                "_namespace_description",
                side_effect=namespace_description,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(root, document, context("tx-terminal-directory"))

            self.assertTrue(fake_terminal.is_dir())
            self.assertEqual(
                "terminal directory survives\n",
                (fake_terminal / "sentinel.txt").read_text("utf-8"),
            )
            manifests = [
                path
                for path in recovery_directory.glob("terminal-*.json")
                if path.is_file()
            ]
            self.assertEqual(1, len(manifests))
            terminal = _read_json(manifests[0])
            self.assertEqual(
                [
                    {
                        "file_type": 16384,
                        "kind": "directory",
                        "path": fake_terminal.relative_to(root).as_posix(),
                    }
                ],
                terminal["invalid_terminals"],
            )
            transaction = _read_json(
                _projection_transaction_path(
                    root,
                    "tx-terminal-directory",
                    document.relative_path,
                )
            )
            self.assertIn("projection_recovery", transaction)

    def test_terminal_reparse_is_retained_without_content_read_or_raw_exception(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            fake_holder = {}
            original_lstat = Path.lstat
            original_operational_read = projection_module._read_operational_bytes

            class ReparseMetadata:
                def __init__(self, metadata):
                    self._metadata = metadata
                    self.st_mode = metadata.st_mode
                    self.st_file_attributes = getattr(metadata, "st_file_attributes", 0) | 0x400

                def __getattr__(self, name):
                    return getattr(self._metadata, name)

            def inject_terminal(root, recovery_directory, document, prior):
                fake = recovery_directory / "terminal-fake.json"
                fake.write_bytes(b"reparse bytes must remain unread\n")
                fake_holder["path"] = fake

            def lstat(path, *args, **kwargs):
                metadata = original_lstat(path, *args, **kwargs)
                if Path(path) == fake_holder.get("path"):
                    return ReparseMetadata(metadata)
                return metadata

            def operational_read(path):
                if Path(path) == fake_holder.get("path"):
                    raise AssertionError("simulated reparse terminal content was read")
                return original_operational_read(path)

            with mock.patch.object(
                Path,
                "lstat",
                autospec=True,
                side_effect=lstat,
            ), mock.patch.object(
                projection_module,
                "_read_operational_bytes",
                side_effect=operational_read,
            ):
                root, document, prior, recovery_directory = (
                    self._exercise_terminal_inventory_failure(
                        temporary_directory,
                        "tx-terminal-reparse",
                        inject_terminal,
                    )
                )

            fake = fake_holder["path"]
            self.assertEqual(b"reparse bytes must remain unread\n", fake.read_bytes())
            manifests = [
                path
                for path in recovery_directory.glob("terminal-*.json")
                if path != fake and path.is_file()
            ]
            self.assertEqual(1, len(manifests))
            terminal = _read_json(manifests[0])
            self.assertEqual("reparse", terminal["invalid_terminals"][0]["kind"])
            self.assertNotIn("raw_sha256", terminal["invalid_terminals"][0])

    def test_invalid_regular_terminal_inventory_is_bounded_strict_and_preserved(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            invalid_paths = []
            original_open = Path.open
            oversized_holder = {}

            def inject_terminal(root, recovery_directory, document, prior):
                transaction_id = "tx-invalid-terminals"
                malformed = b"{"
                malformed_path = recovery_directory / (
                    "terminal-" + hashlib.sha256(malformed).hexdigest() + ".json"
                )
                malformed_path.write_bytes(malformed)
                invalid_paths.append(malformed_path)

                non_object = b"[]\n"
                non_object_path = recovery_directory / (
                    "terminal-" + hashlib.sha256(non_object).hexdigest() + ".json"
                )
                non_object_path.write_bytes(non_object)
                invalid_paths.append(non_object_path)

                oversized = b"{" + b" " * (1024 * 1024)
                oversized_path = recovery_directory / (
                    "terminal-" + hashlib.sha256(oversized).hexdigest() + ".json"
                )
                oversized_path.write_bytes(oversized)
                oversized_holder["path"] = oversized_path
                invalid_paths.append(oversized_path)

                wrong_filename_manifest = _unexpected_terminal_manifest(
                    root,
                    recovery_directory,
                    transaction_id,
                    document,
                    prior,
                )
                wrong_filename = recovery_directory / "terminal-fake.json"
                wrong_filename.write_bytes(transaction_module._json_bytes(wrong_filename_manifest))
                invalid_paths.append(wrong_filename)

                mutations = (
                    {"schema_version": 1},
                    {"status": "in-progress"},
                    {"evidence_paths": [{}]},
                    {"transaction_id": "tx-wrong-terminal"},
                    {"target": "_index/home.md"},
                    {
                        "projection_evidence": {
                            "context_sha256": "0" * 64,
                            "target_path_sha256": hashlib.sha256(
                                document.relative_path.encode("utf-8")
                            ).hexdigest(),
                        }
                    },
                    {
                        "projection_evidence": {
                            "context_sha256": hashlib.sha256(
                                transaction_id.encode("utf-8")
                            ).hexdigest(),
                            "target_path_sha256": "0" * 64,
                        }
                    },
                )
                for mutation in mutations:
                    manifest = _unexpected_terminal_manifest(
                        root,
                        recovery_directory,
                        transaction_id,
                        document,
                        prior,
                    )
                    manifest.update(mutation)
                    path, raw = _write_content_addressed_terminal(
                        recovery_directory,
                        manifest,
                    )
                    invalid_paths.append(path)

            def reject_oversized_open(path, *args, **kwargs):
                if Path(path) == oversized_holder.get("path"):
                    raise AssertionError("oversized terminal was opened")
                return original_open(path, *args, **kwargs)

            with mock.patch.object(
                Path,
                "open",
                autospec=True,
                side_effect=reject_oversized_open,
            ):
                root, document, prior, recovery_directory = (
                    self._exercise_terminal_inventory_failure(
                        temporary_directory,
                        "tx-invalid-terminals",
                        inject_terminal,
                    )
                )

            for path in invalid_paths:
                self.assertTrue(path.is_file())
            self.assertEqual(1024 * 1024 + 1, oversized_holder["path"].stat().st_size)
            manifests = [
                path
                for path in recovery_directory.glob("terminal-*.json")
                if path not in invalid_paths and path.is_file()
            ]
            self.assertEqual(1, len(manifests))
            terminal = _read_json(manifests[0])
            descriptions = terminal["invalid_terminals"]
            self.assertEqual(
                sorted(path.relative_to(root).as_posix() for path in invalid_paths),
                sorted(item["path"] for item in descriptions),
            )
            oversized_description = next(
                item
                for item in descriptions
                if item["path"] == oversized_holder["path"].relative_to(root).as_posix()
            )
            self.assertEqual("regular", oversized_description["kind"])
            self.assertNotIn("raw_sha256", oversized_description)
            for description in descriptions:
                if description["path"] != oversized_description["path"]:
                    self.assertRegex(description["raw_sha256"], r"^[0-9a-f]{64}$")

    def test_terminal_outcome_schemas_reject_missing_extra_empty_and_inconsistent_fields(self):
        fixtures = _strict_terminal_schema_fixtures()
        transaction_id = "tx-schema"
        relative_target = "_index/stale-or-uncertain.md"
        published = b"published"

        for fixture_name, (prior, manifest) in fixtures.items():
            for key in sorted(manifest):
                if key == "terminal_inventory":
                    continue
                mutated = copy.deepcopy(manifest)
                del mutated[key]
                with self.subTest(fixture=fixture_name, mutation="missing-" + key):
                    self.assertFalse(
                        projection_module._terminal_manifest_is_exact(
                            mutated,
                            transaction_id,
                            relative_target,
                            published,
                            prior,
                        )
                    )

            mutated = copy.deepcopy(manifest)
            if manifest["outcome"] == "unexpected-exception":
                mutated["displaced"] = {}
            elif manifest["outcome"] == "quarantine-failed-closed":
                mutated["endpoints"] = {}
            else:
                mutated["endpoints"] = {}
            with self.subTest(fixture=fixture_name, mutation="extra-outcome-field"):
                self.assertFalse(
                    projection_module._terminal_manifest_is_exact(
                        mutated,
                        transaction_id,
                        relative_target,
                        published,
                        prior,
                    )
                )

    def test_fallback_terminal_compacts_exactly_ten_thousand_invalid_entries(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            transaction_id = "tx-compact-invalid-inventory"
            context_hash = hashlib.sha256(transaction_id.encode("utf-8")).hexdigest()
            target_hash = hashlib.sha256(b"_index/stale-or-uncertain.md").hexdigest()
            recovery = (
                ".agent-memory/transactions/projection-recovery/{0}/{1}".format(
                    context_hash,
                    target_hash,
                )
            )
            invalid = []
            for index in range(10000):
                suffix = "-{0:05d}-{1}".format(index, "x" * 120)
                if index == 9999:
                    suffix += "-tail-marker-must-not-echo"
                path = recovery + "/terminal" + suffix + ".json"
                invalid.append(
                    {
                        "file_type": stat.S_IFREG,
                        "kind": "regular",
                        "path": path,
                        "raw_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
                    }
                )

            _, _, _, terminal_path, calls = self._exercise_synthetic_terminal_inventory(
                temporary_directory,
                transaction_id,
                ((), tuple(invalid), None),
            )
            raw = terminal_path.read_bytes()
            self.assertLessEqual(len(raw), 1024 * 1024)
            self.assertNotIn(b"tail-marker-must-not-echo", raw)
            terminal = json.loads(raw.decode("utf-8"))
            self.assertTrue(
                projection_module._terminal_manifest_is_exact(
                    terminal,
                    transaction_id,
                    "_index/stale-or-uncertain.md",
                    b"published",
                    None,
                )
            )
            summary = terminal["terminal_inventory"]
            self.assertEqual(
                {
                    "count": 10000,
                    "invalid_count": 10000,
                    "limit": 10000,
                    "listed_invalid_count": len(terminal["invalid_terminals"]),
                    "valid_count": 0,
                },
                {key: value for key, value in summary.items() if key != "inventory_sha256"},
            )
            self.assertLessEqual(summary["listed_invalid_count"], 64)
            self.assertRegex(summary["inventory_sha256"], r"^[0-9a-f]{64}$")
            compact_mutations = []
            for key in sorted(summary):
                compact_mutations.append(("missing-" + key, key, None, True))
            compact_mutations.extend(
                (
                    ("extra", "extra", "forged", False),
                    ("wrong-count", "count", 9999, False),
                    ("wrong-listed", "listed_invalid_count", 0, False),
                    ("wrong-hash-type", "inventory_sha256", [], False),
                    ("wrong-hash-width", "inventory_sha256", "short", False),
                )
            )
            for label, key, replacement, remove in compact_mutations:
                mutated = copy.deepcopy(terminal)
                if remove:
                    del mutated["terminal_inventory"][key]
                else:
                    mutated["terminal_inventory"][key] = replacement
                with self.subTest(compact_inventory=label):
                    self.assertFalse(
                        projection_module._terminal_manifest_is_exact(
                            mutated,
                            transaction_id,
                            "_index/stale-or-uncertain.md",
                            b"published",
                            None,
                        )
                    )
            self.assertEqual(1, len(calls))

    def test_fallback_terminal_compacts_valid_evidence_and_replays_in_one_inventory_pass(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            transaction_id = "tx-compact-valid-inventory"
            root = Path(temporary_directory) / "memory"
            recovery_directory = (
                root
                / ".agent-memory/transactions/projection-recovery"
                / hashlib.sha256(transaction_id.encode("utf-8")).hexdigest()
                / hashlib.sha256(b"_index/stale-or-uncertain.md").hexdigest()
            )
            document = ProjectionDocument(
                relative_path="_index/stale-or-uncertain.md",
                content="published",
                source_revision="synthetic",
                observed_at="2026-08-30T00:00:00Z",
                expected_target_sha256=None,
            )
            recovery = recovery_directory.relative_to(root).as_posix()
            foreign_path = recovery + "/terminal-foreign.json"
            foreign = [{"kind": "absent", "path": foreign_path}]
            valid = []
            for terminal_index in range(64):
                marker_paths = [
                    recovery
                    + "/body-marker-must-not-echo-{0:02d}-{1:03d}-{2}".format(
                        terminal_index,
                        evidence_index,
                        "x" * 120,
                    )
                    for evidence_index in range(128)
                ]
                evidence_paths = sorted(
                    marker_paths
                    + [recovery + "/displaced.bin", recovery + "/intent.json", foreign_path]
                )
                manifest = _unexpected_terminal_manifest(
                    root,
                    recovery_directory,
                    transaction_id,
                    document,
                    None,
                    error_type="Synthetic{0:02d}".format(terminal_index),
                    evidence_paths=evidence_paths,
                    invalid_terminals=foreign,
                )
                manifest_raw = transaction_module._json_bytes(manifest)
                self.assertLessEqual(len(manifest_raw), 1024 * 1024)
                path = recovery_directory / (
                    "terminal-" + hashlib.sha256(manifest_raw).hexdigest() + ".json"
                )
                valid.append((path, manifest))

            root, target, recovery_directory, terminal_path, calls = (
                self._exercise_synthetic_terminal_inventory(
                    temporary_directory,
                    transaction_id,
                    (tuple(valid), (), None),
                )
            )
            raw = terminal_path.read_bytes()
            self.assertLessEqual(len(raw), 1024 * 1024)
            self.assertNotIn(b"body-marker-must-not-echo", raw)
            terminal = json.loads(raw.decode("utf-8"))
            self.assertTrue(
                projection_module._terminal_manifest_is_exact(
                    terminal,
                    transaction_id,
                    "_index/stale-or-uncertain.md",
                    b"published",
                    None,
                )
            )
            self.assertEqual(64, terminal["terminal_inventory"]["valid_count"])
            self.assertEqual(1, len(calls))
            forged_digest = copy.deepcopy(terminal)
            forged_digest["terminal_inventory"]["inventory_sha256"] = "0" * 64
            self.assertIsNone(
                projection_module._matching_terminal_replay(
                    tuple(valid) + ((terminal_path, forged_digest),),
                    (),
                    None,
                )
            )

            class OnePassInventory:
                def __init__(self, entries):
                    self.entries = entries
                    self.iterations = 0
                    self.yields = 0

                def __iter__(self):
                    self.iterations += 1
                    if self.iterations > 1:
                        raise AssertionError("valid inventory was rescanned")
                    for entry in self.entries:
                        self.yields += 1
                        yield entry

            replay_inventory = OnePassInventory(valid + [(terminal_path, terminal)])
            replay_calls = []

            def terminal_inventory(*args, **kwargs):
                replay_calls.append(True)
                return replay_inventory, (), None

            with mock.patch.object(
                projection_module,
                "_rollback_projection_once",
                side_effect=OSError("synthetic replay failure"),
            ), mock.patch.object(
                projection_module,
                "_terminal_inventory",
                side_effect=terminal_inventory,
            ):
                with self.assertRaises(ConflictError):
                    projection_module._rollback_projection(
                        root,
                        target,
                        b"published",
                        None,
                        transaction_id,
                    )
            self.assertEqual(1, len(replay_calls))
            self.assertEqual(1, replay_inventory.iterations)
            self.assertEqual(len(valid) + 1, replay_inventory.yields)
            self.assertEqual([terminal_path], sorted(recovery_directory.glob("terminal-*.json")))
            self.assertEqual(raw, terminal_path.read_bytes())

    def test_overflow_terminal_replays_exact_path_without_rescanning_excess(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            transaction_id = "tx-overflow-direct-replay"
            overflow = {"count_at_least": 10001, "limit": 10000}
            root, target, recovery, terminal_path, first_calls = (
                self._exercise_synthetic_terminal_inventory(
                    temporary_directory,
                    transaction_id,
                    ((), (), overflow),
                )
            )
            raw = terminal_path.read_bytes()
            replay_calls = []

            def terminal_inventory(*args, **kwargs):
                replay_calls.append(True)
                return (), (), overflow

            with mock.patch.object(
                projection_module,
                "_rollback_projection_once",
                side_effect=OSError("synthetic rollback failure"),
            ), mock.patch.object(
                projection_module,
                "_terminal_inventory",
                side_effect=terminal_inventory,
            ):
                with self.assertRaisesRegex(
                    ConflictError,
                    "replayed exact terminal evidence",
                ):
                    projection_module._rollback_projection(
                        root,
                        target,
                        b"published",
                        None,
                        transaction_id,
                    )
            self.assertEqual(1, len(first_calls))
            self.assertEqual(1, len(replay_calls))
            self.assertEqual([terminal_path], sorted(recovery.glob("terminal-*.json")))
            self.assertEqual(raw, terminal_path.read_bytes())

    def test_locked_terminal_schema_fixtures_are_exact_replays(self):
        transaction_id = "tx-schema"
        relative_target = "_index/stale-or-uncertain.md"
        published = b"published"
        for fixture_name, (prior, manifest) in _strict_terminal_schema_fixtures().items():
            with self.subTest(fixture=fixture_name):
                self.assertTrue(
                    projection_module._terminal_manifest_is_exact(
                        manifest,
                        transaction_id,
                        relative_target,
                        published,
                        prior,
                    )
                )
                terminal_path = Path("terminal-fixture.json")
                replay = projection_module._matching_terminal_replay(
                    ((terminal_path, manifest),),
                    tuple(manifest.get("invalid_terminals", [])),
                    manifest.get("terminal_inventory"),
                )
                self.assertEqual((terminal_path, manifest), replay)

    def test_actual_terminal_producer_shapes_replay_without_new_manifest(self):
        branches = (
            "restored-existing",
            "restored-absence",
            "conflict-regular",
            "conflict-namespace",
            "quarantine-failed",
            "unexpected",
            "unexpected-invalid",
        )
        for branch in branches:
            with self.subTest(branch=branch), tempfile.TemporaryDirectory() as temporary_directory:
                transaction_id = "tx-producer-" + branch
                root = Path(temporary_directory) / "memory"
                root.mkdir()
                target = root / "_index/stale-or-uncertain.md"
                target.parent.mkdir()
                published = b"published"
                prior = None if branch == "restored-absence" else b"prior"
                target.write_bytes(published)
                context_hash = hashlib.sha256(transaction_id.encode("utf-8")).hexdigest()
                target_hash = hashlib.sha256(
                    b"_index/stale-or-uncertain.md"
                ).hexdigest()
                recovery_directory = (
                    root
                    / ".agent-memory/transactions/projection-recovery"
                    / context_hash
                    / target_hash
                )

                if branch.startswith("restored-"):
                    projection_module._rollback_projection(
                        root,
                        target,
                        published,
                        prior,
                        transaction_id,
                    )
                elif branch == "conflict-regular":
                    def cas_checkpoint(stage, cas_target):
                        if stage == "after-projection-quarantine":
                            target.write_bytes(b"unexpected")

                    with mock.patch.object(
                        transaction_module,
                        "_cas_checkpoint",
                        side_effect=cas_checkpoint,
                    ):
                        with self.assertRaises(ConflictError):
                            projection_module._rollback_projection(
                                root,
                                target,
                                published,
                                prior,
                                transaction_id,
                            )
                elif branch == "conflict-namespace":
                    def cas_checkpoint(stage, cas_target):
                        if stage == "before-projection-quarantine":
                            target.unlink()
                            target.mkdir()
                            (target / "sentinel.txt").write_text("survives\n", "utf-8")

                    with mock.patch.object(
                        transaction_module,
                        "_cas_checkpoint",
                        side_effect=cas_checkpoint,
                    ):
                        with self.assertRaises(ConflictError):
                            projection_module._rollback_projection(
                                root,
                                target,
                                published,
                                prior,
                                transaction_id,
                            )
                elif branch == "quarantine-failed":
                    with mock.patch.object(
                        transaction_module,
                        "_move_no_replace",
                        side_effect=ConflictError("injected no-replace failure"),
                    ):
                        with self.assertRaises(ConflictError):
                            projection_module._rollback_projection(
                                root,
                                target,
                                published,
                                prior,
                                transaction_id,
                            )
                else:
                    original_description = projection_module._namespace_description
                    inject_failure = False

                    def cas_checkpoint(stage, cas_target):
                        nonlocal inject_failure
                        if stage == "after-projection-quarantine":
                            if branch == "unexpected-invalid":
                                (recovery_directory / "terminal-fake.json").mkdir()
                            inject_failure = True

                    def namespace_description(memory_root, path):
                        nonlocal inject_failure
                        if (
                            inject_failure
                            and Path(path) == recovery_directory / "displaced.bin"
                        ):
                            inject_failure = False
                            raise OSError("injected producer fallback")
                        return original_description(memory_root, path)

                    with mock.patch.object(
                        transaction_module,
                        "_cas_checkpoint",
                        side_effect=cas_checkpoint,
                    ), mock.patch.object(
                        projection_module,
                        "_namespace_description",
                        side_effect=namespace_description,
                    ):
                        with self.assertRaises(ConflictError):
                            projection_module._rollback_projection(
                                root,
                                target,
                                published,
                                prior,
                                transaction_id,
                            )

                entries = sorted(recovery_directory.glob("terminal-*.json"))
                terminals = [
                    path
                    for path in entries
                    if path.is_file()
                    and len(path.name) == len("terminal-.json") + 64
                ]
                self.assertEqual(1, len(terminals))
                terminal_bytes = terminals[0].read_bytes()
                terminal = json.loads(terminal_bytes.decode("utf-8"))
                self.assertTrue(
                    projection_module._terminal_manifest_is_exact(
                        terminal,
                        transaction_id,
                        "_index/stale-or-uncertain.md",
                        published,
                        prior,
                    )
                )

                with mock.patch.object(
                    projection_module,
                    "_rollback_projection_once",
                    side_effect=OSError("injected replay entry"),
                ):
                    with self.assertRaises(ConflictError):
                        projection_module._rollback_projection(
                            root,
                            target,
                            published,
                            prior,
                            transaction_id,
                        )
                self.assertEqual(entries, sorted(recovery_directory.glob("terminal-*.json")))
                self.assertEqual(terminal_bytes, terminals[0].read_bytes())

    def test_terminal_outcome_nested_schema_and_endpoint_invariants_are_exact(self):
        fixtures = _strict_terminal_schema_fixtures()
        transaction_id = "tx-schema"
        relative_target = "_index/stale-or-uncertain.md"
        published = b"published"

        def replace_field(path, value):
            def mutation(manifest):
                owner = manifest
                for key in path[:-1]:
                    owner = owner[key]
                owner[path[-1]] = value

            return mutation

        def remove_field(path):
            def mutation(manifest):
                owner = manifest
                for key in path[:-1]:
                    owner = owner[key]
                del owner[path[-1]]

            return mutation

        regular_observed = {
            "file_type": stat.S_IFREG,
            "kind": "regular",
            "path": relative_target,
        }
        invalid_entry = copy.deepcopy(fixtures["unexpected-invalid"][1]["invalid_terminals"])
        cases = (
            ("restored-existing", ("displaced",), {}),
            ("restored-existing", ("observed",), {}),
            ("restored-existing", ("displaced", "path"), relative_target),
            ("restored-existing", ("displaced_sha256",), "0" * 64),
            ("restored-existing", ("observed", "path"), "_index/home.md"),
            ("restored-existing", ("observed_sha256",), "0" * 64),
            ("restored-existing", ("displaced", "extra"), "forged"),
            ("restored-absence", ("observed",), regular_observed),
            ("conflict-regular", ("observed",), {}),
            ("conflict-regular", ("observed_sha256",), "0" * 64),
            (
                "conflict-regular",
                ("observed_sha256",),
                "e5bade0e979cb8cf6e53303dae696c6631a5c82ce60386d7a602f85fb249fcc0",
            ),
            ("conflict-namespace", ("displaced_sha256",), "0" * 64),
            ("conflict-namespace", ("displaced", "kind"), "regular"),
            ("conflict-namespace", ("displaced", "path"), relative_target),
            ("conflict-namespace", ("observed", "path"), "_index/home.md"),
            ("quarantine-failed", ("endpoint_hashes",), {}),
            ("quarantine-failed", ("endpoint_hashes",), {"other": None, "target": "0" * 64}),
            ("quarantine-failed", ("endpoint_hashes", "target"), None),
            ("quarantine-failed", ("endpoint_hashes", "target"), "0" * 64),
            ("quarantine-failed", ("endpoint_hashes", "target"), "short"),
            ("quarantine-failed", ("endpoint_hashes", "target"), []),
            ("unexpected", ("endpoints",), {}),
            ("unexpected", ("endpoints", "quarantine", "path"), relative_target),
            ("unexpected", ("endpoints", "target", "path"), "_index/home.md"),
            ("unexpected", ("error_type",), ""),
            ("unexpected", ("error_type",), []),
            ("unexpected-invalid", ("invalid_terminals",), [{}]),
            ("unexpected-invalid", ("invalid_terminals", 0, "extra"), "forged"),
            ("unexpected-overflow", ("invalid_terminals",), invalid_entry),
        )
        for fixture_name, path, value in cases:
            prior, manifest = fixtures[fixture_name]
            mutated = copy.deepcopy(manifest)
            replace_field(path, value)(mutated)
            with self.subTest(fixture=fixture_name, path=path, value=value):
                self.assertFalse(
                    projection_module._terminal_manifest_is_exact(
                        mutated,
                        transaction_id,
                        relative_target,
                        published,
                        prior,
                    )
                )

        nested_missing = (
            ("restored-existing", ("displaced", "path")),
            ("restored-existing", ("observed", "kind")),
            ("conflict-namespace", ("observed", "path")),
            ("quarantine-failed", ("endpoint_hashes", "target")),
            ("unexpected", ("endpoints", "target")),
            ("unexpected-invalid", ("invalid_terminals", 0, "kind")),
        )
        for fixture_name, path in nested_missing:
            prior, manifest = fixtures[fixture_name]
            mutated = copy.deepcopy(manifest)
            remove_field(path)(mutated)
            with self.subTest(fixture=fixture_name, missing=path):
                self.assertFalse(
                    projection_module._terminal_manifest_is_exact(
                        mutated,
                        transaction_id,
                        relative_target,
                        published,
                        prior,
                    )
                )

        for fixture_name, (prior, manifest) in fixtures.items():
            mutated = copy.deepcopy(manifest)
            mutated["evidence_paths"] = []
            with self.subTest(fixture=fixture_name, mutation="empty-evidence"):
                self.assertFalse(
                    projection_module._terminal_manifest_is_exact(
                        mutated,
                        transaction_id,
                        relative_target,
                        published,
                        prior,
                    )
                    )

    def test_unexpected_terminal_evidence_is_exact_and_forgery_gets_successor(self):
        for mutation in ("missing-prior", "extra-recovery-path"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary_directory:
                transaction_id = "tx-unexpected-evidence-" + mutation
                fake_holder = {}

                def inject_terminal(root, recovery_directory, document, prior):
                    manifest = _unexpected_terminal_manifest(
                        root,
                        recovery_directory,
                        transaction_id,
                        document,
                        prior,
                    )
                    prior_path = (
                        recovery_directory
                        / ("prior-" + hashlib.sha256(prior).hexdigest() + ".bin")
                    ).relative_to(root).as_posix()
                    if mutation == "missing-prior":
                        manifest["evidence_paths"].remove(prior_path)
                    else:
                        manifest["evidence_paths"].append(
                            (recovery_directory / "extra.bin").relative_to(root).as_posix()
                        )
                        manifest["evidence_paths"].sort()
                    path, raw = _write_content_addressed_terminal(
                        recovery_directory,
                        manifest,
                    )
                    fake_holder.update(path=path, raw=raw, manifest=manifest)

                root, document, prior, recovery_directory = (
                    self._exercise_terminal_inventory_failure(
                        temporary_directory,
                        transaction_id,
                        inject_terminal,
                    )
                )
                fake = fake_holder["path"]
                self.assertFalse(
                    projection_module._terminal_manifest_is_exact(
                        fake_holder["manifest"],
                        transaction_id,
                        document.relative_path,
                        document.content.encode("utf-8"),
                        prior,
                    )
                )
                self.assertEqual(fake_holder["raw"], fake.read_bytes())
                manifests = sorted(recovery_directory.glob("terminal-*.json"))
                self.assertEqual(2, len(manifests))
                successor_path = next(path for path in manifests if path != fake)
                successor = _read_json(successor_path)
                self.assertEqual("unexpected-exception", successor["outcome"])
                self.assertEqual(
                    [fake.relative_to(root).as_posix()],
                    [item["path"] for item in successor["invalid_terminals"]],
                )
                expected_evidence = sorted(
                    [
                        (recovery_directory / "intent.json").relative_to(root).as_posix(),
                        (
                            recovery_directory
                            / ("prior-" + hashlib.sha256(prior).hexdigest() + ".bin")
                        ).relative_to(root).as_posix(),
                        (recovery_directory / "displaced.bin").relative_to(root).as_posix(),
                        fake.relative_to(root).as_posix(),
                    ]
                )
                self.assertEqual(expected_evidence, successor["evidence_paths"])

    def test_descriptor_wrong_types_are_false_and_terminalized_without_raw_exception(self):
        cases = []
        for field in ("kind", "file_type", "path"):
            for bad_value in ([], {}):
                cases.append(("endpoint", field, bad_value))
        for field in ("kind", "file_type", "path", "raw_sha256", "size"):
            for bad_value in ([], {}):
                cases.append(("invalid", field, bad_value))

        for index, (scope, field, bad_value) in enumerate(cases):
            with self.subTest(
                scope=scope,
                field=field,
                bad_type=type(bad_value).__name__,
            ), tempfile.TemporaryDirectory() as temporary_directory:
                transaction_id = "tx-descriptor-{0}-{1}-{2}".format(
                    scope,
                    field.replace("_", "-"),
                    index,
                )
                fake_holder = {}

                def inject_terminal(root, recovery_directory, document, prior):
                    manifest = _unexpected_terminal_manifest(
                        root,
                        recovery_directory,
                        transaction_id,
                        document,
                        prior,
                    )
                    if scope == "endpoint":
                        manifest["endpoints"]["quarantine"][field] = bad_value
                    else:
                        referenced = (
                            recovery_directory / "terminal-referenced.json"
                        ).relative_to(root).as_posix()
                        description = {
                            "file_type": stat.S_IFREG,
                            "kind": "regular",
                            "path": referenced,
                            "raw_sha256": "0" * 64,
                        }
                        if field == "size":
                            del description["raw_sha256"]
                            description["size"] = bad_value
                        else:
                            description[field] = bad_value
                        manifest["invalid_terminals"] = [description]
                        manifest["evidence_paths"].append(referenced)
                        manifest["evidence_paths"].sort()
                    path, raw = _write_content_addressed_terminal(
                        recovery_directory,
                        manifest,
                    )
                    fake_holder.update(path=path, raw=raw, manifest=manifest)

                root, document, prior, recovery_directory = (
                    self._exercise_terminal_inventory_failure(
                        temporary_directory,
                        transaction_id,
                        inject_terminal,
                    )
                )
                fake = fake_holder["path"]
                self.assertFalse(
                    projection_module._terminal_manifest_is_exact(
                        fake_holder["manifest"],
                        transaction_id,
                        document.relative_path,
                        document.content.encode("utf-8"),
                        prior,
                    )
                )
                self.assertEqual(fake_holder["raw"], fake.read_bytes())
                manifests = sorted(recovery_directory.glob("terminal-*.json"))
                self.assertEqual(2, len(manifests))
                successor_path = next(path for path in manifests if path != fake)
                successor = _read_json(successor_path)
                self.assertEqual("unexpected-exception", successor["outcome"])
                self.assertEqual(
                    [fake.relative_to(root).as_posix()],
                    [item["path"] for item in successor["invalid_terminals"]],
                )

    def test_reviewer_forged_restored_terminal_is_retained_and_gets_successor(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            fake_holder = {}

            def inject_terminal(root, recovery_directory, document, prior):
                context_hash = hashlib.sha256(b"tx-forged-restored").hexdigest()
                target_hash = hashlib.sha256(document.relative_path.encode("utf-8")).hexdigest()
                prior_hash = hashlib.sha256(prior).hexdigest()
                manifest = {
                    "displaced": {},
                    "evidence_paths": sorted(
                        [
                            (recovery_directory / "intent.json").relative_to(root).as_posix(),
                            (
                                recovery_directory / ("prior-" + prior_hash + ".bin")
                            ).relative_to(root).as_posix(),
                        ]
                    ),
                    "outcome": "restored",
                    "prior_sha256": prior_hash,
                    "projection_evidence": {
                        "context_sha256": context_hash,
                        "target_path_sha256": target_hash,
                    },
                    "published_sha256": hashlib.sha256(
                        document.content.encode("utf-8")
                    ).hexdigest(),
                    "schema_version": 2,
                    "status": "terminal",
                    "target": document.relative_path,
                    "transaction_id": "tx-forged-restored",
                }
                path, raw = _write_content_addressed_terminal(
                    recovery_directory,
                    manifest,
                )
                fake_holder["path"] = path
                fake_holder["raw"] = raw

            root, document, prior, recovery_directory = (
                self._exercise_terminal_inventory_failure(
                    temporary_directory,
                    "tx-forged-restored",
                    inject_terminal,
                )
            )

            fake = fake_holder["path"]
            self.assertEqual(fake_holder["raw"], fake.read_bytes())
            manifests = sorted(recovery_directory.glob("terminal-*.json"))
            self.assertEqual(2, len(manifests))
            successor_path = next(path for path in manifests if path != fake)
            successor_raw = successor_path.read_bytes()
            self.assertEqual(
                "terminal-" + hashlib.sha256(successor_raw).hexdigest() + ".json",
                successor_path.name,
            )
            successor = json.loads(successor_raw.decode("utf-8"))
            self.assertEqual("unexpected-exception", successor["outcome"])
            invalid = successor["invalid_terminals"]
            self.assertEqual(1, len(invalid))
            self.assertEqual(fake.relative_to(root).as_posix(), invalid[0]["path"])
            self.assertEqual(
                hashlib.sha256(fake_holder["raw"]).hexdigest(),
                invalid[0]["raw_sha256"],
            )

    def test_exact_valid_terminal_replay_is_idempotently_classified(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            terminal_holder = {}

            def inject_terminal(root, recovery_directory, document, prior):
                manifest = _unexpected_terminal_manifest(
                    root,
                    recovery_directory,
                    "tx-valid-terminal-replay",
                    document,
                    prior,
                )
                path, raw = _write_content_addressed_terminal(
                    recovery_directory,
                    manifest,
                )
                terminal_holder["path"] = path
                terminal_holder["raw"] = raw

            root, document, prior, recovery_directory = (
                self._exercise_terminal_inventory_failure(
                    temporary_directory,
                    "tx-valid-terminal-replay",
                    inject_terminal,
                )
            )

            self.assertEqual(terminal_holder["raw"], terminal_holder["path"].read_bytes())
            self.assertEqual(
                [terminal_holder["path"]],
                sorted(recovery_directory.glob("terminal-*.json")),
            )

    def test_occupied_content_addressed_terminal_is_retained_and_reclassified(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            original_publish = transaction_module._publish_exclusive
            state = {"armed": False, "occupied": None}

            def inject_terminal(root, recovery_directory, document, prior):
                state["armed"] = True
                state["recovery_directory"] = recovery_directory

            def publish_exclusive(path, content, token, root=None):
                candidate = Path(path)
                if (
                    state["armed"]
                    and state["occupied"] is None
                    and candidate.parent == state["recovery_directory"]
                    and candidate.name.startswith("terminal-")
                    and candidate.name.endswith(".json")
                ):
                    candidate.write_bytes(b"occupied terminal bytes survive\n")
                    state["occupied"] = candidate
                return original_publish(path, content, token, root=root)

            with mock.patch.object(
                transaction_module,
                "_publish_exclusive",
                side_effect=publish_exclusive,
            ):
                root, document, prior, recovery_directory = (
                    self._exercise_terminal_inventory_failure(
                        temporary_directory,
                        "tx-occupied-terminal",
                        inject_terminal,
                    )
                )

            occupied = state["occupied"]
            self.assertIsNotNone(occupied)
            self.assertEqual(b"occupied terminal bytes survive\n", occupied.read_bytes())
            manifests = [
                path
                for path in recovery_directory.glob("terminal-*.json")
                if path != occupied and path.is_file()
            ]
            self.assertEqual(1, len(manifests))
            terminal = _read_json(manifests[0])
            self.assertIn(
                occupied.relative_to(root).as_posix(),
                [item["path"] for item in terminal["invalid_terminals"]],
            )

    def test_terminal_inventory_over_ten_thousand_fails_closed_without_deletion(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            terminal_holder = {}

            def inject_terminal(root, recovery_directory, document, prior):
                for index in range(10001):
                    (recovery_directory / ("terminal-{0:05d}.json".format(index))).touch()
                terminal_holder["first"] = recovery_directory / "terminal-00000.json"
                terminal_holder["last"] = recovery_directory / "terminal-10000.json"

            root, document, prior, recovery_directory = (
                self._exercise_terminal_inventory_failure(
                    temporary_directory,
                    "tx-terminal-inventory-bound",
                    inject_terminal,
                )
            )

            self.assertTrue(terminal_holder["first"].is_file())
            self.assertTrue(terminal_holder["last"].is_file())
            manifests = [
                path
                for path in recovery_directory.glob("terminal-*.json")
                if path.name not in ("terminal-00000.json", "terminal-10000.json")
                and path.stat().st_size
            ]
            self.assertEqual(1, len(manifests))
            terminal = _read_json(manifests[0])
            self.assertEqual(
                {"count_at_least": 10001, "limit": 10000},
                terminal["terminal_inventory"],
            )


if __name__ == "__main__":
    unittest.main()
