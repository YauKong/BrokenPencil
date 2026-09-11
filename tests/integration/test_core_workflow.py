import hashlib
import json
import multiprocessing
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_DIR = (
    Path(__file__).resolve().parents[2]
    / "skills"
    / "obsidian-agent-memory"
    / "scripts"
)
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory import (  # noqa: E402
    ConflictError,
    Finding,
    PromotionCandidate,
    RecordCandidate,
    RecordEnvelope,
    TransactionContext,
    build_global_focus,
    build_project_focus,
    build_root_views,
    commit_record,
    compute_body_sha256,
    doctor_memory_root,
    initialize_memory_root,
    preserve_promotion_candidate,
    publish_projection,
    recover_root_write_guard,
    record_relative_path,
    render_record,
    resolve_binding,
    root_write_guard,
    search_accepted_records,
    select_read_adapter,
    update_focus,
)
import obsidian_agent_memory.projections as projection_module  # noqa: E402
import obsidian_agent_memory.transactions as transaction_module  # noqa: E402
import obsidian_agent_memory.validation as validation_module  # noqa: E402


OCCURRED_AT = "2026-08-30T12:00:00Z"
GENERATOR_VERSION = "core-v1"


def _context(transaction_id):
    return TransactionContext(transaction_id, "core-test-agent", OCCURRED_AT)


def _candidate(memory_id, record_type, body):
    envelope = RecordEnvelope(
        memory_id=memory_id,
        record_type=record_type,
        schema_version=2,
        owner_scope="project.demo.{0}".format(record_type),
        project="demo",
        revision=1,
        supersedes=None,
        created_at=OCCURRED_AT,
        observed_at=OCCURRED_AT,
        source="core-test",
        source_revision="fixture-v1",
        body_sha256=compute_body_sha256(body),
    )
    return RecordCandidate(envelope, body)


def _sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _byte_snapshot(root):
    snapshot = {}
    for path in sorted(Path(root).rglob("*"), key=lambda item: item.as_posix()):
        if path.is_file():
            try:
                value = path.read_bytes()
            except PermissionError:
                value = b"<lease-busy>"
            snapshot[path.relative_to(root).as_posix()] = value
    return snapshot


def _root_guard_snapshot(root):
    names = [".agent-memory-root-write.lock"]
    names.extend(
        path.name
        for path in Path(root).glob(".agent-memory-root-write.candidate-*")
    )
    return {
        name: (Path(root) / name).read_bytes()
        for name in sorted(names)
    }


def _hold_root_guard(root, ready, release):
    from obsidian_agent_memory import root_write_guard

    with root_write_guard(Path(root), _context("tx-live-root-guard")):
        ready.set()
        release.wait(30)


def _hold_anchor_candidate(root, ready, release):
    from obsidian_agent_memory.transactions import _Lease

    lease = _Lease.open(Path(root) / ".agent-memory-root-write.anchor.candidate")
    try:
        if not lease.acquire(offset=0):
            raise RuntimeError("fixture anchor candidate lease is busy")
        ready.set()
        release.wait(30)
    finally:
        lease.close()


def _projection_recovery_directory(root, transaction_id, relative_target):
    return (
        Path(root)
        / ".agent-memory/transactions/projection-recovery"
        / _sha256_text(transaction_id)
        / _sha256_text(relative_target)
    )


def _create_projection_recovery_owner(root, transaction_id):
    document = build_project_focus(root, "demo", GENERATOR_VERSION)
    publish_projection(root, document, _context(transaction_id), guard=None)
    context_hash = _sha256_text(transaction_id)
    target_hash = _sha256_text(document.relative_path)
    journal = (
        Path(root)
        / ".agent-memory/transactions/projections"
        / context_hash
        / (target_hash + ".json")
    )
    owner = json.loads(journal.read_text(encoding="utf-8"))
    owner["status"] = "in-progress"
    journal.write_bytes(_canonical_json_bytes(owner))
    recovery = _projection_recovery_directory(root, transaction_id, document.relative_path)
    recovery.mkdir(parents=True)
    intent = {
        "displaced_path": recovery.relative_to(root).as_posix() + "/displaced.bin",
        "prior_path": None,
        "prior_sha256": None,
        "published_sha256": owner["desired"]["target_sha256"],
        "schema_version": 2,
        "status": "in-progress",
        "target": document.relative_path,
        "transaction_id": transaction_id,
    }
    (recovery / "intent.json").write_bytes(_canonical_json_bytes(intent))
    return document, journal, recovery


def _canonical_json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _write_terminal(recovery, manifest):
    raw = _canonical_json_bytes(manifest)
    path = Path(recovery) / (
        "terminal-" + hashlib.sha256(raw).hexdigest() + ".json"
    )
    path.write_bytes(raw)
    return path


class _ForcedFallbackRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, arguments, timeout):
        self.calls.append((tuple(arguments), timeout))
        return subprocess.CompletedProcess(arguments, 1, stdout=b"", stderr=b"")


class CoreWorkflowTests(unittest.TestCase):
    def test_temporary_root_workflow_is_deterministic_and_doctor_clean(self):
        self.maxDiff = None
        with tempfile.TemporaryDirectory() as temporary_text:
            temporary = Path(temporary_text).resolve()
            workspace = temporary / "workspace"
            workspace_child = workspace / "project" / "child"
            memory_root = temporary / "memory-root"
            workspace_child.mkdir(parents=True)
            config_path = temporary / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "bindings": [
                            {
                                "memory_root": str(memory_root),
                                "obsidian_vault": "fixture-vault",
                                "project_id": "demo",
                                "workspace": str(workspace),
                            }
                        ],
                        "schema_version": 1,
                    },
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            binding = resolve_binding(
                explicit_root=None,
                explicit_project=None,
                env={},
                config_path=config_path,
                cwd=workspace_child,
            )
            self.assertEqual(memory_root, binding.memory_root)
            self.assertEqual("demo", binding.project_id)

            created = initialize_memory_root(
                binding.memory_root,
                binding.project_id,
                _context("tx-initialize"),
            )
            session = _candidate("session-core", "session", "session accepted body")
            session_outcome = commit_record(
                memory_root,
                session,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-session"),
            )
            decision = _candidate(
                "decision-core", "decision", "portable decision accepted body"
            )
            decision_outcome = commit_record(
                memory_root,
                decision,
                expected_catalog_revision=1,
                expected_record_revision=None,
                context=_context("tx-decision"),
            )
            self.assertEqual("accepted", session_outcome.status)
            self.assertEqual("accepted", decision_outcome.status)

            competing = _candidate(
                "decision-competing", "decision", "competing stale decision body"
            )
            competing_outcome = commit_record(
                memory_root,
                competing,
                expected_catalog_revision=1,
                expected_record_revision=None,
                context=_context("tx-competing"),
            )
            self.assertEqual("proposed", competing_outcome.status)
            self.assertIsNotNone(competing_outcome.proposal_path)
            self.assertEqual(2, competing_outcome.catalog_revision)
            self.assertFalse((memory_root / record_relative_path(competing.envelope)).exists())

            focus_outcome = update_focus(
                memory_root,
                "demo",
                expected_revision=0,
                record_ids=(decision.envelope.memory_id, session.envelope.memory_id),
                observed_at=OCCURRED_AT,
                context=_context("tx-focus"),
            )
            self.assertEqual("accepted", focus_outcome.status)

            project_document = build_project_focus(
                memory_root, "demo", GENERATOR_VERSION
            )
            global_document = build_global_focus(memory_root, GENERATOR_VERSION)
            project_context = _context("tx-project-projection")
            global_context = _context("tx-global-projection")
            project_path = publish_projection(
                memory_root, project_document, project_context, guard=None
            )
            global_path = publish_projection(
                memory_root, global_document, global_context, guard=None
            )

            for context, document in (
                (project_context, project_document),
                (global_context, global_document),
            ):
                context_hash = _sha256_text(context.transaction_id)
                target_hash = _sha256_text(document.relative_path)
                claim_path = (
                    memory_root
                    / ".agent-memory"
                    / "transactions"
                    / "projections"
                    / context_hash
                    / "unguarded-target.claim"
                )
                journal_path = claim_path.with_name(target_hash + ".json")
                claim = json.loads(claim_path.read_text(encoding="utf-8"))
                journal = json.loads(journal_path.read_text(encoding="utf-8"))
                self.assertEqual(context.transaction_id, claim["transaction_id"])
                self.assertEqual(document.relative_path, claim["target"])
                self.assertEqual(context_hash, claim["context_sha256"])
                self.assertEqual(target_hash, claim["target_path_sha256"])
                self.assertEqual("accepted", journal["status"])
                self.assertEqual(claim["transaction_id"], journal["transaction_id"])
                self.assertEqual(claim["target"], journal["target"])

            orphan = _candidate(
                "decision-orphan", "decision", "portable decision orphan body"
            )
            orphan_path = memory_root / record_relative_path(orphan.envelope)
            orphan_path.parent.mkdir(parents=True, exist_ok=True)
            orphan_path.write_text(
                render_record(orphan.envelope, orphan.body), encoding="utf-8"
            )

            runner = _ForcedFallbackRunner()
            selection = select_read_adapter(
                binding,
                runner,
                executable=temporary / "fake-obsidian",
            )
            self.assertEqual("filesystem", selection.mode)
            self.assertEqual("cli-help-nonzero", selection.reason)
            matches = search_accepted_records(
                memory_root,
                selection.adapter,
                "portable decision",
            )
            self.assertEqual(("decision-core",), tuple(item.envelope.memory_id for item in matches))
            self.assertNotIn("decision-orphan", tuple(item.envelope.memory_id for item in matches))

            promotion_path = preserve_promotion_candidate(
                memory_root,
                PromotionCandidate(
                    candidate_id="promotion-core",
                    source_record_ids=("decision-core", "session-core"),
                    suggested_target="knowledge/portable-memory.md",
                    rationale="Reusable portable memory contract.",
                ),
                _context("tx-promotion"),
            )
            self.assertTrue(promotion_path.is_file())
            self.assertFalse((temporary / "knowledge").exists())

            rebuilt_project = build_project_focus(
                memory_root, "demo", GENERATOR_VERSION
            )
            rebuilt_global = build_global_focus(memory_root, GENERATOR_VERSION)
            self.assertEqual(project_document.content, rebuilt_project.content)
            self.assertEqual(global_document.content, rebuilt_global.content)
            self.assertEqual(project_document.content.encode("utf-8"), project_path.read_bytes())
            self.assertEqual(global_document.content.encode("utf-8"), global_path.read_bytes())

            observed_paths = list(created)
            observed_paths.extend(
                (
                    session_outcome.record_path,
                    decision_outcome.record_path,
                    competing_outcome.proposal_path,
                    project_path,
                    global_path,
                    orphan_path,
                    promotion_path,
                )
            )
            for path in observed_paths:
                self.assertIsNotNone(path)
                Path(path).resolve().relative_to(temporary)
                Path(path).resolve().relative_to(memory_root)

            self.assertEqual((), doctor_memory_root(memory_root))

    def test_projection_drift_is_reported_without_repair(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-drift-initialize"))
            document = build_project_focus(root, "demo", GENERATOR_VERSION)
            target = publish_projection(
                root,
                document,
                _context("tx-drift-projection"),
                guard=None,
            )
            target.write_bytes(target.read_bytes() + b"manual drift\n")
            before = _byte_snapshot(root)
            expected = (
                Finding(
                    code="projection-drift",
                    severity="warning",
                    path="projects/demo/current-focus.md",
                    message="generated projection differs from deterministic canonical output",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_accepted_projection_journals_remain_valid_historical_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-history-initialize"))
            decision = _candidate(
                "decision-history",
                "decision",
                "historical projection decision body",
            )
            committed = commit_record(
                root,
                decision,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-history-decision"),
            )
            self.assertEqual("accepted", committed.status)
            first_focus = update_focus(
                root,
                "demo",
                expected_revision=0,
                record_ids=("decision-history",),
                observed_at="2026-08-30T12:00:00Z",
                context=_context("tx-history-focus-first"),
            )
            self.assertEqual("accepted", first_focus.status)

            first = build_project_focus(root, "demo", GENERATOR_VERSION)
            target = publish_projection(
                root,
                first,
                _context("tx-history-projection-first"),
                guard=None,
            )
            second_focus = update_focus(
                root,
                "demo",
                expected_revision=1,
                record_ids=("decision-history",),
                observed_at="2026-08-30T12:01:00Z",
                context=_context("tx-history-focus-second"),
            )
            self.assertEqual("accepted", second_focus.status)
            second = build_project_focus(root, "demo", GENERATOR_VERSION)
            publish_projection(
                root,
                second,
                _context("tx-history-projection-second"),
                guard=None,
            )

            self.assertNotEqual(first.content, second.content)
            self.assertNotEqual(first.source_revision, second.source_revision)
            self.assertEqual(second.content.encode("utf-8"), target.read_bytes())
            first_journal = (
                root
                / ".agent-memory/transactions/projections"
                / _sha256_text("tx-history-projection-first")
                / (_sha256_text(first.relative_path) + ".json")
            )
            second_journal = (
                root
                / ".agent-memory/transactions/projections"
                / _sha256_text("tx-history-projection-second")
                / (_sha256_text(second.relative_path) + ".json")
            )
            first_document = json.loads(first_journal.read_text(encoding="utf-8"))
            second_document = json.loads(second_journal.read_text(encoding="utf-8"))
            self.assertEqual("accepted", first_document["status"])
            self.assertEqual("accepted", second_document["status"])
            self.assertEqual(
                hashlib.sha256(first.content.encode("utf-8")).hexdigest(),
                first_document["desired"]["target_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(second.content.encode("utf-8")).hexdigest(),
                second_document["desired"]["target_sha256"],
            )
            self.assertEqual((), doctor_memory_root(root))

    def test_projection_doctor_reads_target_once_and_hands_off_observed_hash(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-handoff-init"))
            document = build_project_focus(root, "demo", GENERATOR_VERSION)
            target = root / Path(document.relative_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(document.content.encode("utf-8"))
            expected_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            target_reads = []
            observed_hashes = []
            original_read = validation_module._read_memory_file
            original_builder = validation_module.build_projection_from_observed_target

            def read_once(memory_root, relative):
                if relative == document.relative_path:
                    target_reads.append(relative)
                return original_read(memory_root, relative)

            def observe_handoff(
                memory_root,
                relative_path,
                generator_version,
                observed_target_sha256,
            ):
                if relative_path == document.relative_path:
                    observed_hashes.append(observed_target_sha256)
                return original_builder(
                    memory_root,
                    relative_path,
                    generator_version,
                    observed_target_sha256,
                )

            with mock.patch.object(
                validation_module,
                "_read_memory_file",
                side_effect=read_once,
            ), mock.patch.object(
                validation_module,
                "build_projection_from_observed_target",
                side_effect=observe_handoff,
            ):
                self.assertEqual((), doctor_memory_root(root))

            self.assertEqual([document.relative_path], target_reads)
            self.assertEqual([expected_hash], observed_hashes)

    def test_doctor_discovers_orphan_and_dangling_allowlisted_projections(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-orphan-projection-init"))
            document = build_project_focus(root, "demo", GENERATOR_VERSION)
            relative = "projects/orphan/current-focus.md"
            orphan = root / Path(relative)
            orphan.parent.mkdir(parents=True)
            orphan.write_bytes(document.content.encode("utf-8"))
            self.assertIn(
                Finding(
                    code="projection-drift",
                    severity="warning",
                    path=relative,
                    message="generated projection differs from deterministic canonical output",
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-dangling-projection-init"))
            relative = "_index/home.md"
            dangling = root / Path(relative)
            dangling.parent.mkdir(parents=True)
            try:
                dangling.symlink_to("missing-home.md")
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            self.assertEqual(
                (
                    Finding(
                        code="path-containment",
                        severity="error",
                        path=relative,
                        message="candidate path is invalid, escaping, or a reparse point",
                    ),
                ),
                doctor_memory_root(root),
            )

    def test_real_root_guard_is_active_then_same_bytes_are_stale_after_crash(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-guard-initialize"))
            anchor_before = (root / ".agent-memory-root-write.anchor").read_bytes()
            ready = multiprocessing.Event()
            release = multiprocessing.Event()
            process = multiprocessing.Process(
                target=_hold_root_guard,
                args=(root, ready, release),
            )
            process.start()
            try:
                self.assertTrue(ready.wait(10))
                active_snapshot = _byte_snapshot(root)
                guard_snapshot = _root_guard_snapshot(root)
                import obsidian_agent_memory.transactions as producer_transactions

                wrong_offset = producer_transactions._Lease.open(
                    root / ".agent-memory-root-write.lock"
                )
                try:
                    acquired_at_zero = wrong_offset.acquire(offset=0)
                    self.assertEqual(os.name == "nt", acquired_at_zero)
                finally:
                    wrong_offset.close()
                active = (
                    Finding(
                        code="root-write-active",
                        severity="warning",
                        path=".agent-memory-root-write.lock",
                        message="root-write guard has a live lease",
                    ),
                )
                self.assertEqual(active, doctor_memory_root(root))
                self.assertEqual(active_snapshot, _byte_snapshot(root))
                process.terminate()
                process.join(10)
                self.assertFalse(process.is_alive())
                stale = (
                    Finding(
                        code="root-write-stale",
                        severity="warning",
                        path=".agent-memory-root-write.lock",
                        message="root-write guard lease is acquirable and requires explicit recovery review",
                    ),
                )
                self.assertEqual(stale, doctor_memory_root(root))
                self.assertEqual(guard_snapshot, _root_guard_snapshot(root))
                self.assertEqual(
                    anchor_before,
                    (root / ".agent-memory-root-write.anchor").read_bytes(),
                )
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(10)

    def test_probe_lease_seeks_reads_releases_and_closes_exactly_once(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            path = Path(temporary_text).resolve() / "probe.bin"
            path.write_bytes(b"probe bytes\n")
            descriptor = os.open(
                str(path),
                os.O_RDWR | getattr(os, "O_BINARY", 0),
            )
            lease = validation_module._ProbeLease(descriptor)
            lock_offset = validation_module._OBSERVABLE_GUARD_LOCK_OFFSET
            with mock.patch.object(
                os,
                "lseek",
                wraps=os.lseek,
            ) as seek, mock.patch.object(
                os,
                "read",
                wraps=os.read,
            ) as read, mock.patch.object(
                os,
                "close",
                wraps=os.close,
            ) as close, mock.patch.object(
                os,
                "write",
                side_effect=AssertionError("probe must not write"),
            ), mock.patch.object(
                os,
                "ftruncate",
                side_effect=AssertionError("probe must not truncate"),
            ):
                if os.name == "nt":
                    import msvcrt

                    with mock.patch.object(msvcrt, "locking") as locking:
                        self.assertTrue(lease.acquire(lock_offset))
                        self.assertEqual(b"probe bytes\n", lease.read_bounded(0))
                        lease.close()
                        lease.close()
                        self.assertEqual(
                            [msvcrt.LK_NBLCK, msvcrt.LK_UNLCK],
                            [call.args[1] for call in locking.call_args_list],
                        )
                else:
                    import fcntl

                    with mock.patch.object(fcntl, "flock") as flock:
                        self.assertTrue(lease.acquire(lock_offset))
                        self.assertEqual(b"probe bytes\n", lease.read_bounded(0))
                        lease.close()
                        lease.close()
                        self.assertEqual(2, flock.call_count)
                self.assertEqual(
                    [lock_offset, 0, lock_offset],
                    [call.args[1] for call in seek.call_args_list],
                )
                self.assertGreaterEqual(read.call_count, 1)
                self.assertEqual(1, close.call_count)

    def test_probe_busy_malformed_and_exception_paths_close_exactly_once(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            path = Path(temporary_text).resolve() / "busy.bin"
            path.write_bytes(b"busy probe\n")
            descriptor = os.open(
                str(path),
                os.O_RDWR | getattr(os, "O_BINARY", 0),
            )
            lease = validation_module._ProbeLease(descriptor)
            with mock.patch.object(os, "close", wraps=os.close) as close:
                if os.name == "nt":
                    import msvcrt

                    with mock.patch.object(
                        msvcrt,
                        "locking",
                        side_effect=OSError("busy"),
                    ) as locking:
                        self.assertFalse(lease.acquire(1_048_576))
                        lease.close()
                        self.assertEqual(1, locking.call_count)
                else:
                    import fcntl

                    with mock.patch.object(
                        fcntl,
                        "flock",
                        side_effect=OSError("busy"),
                    ) as flock:
                        self.assertFalse(lease.acquire(1_048_576))
                        lease.close()
                        self.assertEqual(1, flock.call_count)
                self.assertEqual(1, close.call_count)

        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve()
            relative = "oversize.bin"
            (root / relative).write_bytes(b"x" * (1024 * 1024 + 1))
            with mock.patch.object(os, "close", wraps=os.close) as close:
                with self.assertRaises(validation_module._MemoryOversizeError):
                    validation_module._probe_memory_file(root, relative, 0)
            self.assertEqual(1, close.call_count)

        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve()
            relative = "read-error.bin"
            (root / relative).write_bytes(b"read error\n")
            original_close = os.close

            def close_then_fail(descriptor):
                original_close(descriptor)
                raise OSError("injected close failure")

            with mock.patch.object(
                os,
                "read",
                side_effect=OSError("injected read failure"),
            ), mock.patch.object(
                os,
                "close",
                side_effect=close_then_fail,
            ) as close:
                with self.assertRaises(validation_module._MemoryContainmentError):
                    validation_module._probe_memory_file(root, relative, 0)
            self.assertEqual(1, close.call_count)

        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve()
            relative = "memory-read-error.bin"
            (root / relative).write_bytes(b"memory read error\n")
            original_close = os.close

            def memory_close_then_fail(descriptor):
                original_close(descriptor)
                raise OSError("injected memory close failure")

            with mock.patch.object(
                os,
                "read",
                side_effect=OSError("injected memory read failure"),
            ), mock.patch.object(
                os,
                "close",
                side_effect=memory_close_then_fail,
            ) as close:
                with self.assertRaises(validation_module._MemoryContainmentError):
                    validation_module._read_memory_file(root, relative)
            self.assertEqual(1, close.call_count)

    def test_probe_open_uses_the_locked_platform_no_follow_contract(self):
        path = Path("probe-contract.bin")
        if os.name == "nt":
            import ctypes
            import msvcrt
            from types import SimpleNamespace

            create_file = mock.Mock(return_value=12345)
            kernel32 = SimpleNamespace(
                CreateFileW=create_file,
                CloseHandle=mock.Mock(),
            )
            with mock.patch.object(
                ctypes,
                "WinDLL",
                return_value=kernel32,
            ), mock.patch.object(
                msvcrt,
                "open_osfhandle",
                return_value=77,
            ) as open_osfhandle:
                self.assertEqual(77, validation_module._windows_probe_open(path))
            arguments = create_file.call_args.args
            self.assertEqual(0x80000000 | 0x40000000, arguments[1])
            self.assertEqual(0x00000001 | 0x00000002 | 0x00000004, arguments[2])
            self.assertEqual(3, arguments[4])
            self.assertEqual(0x00000080 | 0x00200000, arguments[5])
            self.assertEqual(
                (12345, os.O_RDWR | getattr(os, "O_BINARY", 0)),
                open_osfhandle.call_args.args,
            )

            create_file.reset_mock()
            open_osfhandle.reset_mock()
            with mock.patch.object(
                ctypes,
                "WinDLL",
                return_value=kernel32,
            ), mock.patch.object(
                msvcrt,
                "open_osfhandle",
                return_value=77,
            ) as read_open_osfhandle:
                self.assertEqual(
                    77,
                    validation_module._windows_memory_read_open(path),
                )
            arguments = create_file.call_args.args
            self.assertEqual(0x80000000, arguments[1])
            self.assertEqual(0x00000001 | 0x00000002 | 0x00000004, arguments[2])
            self.assertEqual(3, arguments[4])
            self.assertEqual(0x00000080 | 0x00200000, arguments[5])
            self.assertEqual(
                (12345, os.O_RDONLY | getattr(os, "O_BINARY", 0)),
                read_open_osfhandle.call_args.args,
            )
        else:
            with mock.patch.object(os, "open", return_value=77) as open_file:
                lease = validation_module._ProbeLease.open(path)
            self.assertEqual(77, lease.descriptor)
            flags = open_file.call_args.args[1]
            self.assertTrue(flags & os.O_RDWR)
            self.assertTrue(flags & getattr(os, "O_NOFOLLOW", 0))

    def test_task4_journal_rejects_an_extra_field_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-journal-schema"))
            relative = ".agent-memory/transactions/tx-journal-schema.json"
            journal_path = root / Path(relative)
            document = json.loads(journal_path.read_text(encoding="utf-8"))
            document["unexpected"] = "must-reject"
            journal_path.write_bytes(_canonical_json_bytes(document))
            before = _byte_snapshot(root)
            expected = (
                Finding(
                    code="transaction-invalid",
                    severity="error",
                    path=relative,
                    message="invalid canonical transaction JSON or operation schema",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_doctor_closed_schema_catalog_record_and_focus_taxonomy(self):
        def initialized_root(temporary_text, transaction_id):
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context(transaction_id))
            return root

        with tempfile.TemporaryDirectory() as temporary_text:
            root = initialized_root(temporary_text, "tx-schema-taxonomy")
            relative = ".agent-memory/config.json"
            (root / Path(relative)).write_bytes(
                _canonical_json_bytes({"schema_version": 2, "unexpected": True})
            )
            self.assertEqual(
                (
                    Finding(
                        code="schema-invalid",
                        severity="error",
                        path=relative,
                        message="invalid Schema 2 JSON document",
                    ),
                ),
                doctor_memory_root(root),
            )
        with tempfile.TemporaryDirectory() as temporary_text:
            root = initialized_root(temporary_text, "tx-catalog-taxonomy")
            projection = build_project_focus(root, "demo", GENERATOR_VERSION)
            projection_path = root / Path(projection.relative_path)
            projection_path.parent.mkdir(parents=True, exist_ok=True)
            projection_path.write_bytes(projection.content.encode("utf-8"))
            relative = ".agent-memory/state/catalog.json"
            catalog = json.loads((root / Path(relative)).read_text(encoding="utf-8"))
            catalog["unexpected"] = True
            (root / Path(relative)).write_bytes(_canonical_json_bytes(catalog))
            self.assertEqual(
                (
                    Finding(
                        code="catalog-invalid",
                        severity="error",
                        path=relative,
                        message="invalid canonical catalog JSON or schema",
                    ),
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = initialized_root(temporary_text, "tx-record-missing-init")
            candidate = _candidate("record-missing", "decision", "missing body")
            outcome = commit_record(
                root,
                candidate,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-record-missing"),
            )
            outcome.record_path.unlink()
            self.assertEqual(
                (
                    Finding(
                        code="catalog-record-missing",
                        severity="error",
                        path=".agent-memory/state/catalog.json",
                        message="catalog-selected record is missing: {0}".format(
                            record_relative_path(candidate.envelope).as_posix()
                        ),
                    ),
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = initialized_root(temporary_text, "tx-record-mismatch-init")
            candidate = _candidate("record-mismatch", "decision", "original body")
            outcome = commit_record(
                root,
                candidate,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-record-mismatch"),
            )
            outcome.record_path.write_bytes(outcome.record_path.read_bytes() + b"drift\n")
            relative = record_relative_path(candidate.envelope).as_posix()
            self.assertEqual(
                (
                    Finding(
                        code="catalog-record-mismatch",
                        severity="error",
                        path=relative,
                        message="catalog-selected record envelope, hash, or canonical path does not match",
                    ),
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = initialized_root(temporary_text, "tx-focus-invalid-init")
            relative = ".agent-memory/state/focus/demo.json"
            path = root / Path(relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(_canonical_json_bytes({"schema_version": 2}))
            self.assertEqual(
                (
                    Finding(
                        code="focus-invalid",
                        severity="error",
                        path=relative,
                        message="invalid canonical focus JSON or schema",
                    ),
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = initialized_root(temporary_text, "tx-focus-current-init")
            relative = ".agent-memory/state/focus/demo.json"
            path = root / Path(relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                _canonical_json_bytes(
                    {
                        "observed_at": OCCURRED_AT,
                        "project_id": "demo",
                        "record_ids": ["ghost-record"],
                        "revision": 0,
                        "schema_version": 2,
                    }
                )
            )
            self.assertEqual(
                (
                    Finding(
                        code="focus-record-not-current",
                        severity="error",
                        path=relative,
                        message="focus references a record that is not current in the catalog: ghost-record",
                    ),
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = initialized_root(temporary_text, "tx-focus-time-init")
            relative = ".agent-memory/state/focus/demo.json"
            path = root / Path(relative)
            document = json.loads(path.read_text(encoding="utf-8"))
            document["observed_at"] = "not-a-timestamp"
            path.write_bytes(_canonical_json_bytes(document))
            self.assertEqual(
                (
                    Finding(
                        code="focus-invalid",
                        severity="error",
                        path=relative,
                        message="invalid canonical focus JSON or schema",
                    ),
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = initialized_root(temporary_text, "tx-catalog-oversize-init")
            relative = ".agent-memory/state/catalog.json"
            (root / Path(relative)).write_bytes(b"{" + b" " * (1024 * 1024))
            self.assertEqual(
                (
                    Finding(
                        code="catalog-invalid",
                        severity="error",
                        path=relative,
                        message="invalid canonical catalog JSON or schema",
                    ),
                ),
                doctor_memory_root(root),
            )

    def test_doctor_rejects_a_selected_record_reparse_without_following_it(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            temporary = Path(temporary_text).resolve()
            root = temporary / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-reparse-init"))
            candidate = _candidate("record-reparse", "decision", "owned bytes")
            outcome = commit_record(
                root,
                candidate,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-reparse-record"),
            )
            external = temporary / "external.md"
            external.write_bytes(b"external must remain unread and unchanged\n")
            outcome.record_path.unlink()
            try:
                outcome.record_path.symlink_to(external)
            except OSError as error:
                self.skipTest("symlink creation unavailable: {0}".format(error))
            relative = outcome.record_path.relative_to(root).as_posix()
            expected = (
                Finding(
                    code="path-containment",
                    severity="error",
                    path=relative,
                    message="candidate path is invalid, escaping, or a reparse point",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(
                b"external must remain unread and unchanged\n",
                external.read_bytes(),
            )

    def test_task5_projection_journal_rejects_empty_occurrence(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-projection-schema-init"))
            document = build_project_focus(root, "demo", GENERATOR_VERSION)
            transaction_id = "tx-projection-schema"
            publish_projection(root, document, _context(transaction_id), guard=None)
            context_hash = _sha256_text(transaction_id)
            target_hash = _sha256_text(document.relative_path)
            relative = (
                ".agent-memory/transactions/projections/{0}/{1}.json".format(
                    context_hash, target_hash
                )
            )
            journal_path = root / Path(relative)
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            journal["occurred_at"] = ""
            journal_path.write_bytes(_canonical_json_bytes(journal))
            before = _byte_snapshot(root)
            expected = (
                Finding(
                    code="transaction-invalid",
                    severity="error",
                    path=relative,
                    message="invalid canonical transaction JSON or operation schema",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_in_progress_projection_at_expected_absence_is_not_run(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-incomplete-init"))
            document = build_project_focus(root, "demo", GENERATOR_VERSION)
            transaction_id = "tx-incomplete-not-run"
            target = publish_projection(root, document, _context(transaction_id), guard=None)
            context_hash = _sha256_text(transaction_id)
            target_hash = _sha256_text(document.relative_path)
            relative = (
                ".agent-memory/transactions/projections/{0}/{1}.json".format(
                    context_hash, target_hash
                )
            )
            journal_path = root / Path(relative)
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            journal["status"] = "in-progress"
            journal_path.write_bytes(_canonical_json_bytes(journal))
            target.unlink()
            before = _byte_snapshot(root)
            expected = (
                Finding(
                    code="transaction-incomplete-not-run",
                    severity="warning",
                    path=relative,
                    message="transaction or pre-intent claim has not applied a canonical mutation",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_in_progress_projection_at_third_state_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-ambiguous-init"))
            document = build_project_focus(root, "demo", GENERATOR_VERSION)
            transaction_id = "tx-ambiguous-projection"
            target = publish_projection(root, document, _context(transaction_id), guard=None)
            context_hash = _sha256_text(transaction_id)
            target_hash = _sha256_text(document.relative_path)
            relative = (
                ".agent-memory/transactions/projections/{0}/{1}.json".format(
                    context_hash,
                    target_hash,
                )
            )
            journal_path = root / Path(relative)
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            journal["status"] = "in-progress"
            journal_path.write_bytes(_canonical_json_bytes(journal))
            target.write_bytes(b"third state\n")
            expected = (
                Finding(
                    code="transaction-incomplete-ambiguous",
                    severity="error",
                    path=relative,
                    message="in-progress transaction has no single reconciled canonical outcome",
                ),
                Finding(
                    code="projection-drift",
                    severity="warning",
                    path=document.relative_path,
                    message="generated projection differs from deterministic canonical output",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))

    def test_projection_claim_and_guarded_multi_target_routing_contract(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-routing-init"))
            project = build_project_focus(root, "demo", GENERATOR_VERSION)
            global_focus = build_global_focus(root, GENERATOR_VERSION)
            context = _context("tx-routing-multi-target")
            with root_write_guard(root, context) as guard:
                publish_projection(root, project, context, guard=guard)
                publish_projection(root, global_focus, context, guard=guard)
            self.assertEqual((), doctor_memory_root(root))

            context_hash = _sha256_text(context.transaction_id)
            context_directory = (
                root / ".agent-memory/transactions/projections" / context_hash
            )
            project_hash = _sha256_text(project.relative_path)
            global_hash = _sha256_text(global_focus.relative_path)
            claim = context_directory / "unguarded-target.claim"
            claim.write_bytes(
                _canonical_json_bytes(
                    {
                        "context_sha256": context_hash,
                        "schema_version": 2,
                        "target": project.relative_path,
                        "target_path_sha256": project_hash,
                        "transaction_id": context.transaction_id,
                    }
                )
            )
            claim_relative = claim.relative_to(root).as_posix()
            invalid_claim = (
                Finding(
                    code="transaction-invalid",
                    severity="error",
                    path=claim_relative,
                    message="invalid canonical transaction JSON or operation schema",
                ),
            )
            self.assertEqual(invalid_claim, doctor_memory_root(root))

            project_journal = context_directory / (project_hash + ".json")
            global_journal = context_directory / (global_hash + ".json")
            project_journal_bytes = project_journal.read_bytes()
            project_journal.unlink()
            self.assertEqual(invalid_claim, doctor_memory_root(root))

            global_journal.unlink()
            project_journal.write_bytes(project_journal_bytes)
            self.assertEqual((), doctor_memory_root(root))

            project_journal.unlink()
            claim_only = (
                Finding(
                    code="transaction-incomplete-not-run",
                    severity="warning",
                    path=claim_relative,
                    message="transaction or pre-intent claim has not applied a canonical mutation",
                ),
            )
            before = _byte_snapshot(root)
            self.assertEqual(claim_only, doctor_memory_root(root))
            self.assertEqual(claim_only, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_transaction_reparse_has_containment_precedence_and_unknown_directory_is_invalid(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-transaction-reparse"))
            relative = ".agent-memory/transactions/tx-transaction-reparse.json"
            journal = root / Path(relative)
            retained = journal.with_name("retained-journal.json")
            journal.replace(retained)
            try:
                journal.symlink_to(retained.name)
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            self.assertEqual(
                (
                    Finding(
                        code="path-containment",
                        severity="error",
                        path=relative,
                        message="candidate path is invalid, escaping, or a reparse point",
                    ),
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-unknown-directory-init"))
            unexpected = root / ".agent-memory/transactions/unexpected"
            unexpected.mkdir()
            expected = Finding(
                code="transaction-invalid",
                severity="error",
                path=unexpected.relative_to(root).as_posix(),
                message="invalid canonical transaction JSON or operation schema",
            )
            self.assertIn(expected, doctor_memory_root(root))

        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-overflow-reparse-init"))
            relative = ".agent-memory/transactions/000-reparse"
            reparse = root / Path(relative)
            try:
                reparse.symlink_to("../config.json")
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            expected = (
                Finding(
                    code="path-containment",
                    severity="error",
                    path=relative,
                    message="candidate path is invalid, escaping, or a reparse point",
                ),
            )
            with mock.patch.object(
                validation_module,
                "_MEMORY_INVENTORY_LIMIT",
                1,
            ):
                self.assertEqual(expected, doctor_memory_root(root))

    def test_in_progress_focus_at_desired_hash_is_ran_not_finalized(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-focus-state-init"))
            transaction_id = "tx-focus-state"
            outcome = update_focus(
                root,
                "demo",
                expected_revision=0,
                record_ids=(),
                observed_at="2026-08-30T12:01:00Z",
                context=_context(transaction_id),
            )
            self.assertEqual("accepted", outcome.status)
            relative = ".agent-memory/transactions/{0}.json".format(transaction_id)
            journal_path = root / Path(relative)
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            journal["status"] = "in-progress"
            del journal["focus_revision"]
            journal_path.write_bytes(_canonical_json_bytes(journal))
            before = _byte_snapshot(root)
            expected = (
                Finding(
                    code="transaction-incomplete-ran",
                    severity="error",
                    path=relative,
                    message="in-progress transaction canonical target is at the recorded desired state but was not finalized",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_invalid_task4_pending_suppresses_the_incomplete_outcome(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-pending-init"))
            transaction_id = "tx-pending-focus"
            update_focus(
                root,
                "demo",
                expected_revision=0,
                record_ids=(),
                observed_at=OCCURRED_AT,
                context=_context(transaction_id),
            )
            owner_relative = ".agent-memory/transactions/{0}.json".format(
                transaction_id
            )
            owner_path = root / Path(owner_relative)
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
            owner["status"] = "in-progress"
            del owner["focus_revision"]
            owner_path.write_bytes(_canonical_json_bytes(owner))
            pending_relative = (
                Path(".agent-memory/state/focus")
                / owner["focus_cas"]["pending_name"]
            ).as_posix()
            pending_path = root / Path(pending_relative)
            pending_path.write_bytes(b"wrong pending bytes\n")
            expected = (
                Finding(
                    code="transaction-pending-invalid",
                    severity="error",
                    path=pending_relative,
                    message="transaction-bound pending or recovery evidence is unknown, incomplete, malformed, or mismatched",
                ),
            )

            before = _byte_snapshot(root)
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_pre_cas_task4_intents_at_expected_absence_are_not_run(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-pre-cas-focus-init"))
            transaction_id = "tx-pre-cas-focus"
            update_focus(
                root,
                "demo",
                expected_revision=0,
                record_ids=(),
                observed_at=OCCURRED_AT,
                context=_context(transaction_id),
            )
            owner_relative = ".agent-memory/transactions/{0}.json".format(
                transaction_id
            )
            owner_path = root / Path(owner_relative)
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
            owner["status"] = "in-progress"
            del owner["focus_cas"]
            del owner["focus_revision"]
            owner_path.write_bytes(_canonical_json_bytes(owner))
            (root / Path(owner["target"])).unlink()
            self.assertEqual(
                (
                    Finding(
                        code="transaction-incomplete-not-run",
                        severity="warning",
                        path=owner_relative,
                        message="transaction or pre-intent claim has not applied a canonical mutation",
                    ),
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-pre-cas-promotion-init"))
            source = _candidate("pre-cas-source", "decision", "source")
            commit_record(
                root,
                source,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-pre-cas-source"),
            )
            transaction_id = "tx-pre-cas-promotion"
            proposal = preserve_promotion_candidate(
                root,
                PromotionCandidate(
                    candidate_id="pre-cas-promotion",
                    source_record_ids=(source.envelope.memory_id,),
                    suggested_target="knowledge/pre-cas.md",
                    rationale="Pre-CAS fixture.",
                ),
                _context(transaction_id),
            )
            owner_relative = ".agent-memory/transactions/{0}.json".format(
                transaction_id
            )
            owner_path = root / Path(owner_relative)
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
            owner["status"] = "in-progress"
            del owner["observed_base"]
            del owner["proposal_path"]
            owner_path.write_bytes(_canonical_json_bytes(owner))
            proposal.unlink()
            self.assertEqual(
                (
                    Finding(
                        code="transaction-incomplete-not-run",
                        severity="warning",
                        path=owner_relative,
                        message="transaction or pre-intent claim has not applied a canonical mutation",
                    ),
                ),
                doctor_memory_root(root),
            )

    def test_lone_normal_guard_prefix_is_candidate_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-candidate-init"))
            transaction_id = "tx-candidate-prefix"
            binding = (str(root) + "\0" + transaction_id).encode("utf-8")
            candidate_name = ".agent-memory-root-write.candidate-" + hashlib.sha256(
                binding
            ).hexdigest()
            canonical = (
                json.dumps(
                    {
                        "actor": "core-test-agent",
                        "created_at": OCCURRED_AT,
                        "process_id": os.getpid(),
                        "target": ".",
                        "transaction_id": transaction_id,
                    },
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8")
            candidate_path = root / candidate_name
            candidate_path.write_bytes(canonical[:31])
            before = _byte_snapshot(root)
            expected = (
                Finding(
                    code="root-write-candidate",
                    severity="warning",
                    path=candidate_name,
                    message="candidate-only root-write guard evidence requires explicit recovery review",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_proposal_filename_must_bind_its_transaction(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-proposal-init"))
            accepted = _candidate("proposal-owner", "decision", "accepted owner")
            commit_record(
                root,
                accepted,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-proposal-owner"),
            )
            stale = _candidate("proposal-stale", "decision", "stale intent")
            outcome = commit_record(
                root,
                stale,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-proposal-stale"),
            )
            self.assertEqual("proposed", outcome.status)
            relative = ".agent-memory/state/proposals/proposal-alias.json"
            alias = root / Path(relative)
            alias.write_bytes(outcome.proposal_path.read_bytes())
            before = _byte_snapshot(root)
            expected = (
                Finding(
                    code="proposal-invalid",
                    severity="error",
                    path=relative,
                    message="invalid canonical proposal JSON or schema",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_promotion_semantics_run_only_after_a_valid_proposal_envelope(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-promotion-semantics-init"))
            owner = _candidate("promotion-source", "decision", "source body")
            commit_record(
                root,
                owner,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-promotion-source"),
            )
            proposal = preserve_promotion_candidate(
                root,
                PromotionCandidate(
                    candidate_id="promotion-semantic",
                    source_record_ids=(owner.envelope.memory_id,),
                    suggested_target="knowledge/semantic.md",
                    rationale="Reusable semantic fact.",
                ),
                _context("tx-promotion-semantic"),
            )
            document = json.loads(proposal.read_text(encoding="utf-8"))
            document["desired"]["source_record_ids"] = ["ghost-source"]
            document["expected_base"]["source_record_ids"] = ["ghost-source"]
            proposal.write_bytes(_canonical_json_bytes(document))
            relative = proposal.relative_to(root).as_posix()
            expected = (
                Finding(
                    code="promotion-candidate-invalid",
                    severity="warning",
                    path=relative,
                    message="knowledge promotion candidate is invalid or its source records are not current",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))

    def test_root_recovery_transition_digest_drift_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-recovery-init"))
            ready = multiprocessing.Event()
            release = multiprocessing.Event()
            process = multiprocessing.Process(
                target=_hold_root_guard,
                args=(root, ready, release),
            )
            process.start()
            try:
                self.assertTrue(ready.wait(10))
                lock_hash = hashlib.sha256(
                    (root / ".agent-memory-root-write.lock").read_bytes()
                ).hexdigest()
                process.terminate()
                process.join(10)
                self.assertFalse(process.is_alive())
                with recover_root_write_guard(
                    root,
                    "tx-live-root-guard",
                    lock_hash,
                    _context("tx-root-recovery"),
                    "fixture-authorization",
                ):
                    probe_calls = []
                    original_probe = validation_module._probe_memory_file

                    def record_probe(
                        memory_root,
                        relative,
                        offset,
                        locked_expected=None,
                    ):
                        probe_calls.append((relative, offset))
                        return original_probe(
                            memory_root,
                            relative,
                            offset,
                            locked_expected=locked_expected,
                        )

                    with mock.patch.object(
                        validation_module,
                        "_probe_memory_file",
                        side_effect=record_probe,
                    ):
                        doctor_memory_root(root)
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(10)

            recovery_root = root / ".agent-memory-root-write-recoveries"
            operation_directories = tuple(recovery_root.iterdir())
            self.assertEqual(1, len(operation_directories))
            operation_directory = operation_directories[0]
            self.assertIn(
                (".agent-memory-root-write.lock", 1_048_576),
                probe_calls,
            )
            self.assertTrue(
                any(
                    relative.startswith(".agent-memory-root-write.candidate-")
                    and offset == 1_048_576
                    for relative, offset in probe_calls
                ),
                probe_calls,
            )
            self.assertIn(
                (".agent-memory-root-write.anchor", 0),
                probe_calls,
            )
            self.assertIn(
                (
                    operation_directory.relative_to(root).as_posix()
                    + "/old-artifact.bin",
                    0,
                ),
                probe_calls,
            )
            transition = operation_directory / "010-new-guard-published.json"
            document = json.loads(transition.read_text(encoding="utf-8"))
            document["previous_transition_sha256"] = "0" * 64
            transition.write_bytes(_canonical_json_bytes(document))
            relative = transition.relative_to(root).as_posix()
            before = _byte_snapshot(root)
            expected = (
                Finding(
                    code="root-write-recovery-incomplete",
                    severity="error",
                    path=relative,
                    message="root-write recovery transition chain is incomplete, missing, duplicate, unknown, reordered, or hash-divergent",
                ),
            )

            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_invalid_projection_recovery_terminal_suppresses_owner_outcome(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-recovery-terminal-init"))
            owner = _candidate("recovery-owner", "decision", "rollback owner")
            commit_record(
                root,
                owner,
                expected_catalog_revision=0,
                expected_record_revision=None,
                context=_context("tx-recovery-terminal-owner"),
            )
            proposal = preserve_promotion_candidate(
                root,
                PromotionCandidate(
                    candidate_id="recovery-race-proposal",
                    source_record_ids=(owner.envelope.memory_id,),
                    suggested_target="knowledge/recovery.md",
                    rationale="Fixture operational race.",
                ),
                _context("tx-recovery-race-proposal"),
            )
            proposal_raw = proposal.read_bytes()
            proposal.unlink()
            initial = next(
                document
                for document in build_root_views(root, GENERATOR_VERSION)
                if document.relative_path == "_index/stale-or-uncertain.md"
            )
            publish_projection(
                root,
                initial,
                _context("tx-recovery-terminal-base"),
                guard=None,
            )
            document = next(
                item
                for item in build_root_views(root, GENERATOR_VERSION)
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            transaction_id = "tx-recovery-terminal"

            def checkpoint(stage, memory_root, projection_target):
                if stage == "after-input-recheck":
                    proposal.write_bytes(proposal_raw)

            with mock.patch.object(
                projection_module,
                "_projection_checkpoint",
                side_effect=checkpoint,
            ):
                with self.assertRaises(ConflictError):
                    publish_projection(
                        root,
                        document,
                        _context(transaction_id),
                        guard=None,
                    )

            context_hash = _sha256_text(transaction_id)
            target_hash = _sha256_text(document.relative_path)
            owner_relative = (
                ".agent-memory/transactions/projections/{0}/{1}.json".format(
                    context_hash,
                    target_hash,
                )
            )
            recovery = _projection_recovery_directory(
                root,
                transaction_id,
                document.relative_path,
            )
            terminal = next(recovery.glob("terminal-*.json"))
            healthy_findings = doctor_memory_root(root)
            self.assertIn(
                Finding(
                    code="transaction-incomplete-not-run",
                    severity="warning",
                    path=owner_relative,
                    message="transaction or pre-intent claim has not applied a canonical mutation",
                ),
                healthy_findings,
            )
            self.assertFalse(
                any(
                    finding.code in ("transaction-invalid", "transaction-pending-invalid")
                    and finding.path.startswith(
                        ".agent-memory/transactions/projection-recovery/"
                    )
                    for finding in healthy_findings
                )
            )
            displaced = recovery / "displaced.bin"
            displaced.write_bytes(displaced.read_bytes() + b"drift")
            displaced_relative = displaced.relative_to(root).as_posix()
            before = _byte_snapshot(root)
            findings = doctor_memory_root(root)
            self.assertIn(
                Finding(
                    code="transaction-pending-invalid",
                    severity="error",
                    path=displaced_relative,
                    message="transaction-bound pending or recovery evidence is unknown, incomplete, malformed, or mismatched",
                ),
                findings,
            )
            self.assertFalse(
                any(
                    finding.path == owner_relative
                    and finding.code.startswith("transaction-incomplete-")
                    for finding in findings
                )
            )
            self.assertEqual(findings, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))

    def test_projection_terminal_inventory_overflow_is_transaction_invalid(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-terminal-overflow-init"))
            _, owner, recovery = _create_projection_recovery_owner(
                root,
                "tx-terminal-overflow",
            )
            for index in range(10001):
                (recovery / "terminal-{0:05d}.json".format(index)).touch()
            relative = recovery.relative_to(root).as_posix()
            expected = Finding(
                code="transaction-invalid",
                severity="error",
                path=relative,
                message="invalid canonical transaction JSON or operation schema",
            )

            findings = doctor_memory_root(root)
            self.assertIn(expected, findings)
            self.assertFalse(
                any(
                    finding.path == owner.relative_to(root).as_posix()
                    and finding.code.startswith("transaction-incomplete-")
                    for finding in findings
                )
            )

    def test_projection_outer_layouts_have_independent_inventory_bounds(self):
        namespaces = (
            ".agent-memory/transactions/projections",
            ".agent-memory/transactions/projection-recovery",
        )
        for namespace in namespaces:
            with self.subTest(namespace=namespace), tempfile.TemporaryDirectory() as temporary_text:
                root = Path(temporary_text).resolve() / "memory-root"
                initialize_memory_root(root, "demo", _context("tx-outer-bound-init"))
                directory = root / Path(namespace)
                directory.mkdir(parents=True, exist_ok=True)
                for index in range(10001):
                    name = hashlib.sha256(str(index).encode("ascii")).hexdigest()
                    (directory / name).mkdir()
                expected = Finding(
                    code="transaction-invalid",
                    severity="error",
                    path=namespace,
                    message="invalid canonical transaction JSON or operation schema",
                )
                findings = doctor_memory_root(root)
                self.assertIn(expected, findings)

    def test_projection_outer_layout_bounds_are_aggregate_not_per_directory(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-aggregate-bound-init"))
            _create_projection_recovery_owner(root, "tx-aggregate-bound-a")
            _create_projection_recovery_owner(root, "tx-aggregate-bound-b")
            expected = {
                Finding(
                    code="transaction-invalid",
                    severity="error",
                    path=".agent-memory/transactions/projections",
                    message="invalid canonical transaction JSON or operation schema",
                ),
                Finding(
                    code="transaction-invalid",
                    severity="error",
                    path=".agent-memory/transactions/projection-recovery",
                    message="invalid canonical transaction JSON or operation schema",
                ),
            }
            with mock.patch.object(
                validation_module,
                "_MEMORY_INVENTORY_LIMIT",
                3,
            ):
                findings = doctor_memory_root(root)
            self.assertTrue(expected.issubset(set(findings)), findings)

    def test_projection_nonterminal_inventory_overflow_is_pending_invalid(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-evidence-overflow-init"))
            _, owner, recovery = _create_projection_recovery_owner(
                root,
                "tx-evidence-overflow",
            )
            for index in range(10000):
                (recovery / "evidence-{0:05d}.bin".format(index)).touch()
            relative = recovery.relative_to(root).as_posix()
            expected = Finding(
                code="transaction-pending-invalid",
                severity="error",
                path=relative,
                message="transaction-bound pending or recovery evidence is unknown, incomplete, malformed, or mismatched",
            )

            findings = doctor_memory_root(root)
            self.assertIn(expected, findings)
            self.assertFalse(
                any(
                    finding.path == owner.relative_to(root).as_posix()
                    and finding.code.startswith("transaction-incomplete-")
                    for finding in findings
                )
            )

    def test_compact_terminal_inventory_requires_the_lexical_invalid_prefix(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-compact-init"))
            document, owner_path, recovery = _create_projection_recovery_owner(
                root,
                "tx-compact-terminal",
            )
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
            displaced = recovery / "displaced.bin"
            target = root / Path(document.relative_path)
            displaced.write_bytes(target.read_bytes())
            recovery_relative = recovery.relative_to(root).as_posix()
            invalid_paths = []
            invalid_descriptions = []
            for name in ("terminal-a.json", "terminal-b.json"):
                path = recovery / name
                path.mkdir()
                relative = path.relative_to(root).as_posix()
                invalid_paths.append(relative)
                invalid_descriptions.append(
                    {
                        "file_type": stat.S_IFDIR,
                        "kind": "directory",
                        "path": relative,
                    }
                )
            digest = hashlib.sha256()
            digest.update(b"projection-terminal-inventory-v1\n")
            for description in invalid_descriptions:
                digest.update(
                    _canonical_json_bytes(
                        {
                            "classification": "invalid",
                            "description": description,
                        }
                    )
                )
            inventory = {
                "count": 2,
                "invalid_count": 2,
                "inventory_sha256": digest.hexdigest(),
                "limit": 10000,
                "listed_invalid_count": 1,
                "valid_count": 0,
            }

            def terminal_manifest(description, invalid_path):
                return {
                    "endpoints": {
                        "quarantine": {
                            "file_type": stat.S_IFREG,
                            "kind": "regular",
                            "path": displaced.relative_to(root).as_posix(),
                        },
                        "target": {
                            "file_type": stat.S_IFREG,
                            "kind": "regular",
                            "path": document.relative_path,
                        },
                    },
                    "error_type": "OSError",
                    "evidence_paths": sorted(
                        (
                            recovery_relative + "/intent.json",
                            displaced.relative_to(root).as_posix(),
                            document.relative_path,
                            invalid_path,
                        )
                    ),
                    "invalid_terminals": [description],
                    "outcome": "unexpected-exception",
                    "prior_sha256": None,
                    "projection_evidence": {
                        "context_sha256": _sha256_text("tx-compact-terminal"),
                        "target_path_sha256": _sha256_text(document.relative_path),
                    },
                    "published_sha256": owner["desired"]["target_sha256"],
                    "schema_version": 2,
                    "status": "terminal",
                    "target": document.relative_path,
                    "terminal_inventory": inventory,
                    "transaction_id": "tx-compact-terminal",
                }

            valid_manifest = terminal_manifest(
                invalid_descriptions[0],
                invalid_paths[0],
            )
            valid_raw = _canonical_json_bytes(valid_manifest)
            terminal = recovery / (
                "terminal-" + hashlib.sha256(valid_raw).hexdigest() + ".json"
            )
            terminal.write_bytes(valid_raw)
            healthy = doctor_memory_root(root)
            self.assertFalse(
                any(
                    finding.code in ("transaction-invalid", "transaction-pending-invalid")
                    and finding.path.startswith(recovery_relative)
                    for finding in healthy
                ),
                healthy,
            )

            forged_manifest = terminal_manifest(
                invalid_descriptions[1],
                invalid_paths[1],
            )
            forged_raw = _canonical_json_bytes(forged_manifest)
            terminal.unlink()
            forged = recovery / (
                "terminal-" + hashlib.sha256(forged_raw).hexdigest() + ".json"
            )
            forged.write_bytes(forged_raw)
            expected = Finding(
                code="transaction-invalid",
                severity="error",
                path=forged.relative_to(root).as_posix(),
                message="invalid canonical transaction JSON or operation schema",
            )
            findings = doctor_memory_root(root)
            self.assertIn(expected, findings)
            self.assertFalse(
                any(
                    finding.path == owner_path.relative_to(root).as_posix()
                    and finding.code.startswith("transaction-incomplete-")
                    for finding in findings
                )
            )

    def test_compact_terminal_candidate_replay_recomputes_inventory_at_most_once(self):
        inventory = {
            "count": 99,
            "invalid_count": 0,
            "inventory_sha256": "0" * 64,
            "limit": 10000,
            "listed_invalid_count": 0,
            "valid_count": 99,
        }
        valid = tuple(
            (
                "recovery/terminal-{0:064x}.json".format(index),
                {
                    "invalid_terminals": [],
                    "terminal_inventory": dict(inventory),
                },
            )
            for index in range(100)
        )
        with mock.patch.object(
            validation_module,
            "_projection_terminal_compact_inventory",
            wraps=validation_module._projection_terminal_compact_inventory,
        ) as compact:
            self.assertIsNone(
                validation_module._matching_projection_terminal(valid, ())
            )
        self.assertLessEqual(compact.call_count, 1)

    def test_missing_unexpected_displaced_version_is_pending_invalid(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-unexpected-copy-init"))
            transaction_id = "tx-unexpected-copy"
            document, owner_path, recovery = _create_projection_recovery_owner(
                root,
                transaction_id,
            )
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
            target = root / Path(document.relative_path)
            observed_bytes = target.read_bytes()
            observed_hash = hashlib.sha256(observed_bytes).hexdigest()
            displaced_bytes = b"conflicting displaced bytes\n"
            displaced_hash = hashlib.sha256(displaced_bytes).hexdigest()
            displaced = recovery / "displaced.bin"
            displaced.write_bytes(displaced_bytes)
            observed = recovery / ("observed-" + observed_hash + ".bin")
            observed.write_bytes(observed_bytes)
            recovery_relative = recovery.relative_to(root).as_posix()
            unexpected_relative = (
                recovery_relative + "/unexpected-" + displaced_hash + ".bin"
            )
            manifest = {
                "displaced": {
                    "file_type": stat.S_IFREG,
                    "kind": "regular",
                    "path": displaced.relative_to(root).as_posix(),
                },
                "displaced_path": displaced.relative_to(root).as_posix(),
                "displaced_sha256": displaced_hash,
                "evidence_paths": sorted(
                    (
                        recovery_relative + "/intent.json",
                        unexpected_relative,
                        observed.relative_to(root).as_posix(),
                    )
                ),
                "observed": {
                    "file_type": stat.S_IFREG,
                    "kind": "regular",
                    "path": document.relative_path,
                },
                "observed_sha256": observed_hash,
                "outcome": "conflict-preserved",
                "prior_sha256": None,
                "projection_evidence": {
                    "context_sha256": _sha256_text(transaction_id),
                    "target_path_sha256": _sha256_text(document.relative_path),
                },
                "published_sha256": owner["desired"]["target_sha256"],
                "schema_version": 2,
                "status": "terminal",
                "target": document.relative_path,
                "transaction_id": transaction_id,
            }
            _write_terminal(recovery, manifest)
            expected = Finding(
                code="transaction-pending-invalid",
                severity="error",
                path=unexpected_relative,
                message="transaction-bound pending or recovery evidence is unknown, incomplete, malformed, or mismatched",
            )
            findings = doctor_memory_root(root)
            self.assertIn(expected, findings)
            self.assertFalse(
                any(
                    finding.path == owner_path.relative_to(root).as_posix()
                    and finding.code.startswith("transaction-incomplete-")
                    for finding in findings
                )
            )

    def test_restored_absence_endpoint_divergence_is_pending_invalid(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-endpoint-init"))
            document, owner_path, recovery = _create_projection_recovery_owner(
                root,
                "tx-endpoint-restored",
            )
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
            target = root / Path(document.relative_path)
            published = target.read_bytes()
            displaced = recovery / "displaced.bin"
            displaced.write_bytes(published)
            target.unlink()
            recovery_relative = recovery.relative_to(root).as_posix()
            manifest = {
                "displaced": {
                    "file_type": stat.S_IFREG,
                    "kind": "regular",
                    "path": displaced.relative_to(root).as_posix(),
                },
                "displaced_path": displaced.relative_to(root).as_posix(),
                "displaced_sha256": hashlib.sha256(published).hexdigest(),
                "evidence_paths": [recovery_relative + "/intent.json"],
                "observed": {"kind": "absent", "path": document.relative_path},
                "observed_sha256": None,
                "outcome": "restored",
                "prior_sha256": None,
                "projection_evidence": {
                    "context_sha256": _sha256_text("tx-endpoint-restored"),
                    "target_path_sha256": _sha256_text(document.relative_path),
                },
                "published_sha256": owner["desired"]["target_sha256"],
                "schema_version": 2,
                "status": "terminal",
                "target": document.relative_path,
                "transaction_id": "tx-endpoint-restored",
            }
            _write_terminal(recovery, manifest)
            healthy = doctor_memory_root(root)
            self.assertFalse(
                any(
                    finding.code in ("transaction-invalid", "transaction-pending-invalid")
                    and finding.path.startswith(recovery_relative)
                    for finding in healthy
                ),
                healthy,
            )

            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"late endpoint drift\n")
            expected = Finding(
                code="transaction-pending-invalid",
                severity="error",
                path=document.relative_path,
                message="transaction-bound pending or recovery evidence is unknown, incomplete, malformed, or mismatched",
            )
            findings = doctor_memory_root(root)
            self.assertIn(expected, findings)
            self.assertFalse(
                any(
                    finding.path == owner_path.relative_to(root).as_posix()
                    and finding.code.startswith("transaction-incomplete-")
                    for finding in findings
                )
            )

    def test_projection_recovery_accepts_all_terminal_family_shapes(self):
        cases = (
            "conflict-regular",
            "conflict-namespace",
            "quarantine-failed",
            "unexpected",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary_text:
                root = Path(temporary_text).resolve() / "memory-root"
                initialize_memory_root(
                    root,
                    "demo",
                    _context("tx-family-init-" + case),
                )
                transaction_id = "tx-family-" + case
                document, owner_path, recovery = _create_projection_recovery_owner(
                    root,
                    transaction_id,
                )
                owner = json.loads(owner_path.read_text(encoding="utf-8"))
                target = root / Path(document.relative_path)
                published = target.read_bytes()
                published_hash = hashlib.sha256(published).hexdigest()
                recovery_relative = recovery.relative_to(root).as_posix()
                intent_relative = recovery_relative + "/intent.json"
                displaced = recovery / "displaced.bin"
                common = {
                    "prior_sha256": None,
                    "projection_evidence": {
                        "context_sha256": _sha256_text(transaction_id),
                        "target_path_sha256": _sha256_text(document.relative_path),
                    },
                    "published_sha256": published_hash,
                    "schema_version": 2,
                    "status": "terminal",
                    "target": document.relative_path,
                    "transaction_id": transaction_id,
                }
                if case == "conflict-regular":
                    displaced.write_bytes(published)
                    observed = recovery / ("observed-" + published_hash + ".bin")
                    observed.write_bytes(published)
                    manifest = {
                        **common,
                        "displaced": {
                            "file_type": stat.S_IFREG,
                            "kind": "regular",
                            "path": displaced.relative_to(root).as_posix(),
                        },
                        "displaced_path": displaced.relative_to(root).as_posix(),
                        "displaced_sha256": published_hash,
                        "evidence_paths": sorted(
                            (intent_relative, observed.relative_to(root).as_posix())
                        ),
                        "observed": {
                            "file_type": stat.S_IFREG,
                            "kind": "regular",
                            "path": document.relative_path,
                        },
                        "observed_sha256": published_hash,
                        "outcome": "conflict-preserved",
                    }
                elif case == "conflict-namespace":
                    displaced.mkdir()
                    manifest = {
                        **common,
                        "displaced": {
                            "file_type": stat.S_IFDIR,
                            "kind": "directory",
                            "path": displaced.relative_to(root).as_posix(),
                        },
                        "evidence_paths": sorted(
                            (intent_relative, document.relative_path)
                        ),
                        "observed": {
                            "file_type": stat.S_IFREG,
                            "kind": "regular",
                            "path": document.relative_path,
                        },
                        "outcome": "conflict-preserved",
                    }
                elif case == "quarantine-failed":
                    target_evidence = recovery / (
                        "target-" + published_hash + ".bin"
                    )
                    target_evidence.write_bytes(published)
                    manifest = {
                        **common,
                        "endpoint_hashes": {
                            "quarantine": None,
                            "target": published_hash,
                        },
                        "evidence_paths": sorted(
                            (intent_relative, target_evidence.relative_to(root).as_posix())
                        ),
                        "outcome": "quarantine-failed-closed",
                    }
                else:
                    displaced.write_bytes(published)
                    manifest = {
                        **common,
                        "endpoints": {
                            "quarantine": {
                                "file_type": stat.S_IFREG,
                                "kind": "regular",
                                "path": displaced.relative_to(root).as_posix(),
                            },
                            "target": {
                                "file_type": stat.S_IFREG,
                                "kind": "regular",
                                "path": document.relative_path,
                            },
                        },
                        "error_type": "OSError",
                        "evidence_paths": sorted(
                            (
                                intent_relative,
                                displaced.relative_to(root).as_posix(),
                                document.relative_path,
                            )
                        ),
                        "invalid_terminals": [],
                        "outcome": "unexpected-exception",
                    }
                _write_terminal(recovery, manifest)
                findings = doctor_memory_root(root)
                self.assertFalse(
                    any(
                        finding.code in (
                            "transaction-invalid",
                            "transaction-pending-invalid",
                        )
                        and finding.path.startswith(recovery_relative)
                        for finding in findings
                    ),
                    findings,
                )

    def test_actual_task5_terminal_producers_are_doctor_compatible(self):
        branches = (
            "restored",
            "conflict-regular",
            "conflict-namespace",
            "quarantine-failed",
            "unexpected",
        )
        for branch in branches:
            with self.subTest(branch=branch), tempfile.TemporaryDirectory() as temporary_text:
                root = Path(temporary_text).resolve() / "memory-root"
                initialize_memory_root(
                    root,
                    "demo",
                    _context("tx-producer-init-" + branch),
                )
                transaction_id = "tx-producer-" + branch
                document = build_project_focus(root, "demo", GENERATOR_VERSION)
                publish_projection(
                    root,
                    document,
                    _context(transaction_id),
                    guard=None,
                )
                target = root / Path(document.relative_path)
                published = target.read_bytes()
                context_hash = _sha256_text(transaction_id)
                target_hash = _sha256_text(document.relative_path)
                journal = (
                    root
                    / ".agent-memory/transactions/projections"
                    / context_hash
                    / (target_hash + ".json")
                )
                owner = json.loads(journal.read_text(encoding="utf-8"))
                owner["status"] = "in-progress"
                journal.write_bytes(_canonical_json_bytes(owner))
                recovery = _projection_recovery_directory(
                    root,
                    transaction_id,
                    document.relative_path,
                )

                if branch == "restored":
                    projection_module._rollback_projection(
                        root,
                        target,
                        published,
                        None,
                        transaction_id,
                    )
                elif branch == "conflict-regular":
                    def regular_checkpoint(stage, cas_target):
                        if stage == "after-projection-quarantine":
                            target.write_bytes(b"unexpected endpoint bytes\n")

                    with mock.patch.object(
                        transaction_module,
                        "_cas_checkpoint",
                        side_effect=regular_checkpoint,
                    ):
                        with self.assertRaises(ConflictError):
                            projection_module._rollback_projection(
                                root,
                                target,
                                published,
                                None,
                                transaction_id,
                            )
                elif branch == "conflict-namespace":
                    def namespace_checkpoint(stage, cas_target):
                        if stage == "before-projection-quarantine":
                            target.unlink()
                            target.mkdir()
                            (target / "sentinel.txt").write_text(
                                "retained namespace\n",
                                encoding="utf-8",
                            )

                    with mock.patch.object(
                        transaction_module,
                        "_cas_checkpoint",
                        side_effect=namespace_checkpoint,
                    ):
                        with self.assertRaises(ConflictError):
                            projection_module._rollback_projection(
                                root,
                                target,
                                published,
                                None,
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
                                None,
                                transaction_id,
                            )
                else:
                    original_description = projection_module._namespace_description
                    inject_failure = {"armed": False}

                    def unexpected_checkpoint(stage, cas_target):
                        if stage == "after-projection-quarantine":
                            inject_failure["armed"] = True

                    def namespace_description(memory_root, path):
                        if (
                            inject_failure["armed"]
                            and Path(path) == recovery / "displaced.bin"
                        ):
                            inject_failure["armed"] = False
                            raise OSError("injected producer fallback")
                        return original_description(memory_root, path)

                    with mock.patch.object(
                        transaction_module,
                        "_cas_checkpoint",
                        side_effect=unexpected_checkpoint,
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
                                None,
                                transaction_id,
                            )

                terminals = tuple(recovery.glob("terminal-*.json"))
                self.assertEqual(1, len(terminals))
                terminal_raw = terminals[0].read_bytes()
                self.assertEqual(
                    terminals[0].name,
                    "terminal-"
                    + hashlib.sha256(terminal_raw).hexdigest()
                    + ".json",
                )
                recovery_relative = recovery.relative_to(root).as_posix()
                findings = doctor_memory_root(root)
                self.assertFalse(
                    any(
                        finding.code
                        in ("transaction-invalid", "transaction-pending-invalid")
                        and finding.path.startswith(recovery_relative)
                        for finding in findings
                    ),
                    findings,
                )

    def test_anchor_bootstrap_candidate_is_active_then_stale_by_offset_zero_lease(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-anchor-init"))
            anchor = root / ".agent-memory-root-write.anchor"
            candidate = root / ".agent-memory-root-write.anchor.candidate"
            os.link(str(anchor), str(candidate))
            exact_bytes = anchor.read_bytes()
            ready = multiprocessing.Event()
            release = multiprocessing.Event()
            process = multiprocessing.Process(
                target=_hold_anchor_candidate,
                args=(root, ready, release),
            )
            process.start()
            try:
                self.assertTrue(ready.wait(10))
                active = (
                    Finding(
                        code="root-write-anchor-candidate-active",
                        severity="warning",
                        path=".agent-memory-root-write.anchor.candidate",
                        message="root-write namespace bootstrap candidate has a live lease",
                    ),
                )
                self.assertEqual(active, doctor_memory_root(root))
                self.assertEqual(active, doctor_memory_root(root))
            finally:
                release.set()
                process.join(10)
                if process.is_alive():
                    process.terminate()
                    process.join(10)
            self.assertEqual(0, process.exitcode)
            stale = (
                Finding(
                    code="root-write-anchor-candidate-stale",
                    severity="warning",
                    path=".agent-memory-root-write.anchor.candidate",
                    message="root-write namespace bootstrap candidate is stale-resumable",
                ),
            )
            before = _byte_snapshot(root)
            self.assertEqual(stale, doctor_memory_root(root))
            self.assertEqual(stale, doctor_memory_root(root))
            self.assertEqual(before, _byte_snapshot(root))
            self.assertEqual(exact_bytes, anchor.read_bytes())
            self.assertEqual(exact_bytes, candidate.read_bytes())

    def test_root_anchor_and_candidate_malformed_taxonomy(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-anchor-missing-init"))
            (root / ".agent-memory-root-write.anchor").unlink()
            self.assertEqual(
                (
                    Finding(
                        code="root-write-anchor-missing",
                        severity="error",
                        path=".agent-memory-root-write.anchor",
                        message="initialized root is missing the root-write namespace anchor",
                    ),
                ),
                doctor_memory_root(root),
            )
            bootstrap = root / ".agent-memory-root-write.anchor.candidate"
            bootstrap.write_bytes(
                b'{"purpose":"root-write-namespace","schema_version":1}\n'[:19]
            )
            ready = multiprocessing.Event()
            release = multiprocessing.Event()
            process = multiprocessing.Process(
                target=_hold_anchor_candidate,
                args=(root, ready, release),
            )
            process.start()
            try:
                self.assertTrue(ready.wait(10))
                self.assertIn(
                    Finding(
                        code="root-write-anchor-candidate-active",
                        severity="warning",
                        path=".agent-memory-root-write.anchor.candidate",
                        message="root-write namespace bootstrap candidate has a live lease",
                    ),
                    doctor_memory_root(root),
                )
            finally:
                release.set()
                process.join(10)
                if process.is_alive():
                    process.terminate()
                    process.join(10)
            self.assertIn(
                Finding(
                    code="root-write-anchor-candidate-stale",
                    severity="warning",
                    path=".agent-memory-root-write.anchor.candidate",
                    message="root-write namespace bootstrap candidate is stale-resumable",
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-anchor-malformed-init"))
            (root / ".agent-memory-root-write.anchor").write_bytes(b"malformed\n")
            self.assertEqual(
                (
                    Finding(
                        code="root-write-anchor-malformed",
                        severity="error",
                        path=".agent-memory-root-write.anchor",
                        message="root-write namespace anchor bytes are malformed",
                    ),
                ),
                doctor_memory_root(root),
            )

        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-bootstrap-malformed-init"))
            anchor = root / ".agent-memory-root-write.anchor"
            candidate = root / ".agent-memory-root-write.anchor.candidate"
            candidate.write_bytes(anchor.read_bytes())
            self.assertEqual(
                (
                    Finding(
                        code="root-write-anchor-candidate-malformed",
                        severity="error",
                        path=".agent-memory-root-write.anchor.candidate",
                        message="root-write namespace bootstrap candidate bytes or identity are malformed",
                    ),
                ),
                doctor_memory_root(root),
            )

    def test_root_guard_candidate_rejects_nonprefix_binding_and_inventory_anomalies(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-candidate-malformed-init"))

            def candidate_name(transaction_id):
                binding = (str(root) + "\0" + transaction_id).encode("utf-8")
                return ".agent-memory-root-write.candidate-" + hashlib.sha256(
                    binding
                ).hexdigest()

            first_name = candidate_name("tx-candidate-malformed")
            first = root / first_name
            first.write_bytes(b'{"actor":"x"')
            malformed = Finding(
                code="root-write-malformed",
                severity="error",
                path=first_name,
                message="root-write guard bytes, identity, or candidate inventory are malformed",
            )
            self.assertEqual((malformed,), doctor_memory_root(root))

            first.write_bytes(
                _canonical_json_bytes(
                    {
                        "actor": "core-test-agent",
                        "created_at": OCCURRED_AT,
                        "process_id": os.getpid(),
                        "target": ".",
                        "transaction_id": "different-transaction",
                    }
                )
            )
            self.assertEqual((malformed,), doctor_memory_root(root))

            second_name = candidate_name("tx-candidate-second")
            (root / second_name).write_bytes(b"")
            expected = tuple(
                sorted(
                    (
                        malformed,
                        Finding(
                            code="root-write-malformed",
                            severity="error",
                            path=second_name,
                            message="root-write guard bytes, identity, or candidate inventory are malformed",
                        ),
                    ),
                    key=lambda finding: (
                        finding.severity,
                        finding.code,
                        finding.path,
                        finding.message,
                    ),
                )
            )
            self.assertEqual(expected, doctor_memory_root(root))

    def test_root_guard_candidate_requires_lowercase_sha256_suffix(self):
        for suffix in ("junk", "A" * 64):
            with self.subTest(suffix=suffix):
                with tempfile.TemporaryDirectory() as temporary_text:
                    root = Path(temporary_text).resolve() / "memory-root"
                    initialize_memory_root(
                        root,
                        "demo",
                        _context("tx-candidate-suffix-init"),
                    )
                    relative = ".agent-memory-root-write.candidate-" + suffix
                    (root / relative).write_bytes(b"")
                    expected = (
                        Finding(
                            code="root-write-malformed",
                            severity="error",
                            path=relative,
                            message="root-write guard bytes, identity, or candidate inventory are malformed",
                        ),
                    )
                    self.assertEqual(expected, doctor_memory_root(root))

    def test_root_guard_inventory_overflow_is_one_stable_malformed_finding(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-root-overflow-init"))
            candidate_relative = ".agent-memory-root-write.candidate-" + ("a" * 64)
            (root / candidate_relative).write_bytes(b"")
            for index in range(10001):
                (root / "root-entry-{0:05d}".format(index)).touch()
            expected = (
                Finding(
                    code="root-write-malformed",
                    severity="error",
                    path=".agent-memory-root-write.lock",
                    message="root-write guard bytes, identity, or candidate inventory are malformed",
                ),
            )

            first = doctor_memory_root(root)
            second = doctor_memory_root(root)

            self.assertEqual(expected, first)
            self.assertEqual(first, second)
            self.assertNotIn(
                Finding(
                    code="root-write-candidate",
                    severity="warning",
                    path=candidate_relative,
                    message="candidate-only root-write guard evidence requires explicit recovery review",
                ),
                first,
            )

    def test_root_guard_inventory_does_not_use_unbounded_path_iteration(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-root-bounded-init"))

            with mock.patch.object(
                Path,
                "iterdir",
                side_effect=AssertionError("root inventory must be bounded before sorting"),
            ):
                self.assertEqual((), doctor_memory_root(root))

    def test_root_guard_inventory_containment_precedes_overflow(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-root-priority-init"))
            relative = ".agent-memory-root-write.candidate-" + ("b" * 64)
            (root / relative).mkdir()
            expected = (
                Finding(
                    code="path-containment",
                    severity="error",
                    path=relative,
                    message="candidate path is invalid, escaping, or a reparse point",
                ),
            )

            with mock.patch.object(
                validation_module,
                "_ROOT_GUARD_INVENTORY_LIMIT",
                4,
            ):
                self.assertEqual(expected, doctor_memory_root(root))

    def test_dangling_canonical_root_guard_is_containment_not_absence(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-dangling-guard-init"))
            relative = ".agent-memory-root-write.lock"
            guard = root / relative
            try:
                guard.symlink_to("missing-root-write-guard")
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            expected = (
                Finding(
                    code="path-containment",
                    severity="error",
                    path=relative,
                    message="candidate path is invalid, escaping, or a reparse point",
                ),
            )
            self.assertEqual(expected, doctor_memory_root(root))

    def test_dangling_candidate_only_root_guard_is_containment_not_exception(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-dangling-candidate-init"))
            relative = ".agent-memory-root-write.candidate-" + ("a" * 64)
            candidate = root / relative
            try:
                candidate.symlink_to("missing-root-write-candidate")
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            expected = (
                Finding(
                    code="path-containment",
                    severity="error",
                    path=relative,
                    message="candidate path is invalid, escaping, or a reparse point",
                ),
            )
            self.assertEqual(expected, doctor_memory_root(root))

    def test_dangling_paired_root_guard_candidate_does_not_misclassify_canonical(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-paired-candidate-init"))
            ready = multiprocessing.Event()
            release = multiprocessing.Event()
            process = multiprocessing.Process(
                target=_hold_root_guard,
                args=(root, ready, release),
            )
            process.start()
            try:
                self.assertTrue(ready.wait(10))
                process.terminate()
                process.join(10)
                self.assertFalse(process.is_alive())
                candidates = tuple(root.glob(".agent-memory-root-write.candidate-*"))
                self.assertEqual(1, len(candidates))
                candidate = candidates[0]
                relative = candidate.name
                candidate.unlink()
                try:
                    candidate.symlink_to("missing-root-write-candidate")
                except OSError as error:
                    self.skipTest("file symlinks unavailable: {0}".format(error))
                expected = (
                    Finding(
                        code="path-containment",
                        severity="error",
                        path=relative,
                        message="candidate path is invalid, escaping, or a reparse point",
                    ),
                )
                self.assertEqual(expected, doctor_memory_root(root))
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(10)

    def test_canonical_containment_preserves_independent_candidate_finding(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-independent-candidate-init"))
            canonical_relative = ".agent-memory-root-write.lock"
            candidate_relative = ".agent-memory-root-write.candidate-" + ("b" * 64)
            try:
                (root / canonical_relative).symlink_to("missing-canonical-guard")
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            (root / candidate_relative).write_bytes(b"")
            expected = (
                Finding(
                    code="path-containment",
                    severity="error",
                    path=canonical_relative,
                    message="candidate path is invalid, escaping, or a reparse point",
                ),
                Finding(
                    code="root-write-candidate",
                    severity="warning",
                    path=candidate_relative,
                    message="candidate-only root-write guard evidence requires explicit recovery review",
                ),
            )
            self.assertEqual(expected, doctor_memory_root(root))

    def test_multi_candidate_containment_precedes_inventory_malformed(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-multi-candidate-init"))
            dangling_relative = ".agent-memory-root-write.candidate-" + ("c" * 64)
            regular_relative = ".agent-memory-root-write.candidate-" + ("d" * 64)
            try:
                (root / dangling_relative).symlink_to("missing-candidate")
            except OSError as error:
                self.skipTest("file symlinks unavailable: {0}".format(error))
            (root / regular_relative).write_bytes(b"")
            expected = (
                Finding(
                    code="path-containment",
                    severity="error",
                    path=dangling_relative,
                    message="candidate path is invalid, escaping, or a reparse point",
                ),
                Finding(
                    code="root-write-candidate",
                    severity="warning",
                    path=regular_relative,
                    message="candidate-only root-write guard evidence requires explicit recovery review",
                ),
            )
            probe_calls = []
            original_probe = validation_module._probe_memory_file

            def record_probe(
                memory_root,
                relative,
                offset,
                locked_expected=None,
            ):
                probe_calls.append(relative)
                return original_probe(
                    memory_root,
                    relative,
                    offset,
                    locked_expected=locked_expected,
                )

            with mock.patch.object(
                validation_module,
                "_probe_memory_file",
                side_effect=record_probe,
            ):
                self.assertEqual(expected, doctor_memory_root(root))
            self.assertEqual(1, probe_calls.count(dangling_relative), probe_calls)
            self.assertEqual(1, probe_calls.count(regular_relative), probe_calls)

    def test_nonmatching_candidate_containment_does_not_poison_valid_pair(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            root = Path(temporary_text).resolve() / "memory-root"
            initialize_memory_root(root, "demo", _context("tx-extra-candidate-init"))
            ready = multiprocessing.Event()
            release = multiprocessing.Event()
            process = multiprocessing.Process(
                target=_hold_root_guard,
                args=(root, ready, release),
            )
            process.start()
            try:
                self.assertTrue(ready.wait(10))
                process.terminate()
                process.join(10)
                self.assertFalse(process.is_alive())
                relative = ".agent-memory-root-write.candidate-" + ("e" * 64)
                try:
                    (root / relative).symlink_to("missing-extra-candidate")
                except OSError as error:
                    self.skipTest("file symlinks unavailable: {0}".format(error))
                expected = (
                    Finding(
                        code="path-containment",
                        severity="error",
                        path=relative,
                        message="candidate path is invalid, escaping, or a reparse point",
                    ),
                    Finding(
                        code="root-write-stale",
                        severity="warning",
                        path=".agent-memory-root-write.lock",
                        message="root-write guard lease is acquirable and requires explicit recovery review",
                    ),
                )
                self.assertEqual(expected, doctor_memory_root(root))
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(10)


if __name__ == "__main__":
    unittest.main()
