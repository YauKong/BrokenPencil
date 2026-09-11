import json
import multiprocessing
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory.transactions import commit_record  # noqa: E402
from obsidian_agent_memory.models import RecordEnvelope  # noqa: E402
from obsidian_agent_memory.records import parse_record, render_record  # noqa: E402
from obsidian_agent_memory.session_relationships import (  # noqa: E402
    SessionRelationship,
    render_session_relationship,
)
from tests.helpers import (  # noqa: E402
    candidate,
    context,
    contend_for_root_guard,
    crash_with_root_guard,
    hold_recovery_guard,
    initialize,
    sha256,
)


def _compete(root, memory_id, transaction_id, start_event, result_queue):
    start_event.wait(10)
    outcome = commit_record(
        Path(root),
        candidate(memory_id=memory_id, body="desired " + memory_id),
        0,
        None,
        context(transaction_id),
    )
    result_queue.put(
        (outcome.status, outcome.conflict_code, memory_id, str(outcome.proposal_path or ""))
    )


def _compete_session(root, memory_id, transaction_id, start_event, result_queue):
    relationship = render_session_relationship(
        SessionRelationship("completed", "story-demo", ())
    )
    body = "# Session: Concurrent demo\n\n{0}\n## Outcome\n\nCompleted.\n".format(
        relationship
    )
    start_event.wait(10)
    outcome = commit_record(
        Path(root),
        candidate(
            memory_id=memory_id,
            body=body,
            record_type="session",
            owner_scope="project.demo.session",
        ),
        1,
        None,
        context(transaction_id),
    )
    result_queue.put(
        (outcome.status, outcome.conflict_code, memory_id, str(outcome.proposal_path or ""))
    )


class ConcurrentTransactionTests(unittest.TestCase):
    def test_parallel_sessions_preserve_the_root_busy_candidate(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory-sessions"
            initialize(root, "tx-init-sessions")
            story = commit_record(
                root,
                candidate(
                    memory_id="story-demo",
                    body="# Story: Demo\n",
                    record_type="story",
                    owner_scope="project.demo.story",
                ),
                0,
                None,
                context("tx-story"),
            )
            self.assertEqual("accepted", story.status)
            start_event = multiprocessing.Event()
            result_queue = multiprocessing.Queue()
            processes = [
                multiprocessing.Process(
                    target=_compete_session,
                    args=(
                        str(root),
                        "session-" + suffix,
                        "tx-session-" + suffix,
                        start_event,
                        result_queue,
                    ),
                )
                for suffix in ("a", "b")
            ]
            for process in processes:
                process.start()
            start_event.set()
            for process in processes:
                process.join(15)
                self.assertFalse(process.is_alive())
                self.assertEqual(0, process.exitcode)

            results = [result_queue.get(timeout=5) for _ in processes]
            self.assertEqual(["accepted", "proposed"], sorted(item[0] for item in results))
            proposed = next(item for item in results if item[0] == "proposed")
            self.assertEqual("root-write-busy", proposed[1])
            proposal = json.loads(Path(proposed[3]).read_text("utf-8"))
            self.assertEqual(proposed[2], proposal["desired"]["memory_id"])
            self.assertEqual(
                {"story-demo", next(item[2] for item in results if item[0] == "accepted")},
                set(
                    json.loads(
                        (root / ".agent-memory/state/catalog.json").read_text("utf-8")
                    )["records"]
                ),
            )

    def test_five_three_process_safe_races_preserve_both_desired_changes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            for iteration in range(5):
                with self.subTest(iteration=iteration):
                    root = Path(temporary_directory) / ("memory-" + str(iteration))
                    initialize(root, "tx-init-" + str(iteration))
                    start_event = multiprocessing.Event()
                    result_queue = multiprocessing.Queue()
                    processes = [
                        multiprocessing.Process(
                            target=_compete,
                            args=(
                                str(root),
                                "memory-a-" + str(iteration),
                                "tx-a-" + str(iteration),
                                start_event,
                                result_queue,
                            ),
                        ),
                        multiprocessing.Process(
                            target=_compete,
                            args=(
                                str(root),
                                "memory-b-" + str(iteration),
                                "tx-b-" + str(iteration),
                                start_event,
                                result_queue,
                            ),
                        ),
                    ]
                    for process in processes:
                        process.start()
                    start_event.set()
                    for process in processes:
                        process.join(15)
                        self.assertFalse(process.is_alive())
                        self.assertEqual(0, process.exitcode)
                    results = [result_queue.get(timeout=5) for _ in processes]
                    self.assertEqual(["accepted", "proposed"], sorted(result[0] for result in results))
                    catalog = json.loads((root / ".agent-memory/state/catalog.json").read_text("utf-8"))
                    self.assertEqual(1, catalog["revision"])
                    self.assertEqual(1, len(catalog["records"]))
                    accepted_id = next(iter(catalog["records"]))
                    proposed_result = next(result for result in results if result[0] == "proposed")
                    proposal = json.loads(Path(proposed_result[3]).read_text("utf-8"))
                    self.assertEqual(proposed_result[2], proposal["desired"]["memory_id"])
                    self.assertNotEqual(accepted_id, proposed_result[2])
                    losing_payload = proposal["desired"]["record_candidate"]
                    losing_envelope = RecordEnvelope(**losing_payload["envelope"])
                    losing_rendered = render_record(losing_envelope, losing_payload["body"])
                    self.assertEqual(
                        (losing_envelope, "desired " + proposed_result[2] + "\n"),
                        parse_record(losing_rendered),
                    )
                    accepted_path = root / catalog["records"][accepted_id]["relative_path"]
                    accepted_envelope, accepted_body = parse_record(
                        accepted_path.read_text("utf-8")
                    )
                    self.assertEqual(accepted_id, accepted_envelope.memory_id)
                    self.assertEqual("desired " + accepted_id + "\n", accepted_body)
                    self.assertEqual(
                        {"memory-a-" + str(iteration), "memory-b-" + str(iteration)},
                        {accepted_id, losing_envelope.memory_id},
                    )
                    self.assertEqual(1, len(list((root / "_records").rglob("*.md"))))

    def test_recovery_namespace_excludes_contender_until_rotation_exits(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            crashed = multiprocessing.Process(
                target=crash_with_root_guard,
                args=(str(root), "tx-dead-race"),
            )
            crashed.start()
            crashed.join(10)
            self.assertEqual(23, crashed.exitcode)
            expected_hash = sha256(root / ".agent-memory-root-write.lock")

            recovery_ready = multiprocessing.Event()
            release_recovery = multiprocessing.Event()
            recovery = multiprocessing.Process(
                target=hold_recovery_guard,
                args=(
                    str(root),
                    "tx-dead-race",
                    expected_hash,
                    "tx-recovery-race",
                    "incident-race",
                    recovery_ready,
                    release_recovery,
                ),
            )
            recovery.start()
            self.assertTrue(recovery_ready.wait(10))

            contender_started = multiprocessing.Event()
            contender_acquired = multiprocessing.Event()
            contender = multiprocessing.Process(
                target=contend_for_root_guard,
                args=(str(root), "tx-contender", contender_started, contender_acquired),
            )
            contender.start()
            self.assertTrue(contender_started.wait(10))
            self.assertFalse(contender_acquired.wait(0.5))
            release_recovery.set()
            self.assertTrue(contender_acquired.wait(10))
            recovery.join(10)
            contender.join(10)
            self.assertEqual(0, recovery.exitcode)
            self.assertEqual(0, contender.exitcode)


if __name__ == "__main__":
    unittest.main()
