import multiprocessing
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory.errors import ConflictError, LockBusyError  # noqa: E402
from obsidian_agent_memory.models import PromotionCandidate, RootWriteGuard  # noqa: E402
from obsidian_agent_memory.projections import (  # noqa: E402
    build_project_focus,
    build_project_views,
    publish_projection,
)
from obsidian_agent_memory.transactions import (  # noqa: E402
    commit_record,
    preserve_promotion_candidate,
    root_write_guard,
    update_focus,
)
from tests.helpers import candidate, context, initialize  # noqa: E402


def _publish_competitor(
    root,
    generator_version,
    transaction_id,
    ready_event,
    publish_event,
    result_queue,
):
    document = build_project_focus(Path(root), "demo", generator_version)
    ready_event.set()
    publish_event.wait(10)
    try:
        path = publish_projection(Path(root), document, context(transaction_id))
    except ConflictError as error:
        result_queue.put(("conflict", type(error).__name__, str(error)))
    else:
        result_queue.put(("published", generator_version, path.read_text("utf-8")))


def _publish_story_competitor(
    root,
    generator_version,
    transaction_id,
    ready_event,
    publish_event,
    result_queue,
):
    document = next(
        item
        for item in build_project_views(Path(root), "demo", generator_version)
        if item.relative_path == "projects/demo/stories/story-demo.md"
    )
    ready_event.set()
    publish_event.wait(10)
    try:
        path = publish_projection(Path(root), document, context(transaction_id))
    except ConflictError as error:
        result_queue.put(("conflict", type(error).__name__, str(error)))
    else:
        result_queue.put(("published", generator_version, path.read_text("utf-8")))


def _try_reconstructed_guard_writers(root, inherited_guard, result_queue):
    import obsidian_agent_memory.transactions as transaction_module

    root_path = Path(root).resolve()
    lock_path = root_path / ".agent-memory-root-write.lock"
    reader = transaction_module._Lease.open(lock_path)
    try:
        lock_bytes = reader.read_all()
    finally:
        reader.close()
    owner = context("tx-forked-guard")
    reconstructed = RootWriteGuard(
        root_path,
        lock_path,
        hashlib.sha256(lock_bytes).hexdigest(),
        owner.transaction_id,
    )
    operations = (
        lambda: commit_record(
            root_path,
            candidate(memory_id="forked-record"),
            1,
            None,
            owner,
            guard=reconstructed,
        ),
        lambda: update_focus(
            root_path,
            "demo",
            1,
            ("story-demo",),
            "2026-08-30T02:00:00Z",
            owner,
            guard=reconstructed,
        ),
        lambda: preserve_promotion_candidate(
            root_path,
            PromotionCandidate(
                "forked-promotion",
                ("story-demo",),
                "knowledge/demo",
                "forked guard must not publish",
            ),
            owner,
            guard=reconstructed,
        ),
        lambda: publish_projection(
            root_path,
            build_project_focus(root_path, "demo", "generator-1"),
            owner,
            guard=reconstructed,
        ),
        lambda: update_focus(
            root_path,
            "demo",
            1,
            ("story-demo",),
            "2026-08-30T02:00:00Z",
            owner,
            guard=inherited_guard,
        ),
    )
    results = []
    for operation in operations:
        try:
            operation()
        except LockBusyError:
            results.append("rejected")
        except BaseException as error:
            results.append(type(error).__name__)
        else:
            results.append("mutated")
    result_queue.put(tuple(results))


class ConcurrentProjectionTests(unittest.TestCase):
    def test_two_processes_never_silently_overwrite_story_timeline_projection(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            self.assertEqual(
                "accepted",
                commit_record(
                    root,
                    candidate(
                        memory_id="story-demo",
                        record_type="story",
                        owner_scope="project.demo.story",
                    ),
                    0,
                    None,
                    context("tx-concurrent-story-record"),
                ).status,
            )
            session_body = (
                "# Session: Concurrent projection work\n\n"
                "## Session Relationship\n"
                "session_status: completed\n"
                "primary_story_id: story-demo\n"
                "related_story_id: none\n\n"
                "## Outcome\n\nTimeline input committed.\n"
            )
            self.assertEqual(
                "accepted",
                commit_record(
                    root,
                    candidate(
                        memory_id="session-demo",
                        body=session_body,
                        record_type="session",
                        owner_scope="project.demo.session",
                    ),
                    1,
                    None,
                    context("tx-concurrent-session-record"),
                ).status,
            )
            self.assertEqual(
                "accepted",
                update_focus(
                    root,
                    "demo",
                    0,
                    ("story-demo",),
                    "2026-08-30T01:00:00Z",
                    context("tx-concurrent-story-focus"),
                ).status,
            )
            ready_events = [multiprocessing.Event(), multiprocessing.Event()]
            publish_events = [multiprocessing.Event(), multiprocessing.Event()]
            result_queue = multiprocessing.Queue()
            processes = [
                multiprocessing.Process(
                    target=_publish_story_competitor,
                    args=(
                        str(root),
                        "generator-" + suffix,
                        "tx-concurrent-story-" + suffix,
                        ready_events[index],
                        publish_events[index],
                        result_queue,
                    ),
                )
                for index, suffix in enumerate(("a", "b"))
            ]
            for process in processes:
                process.start()
            for ready_event in ready_events:
                self.assertTrue(ready_event.wait(10))
            publish_events[0].set()
            processes[0].join(15)
            self.assertFalse(processes[0].is_alive())
            self.assertEqual(0, processes[0].exitcode)
            publish_events[1].set()
            processes[1].join(15)
            for process in processes:
                self.assertFalse(process.is_alive())
                self.assertEqual(0, process.exitcode)
            results = [result_queue.get(timeout=5) for _ in processes]
            self.assertEqual(["conflict", "published"], sorted(item[0] for item in results))
            conflict = next(item for item in results if item[0] == "conflict")
            self.assertIn("appeared after build", conflict[2])
            published = next(item for item in results if item[0] == "published")
            self.assertIn("session-demo` (completed, primary)", published[2])
            target = root / "projects/demo/stories/story-demo.md"
            self.assertEqual(published[2], target.read_text("utf-8"))

    def test_two_processes_from_same_absent_target_never_silently_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            self.assertEqual(
                "accepted",
                commit_record(
                    root,
                    candidate(memory_id="story-demo", record_type="story", owner_scope="project.demo.story"),
                    0,
                    None,
                    context("tx-concurrent-record"),
                ).status,
            )
            self.assertEqual(
                "accepted",
                update_focus(
                    root,
                    "demo",
                    0,
                    ("story-demo",),
                    "2026-08-30T01:00:00Z",
                    context("tx-concurrent-focus"),
                ).status,
            )
            ready_events = [multiprocessing.Event(), multiprocessing.Event()]
            publish_events = [multiprocessing.Event(), multiprocessing.Event()]
            result_queue = multiprocessing.Queue()
            processes = [
                multiprocessing.Process(
                    target=_publish_competitor,
                    args=(
                        str(root),
                        "generator-" + suffix,
                        "tx-concurrent-" + suffix,
                        ready_events[index],
                        publish_events[index],
                        result_queue,
                    ),
                )
                for index, suffix in enumerate(("a", "b"))
            ]
            for process in processes:
                process.start()
            for ready_event in ready_events:
                self.assertTrue(ready_event.wait(10))
            publish_events[0].set()
            processes[0].join(15)
            self.assertFalse(processes[0].is_alive())
            self.assertEqual(0, processes[0].exitcode)
            publish_events[1].set()
            processes[1].join(15)
            for process in processes:
                self.assertFalse(process.is_alive())
                self.assertEqual(0, process.exitcode)
            results = [result_queue.get(timeout=5) for _ in processes]
            self.assertEqual(["conflict", "published"], sorted(result[0] for result in results))
            conflict = next(result for result in results if result[0] == "conflict")
            self.assertEqual("ConflictError", conflict[1])
            self.assertIn("appeared after build", conflict[2])
            published = next(result for result in results if result[0] == "published")
            target = root / "projects/demo/current-focus.md"
            self.assertEqual(published[2], target.read_text("utf-8"))

    def test_other_process_cannot_reconstruct_root_guard_ownership_from_lock_bytes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "memory"
            initialize(root)
            self.assertEqual(
                "accepted",
                commit_record(
                    root,
                    candidate(memory_id="story-demo", record_type="story", owner_scope="project.demo.story"),
                    0,
                    None,
                    context("tx-fork-record"),
                ).status,
            )
            self.assertEqual(
                "accepted",
                update_focus(
                    root,
                    "demo",
                    0,
                    ("story-demo",),
                    "2026-08-30T01:00:00Z",
                    context("tx-fork-focus"),
                ).status,
            )
            result_queue = multiprocessing.Queue()
            with root_write_guard(root, context("tx-forked-guard")) as guard:
                process = multiprocessing.Process(
                    target=_try_reconstructed_guard_writers,
                    args=(str(root), guard, result_queue),
                )
                process.start()
                process.join(15)
                self.assertFalse(process.is_alive())
                self.assertEqual(0, process.exitcode)
                self.assertEqual(
                    ("rejected", "rejected", "rejected", "rejected", "rejected"),
                    result_queue.get(timeout=5),
                )
                self.assertFalse(
                    (
                        root
                        / ".agent-memory/transactions/projections"
                        / hashlib.sha256(b"tx-forked-guard").hexdigest()
                        / (
                            hashlib.sha256(b"projects/demo/current-focus.md").hexdigest()
                            + ".json"
                        )
                    ).exists()
                )

            self.assertFalse((root / "projects/demo/current-focus.md").exists())
            self.assertFalse(
                (root / ".agent-memory/state/proposals/forked-promotion.json").exists()
            )


if __name__ == "__main__":
    unittest.main()
