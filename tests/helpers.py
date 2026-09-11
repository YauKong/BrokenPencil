import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "skills" / "obsidian-agent-memory" / "scripts"
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "vaults"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory.models import RecordCandidate, RecordEnvelope, TransactionContext
from obsidian_agent_memory.records import compute_body_sha256
from obsidian_agent_memory.transactions import initialize_memory_root


OCCURRED_AT = "2026-08-30T00:00:00Z"


def fixture_root(name: str) -> Path:
    root = FIXTURE_ROOT / name
    if not root.is_dir():
        raise AssertionError("unknown vault fixture: %s" % name)
    return root


def copy_vault_fixture(name: str, destination: Path) -> Path:
    target = destination / name
    shutil.copytree(fixture_root(name), target)
    return target


def tree_hashes(root: Path) -> Tuple[Tuple[str, str], ...]:
    values = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative_path = path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        values.append((relative_path, digest))
    return tuple(values)


def context(transaction_id):
    return TransactionContext(transaction_id, "test-agent", OCCURRED_AT)


def candidate(
    memory_id="memory-1",
    revision=1,
    supersedes=None,
    body="accepted body",
    record_type="decision",
    project="demo",
    owner_scope="project.demo.decision",
):
    envelope = RecordEnvelope(
        memory_id=memory_id,
        record_type=record_type,
        schema_version=2,
        owner_scope=owner_scope,
        project=project,
        revision=revision,
        supersedes=supersedes,
        created_at=OCCURRED_AT,
        observed_at=OCCURRED_AT,
        source="test-source",
        source_revision="source-1",
        body_sha256=compute_body_sha256(body),
    )
    return RecordCandidate(envelope, body)


def initialize(root, transaction_id="tx-init"):
    return initialize_memory_root(Path(root), "demo", context(transaction_id))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def crash_with_root_guard(root, transaction_id):
    from obsidian_agent_memory.transactions import root_write_guard

    with root_write_guard(Path(root), context(transaction_id)):
        os._exit(23)


def crash_during_recovery(
    root,
    target_transaction_id,
    expected_lock_sha256,
    recovery_transaction_id,
    authorization_ref,
    crash_stage,
):
    import obsidian_agent_memory.transactions as transactions

    def checkpoint(stage):
        if stage == crash_stage:
            os._exit(31)

    original_publish_transition = transactions._publish_transition

    def publish_transition(memory_root, path, document, operation_id):
        if (
            crash_stage == "before-removed-transition"
            and path.name == "020-old-artifact-removed.json"
        ):
            token = hashlib.sha256(
                (str(Path(root).resolve()) + "\0" + target_transaction_id).encode("utf-8")
            ).hexdigest()
            old_candidate = Path(root) / (".agent-memory-root-write.candidate-" + token)
            if old_candidate.exists():
                os._exit(33)
            os._exit(31)
        return original_publish_transition(memory_root, path, document, operation_id)

    transactions._recovery_checkpoint = checkpoint
    transactions._publish_transition = publish_transition
    with transactions.recover_root_write_guard(
        Path(root),
        target_transaction_id,
        expected_lock_sha256,
        context(recovery_transaction_id),
        authorization_ref,
    ):
        os._exit(32)


def crash_during_anchor_bootstrap(root, transaction_id, crash_stage):
    import obsidian_agent_memory.transactions as transactions

    def checkpoint(stage):
        if stage == crash_stage:
            os._exit(41)

    transactions._anchor_checkpoint = checkpoint
    with transactions.root_write_guard(Path(root), context(transaction_id)):
        os._exit(42)


def hold_one_byte_lease(path, ready_event, release_event):
    import obsidian_agent_memory.transactions as transactions

    lease = transactions._Lease.open(Path(path))
    if not lease.acquire():
        os._exit(51)
    ready_event.set()
    release_event.wait(10)
    lease.close()


def hold_recovery_guard(
    root,
    target_transaction_id,
    expected_hash,
    recovery_transaction_id,
    authorization_ref,
    ready_event,
    release_event,
):
    import obsidian_agent_memory.transactions as transactions

    with transactions.recover_root_write_guard(
        Path(root),
        target_transaction_id,
        expected_hash,
        context(recovery_transaction_id),
        authorization_ref,
    ):
        ready_event.set()
        release_event.wait(10)


def contend_for_root_guard(root, transaction_id, started_event, acquired_event):
    import time

    from obsidian_agent_memory.errors import LockBusyError
    from obsidian_agent_memory.transactions import root_write_guard

    started_event.set()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with root_write_guard(Path(root), context(transaction_id)):
                acquired_event.set()
                return
        except LockBusyError:
            time.sleep(0.01)
    os._exit(61)
