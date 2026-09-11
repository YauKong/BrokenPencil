import json
import shutil
from pathlib import Path

from tests import helpers as _helpers

from obsidian_agent_memory import (
    RecordCandidate,
    RecordEnvelope,
    TransactionContext,
    build_project_views,
    build_root_views,
    commit_record,
    compute_body_sha256,
    initialize_memory_root,
    publish_projection,
    update_focus,
)


PROJECT_ID = "demo"
ACTOR = "fixture-builder"
SOURCE = "fixture-source"
SOURCE_REVISION = "fixture-source-r1"
GENERATOR_VERSION = "fixture-builder-v1"
STORY_ID = "story-demo-cache"
STORY_BODY = "# Demo cache story\n\nThe asset cache is enabled for fictional previews.\n"


def _context(transaction_id: str, second: int) -> TransactionContext:
    return TransactionContext(
        transaction_id=transaction_id,
        actor=ACTOR,
        occurred_at="2026-01-01T00:00:{0:02d}Z".format(second),
    )


def _marker_bytes(name: str) -> bytes:
    value = {"fixture_id": name, "fixture_version": 1}
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _story_candidate() -> RecordCandidate:
    observed_at = "2026-01-01T00:00:01Z"
    envelope = RecordEnvelope(
        memory_id=STORY_ID,
        record_type="story",
        schema_version=2,
        owner_scope="project.demo.story",
        project=PROJECT_ID,
        revision=1,
        supersedes=None,
        created_at=observed_at,
        observed_at=observed_at,
        source=SOURCE,
        source_revision=SOURCE_REVISION,
        body_sha256=compute_body_sha256(STORY_BODY),
    )
    return RecordCandidate(envelope=envelope, body=STORY_BODY)


def build_v2_clean(root: Path) -> Path:
    """Build the checked-in Schema-2 fixture only through Plan 1 public writes."""
    root = Path(root)
    initialize_memory_root(root, PROJECT_ID, _context("fixture-v2-init", 0))

    story = commit_record(
        root,
        _story_candidate(),
        expected_catalog_revision=0,
        expected_record_revision=None,
        context=_context("fixture-v2-story", 1),
    )
    if story.status != "accepted":
        raise AssertionError("fixture story was not accepted")

    focus = update_focus(
        root,
        PROJECT_ID,
        expected_revision=0,
        record_ids=(STORY_ID,),
        observed_at="2026-01-01T00:00:02Z",
        context=_context("fixture-v2-focus", 2),
    )
    if focus.status != "accepted":
        raise AssertionError("fixture focus was not accepted")

    documents = build_root_views(root, GENERATOR_VERSION) + build_project_views(
        root, PROJECT_ID, GENERATOR_VERSION
    )
    for index, document in enumerate(documents, start=3):
        publish_projection(
            root,
            document,
            _context("fixture-v2-projection-{0:02d}".format(index), index),
        )

    # The exact fixture tree retains the three canonical operation journals named
    # by Task 1, while projection transactions are builder-only evidence.
    projection_transactions = root / ".agent-memory" / "transactions" / "projections"
    shutil.rmtree(projection_transactions)

    (root / ".agent-memory-fixture.json").write_bytes(_marker_bytes("v2-clean"))
    return root
