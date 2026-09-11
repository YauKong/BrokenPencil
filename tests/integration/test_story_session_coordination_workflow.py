import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tests.helpers import candidate, context, copy_vault_fixture

from obsidian_agent_memory import (
    AuthorizationGate,
    CoordinationContext,
    OperationScope,
    StoryDelta,
    apply_migration,
    build_project_views,
    build_root_views,
    build_story_revision_candidate,
    build_unbound_session_candidate,
    commit_record,
    load_catalog,
    parse_proposal_artifact,
    plan_v1_to_v2,
    preserve_unbound_session_candidate,
    read_accepted_record,
    relationship_from_context,
    render_session_relationship,
)


FIXTURE_GATE = AuthorizationGate(OperationScope.FIXTURE, None)
STORY_ID = "story-coordination"
DECISION_ID = "decision-explicit-membership"

STORY_BODY = """# Story: Parallel project work gained explicit coordination

## Situation

Parallel tasks could finish without one confirmed narrative owner.

## Current State

The Story exists but has no accepted Session turning point.

## Turning Points

- none

## Failure Mode

Session membership could be inferred from titles or dates.

## Resolution

none

## Open Questions

- none

## Related Decision IDs

- none
"""


def _session_body(title, relationship, outcome):
    return (
        "# Session: " + title + "\n\n"
        + render_session_relationship(relationship)
        + "\n## Outcome\n\n"
        + outcome
        + "\n"
    )


def _record(memory_id, body, record_type, observed_at):
    value = candidate(
        memory_id=memory_id,
        body=body,
        record_type=record_type,
        project="demo",
        owner_scope="project.demo." + record_type,
    )
    return replace(value, envelope=replace(value.envelope, observed_at=observed_at))


class StorySessionCoordinationWorkflowTests(unittest.TestCase):
    def test_story_session_coordination_is_lossless_and_reviewable(self):
        with tempfile.TemporaryDirectory() as temporary_text:
            temporary = Path(temporary_text)
            root = copy_vault_fixture(
                "v2-story-session-coordination",
                temporary / "source",
            )
            bundle = plan_v1_to_v2(
                root,
                temporary / "planning",
                context("tx-story-session-plan"),
                FIXTURE_GATE,
            )
            migrated = apply_migration(
                root,
                bundle,
                bundle.bundle_sha256,
                context("tx-story-session-apply"),
                FIXTURE_GATE,
            )
            self.assertEqual("applied", migrated.status)

            catalog_revision = load_catalog(root).revision
            story = _record(
                STORY_ID,
                STORY_BODY,
                "story",
                "2026-09-07T09:00:00Z",
            )
            story_outcome = commit_record(
                root,
                story,
                catalog_revision,
                None,
                context("tx-story-seed"),
            )
            self.assertEqual("accepted", story_outcome.status)

            decision = _record(
                DECISION_ID,
                "# Decision: Session membership is explicit\n\n"
                "Story links come only from coordinator or user confirmation.\n",
                "decision",
                "2026-09-07T09:01:00Z",
            )
            decision_outcome = commit_record(
                root,
                decision,
                load_catalog(root).revision,
                None,
                context("tx-decision-seed"),
            )
            self.assertEqual("accepted", decision_outcome.status)

            coordination = CoordinationContext(
                project_id="demo",
                coordinator_task_id="task-controller",
                primary_story_id=STORY_ID,
                related_story_ids=(),
                expected_story_revision=1,
                allowed_scope=("records", "projections"),
            )
            session_specs = (
                (
                    "session-completed",
                    "2026-09-07T10:00:00Z",
                    "completed",
                    "Completed the first parallel slice.",
                ),
                (
                    "session-parallel",
                    "2026-09-07T10:05:00Z",
                    "completed",
                    "Completed the competing parallel slice.",
                ),
                (
                    "session-failed",
                    "2026-09-07T10:10:00Z",
                    "failed",
                    "Stopped with retained failure evidence.",
                ),
            )
            session_outcomes = {}
            for memory_id, observed_at, status, outcome in session_specs:
                relationship = relationship_from_context(coordination, status)
                session = _record(
                    memory_id,
                    _session_body(memory_id + " work", relationship, outcome),
                    "session",
                    observed_at,
                )
                session_outcomes[memory_id] = commit_record(
                    root,
                    session,
                    load_catalog(root).revision,
                    None,
                    context("tx-" + memory_id),
                )

            accepted_story = read_accepted_record(root, STORY_ID)
            first_delta = StoryDelta(
                story_id=STORY_ID,
                expected_revision=1,
                source_session_id="session-completed",
                current_state="The first parallel result is accepted.",
                turning_points=(
                    "session-completed: Accepted the first parallel result.",
                ),
                failure_mode=None,
                resolution="Explicit membership survived parallel execution.",
                open_questions=(),
                related_decision_ids=(DECISION_ID,),
            )
            second_delta = StoryDelta(
                story_id=STORY_ID,
                expected_revision=1,
                source_session_id="session-parallel",
                current_state="The competing result should replace the winner.",
                turning_points=(
                    "session-parallel: Proposed a competing parallel result.",
                ),
                failure_mode=None,
                resolution=None,
                open_questions=(),
                related_decision_ids=(DECISION_ID,),
            )
            winning_candidate = build_story_revision_candidate(
                accepted_story,
                first_delta,
                "2026-09-07T10:15:00Z",
                "fixture-agent",
                "session-completed",
            )
            competing_candidate = build_story_revision_candidate(
                accepted_story,
                second_delta,
                "2026-09-07T10:16:00Z",
                "fixture-agent",
                "session-parallel",
            )
            base_catalog_revision = load_catalog(root).revision
            winning_story_delta = commit_record(
                root,
                winning_candidate,
                base_catalog_revision,
                1,
                context("tx-story-delta-winner"),
            )
            competing_story_delta = commit_record(
                root,
                competing_candidate,
                base_catalog_revision,
                1,
                context("tx-story-delta-conflict"),
            )

            unbound_relationship = relationship_from_context(
                CoordinationContext(
                    project_id="demo",
                    coordinator_task_id="task-direct",
                    primary_story_id=None,
                    related_story_ids=(),
                    expected_story_revision=None,
                    allowed_scope=("records",),
                ),
                "completed",
            )
            unbound_session = _record(
                "session-unbound",
                _session_body(
                    "Direct work without binding",
                    unbound_relationship,
                    "Awaiting explicit Story confirmation.",
                ),
                "session",
                "2026-09-07T10:20:00Z",
            )
            unbound = build_unbound_session_candidate(
                unbound_session,
                suggested_primary=STORY_ID,
                primary_evidence="The user may later confirm this Story.",
                intended_story_delta=StoryDelta(
                    story_id=STORY_ID,
                    expected_revision=2,
                    source_session_id="session-unbound",
                    current_state="This remains only intended work.",
                    turning_points=(
                        "session-unbound: Proposed an unbound result.",
                    ),
                    failure_mode=None,
                    resolution=None,
                    open_questions=(),
                    related_decision_ids=(),
                ),
                origin_task_id="task-direct",
            )
            unbound_proposal = preserve_unbound_session_candidate(
                root,
                unbound,
                context("tx-session-unbound"),
            )
            parsed_unbound = parse_proposal_artifact(
                unbound_proposal.relative_to(root).as_posix(),
                unbound_proposal.read_bytes(),
            )

            story_projection = next(
                item
                for item in build_project_views(root, "demo", "fixture-v1")
                if item.relative_path
                == "projects/demo/stories/{0}.md".format(STORY_ID)
            )
            stale_projection = next(
                item
                for item in build_root_views(root, "fixture-v1")
                if item.relative_path == "_index/stale-or-uncertain.md"
            )
            accepted_after_conflict = read_accepted_record(root, STORY_ID)

            self.assertEqual(
                "accepted",
                session_outcomes["session-completed"].status,
            )
            self.assertEqual("accepted", session_outcomes["session-failed"].status)
            self.assertEqual("accepted", winning_story_delta.status)
            self.assertEqual("proposed", competing_story_delta.status)
            self.assertTrue(unbound_proposal.is_file())
            self.assertEqual("tx-session-unbound", parsed_unbound.proposal_id)
            self.assertIn("session-completed` (completed, primary)", story_projection.content)
            self.assertIn("session-parallel` (completed, primary)", story_projection.content)
            self.assertIn("session-failed` (failed, primary)", story_projection.content)
            self.assertNotIn("session-unbound", story_projection.content)
            self.assertIn("tx-story-delta-conflict", story_projection.content)
            self.assertIn("legacy-session-unbound", stale_projection.content)
            self.assertIn("tx-session-unbound", stale_projection.content)
            self.assertEqual(2, accepted_after_conflict.envelope.revision)
            self.assertIn("Accepted the first parallel result.", accepted_after_conflict.body)
            self.assertNotIn("Proposed a competing parallel result.", accepted_after_conflict.body)


if __name__ == "__main__":
    unittest.main()
