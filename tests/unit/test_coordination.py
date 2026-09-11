import sys
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory.coordination import (  # noqa: E402
    build_unbound_session_candidate,
    relationship_from_context,
    validate_coordination_context,
)
from obsidian_agent_memory.errors import ValidationError  # noqa: E402
from obsidian_agent_memory.models import CoordinationContext  # noqa: E402
from obsidian_agent_memory.session_relationships import SessionRelationship  # noqa: E402
from obsidian_agent_memory.story_profiles import StoryDelta  # noqa: E402
from tests.helpers import candidate  # noqa: E402


def _unbound_session():
    return candidate(
        memory_id="session-demo",
        body=(
            "# Session: Direct project work\n\n"
            "## Session Relationship\n"
            "session_status: completed\n"
            "primary_story_id: none\n"
            "related_story_id: none\n\n"
            "## Outcome\n\nWork awaits Story confirmation.\n"
        ),
        record_type="session",
        project="demo",
        owner_scope="project.demo.session",
    )


class CoordinationTests(unittest.TestCase):
    def test_delegated_context_builds_confirmed_relationship(self):
        value = CoordinationContext(
            project_id="demo",
            coordinator_task_id="task-controller",
            primary_story_id="story-demo",
            related_story_ids=("story-related",),
            expected_story_revision=3,
            allowed_scope=("records", "projections"),
        )

        self.assertIs(value, validate_coordination_context(value))
        self.assertEqual(
            SessionRelationship("completed", "story-demo", ("story-related",)),
            relationship_from_context(value, "completed"),
        )

    def test_context_rejects_incomplete_or_contradictory_routing(self):
        valid = CoordinationContext(
            project_id="demo",
            coordinator_task_id="task-controller",
            primary_story_id="story-demo",
            related_story_ids=("story-related",),
            expected_story_revision=3,
            allowed_scope=("records", "projections"),
        )
        mutations = (
            ("missing project", valid.__class__("", valid.coordinator_task_id, valid.primary_story_id, valid.related_story_ids, valid.expected_story_revision, valid.allowed_scope)),
            ("primary without revision", valid.__class__(valid.project_id, valid.coordinator_task_id, valid.primary_story_id, valid.related_story_ids, None, valid.allowed_scope)),
            ("revision without primary", valid.__class__(valid.project_id, valid.coordinator_task_id, None, valid.related_story_ids, 3, valid.allowed_scope)),
            ("duplicate related", valid.__class__(valid.project_id, valid.coordinator_task_id, valid.primary_story_id, ("story-related", "story-related"), valid.expected_story_revision, valid.allowed_scope)),
            ("primary repeated", valid.__class__(valid.project_id, valid.coordinator_task_id, valid.primary_story_id, ("story-demo",), valid.expected_story_revision, valid.allowed_scope)),
            ("invalid scope", valid.__class__(valid.project_id, valid.coordinator_task_id, valid.primary_story_id, valid.related_story_ids, valid.expected_story_revision, ("records", "dispatch"))),
        )
        for label, value in mutations:
            with self.subTest(label=label):
                with self.assertRaises(ValidationError):
                    validate_coordination_context(value)

    def test_unbound_direct_task_never_infers_current_focus_story(self):
        value = build_unbound_session_candidate(
            _unbound_session(),
            suggested_primary=None,
            origin_task_id="task-direct",
        )

        self.assertEqual("demo", value.project_id)
        self.assertIsNone(value.candidate_primary_story_id)
        self.assertEqual((), value.candidate_related_story_ids)

    def test_suggestions_require_explicit_evidence_and_do_not_change_session_body(self):
        session = _unbound_session()
        value = build_unbound_session_candidate(
            session,
            suggested_primary="story-demo",
            primary_evidence="User named this Story.",
            suggested_related=(("story-related", "Same accepted outcome."),),
            origin_task_id="task-direct",
            coordinator_task_id="task-controller",
        )

        self.assertEqual(session, value.session_candidate)
        self.assertEqual("story-demo", value.candidate_primary_story_id)
        self.assertEqual(("story-related",), value.candidate_related_story_ids)
        with self.assertRaises(ValidationError):
            build_unbound_session_candidate(
                session,
                suggested_primary="story-demo",
                origin_task_id="task-direct",
            )

    def test_intended_delta_must_target_a_suggested_story_and_the_same_session(self):
        session = _unbound_session()
        delta = StoryDelta(
            story_id="story-demo",
            expected_revision=2,
            source_session_id="session-demo",
            current_state="Awaiting reconciliation.",
            turning_points=("session-demo: Recorded the result.",),
            failure_mode=None,
            resolution=None,
            open_questions=(),
            related_decision_ids=(),
        )
        value = build_unbound_session_candidate(
            session,
            suggested_primary="story-demo",
            primary_evidence="User named this Story.",
            intended_story_delta=delta,
            origin_task_id="task-direct",
        )
        self.assertEqual(delta, value.intended_story_delta)

        with self.assertRaises(ValidationError):
            build_unbound_session_candidate(
                session,
                suggested_primary="story-other",
                primary_evidence="Text similarity only.",
                intended_story_delta=delta,
                origin_task_id="task-direct",
            )


if __name__ == "__main__":
    unittest.main()
