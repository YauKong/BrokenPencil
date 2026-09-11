import sys
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory import (  # noqa: E402
    SessionRelationship,
    ValidationError,
    parse_session_relationship,
    render_session_relationship,
)


def _session_body(block):
    return "# Session: Demo\n\n{0}\n## User Goal\n\nDemo\n".format(block)


class SessionRelationshipTests(unittest.TestCase):
    def test_round_trips_canonical_relationship_block(self):
        value = SessionRelationship("completed", "story-primary", ("story-a", "story-z"))
        expected = (
            "## Session Relationship\n"
            "session_status: completed\n"
            "primary_story_id: story-primary\n"
            "related_story_id: story-a\n"
            "related_story_id: story-z\n"
        )

        self.assertEqual(expected, render_session_relationship(value))
        self.assertEqual(value, parse_session_relationship(_session_body(expected)))

    def test_zero_relationship_uses_explicit_none(self):
        value = SessionRelationship("failed", None, ())

        rendered = render_session_relationship(value)

        self.assertEqual(
            (
                "## Session Relationship\n"
                "session_status: failed\n"
                "primary_story_id: none\n"
                "related_story_id: none\n"
            ),
            rendered,
        )
        self.assertEqual(value, parse_session_relationship(_session_body(rendered)))

    def test_renderer_sorts_related_story_ids_lexically(self):
        value = SessionRelationship("cancelled", None, ("story-z", "story-a"))

        rendered = render_session_relationship(value)

        self.assertLess(rendered.index("related_story_id: story-a"), rendered.index("related_story_id: story-z"))

    def test_rejects_missing_repeated_or_misplaced_relationship_section(self):
        valid = render_session_relationship(SessionRelationship("completed", None, ()))
        cases = (
            "# Session: Demo\n\n## User Goal\n\nDemo\n",
            _session_body(valid + "\n" + valid),
            "# Session: Demo\n\nIntro text.\n\n" + valid + "\n## User Goal\n\nDemo\n",
        )

        for body in cases:
            with self.subTest(body=body), self.assertRaises(ValidationError):
                parse_session_relationship(body)

    def test_rejects_invalid_status_and_scalar_fields(self):
        cases = (
            (
                "## Session Relationship\n"
                "session_status: active\n"
                "primary_story_id: none\n"
                "related_story_id: none\n"
            ),
            (
                "## Session Relationship\n"
                "session_status: completed\n"
                "session_status: failed\n"
                "primary_story_id: none\n"
                "related_story_id: none\n"
            ),
            (
                "## Session Relationship\n"
                "session_status: completed\n"
                "primary_story_id: Story Invalid\n"
                "related_story_id: none\n"
            ),
        )

        for block in cases:
            with self.subTest(block=block), self.assertRaises(ValidationError):
                parse_session_relationship(_session_body(block))

    def test_rejects_contradictory_or_nondeterministic_related_ids(self):
        cases = (
            (
                "## Session Relationship\n"
                "session_status: completed\n"
                "primary_story_id: story-primary\n"
                "related_story_id: none\n"
                "related_story_id: story-a\n"
            ),
            (
                "## Session Relationship\n"
                "session_status: completed\n"
                "primary_story_id: story-primary\n"
                "related_story_id: story-primary\n"
            ),
            (
                "## Session Relationship\n"
                "session_status: completed\n"
                "primary_story_id: none\n"
                "related_story_id: story-a\n"
                "related_story_id: story-a\n"
            ),
            (
                "## Session Relationship\n"
                "session_status: completed\n"
                "primary_story_id: none\n"
                "related_story_id: story-z\n"
                "related_story_id: story-a\n"
            ),
        )

        for block in cases:
            with self.subTest(block=block), self.assertRaises(ValidationError):
                parse_session_relationship(_session_body(block))

    def test_renderer_rejects_invalid_or_duplicate_relationship_values(self):
        cases = (
            SessionRelationship("active", None, ()),
            SessionRelationship("completed", "Story Invalid", ()),
            SessionRelationship("completed", "story-a", ("story-a",)),
            SessionRelationship("completed", None, ("story-a", "story-a")),
        )

        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                render_session_relationship(value)


if __name__ == "__main__":
    unittest.main()
