import sys
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory import (  # noqa: E402
    AcceptedRecord,
    RecordEnvelope,
    StoryDelta,
    StoryProfile,
    ValidationError,
    apply_story_delta,
    build_story_revision_candidate,
    compute_body_sha256,
    parse_story_profile,
    render_story_profile,
)


CURRENT_BODY = (
    "# Story: Demo cache gained an explicit lifecycle\n"
    "\n"
    "## Situation\n"
    "\n"
    "Cache ownership was implicit.\n"
    "\n"
    "## Current State\n"
    "\n"
    "The cache is initialized explicitly.\n"
    "\n"
    "## Turning Points\n"
    "\n"
    "- session-bootstrap: Added explicit initialization.\n"
    "\n"
    "## Failure Mode\n"
    "\n"
    "none\n"
    "\n"
    "## Resolution\n"
    "\n"
    "Initialization now owns cache creation.\n"
    "\n"
    "## Open Questions\n"
    "\n"
    "- Should eviction be generation fenced?\n"
    "\n"
    "## Related Decision IDs\n"
    "\n"
    "- decision-bootstrap\n"
)


def _current_record(body=CURRENT_BODY):
    envelope = RecordEnvelope(
        memory_id="story-demo",
        record_type="story",
        schema_version=2,
        owner_scope="project.demo.story",
        project="demo",
        revision=2,
        supersedes="story-demo@1",
        created_at="2026-09-01T00:00:00Z",
        observed_at="2026-09-02T00:00:00Z",
        source="fixture-source",
        source_revision="fixture-r2",
        body_sha256=compute_body_sha256(body),
    )
    return AcceptedRecord(envelope, body, "_records/projects/demo/stories/story-demo--r0002.md", 4)


def _delta(**changes):
    values = {
        "story_id": "story-demo",
        "expected_revision": 2,
        "source_session_id": "session-demo",
        "current_state": "Cache invalidation is now explicit.",
        "turning_points": ("session-demo: Added generation fencing.",),
        "failure_mode": None,
        "resolution": None,
        "open_questions": (),
        "related_decision_ids": ("decision-fence",),
    }
    values.update(changes)
    return StoryDelta(**values)


class StoryProfileTests(unittest.TestCase):
    def test_round_trips_the_exact_story_profile(self):
        profile = parse_story_profile(CURRENT_BODY)

        self.assertEqual("Demo cache gained an explicit lifecycle", profile.title)
        self.assertEqual(
            ("session-bootstrap: Added explicit initialization.",),
            profile.turning_points,
        )
        self.assertEqual(("decision-bootstrap",), profile.related_decision_ids)
        self.assertEqual(CURRENT_BODY, render_story_profile(profile))

    def test_round_trips_multi_paragraph_story_prose(self):
        body = CURRENT_BODY.replace(
            "Cache ownership was implicit.",
            "Cache ownership was implicit.\n\nThe failure affected multiple callers.",
        )

        profile = parse_story_profile(body)

        self.assertIn("\n\n", profile.situation)
        self.assertEqual(body, render_story_profile(profile))

    def test_story_profile_rejects_owned_decision_section_and_identifier_title(self):
        cases = (
            CURRENT_BODY.replace("## Current State", "## Decision", 1),
            CURRENT_BODY.replace(
                "# Story: Demo cache gained an explicit lifecycle",
                "# Story: story-demo",
                1,
            ),
        )

        for body in cases:
            with self.subTest(body=body), self.assertRaises(ValidationError):
                parse_story_profile(body)

    def test_delta_appends_one_source_bound_turning_point(self):
        current = parse_story_profile(CURRENT_BODY)

        updated = apply_story_delta(current, _delta())
        rendered = render_story_profile(updated)

        self.assertIn("session-bootstrap: Added explicit initialization.", rendered)
        self.assertIn("session-demo: Added generation fencing.", rendered)
        self.assertIn("Cache invalidation is now explicit.", rendered)
        self.assertNotIn("## Decision\n", rendered)
        self.assertEqual(
            ("decision-bootstrap", "decision-fence"),
            updated.related_decision_ids,
        )

    def test_delta_rejects_unbound_or_duplicate_turning_point_sources(self):
        current = parse_story_profile(CURRENT_BODY)
        cases = (
            _delta(turning_points=("session-other: Wrong source.",)),
            _delta(source_session_id="session-bootstrap"),
            _delta(
                turning_points=(
                    "session-demo: First change.",
                    "session-demo: Second change.",
                )
            ),
        )

        for delta in cases:
            with self.subTest(delta=delta), self.assertRaises(ValidationError):
                apply_story_delta(current, delta)

    def test_builds_exact_next_story_revision_candidate(self):
        candidate = build_story_revision_candidate(
            _current_record(),
            _delta(),
            "2026-09-07T10:00:00Z",
            "codex",
            "task-result-1",
        )

        self.assertEqual(3, candidate.envelope.revision)
        self.assertEqual("story-demo@2", candidate.envelope.supersedes)
        self.assertEqual("story-demo", candidate.envelope.memory_id)
        self.assertEqual("2026-09-01T00:00:00Z", candidate.envelope.created_at)
        self.assertEqual("2026-09-07T10:00:00Z", candidate.envelope.observed_at)
        self.assertEqual("codex", candidate.envelope.source)
        self.assertEqual("task-result-1", candidate.envelope.source_revision)
        self.assertEqual(
            compute_body_sha256(candidate.body),
            candidate.envelope.body_sha256,
        )

    def test_candidate_builder_rejects_wrong_story_identity_or_revision(self):
        cases = (
            _delta(story_id="story-other"),
            _delta(expected_revision=1),
        )

        for delta in cases:
            with self.subTest(delta=delta), self.assertRaises(ValidationError):
                build_story_revision_candidate(
                    _current_record(),
                    delta,
                    "2026-09-07T10:00:00Z",
                    "codex",
                    "task-result-1",
                )

    def test_render_sorts_open_questions_and_decision_ids(self):
        profile = StoryProfile(
            title="Cache failures gained deterministic recovery",
            situation="Recovery was implicit.",
            current_state="Recovery is explicit.",
            turning_points=("session-z: Added recovery.",),
            failure_mode=None,
            resolution=None,
            open_questions=("Z question?", "A question?"),
            related_decision_ids=("decision-z", "decision-a"),
        )

        rendered = render_story_profile(profile)

        self.assertLess(rendered.index("- A question?"), rendered.index("- Z question?"))
        self.assertLess(rendered.index("- decision-a"), rendered.index("- decision-z"))


if __name__ == "__main__":
    unittest.main()
