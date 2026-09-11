import hashlib
import sys
import unittest
from dataclasses import replace
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "skills" / "obsidian-agent-memory" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory import (  # noqa: E402
    RecordEnvelope,
    ValidationError,
    compute_body_sha256,
    normalize_body,
    parse_record,
    record_relative_path,
    render_record,
)
from obsidian_agent_memory.records import _validate_supersedes  # noqa: E402


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.body = "first line  \r\nsecond line\t\rthird line"
        self.normalized_body = "first line\nsecond line\nthird line\n"
        self.body_sha256 = hashlib.sha256(
            b"first line\nsecond line\nthird line\n"
        ).hexdigest()
        self.envelope = RecordEnvelope(
            memory_id="memory-1",
            record_type="decision",
            schema_version=2,
            owner_scope="project.demo.decision",
            project="demo",
            revision=9,
            supersedes="memory-1@8",
            created_at="2026-08-30T00:00:00Z",
            observed_at="2026-08-30T01:02:03+08:00",
            source="test-source",
            source_revision="source-1",
            body_sha256=self.body_sha256,
        )

    def test_normalizes_body_hashes_utf8_and_round_trips_canonical_record(self):
        expected = (
            "---\n"
            "memory_id: memory-1\n"
            "record_type: decision\n"
            "schema_version: 2\n"
            "owner_scope: project.demo.decision\n"
            "project: demo\n"
            "revision: 9\n"
            "supersedes: memory-1@8\n"
            "created_at: 2026-08-30T00:00:00Z\n"
            "observed_at: 2026-08-30T01:02:03+08:00\n"
            "source: test-source\n"
            "source_revision: source-1\n"
            "body_sha256: " + self.body_sha256 + "\n"
            "---\n"
            "first line\nsecond line\nthird line\n"
        )

        self.assertEqual(self.normalized_body, normalize_body(self.body))
        self.assertEqual(self.body_sha256, compute_body_sha256(self.body))
        self.assertEqual(expected, render_record(self.envelope, self.body))
        self.assertEqual((self.envelope, self.normalized_body), parse_record(expected))

    def test_rejects_noncanonical_frontmatter_shapes_and_field_order(self):
        rendered = render_record(self.envelope, self.normalized_body)
        invalid_documents = (
            rendered.replace("memory_id: memory-1\n", "", 1),
            rendered.replace("memory_id: memory-1\n", "memory_id: memory-1\nmemory_id: other\n", 1),
            rendered.replace("memory_id: memory-1\nrecord_type: decision\n", "record_type: decision\nmemory_id: memory-1\n", 1),
            rendered.replace("record_type: decision\n", "unknown: value\nrecord_type: decision\n", 1),
            rendered.replace("source: test-source", "source: [test-source]", 1),
            rendered.replace("source: test-source", "source: {name: test-source}", 1),
            rendered.replace("source: test-source", "source: |\n  test-source", 1),
            rendered.replace("source: test-source", "source: !tag test-source", 1),
            rendered.replace("source: test-source", "source: &anchor test-source", 1),
            rendered.replace("source: test-source", 'source: "test-source"', 1),
            rendered.replace("source: test-source", "source: test\t-source", 1),
        )

        for document in invalid_documents:
            with self.subTest(document=document):
                with self.assertRaises(ValidationError):
                    parse_record(document)

    def test_rejects_invalid_envelopes_and_body_hash_mismatch(self):
        invalid_envelopes = (
            replace(self.envelope, schema_version=1),
            replace(self.envelope, revision=0),
            replace(self.envelope, created_at="2026-08-30"),
            replace(self.envelope, body_sha256="f" * 63),
            replace(self.envelope, body_sha256="g" * 64),
            replace(self.envelope, memory_id="../escape"),
            replace(self.envelope, project="Other"),
            replace(self.envelope, owner_scope="project.demo.story"),
            replace(self.envelope, source="bad/source"),
            replace(self.envelope, source_revision="bad/revision"),
            replace(self.envelope, supersedes="memory-1@0"),
            replace(self.envelope, supersedes="other-memory@8"),
        )

        for envelope in invalid_envelopes:
            with self.subTest(envelope=envelope):
                with self.assertRaises(ValidationError):
                    render_record(envelope, self.normalized_body)

        mismatched_body = self.normalized_body + "changed\n"
        with self.assertRaises(ValidationError):
            render_record(self.envelope, mismatched_body)

    def test_parser_rejects_tampered_semantic_scalars_and_body(self):
        rendered = render_record(self.envelope, self.normalized_body)
        invalid_documents = (
            rendered.replace("schema_version: 2", "schema_version: 1", 1),
            rendered.replace("revision: 9", "revision: 0", 1),
            rendered.replace("created_at: 2026-08-30T00:00:00Z", "created_at: 2026-08-30", 1),
            rendered.replace("owner_scope: project.demo.decision", "owner_scope: project.other.decision", 1),
            rendered.replace("project: demo", "project: none", 1),
            rendered.replace(self.body_sha256, "g" * 64, 1),
            rendered + "tampered\n",
        )

        for document in invalid_documents:
            with self.subTest(document=document):
                with self.assertRaises(ValidationError):
                    parse_record(document)

    def test_supersedes_validator_rejects_unsafe_captured_memory_ids(self):
        for unsafe_memory_id in ("con", "name."):
            invalid = replace(
                self.envelope,
                memory_id=unsafe_memory_id,
                supersedes="{0}@1".format(unsafe_memory_id),
            )
            with self.subTest(memory_id=unsafe_memory_id):
                with self.assertRaises(ValidationError):
                    _validate_supersedes(invalid)

    def test_round_trips_body_containing_unicode_line_separator(self):
        body = "first\u2028second"
        body_sha256 = hashlib.sha256("first\u2028second\n".encode("utf-8")).hexdigest()
        envelope = replace(self.envelope, body_sha256=body_sha256)

        rendered = render_record(envelope, body)

        self.assertEqual((envelope, "first\u2028second\n"), parse_record(rendered))

    def test_rejects_project_and_owner_scope_mismatches_for_every_type(self):
        cases = (
            ("session", "project.demo.session", "demo"),
            ("story", "project.demo.story", "demo"),
            ("decision", "project.demo.decision", "demo"),
            ("preference", "user.preference", None),
            ("runbook", "agent.runbook", None),
            ("migration", "meta.migration", None),
            ("maintenance", "meta.maintenance", None),
        )

        for record_type, owner_scope, project in cases:
            valid = replace(self.envelope, record_type=record_type, owner_scope=owner_scope, project=project)
            wrong_owner_scope = (
                "project.other.{0}".format(record_type)
                if project is not None
                else ("meta.migration" if record_type == "maintenance" else "meta.maintenance")
            )
            with self.subTest(record_type=record_type, mismatch="owner"):
                with self.assertRaises(ValidationError):
                    render_record(replace(valid, owner_scope=wrong_owner_scope), self.normalized_body)
            with self.subTest(record_type=record_type, mismatch="project"):
                wrong_project = None if project is not None else "demo"
                with self.assertRaises(ValidationError):
                    render_record(replace(valid, project=wrong_project), self.normalized_body)

    def test_maps_valid_records_to_exact_relative_paths(self):
        cases = (
            ("session", "project.demo.session", "demo", "_records/projects/demo/sessions/memory-1--r0009.md"),
            ("story", "project.demo.story", "demo", "_records/projects/demo/stories/memory-1--r0009.md"),
            ("decision", "project.demo.decision", "demo", "_records/projects/demo/decisions/memory-1--r0009.md"),
            ("preference", "user.preference", None, "_records/preferences/memory-1--r0009.md"),
            ("runbook", "agent.runbook", None, "_records/runbooks/memory-1--r0009.md"),
            ("migration", "meta.migration", None, "_records/meta/migrations/memory-1--r0009.md"),
            ("maintenance", "meta.maintenance", None, "_records/meta/maintenance/memory-1--r0009.md"),
        )

        for record_type, owner_scope, project, expected_path in cases:
            envelope = replace(self.envelope, record_type=record_type, owner_scope=owner_scope, project=project)
            with self.subTest(record_type=record_type):
                self.assertEqual(Path(expected_path), record_relative_path(envelope))

    def test_formats_record_path_revisions_with_required_width(self):
        revision_rows = (
            (1, "_records/projects/demo/decisions/memory-1--r0001.md"),
            (9, "_records/projects/demo/decisions/memory-1--r0009.md"),
            (10, "_records/projects/demo/decisions/memory-1--r0010.md"),
            (10000, "_records/projects/demo/decisions/memory-1--r10000.md"),
        )

        for revision, expected_path in revision_rows:
            with self.subTest(revision=revision):
                self.assertEqual(
                    Path(expected_path), record_relative_path(replace(self.envelope, revision=revision))
                )

    def test_fixed_records_render_deterministically_across_types_line_endings_and_revisions(self):
        type_rows = (
            ("session", "project.demo.session", "demo"),
            ("story", "project.demo.story", "demo"),
            ("decision", "project.demo.decision", "demo"),
            ("preference", "user.preference", None),
            ("runbook", "agent.runbook", None),
            ("migration", "meta.migration", None),
            ("maintenance", "meta.maintenance", None),
        )
        revision_rows = (
            (1, "café  \n雪\t"),
            (9, "café  \r\n雪\t"),
            (10, "café  \n雪\t"),
            (10000, "café  \r\n雪\t"),
        )
        expected_hash = hashlib.sha256("café\n雪\n".encode("utf-8")).hexdigest()

        for record_type, owner_scope, project in type_rows:
            for revision, body in revision_rows:
                envelope = replace(
                    self.envelope,
                    record_type=record_type,
                    owner_scope=owner_scope,
                    project=project,
                    revision=revision,
                    supersedes=None,
                    body_sha256=expected_hash,
                )
                with self.subTest(record_type=record_type, revision=revision):
                    first_render = render_record(envelope, body)
                    self.assertEqual(first_render, render_record(envelope, body))
                    self.assertEqual((envelope, "café\n雪\n"), parse_record(first_render))


if __name__ == "__main__":
    unittest.main()
