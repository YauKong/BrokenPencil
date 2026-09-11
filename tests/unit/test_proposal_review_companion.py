import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from devtools.proposal_review_companion import build_review_model, main, render_fragment


class ReviewModelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        snapshot = self.bundle / "snapshot" / "files" / "skills" / "example.md"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_text(
            "---\ntitle: Title\ntags:\n  - example\n---\n# Other heading\n\n" + "A" * 1900,
            encoding="utf-8",
        )
        snapshot_raw = snapshot.read_bytes()
        self.item = {
            "candidate_owner": {
                "candidate_memory_id": "migr-example",
                "owner_scope": "agent.runbook",
                "project_id": None,
                "record_type": "runbook",
            },
            "decision_code": "review-path-owner",
            "evidence_ids": [],
            "live_source_state": "unchanged",
            "prior_classification": "ambiguous-owner",
            "proposal_id": "action-example",
            "proposal_path": ".agent-memory/state/proposals/action-example.json",
            "proposal_sha256": "1" * 64,
            "proposal_size": 123,
            "refined_status": "path-owner-candidate",
            "snapshot_path": "snapshot/files/skills/example.md",
            "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
            "source_path": "skills/example.md",
            "source_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        }
        self.document = {
            "classifier_version": "owner-block-v1",
            "code_identity": {"kind": "git-commit", "revision": "abc", "tree_state": "clean"},
            "evidence": [],
            "items": [self.item],
            "report_kind": "migration-proposal-review",
            "review_id": "review-example",
            "run_context": {"actor": "codex", "observed_at": "2026-09-07T00:00:00Z"},
            "schema_version": 1,
            "summary": {
                "prior_classification_counts": {"ambiguous-owner": 1, "unused-class": 0},
                "refined_status_counts": {"path-owner-candidate": 1, "unused-status": 0},
                "total": 1,
            },
        }
        self.report = self.root / "report.json"
        self._write_report()

    def _write_report(self):
        self.report.write_text(
            json.dumps(self.document, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        return hashlib.sha256(self.report.read_bytes()).hexdigest()

    def test_builds_bounded_report_bound_model(self):
        model = build_review_model(self.report, self.bundle, self._write_report())
        self.assertEqual("review-example", model["binding"]["review_id"])
        self.assertEqual("Title", model["items"][0]["title"])
        self.assertLessEqual(len(model["items"][0]["excerpt"]), 1601)
        self.assertEqual(
            {
                "candidate_owner",
                "decision_code",
                "evidence_ids",
                "excerpt",
                "hint",
                "live_source_state",
                "prior_classification",
                "proposal_id",
                "refined_status",
                "snapshot_path",
                "snapshot_sha256",
                "source_path",
                "source_sha256",
                "title",
            },
            set(model["items"][0]),
        )

    def test_rejects_report_hash_mismatch(self):
        with self.assertRaisesRegex(ValueError, "report SHA-256"):
            build_review_model(self.report, self.bundle, "0" * 64)

    def test_rejects_uppercase_expected_hash(self):
        with self.assertRaisesRegex(ValueError, "lowercase"):
            build_review_model(self.report, self.bundle, self._write_report().upper())

    def test_rejects_snapshot_escape(self):
        outside = self.root / "outside.md"
        outside.write_text("outside", encoding="utf-8")
        self.item["snapshot_path"] = "../outside.md"
        self.item["snapshot_sha256"] = hashlib.sha256(outside.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "contained"):
            build_review_model(self.report, self.bundle, self._write_report())

    def test_rejects_snapshot_hash_mismatch(self):
        self.item["snapshot_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "snapshot SHA-256"):
            build_review_model(self.report, self.bundle, self._write_report())

    def test_labels_invalid_utf8_without_lossy_decoding(self):
        snapshot = self.bundle / self.item["snapshot_path"]
        snapshot.write_bytes(b"\xff")
        digest = hashlib.sha256(b"\xff").hexdigest()
        self.item["snapshot_sha256"] = digest
        self.item["source_sha256"] = digest
        model = build_review_model(self.report, self.bundle, self._write_report())
        self.assertEqual("example.md", model["items"][0]["title"])
        self.assertIn("非 UTF-8", model["items"][0]["excerpt"])
        self.assertNotIn("�", model["items"][0]["excerpt"])

    def test_rejects_source_larger_than_two_mib(self):
        snapshot = self.bundle / self.item["snapshot_path"]
        snapshot.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        self.item["snapshot_sha256"] = digest
        self.item["source_sha256"] = digest
        with self.assertRaisesRegex(ValueError, "2 MiB"):
            build_review_model(self.report, self.bundle, self._write_report())

    def test_rejects_inconsistent_summary(self):
        self.document["summary"]["total"] = 2
        with self.assertRaisesRegex(ValueError, "summary"):
            build_review_model(self.report, self.bundle, self._write_report())


class RenderContractTests(unittest.TestCase):
    def setUp(self):
        self.model = {
            "binding": {
                "review_id": "review-example",
                "report_sha256": "a" * 64,
                "classifier_version": "owner-block-v1",
                "code_identity": {"kind": "git-commit", "revision": "abc", "tree_state": "clean"},
            },
            "summary": {
                "total": 2,
                "prior_classification_counts": {"ambiguous-owner": 2},
                "refined_status_counts": {"path-owner-candidate": 2},
            },
            "items": [
                {
                    "candidate_owner": {
                        "candidate_memory_id": "migr-a",
                        "owner_scope": "agent.runbook",
                        "project_id": None,
                        "record_type": "runbook",
                    },
                    "decision_code": "review-path-owner",
                    "evidence_ids": [],
                    "excerpt": "---\ntitle: A </script> test\n---\nBody",
                    "hint": {"action": "confirm-candidate", "reason": "Hint only"},
                    "live_source_state": "unchanged",
                    "prior_classification": "ambiguous-owner",
                    "proposal_id": "proposal-a",
                    "refined_status": "path-owner-candidate",
                    "snapshot_path": "snapshot/files/skills/a.md",
                    "snapshot_sha256": "b" * 64,
                    "source_path": "skills/a.md",
                    "source_sha256": "b" * 64,
                    "title": "A",
                },
                {
                    "candidate_owner": {
                        "candidate_memory_id": "migr-b",
                        "owner_scope": "meta.maintenance",
                        "project_id": None,
                        "record_type": "maintenance",
                    },
                    "decision_code": "choose-fact-owner",
                    "evidence_ids": ["evidence-a"],
                    "excerpt": "Body",
                    "hint": {"action": "keep-unresolved", "reason": "Hint only"},
                    "live_source_state": "unchanged",
                    "prior_classification": "ambiguous-owner",
                    "proposal_id": "proposal-b",
                    "refined_status": "path-owner-candidate",
                    "snapshot_path": "snapshot/files/meta/b.md",
                    "snapshot_sha256": "c" * 64,
                    "source_path": "meta/b.md",
                    "source_sha256": "c" * 64,
                    "title": "B",
                },
            ],
        }
        self.template = Path(__file__).resolve().parents[2] / "devtools" / "proposal_review_companion_template.html"

    def test_renders_literal_local_interactive_fragment(self):
        fragment = render_fragment(self.model, self.template, ("proposal-a", "proposal-b"))
        self.assertIn('id="agent-memory-review-companion"', fragment)
        self.assertEqual(1, fragment.count('id="agent-memory-review-companion"'))
        self.assertNotIn("__PROPOSAL_REVIEW_DATA__", fragment)
        self.assertIn("proposal-a", fragment)
        self.assertIn("confirm-candidate", fragment)
        self.assertIn("change-owner", fragment)
        self.assertIn("sources-only", fragment)
        self.assertIn("knowledge-base-candidate", fragment)
        self.assertIn("keep-unresolved", fragment)
        self.assertIn("agent.runbook", fragment)
        self.assertIn("meta.maintenance", fragment)
        self.assertIn("localStorage", fragment)
        self.assertIn("sendFollowUpMessage", fragment)
        self.assertIn("navigator.clipboard", fragment)
        self.assertIn("浏览器模式：已复制给 Codex 的消息", fragment)
        self.assertIn("20", fragment)
        self.assertIn("aria-live", fragment)
        self.assertIn("@media", fragment)
        lowered = fragment.casefold()
        for forbidden in ("fetch(", "xmlhttprequest", "websocket", "<!doctype", "<html", "<head>", "<body"):
            self.assertNotIn(forbidden, lowered)

    def test_escapes_script_terminator_in_embedded_json(self):
        fragment = render_fragment(self.model, self.template, ())
        self.assertNotIn("</script> test", fragment)
        self.assertIn("<\\/script> test", fragment)

    def test_rejects_unknown_preconfirmed_id(self):
        with self.assertRaisesRegex(ValueError, "preconfirmed"):
            render_fragment(self.model, self.template, ("missing",))


class CompanionCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.bundle = root / "bundle"
        snapshot = self.bundle / "snapshot" / "files" / "skills" / "a.md"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_text("---\ntitle: A\n---\nBody", encoding="utf-8")
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        item = {
            "candidate_owner": {"candidate_memory_id": "migr-a", "owner_scope": "agent.runbook", "project_id": None, "record_type": "runbook"},
            "decision_code": "review-path-owner", "evidence_ids": [], "live_source_state": "unchanged",
            "prior_classification": "ambiguous-owner", "proposal_id": "proposal-a",
            "proposal_path": ".agent-memory/state/proposals/proposal-a.json", "proposal_sha256": "1" * 64,
            "proposal_size": 10, "refined_status": "path-owner-candidate",
            "snapshot_path": "snapshot/files/skills/a.md", "snapshot_sha256": digest,
            "source_path": "skills/a.md", "source_sha256": digest,
        }
        document = {
            "classifier_version": "owner-block-v1", "code_identity": None, "evidence": [], "items": [item],
            "report_kind": "migration-proposal-review", "review_id": "review-cli", "run_context": {}, "schema_version": 1,
            "summary": {"prior_classification_counts": {"ambiguous-owner": 1}, "refined_status_counts": {"path-owner-candidate": 1}, "total": 1},
        }
        self.report = root / "report.json"
        self.report.write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
        self.report_sha = hashlib.sha256(self.report.read_bytes()).hexdigest()
        self.template = Path(__file__).resolve().parents[2] / "devtools" / "proposal_review_companion_template.html"
        self.root = root

    def _args(self, output):
        return [
            "--report", str(self.report), "--report-sha256", self.report_sha,
            "--bundle", str(self.bundle), "--template", str(self.template),
            "--output", str(output), "--preconfirmed", "proposal-a",
        ]

    def test_cli_requires_explicit_arguments(self):
        with self.assertRaises(SystemExit):
            main([])

    def test_cli_creates_deterministic_fragment_and_refuses_replacement(self):
        first = self.root / "first.html"
        second = self.root / "second.html"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(0, main(self._args(first)))
        summary = json.loads(stdout.getvalue())
        self.assertEqual(1, summary["item_count"])
        self.assertEqual(1, summary["preconfirmed_count"])
        self.assertEqual(first.stat().st_size, summary["bytes"])
        self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(), summary["sha256"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(0, main(self._args(second)))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        before = first.read_bytes()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(2, main(self._args(first)))
        self.assertEqual(before, first.read_bytes())


if __name__ == "__main__":
    unittest.main()
