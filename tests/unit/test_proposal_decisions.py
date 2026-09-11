import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: F401 - installs the source package path

from obsidian_agent_memory.errors import ValidationError
from obsidian_agent_memory.proposal_decisions import (
    bind_proposal_decisions,
    load_proposal_decisions,
)
from obsidian_agent_memory.proposal_review import ProposalReviewArtifact


_REVIEW_ID = "review-" + "9" * 64
_REPORT_SHA256 = "a" * 64
_SESSION_SOURCE = "projects/demo/sessions/example.md"
_SESSION_SNAPSHOT_SHA256 = "6" * 64
_SESSION_MEMORY_ID = "migr-4c809c9619997c68a02f376f"


def _decision_document():
    return {
        "schema_version": 1,
        "evidence_kind": "proposal-review-decisions",
        "review_id": _REVIEW_ID,
        "report_sha256": _REPORT_SHA256,
        "mutation_authorized": False,
        "decisions": [
            {
                "proposal_id": "action-11111111111111111111",
                "state": "confirm-candidate",
                "owner_scope": "project.demo.session",
                "project_id": "demo",
                "note": "confirmed from the reviewed snapshot",
            },
            {
                "proposal_id": "action-22222222222222222222",
                "state": "change-owner",
                "owner_scope": "meta.maintenance",
                "project_id": None,
                "note": "maintenance owns the durable operation",
            },
            {
                "proposal_id": "action-33333333333333333333",
                "state": "keep-unresolved",
                "owner_scope": None,
                "project_id": None,
                "note": "mixed ownership still needs review",
            },
            {
                "proposal_id": "action-44444444444444444444",
                "state": "knowledge-base-candidate",
                "owner_scope": None,
                "project_id": None,
                "note": "candidate only; no knowledge write occurred",
            },
            {
                "proposal_id": "action-55555555555555555555",
                "state": "sources-only",
                "owner_scope": None,
                "project_id": None,
                "note": "retain immutable source evidence",
            },
        ],
    }


def _decision_bytes(document, crlf=False):
    raw = json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")
    return raw.replace(b"\n", b"\r\n") if crlf else raw


def _report_artifact():
    items = [
        {
            "proposal_id": "action-11111111111111111111",
            "source_path": _SESSION_SOURCE,
            "snapshot_sha256": _SESSION_SNAPSHOT_SHA256,
            "candidate_owner": {
                "candidate_memory_id": _SESSION_MEMORY_ID,
                "owner_scope": "project.demo.session",
                "project_id": "demo",
                "record_type": "session",
            },
        },
        {
            "proposal_id": "action-22222222222222222222",
            "source_path": "meta/legacy-maintenance.md",
            "snapshot_sha256": "7" * 64,
            "candidate_owner": {
                "candidate_memory_id": "migr-df06d868a6b8adb962bd09ab",
                "owner_scope": "agent.runbook",
                "project_id": None,
                "record_type": "runbook",
            },
        },
    ]
    for index in range(3, 6):
        items.append(
            {
                "proposal_id": "action-{0:020d}".format(index * int("1" * 20)),
                "source_path": "meta/source-{0}.md".format(index),
                "snapshot_sha256": str(index) * 64,
                "candidate_owner": None,
            }
        )
    return ProposalReviewArtifact(
        document={"items": items, "summary": {"total": 5}},
        raw=b"synthetic report bytes",
        review_id=_REVIEW_ID,
        report_sha256=_REPORT_SHA256,
    )


class ProposalDecisionLoaderTests(unittest.TestCase):
    def _load(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decisions.json"
            path.write_bytes(raw)
            return load_proposal_decisions(path)

    def test_preserves_approved_crlf_bytes_and_hash(self):
        raw = _decision_bytes(_decision_document(), crlf=True)

        envelope = self._load(raw)

        self.assertEqual(raw, envelope.raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), envelope.decisions_sha256)
        self.assertEqual(_REVIEW_ID, envelope.review_id)
        self.assertEqual(_REPORT_SHA256, envelope.report_sha256)
        self.assertEqual(
            (
                "confirm-candidate",
                "change-owner",
                "keep-unresolved",
                "knowledge-base-candidate",
                "sources-only",
            ),
            tuple(decision.state for decision in envelope.decisions),
        )

    def test_rejects_duplicate_keys_and_unknown_fields(self):
        duplicate = (
            b'{"schema_version":1,"schema_version":1,'
            b'"evidence_kind":"proposal-review-decisions",'
            b'"review_id":"review-' + b"9" * 64 + b'",'
            b'"report_sha256":"' + b"a" * 64 + b'",'
            b'"mutation_authorized":false,"decisions":[]}'
        )
        with self.assertRaises(ValidationError):
            self._load(duplicate)

        document = _decision_document()
        document["unexpected"] = "not allowed"
        with self.assertRaises(ValidationError):
            self._load(_decision_bytes(document))

    def test_rejects_invalid_state_owner_and_order_combinations(self):
        mutations = []

        authorized = _decision_document()
        authorized["mutation_authorized"] = True
        mutations.append(authorized)

        duplicate = _decision_document()
        duplicate["decisions"][1]["proposal_id"] = duplicate["decisions"][0]["proposal_id"]
        mutations.append(duplicate)

        unordered = _decision_document()
        unordered["decisions"][0], unordered["decisions"][1] = (
            unordered["decisions"][1],
            unordered["decisions"][0],
        )
        mutations.append(unordered)

        missing_confirmed_owner = _decision_document()
        missing_confirmed_owner["decisions"][0]["owner_scope"] = None
        missing_confirmed_owner["decisions"][0]["project_id"] = None
        mutations.append(missing_confirmed_owner)

        no_record_owner = _decision_document()
        no_record_owner["decisions"][2]["owner_scope"] = "agent.runbook"
        mutations.append(no_record_owner)

        incomplete_project_owner = _decision_document()
        incomplete_project_owner["decisions"][1]["owner_scope"] = "project.demo.story"
        mutations.append(incomplete_project_owner)

        unsupported = _decision_document()
        unsupported["decisions"][4]["state"] = "accept-everything"
        mutations.append(unsupported)

        overlong_note = _decision_document()
        overlong_note["decisions"][4]["note"] = "x" * 4097
        mutations.append(overlong_note)

        for document in mutations:
            with self.subTest(document=document):
                with self.assertRaises(ValidationError):
                    self._load(_decision_bytes(document))


class ProposalDecisionBindingTests(unittest.TestCase):
    def _loaded(self, document=None):
        raw = _decision_bytes(document or _decision_document(), crlf=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decisions.json"
            path.write_bytes(raw)
            return load_proposal_decisions(path)

    def test_binds_complete_decisions_and_source_stable_identity(self):
        decisions = self._loaded()

        bound = bind_proposal_decisions(decisions, _report_artifact())

        self.assertEqual(decisions, bound)
        self.assertEqual(_SESSION_MEMORY_ID, _report_artifact().document["items"][0]["candidate_owner"]["candidate_memory_id"])

    def test_rejects_partial_unknown_or_owner_inconsistent_decisions(self):
        partial_document = _decision_document()
        partial_document["decisions"] = partial_document["decisions"][:-1]

        unknown_document = _decision_document()
        unknown_document["decisions"][-1]["proposal_id"] = "action-99999999999999999999"

        wrong_confirm_owner = _decision_document()
        wrong_confirm_owner["decisions"][0]["owner_scope"] = "project.demo.story"

        wrong_change_project = _decision_document()
        wrong_change_project["decisions"][1]["owner_scope"] = "project.demo.story"
        wrong_change_project["decisions"][1]["project_id"] = "other"

        for document in (
            partial_document,
            unknown_document,
            wrong_confirm_owner,
            wrong_change_project,
        ):
            with self.subTest(document=document):
                with self.assertRaises(ValidationError):
                    bind_proposal_decisions(self._loaded(document), _report_artifact())

    def test_rejects_report_candidate_with_non_source_stable_memory_id(self):
        report = _report_artifact()
        items = [dict(item) for item in report.document["items"]]
        items[0]["candidate_owner"] = dict(items[0]["candidate_owner"])
        items[0]["candidate_owner"]["candidate_memory_id"] = "migr-aaaaaaaaaaaaaaaaaaaaaaaa"
        report = ProposalReviewArtifact(
            document={"items": items, "summary": {"total": 5}},
            raw=report.raw,
            review_id=report.review_id,
            report_sha256=report.report_sha256,
        )

        with self.assertRaises(ValidationError):
            bind_proposal_decisions(self._loaded(), report)


if __name__ == "__main__":
    unittest.main()
