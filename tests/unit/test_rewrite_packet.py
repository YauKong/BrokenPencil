import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: F401 - installs the source package path
from tests.unit.test_proposal_decisions import (
    _decision_bytes,
    _decision_document,
    _report_artifact,
)
from tests.unit.test_rewrite_artifacts import (
    _MEMORY_ID,
    _PROPOSAL_ID,
    _SNAPSHOT_SHA256,
    _candidate_document,
    _canonical,
)

from obsidian_agent_memory.errors import ConflictError, ValidationError
from obsidian_agent_memory.proposal_decisions import (
    bind_proposal_decisions,
    load_proposal_decisions,
)
from obsidian_agent_memory.rewrite_artifacts import (
    load_rewrite_candidate,
    load_semantic_review,
)
from obsidian_agent_memory.rewrite_packet import (
    bind_rewrite_packet,
    load_rewrite_packet,
    seal_rewrite_packet,
)
from obsidian_agent_memory.runtime_identity import CodeIdentity


def _semantic_review(proposal_id, rewrite_sha256, outcome="pass"):
    passed = outcome == "pass"
    return {
        "schema_version": 1,
        "evidence_kind": "proposal-resolution-semantic-review",
        "proposal_id": proposal_id,
        "rewrite_sha256": rewrite_sha256,
        "reviewer_profile": "independent-luna-medium",
        "checks": {
            "material_facts_retained": True,
            "no_unsupported_claims": True,
            "ownership_not_duplicated": passed,
            "evidence_spans_support_sections": True,
            "story_membership_not_inferred": True,
        },
        "outcome": outcome,
        "reason_codes": [] if passed else ["multiple-durable-owners"],
    }


class RewritePacketTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        decision_path = self.base / "decisions.json"
        decision_path.write_bytes(_decision_bytes(_decision_document(), crlf=True))
        base_report = _report_artifact()
        items = []
        for index, source in enumerate(base_report.document["items"], 1):
            item = dict(source)
            item["proposal_sha256"] = str(index + 4) * 64
            item.setdefault(
                "snapshot_path",
                "snapshot/files/" + item["source_path"],
            )
            items.append(item)
        items[0]["snapshot_sha256"] = _SNAPSHOT_SHA256
        items[0]["candidate_owner"] = dict(items[0]["candidate_owner"])
        items[0]["candidate_owner"]["candidate_memory_id"] = _MEMORY_ID
        self.report = replace(
            base_report,
            document={"items": items, "summary": {"total": 5}},
        )
        self.decisions = bind_proposal_decisions(
            load_proposal_decisions(decision_path), self.report
        )
        self.identity = CodeIdentity(
            {"kind": "fixture", "revision": "proposal-resolution-fixture-v1"}
        )
        self.rewrites = self._rewrites()
        self.reviews = self._reviews(self.rewrites)

    def _load_rewrite(self, name, document):
        path = self.base / name
        path.write_bytes(_canonical(document))
        return load_rewrite_candidate(path)

    def _load_review(self, name, document):
        path = self.base / name
        path.write_bytes(_canonical(document))
        return load_semantic_review(path)

    def _rewrites(self):
        confirm = _candidate_document()
        confirm["decisions_sha256"] = self.decisions.decisions_sha256

        changed = _candidate_document()
        changed["proposal_id"] = "action-22222222222222222222"
        changed["decision_state"] = "change-owner"
        changed["decisions_sha256"] = self.decisions.decisions_sha256
        changed["source"] = {
            "source_path": "meta/legacy-maintenance.md",
            "snapshot_path": "snapshot/files/meta/legacy-maintenance.md",
            "snapshot_sha256": "7" * 64,
            "proposal_sha256": "6" * 64,
        }
        changed["target"] = {
            "memory_id": "migr-df06d868a6b8adb962bd09ab",
            "record_type": "maintenance",
            "owner_scope": "meta.maintenance",
            "project_id": None,
        }
        body = (
            "# Maintenance: Legacy maintenance outcome remains explicit\n\n"
            "## Audit Scope\n\nThe fixture source only.\n\n"
            "## Findings\n\nOne durable maintenance outcome.\n\n"
            "## Reviewed Actions\n\nPreserve and validate the rewrite.\n\n"
            "## Applied Transactions\n\nnone\n\n"
            "## Verification\n\nThe packet hashes every candidate.\n"
        )
        changed["rewrite"]["title"] = (
            "Maintenance: Legacy maintenance outcome remains explicit"
        )
        changed["rewrite"]["body"] = body
        changed["rewrite"]["body_sha256"] = hashlib.sha256(
            body.encode("utf-8")
        ).hexdigest()
        return (
            self._load_rewrite("confirm.json", confirm),
            self._load_rewrite("changed.json", changed),
        )

    def _reviews(self, rewrites):
        return tuple(
            self._load_review(
                "review-{0}.json".format(index),
                _semantic_review(rewrite.proposal_id, rewrite.rewrite_sha256),
            )
            for index, rewrite in enumerate(rewrites, 1)
        )

    def _seal(self, output=None, rewrites=None, reviews=None):
        return seal_rewrite_packet(
            output or self.base / "packet",
            self.report,
            self.decisions,
            rewrites if rewrites is not None else self.rewrites,
            reviews if reviews is not None else self.reviews,
            self.identity,
        )

    def test_seals_and_loads_exact_complete_inventory(self):
        packet = self._seal()
        loaded = load_rewrite_packet(packet.root)

        self.assertEqual(packet.packet_sha256, loaded.packet_sha256)
        self.assertEqual(2, loaded.accepted_count)
        self.assertEqual(
            (
                ("change-owner", 1),
                ("confirm-candidate", 1),
                ("keep-unresolved", 1),
                ("knowledge-base-candidate", 1),
                ("sources-only", 1),
            ),
            loaded.decision_state_counts,
        )
        self.assertEqual(
            ("manifest.json", "rewrites", "semantic-review"),
            tuple(sorted(path.name for path in loaded.root.iterdir())),
        )
        bind_rewrite_packet(
            loaded, self.report, self.decisions, self.identity
        )

    def test_zero_count_states_remain_explicit_in_manifest(self):
        document = _decision_document()
        document["decisions"][3]["state"] = "keep-unresolved"
        document["decisions"][4]["state"] = "keep-unresolved"
        decision_path = self.base / "zero-count-decisions.json"
        decision_path.write_bytes(_decision_bytes(document, crlf=True))
        decisions = bind_proposal_decisions(
            load_proposal_decisions(decision_path), self.report
        )
        rewrites = []
        reviews = []
        for index, original in enumerate(self.rewrites, 1):
            rewrite_document = json.loads(original.raw.decode("utf-8"))
            rewrite_document["decisions_sha256"] = decisions.decisions_sha256
            rewrite_path = self.base / "zero-count-rewrite-{0}.json".format(index)
            rewrite_path.write_bytes(_canonical(rewrite_document))
            rewrite = load_rewrite_candidate(rewrite_path)
            rewrites.append(rewrite)
            review_path = self.base / "zero-count-review-{0}.json".format(index)
            review_path.write_bytes(
                _canonical(_semantic_review(rewrite.proposal_id, rewrite.rewrite_sha256))
            )
            reviews.append(load_semantic_review(review_path))

        packet = seal_rewrite_packet(
            self.base / "zero-count-packet",
            self.report,
            decisions,
            tuple(rewrites),
            tuple(reviews),
            self.identity,
        )

        self.assertEqual(
            (
                ("change-owner", 1),
                ("confirm-candidate", 1),
                ("keep-unresolved", 3),
                ("knowledge-base-candidate", 0),
                ("sources-only", 0),
            ),
            packet.decision_state_counts,
        )

    def test_rejects_missing_extra_duplicate_or_failed_candidate_pairs(self):
        duplicate_rewrite = self.rewrites + (self.rewrites[0],)
        failed_review = replace(self.reviews[0], outcome="rewrite-needs-split")
        cases = (
            (self.rewrites[:-1], self.reviews),
            (duplicate_rewrite, self.reviews),
            (self.rewrites, self.reviews[:-1]),
            (self.rewrites, (failed_review, self.reviews[1])),
        )
        for index, (rewrites, reviews) in enumerate(cases, 1):
            with self.subTest(index=index):
                with self.assertRaises(ValidationError):
                    self._seal(
                        output=self.base / "packet-{0}".format(index),
                        rewrites=rewrites,
                        reviews=reviews,
                    )

    def test_rejects_review_bound_to_wrong_rewrite(self):
        wrong = replace(self.reviews[0], rewrite_sha256="0" * 64)
        with self.assertRaises(ValidationError):
            self._seal(reviews=(wrong, self.reviews[1]))

    def test_existing_destination_is_never_replaced(self):
        output = self.base / "occupied"
        output.mkdir()
        marker = output / "keep.txt"
        marker.write_text("keep", encoding="utf-8")

        with self.assertRaises(ConflictError):
            self._seal(output=output)

        self.assertEqual("keep", marker.read_text("utf-8"))
        self.assertEqual(("keep.txt",), tuple(path.name for path in output.iterdir()))

    def test_loader_rejects_manifest_or_inventory_tampering(self):
        packet = self._seal()
        manifest_path = packet.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text("utf-8"))
        manifest["accepted_count"] = 3
        manifest_path.write_bytes(_canonical(manifest))
        with self.assertRaises(ValidationError):
            load_rewrite_packet(packet.root)

    def test_loader_recomputes_accepted_count_from_state_counts(self):
        packet = self._seal()
        manifest_path = packet.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text("utf-8"))
        manifest["decision_state_counts"]["confirm-candidate"] = 0
        manifest["decision_state_counts"]["keep-unresolved"] = 2
        core = dict(manifest)
        core.pop("packet_sha256")
        manifest["packet_sha256"] = hashlib.sha256(
            b"proposal-resolution-rewrite-packet-v1\n" + _canonical(core)
        ).hexdigest()
        manifest_path.write_bytes(_canonical(manifest))

        with self.assertRaises(ValidationError):
            load_rewrite_packet(packet.root)

        packet = self._seal(output=self.base / "packet-extra")
        (packet.root / "unexpected.txt").write_text("extra", encoding="utf-8")
        with self.assertRaises(ValidationError):
            load_rewrite_packet(packet.root)

    def test_binding_rejects_report_decision_or_code_identity_drift(self):
        packet = self._seal()
        wrong_identity = CodeIdentity(
            {"kind": "fixture", "revision": "proposal-resolution-fixture-v2"}
        )
        wrong_report = replace(self.report, report_sha256="0" * 64)
        wrong_decisions = replace(self.decisions, decisions_sha256="0" * 64)

        for report, decisions, identity in (
            (wrong_report, self.decisions, self.identity),
            (self.report, wrong_decisions, self.identity),
            (self.report, self.decisions, wrong_identity),
        ):
            with self.subTest(report=report.report_sha256, identity=identity.document):
                with self.assertRaises(ValidationError):
                    bind_rewrite_packet(packet, report, decisions, identity)


if __name__ == "__main__":
    unittest.main()
