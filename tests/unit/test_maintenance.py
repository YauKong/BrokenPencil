import dataclasses
import hashlib
import json
import multiprocessing
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import (
    copy_vault_fixture,
    crash_during_recovery,
    crash_with_root_guard,
    context,
    tree_hashes,
)
from tests.unit.test_artifact_schemas import (
    _applied_golden_migration,
    _duplicate_apply_journal,
)

from obsidian_agent_memory import (
    AuthorizationGate,
    CleanupAction,
    CleanupDisposition,
    CleanupPlan,
    ConflictError,
    Finding,
    GuardRecoveryResult,
    LockBusyError,
    MaintenanceAudit,
    OperationScope,
    PlanInvalidatedError,
    RecordCandidate,
    RecordEnvelope,
    audit_vault,
    build_cleanup_plan,
    commit_record,
    compute_body_sha256,
    render_record,
    recover_stale_root_guard,
    root_write_guard,
    ValidationError,
    validate_cleanup_source,
)
import obsidian_agent_memory.maintenance as maintenance_module


FIXTURE_GATE = AuthorizationGate(OperationScope.FIXTURE, None)
PLAN_GATE = AuthorizationGate(OperationScope.FIXTURE, "cleanup-review-001")
RECOVERY_GATE = AuthorizationGate(OperationScope.FIXTURE, "incident-cleanup-001")
COUNT_KEYS = (
    "accepted-records",
    "findings-error",
    "findings-total",
    "findings-warning",
    "locks",
    "migration-artifacts",
    "projections",
    "proposals",
    "sources",
    "transactions",
)
EXPECTED_V2_CLEAN_COUNTS = (
    ("accepted-records", 1),
    ("findings-error", 0),
    ("findings-total", 0),
    ("findings-warning", 0),
    ("locks", 0),
    ("migration-artifacts", 0),
    ("projections", 7),
    ("proposals", 0),
    ("sources", 0),
    ("transactions", 3),
)


def _canonical_audit(audit):
    return json.dumps(
        dataclasses.asdict(audit),
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_dataclass(value):
    return json.dumps(
        dataclasses.asdict(value),
        sort_keys=True,
        separators=(",", ":"),
    )


def _hold_root_guard(root, ready, release):
    with root_write_guard(Path(root), context("cleanup-live-holder")):
        ready.set()
        release.wait(10)


def _tree_hashes_except(root, excluded):
    values = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except PermissionError:
            digest = "<leased>"
        values.append((relative, digest))
    return tuple(values)


def _write(root, relative, raw):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def _count(audit, key):
    return dict(audit.counts)[key]


def _codes(audit):
    return {finding.code for finding in audit.findings}


def _replace_story(root, memory_id, body, source="fixture-source", source_revision="fixture-source-r1"):
    observed_at = "2026-01-01T00:00:01Z"
    envelope = RecordEnvelope(
        memory_id=memory_id,
        record_type="story",
        schema_version=2,
        owner_scope="project.demo.story",
        project="demo",
        revision=1,
        supersedes=None,
        created_at=observed_at,
        observed_at=observed_at,
        source=source,
        source_revision=source_revision,
        body_sha256=compute_body_sha256(body),
    )
    relative = "_records/projects/demo/stories/{0}--r0001.md".format(memory_id)
    _write(root, relative, render_record(envelope, body).encode("utf-8"))
    catalog_path = root / ".agent-memory/state/catalog.json"
    catalog = json.loads(catalog_path.read_text("utf-8"))
    catalog["records"][memory_id] = {
        "memory_id": memory_id,
        "owner_scope": "project.demo.story",
        "project": "demo",
        "record_type": "story",
        "relative_path": relative,
        "revision": 1,
    }
    catalog_path.write_bytes(
        (json.dumps(catalog, sort_keys=True, indent=2) + "\n").encode("utf-8")
    )


def _add_canonical_proposal(root):
    body = "changed duplicate body\n"
    observed_at = "2026-01-01T00:00:01Z"
    envelope = RecordEnvelope(
        memory_id="story-demo-cache",
        record_type="story",
        schema_version=2,
        owner_scope="project.demo.story",
        project="demo",
        revision=1,
        supersedes=None,
        created_at=observed_at,
        observed_at=observed_at,
        source="fixture-source",
        source_revision="fixture-source-r1",
        body_sha256=compute_body_sha256(body),
    )
    outcome = commit_record(
        root,
        RecordCandidate(envelope, body),
        1,
        None,
        context("audit-proposal"),
    )
    if outcome.status != "proposed":
        raise AssertionError("fixture proposal was not preserved")
    transaction = root / ".agent-memory/transactions/audit-proposal.json"
    if transaction.exists():
        transaction.unlink()


class MaintenanceAuditTests(unittest.TestCase):
    def test_migration_review_proposal_written_by_apply_is_counted_as_canonical(self):
        root, _, result = _applied_golden_migration(self)

        audit = audit_vault(root, FIXTURE_GATE)

        self.assertEqual(len(result.proposal_paths), dict(audit.counts)["proposals"])

    def test_unbound_migration_proposals_are_not_counted(self):
        applied_root, _, result = _applied_golden_migration(self)
        selected_path = result.proposal_paths[0]
        selected_raw = (applied_root / selected_path).read_bytes()

        with tempfile.TemporaryDirectory() as temporary:
            unbound_root = copy_vault_fixture("v2-clean", Path(temporary))
            _write(unbound_root, selected_path, selected_raw)
            unbound = audit_vault(unbound_root, FIXTURE_GATE)
            self.assertEqual(0, _count(unbound, "proposals"))
            self.assertIn("proposal-unbound", _codes(unbound))

        _duplicate_apply_journal(applied_root)
        duplicate = audit_vault(applied_root, FIXTURE_GATE)
        self.assertEqual(0, _count(duplicate, "proposals"))
        self.assertIn("proposal-unbound", _codes(duplicate))

        with tempfile.TemporaryDirectory() as temporary:
            malformed_root = copy_vault_fixture("v2-clean", Path(temporary))
            _write(malformed_root, selected_path, b"{}\n")
            malformed = audit_vault(malformed_root, FIXTURE_GATE)
            self.assertEqual(0, _count(malformed, "proposals"))
            self.assertIn("proposal-invalid", _codes(malformed))
            self.assertNotIn("proposal-unbound", _codes(malformed))

    def test_all_fixtures_are_deterministic_and_read_only(self):
        fixture_names = (
            "v1-minimal",
            "v1-duplicate-owners",
            "v1-focus-drift",
            "v1-embedded-knowledge",
            "v1-partially-migrated",
            "v2-clean",
        )
        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name), tempfile.TemporaryDirectory() as temporary:
                root = copy_vault_fixture(fixture_name, Path(temporary))
                before = tree_hashes(root)
                audit_one = audit_vault(root, FIXTURE_GATE)
                audit_two = audit_vault(root, FIXTURE_GATE)
                self.assertIsInstance(audit_one, MaintenanceAudit)
                self.assertEqual(audit_one, audit_two)
                self.assertEqual(_canonical_audit(audit_one), _canonical_audit(audit_two))
                self.assertEqual(before, tree_hashes(root))
                self.assertEqual(tuple(sorted(audit_one.counts)), audit_one.counts)
                self.assertEqual(
                    tuple(
                        sorted(
                            audit_one.findings,
                            key=lambda item: (item.severity, item.code, item.path, item.message),
                        )
                    ),
                    audit_one.findings,
                )
                self.assertEqual(COUNT_KEYS, tuple(key for key, _ in audit_one.counts))
                self.assertTrue(all(value >= 0 for _, value in audit_one.counts))
                counts = dict(audit_one.counts)
                self.assertEqual(
                    counts["findings-total"],
                    counts["findings-error"] + counts["findings-warning"],
                )

    def test_v2_clean_has_the_exact_zero_complete_count_tuple(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            self.assertEqual(EXPECTED_V2_CLEAN_COUNTS, audit_vault(root, FIXTURE_GATE).counts)

    def test_operation_gate_is_checked_before_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                maintenance_module,
                "_inventory_vault",
                side_effect=AssertionError("inventory ran before authorization"),
            ) as inventory:
                with self.assertRaisesRegex(ValidationError, "fixture marker"):
                    audit_vault(root, FIXTURE_GATE)
            inventory.assert_not_called()

    def test_every_operational_byte_changes_the_maintenance_revision(self):
        cases = (
            (
                ".agent-memory/transactions/audit-extra.json",
                b'{"operation":"audit","schema_version":2,"status":"in-progress","transaction_id":"audit-extra"}\n',
                "orphaned-migration-artifact",
            ),
            (
                ".agent-memory/transactions/migrations/orphan/rollback/source.bin",
                b"rollback-byte\n",
                "orphaned-migration-artifact",
            ),
            (
                ".agent-memory/state/locks/audit.lock",
                b"locked\n",
                "stale-lock-review",
            ),
            (
                ".agent-memory-root-write.lock",
                b"guard\n",
                "stale-lock-review",
            ),
            (
                ".agent-memory-root-write.anchor.candidate",
                b"candidate\n",
                "stale-lock-review",
            ),
            (
                ".agent-memory-root-write-recoveries/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/000-started.json",
                b"{}\n",
                "root-write-recovery-incomplete",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            before = audit_vault(root, FIXTURE_GATE)
            _add_canonical_proposal(root)
            after = audit_vault(root, FIXTURE_GATE)
            self.assertNotEqual(before.source_revision, after.source_revision)
            self.assertIn("unresolved-proposal", _codes(after))
        for relative, raw, expected_code in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = copy_vault_fixture("v2-clean", Path(temporary))
                before = audit_vault(root, FIXTURE_GATE)
                _write(root, relative, raw)
                after = audit_vault(root, FIXTURE_GATE)
                self.assertNotEqual(before.source_revision, after.source_revision)
                self.assertIn(expected_code, _codes(after))

    def test_category_counts_use_non_overlapping_operational_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            baseline = audit_vault(root, FIXTURE_GATE)
            _write(root, "_sources/projects/demo/source.txt", b"bounded source\n")
            _add_canonical_proposal(root)
            journal = (root / ".agent-memory/transactions/fixture-v2-focus.json").read_text("utf-8")
            journal = journal.replace("fixture-v2-focus", "audit-extra")
            _write(root, ".agent-memory/transactions/audit-extra.json", journal.encode("utf-8"))
            _write(root, ".agent-memory/state/locks/audit.lock", b"locked\n")
            _write(
                root,
                ".agent-memory/transactions/migrations/orphan/rollback/source.bin",
                b"rollback\n",
            )
            changed = audit_vault(root, FIXTURE_GATE)
            for key in ("sources", "proposals", "transactions", "locks", "migration-artifacts"):
                self.assertEqual(_count(baseline, key) + 1, _count(changed, key), key)

    def test_record_relationship_findings_are_provenance_and_revision_based(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            _replace_story(
                root,
                "story-other-owner",
                "# Other owner\n\nA distinct body with the same durable source identity.\n",
            )
            audit = audit_vault(root, FIXTURE_GATE)
            self.assertIn("duplicate-durable-owner", _codes(audit))
            finding = next(item for item in audit.findings if item.code == "duplicate-durable-owner")
            self.assertEqual("error", finding.severity)

        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v1-duplicate-owners", Path(temporary))
            finding = next(
                item
                for item in audit_vault(root, FIXTURE_GATE).findings
                if item.code == "duplicate-durable-owner"
            )
            self.assertEqual("warning", finding.severity)

        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            focus_path = root / ".agent-memory/state/focus/demo.json"
            focus = json.loads(focus_path.read_text("utf-8"))
            focus["record_ids"] = ["missing-revision"]
            focus_path.write_text(json.dumps(focus, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            self.assertIn("stale-current-record", _codes(audit_vault(root, FIXTURE_GATE)))

        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            _replace_story(root, "story-demo-cache", "# Links\n\n[[story-other]]\n")
            self.assertIn("fragmented-story", _codes(audit_vault(root, FIXTURE_GATE)))

    def test_legacy_content_findings_have_stable_codes(self):
        cases = (
            (
                "projects/demo/current-focus.md",
                b"# Current focus\n\n## History\n\n- old completed work\n",
                "current-focus-history",
            ),
            (
                "projects/demo/sessions/old.md",
                b"# Legacy session\n",
                "obsolete-schema-path",
            ),
            (
                "_sources/projects/demo/chat.txt",
                b"User: can you do this?\nAssistant: yes\n",
                "raw-chat-pattern",
            ),
            (
                "_sources/projects/demo/links.md",
                b"See [[definitely-missing-note]].\n",
                "broken-wikilink",
            ),
            (
                "knowledge/modeling/retopology.md",
                b"# Retopology\n\nDecision: keep this reusable technique.\n",
                "embedded-knowledge-decision",
            ),
        )
        for relative, raw, expected_code in cases:
            with self.subTest(code=expected_code), tempfile.TemporaryDirectory() as temporary:
                root = copy_vault_fixture("v2-clean", Path(temporary))
                _write(root, relative, raw)
                self.assertIn(expected_code, _codes(audit_vault(root, FIXTURE_GATE)))

    def test_proposal_migration_projection_lock_and_recovery_findings(self):
        cases = (
            (
                ".agent-memory/transactions/migrations/orphan/rollback/source.bin",
                b"rollback\n",
                "orphaned-migration-artifact",
            ),
            (
                "projects/demo/overview.md",
                b"manual projection bytes\n",
                "projection-drift",
            ),
            (
                ".agent-memory/state/locks/audit.lock",
                b"locked\n",
                "stale-lock-review",
            ),
            (
                ".agent-memory-root-write-recoveries/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/000-started.json",
                b"{}\n",
                "root-write-recovery-incomplete",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            _add_canonical_proposal(root)
            self.assertIn("unresolved-proposal", _codes(audit_vault(root, FIXTURE_GATE)))
        for relative, raw, expected_code in cases:
            with self.subTest(code=expected_code), tempfile.TemporaryDirectory() as temporary:
                root = copy_vault_fixture("v2-clean", Path(temporary))
                _write(root, relative, raw)
                finding = next(
                    item
                    for item in audit_vault(root, FIXTURE_GATE).findings
                    if item.code == expected_code
                )
                self.assertFalse(Path(finding.path.split(":", 1)[0]).is_absolute())

    def test_secret_finding_reports_only_relative_path_and_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            _write(
                root,
                "_sources/projects/demo/credential-sample.txt",
                b"header\napi_key = fictional-secret-value\nfooter\n",
            )
            audit = audit_vault(root, FIXTURE_GATE)
            finding = next(item for item in audit.findings if item.code == "secret-pattern")
            self.assertEqual(
                "_sources/projects/demo/credential-sample.txt:2",
                finding.path,
            )
            self.assertNotIn("fictional-secret-value", finding.message)
            self.assertNotIn("fictional-secret-value", repr(audit))
            self.assertNotIn("fictional-secret-value", _canonical_audit(audit))


class CleanupPlanTests(unittest.TestCase):
    def _fixed_audit(self, root):
        paths = {
            "duplicate-durable-owner": "AGENTS.md",
            "stale-current-record": "AGENTS.md",
            "fragmented-story": "AGENTS.md",
            "current-focus-history": "projects/demo/current-focus.md",
            "obsolete-schema-path": "AGENTS.md",
            "raw-chat-pattern": "_sources/projects/demo/raw.txt",
            "broken-wikilink": "AGENTS.md",
            "unresolved-proposal": ".agent-memory/state/proposals/review.json",
            "secret-pattern": "_sources/projects/demo/raw.txt:1",
            "orphaned-migration-artifact": ".agent-memory/transactions/migration-review/rollback/source.bin",
            "projection-drift": "projects/demo/overview.md",
            "stale-lock-review": ".agent-memory/state/locks/stale.lock",
            "root-write-recovery-incomplete": ".agent-memory/state/locks/stale.lock",
            "embedded-knowledge-decision": "knowledge/modeling/topic.md",
        }
        _write(root, "_sources/projects/demo/raw.txt", b"reviewed raw provenance\n")
        _write(
            root,
            ".agent-memory/state/proposals/review.json",
            b'{"operation":"review","schema_version":2}\n',
        )
        _write(
            root,
            ".agent-memory/transactions/migration-review/rollback/source.bin",
            b"rollback evidence\n",
        )
        _write(root, ".agent-memory/state/locks/stale.lock", b"stale lock\n")
        _write(root, "knowledge/modeling/topic.md", b"# Topic\n")
        base = audit_vault(root, PLAN_GATE)
        findings = tuple(
            Finding(
                code=code,
                severity="error" if code in ("secret-pattern", "root-write-recovery-incomplete") else "warning",
                path=path,
                message="fixed cleanup finding for " + code,
            )
            for code, path in paths.items()
        )
        return dataclasses.replace(base, findings=findings), paths

    def test_maps_every_finding_to_deterministic_reviewed_actions(self):
        expected_dispositions = {
            "duplicate-durable-owner": CleanupDisposition.MERGE,
            "stale-current-record": CleanupDisposition.SUPERSEDE,
            "fragmented-story": CleanupDisposition.MERGE,
            "current-focus-history": CleanupDisposition.REGENERATE,
            "obsolete-schema-path": CleanupDisposition.ARCHIVE,
            "raw-chat-pattern": CleanupDisposition.REVIEW,
            "broken-wikilink": CleanupDisposition.REVIEW,
            "unresolved-proposal": CleanupDisposition.REVIEW,
            "secret-pattern": CleanupDisposition.REVIEW,
            "orphaned-migration-artifact": CleanupDisposition.REVIEW,
            "projection-drift": CleanupDisposition.REGENERATE,
            "stale-lock-review": CleanupDisposition.REVIEW,
            "root-write-recovery-incomplete": CleanupDisposition.REVIEW,
            "embedded-knowledge-decision": CleanupDisposition.REVIEW,
        }
        blocked_codes = {
            "raw-chat-pattern",
            "secret-pattern",
            "unresolved-proposal",
            "orphaned-migration-artifact",
            "stale-lock-review",
            "root-write-recovery-incomplete",
            "embedded-knowledge-decision",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            audit, paths = self._fixed_audit(root)
            first = build_cleanup_plan(root, audit, context("cleanup-plan"), PLAN_GATE)
            second = build_cleanup_plan(root, audit, context("cleanup-plan"), PLAN_GATE)

            self.assertIsInstance(first, CleanupPlan)
            self.assertEqual(first, second)
            self.assertEqual(_canonical_dataclass(first), _canonical_dataclass(second))
            self.assertEqual(audit.source_revision, first.source_revision)
            self.assertEqual("test-agent", first.actor)
            self.assertEqual("cleanup-review-001", first.authorization_ref)
            all_actions = first.actions + first.blocked_actions
            self.assertEqual(set(expected_dispositions), {item.finding_code for item in all_actions})
            self.assertEqual(blocked_codes, {item.finding_code for item in first.blocked_actions})
            self.assertTrue(all(isinstance(item, CleanupAction) for item in all_actions))
            self.assertTrue(all(item.requires_explicit_approval for item in all_actions))
            self.assertTrue(all(item.disposition is CleanupDisposition.REVIEW for item in first.blocked_actions))
            by_code = {item.finding_code: item for item in all_actions}
            for code, disposition in expected_dispositions.items():
                self.assertEqual(disposition, by_code[code].disposition, code)
                expected_path = paths[code].split(":", 1)[0]
                self.assertEqual((expected_path,), by_code[code].source_paths)
                self.assertEqual(
                    ((expected_path, hashlib.sha256((root / expected_path).read_bytes()).hexdigest()),),
                    by_code[code].expected_hashes,
                )
            self.assertEqual(
                tuple(
                    sorted(
                        first.actions,
                        key=lambda item: (
                            item.disposition.value,
                            item.finding_code,
                            item.source_paths,
                            item.action_id,
                        ),
                    )
                ),
                first.actions,
            )
            self.assertEqual(
                tuple(
                    sorted(
                        first.blocked_actions,
                        key=lambda item: (
                            item.disposition.value,
                            item.finding_code,
                            item.source_paths,
                            item.action_id,
                        ),
                    )
                ),
                first.blocked_actions,
            )
            self.assertFalse(hasattr(maintenance_module, "apply_cleanup_plan"))
            self.assertFalse(hasattr(__import__("obsidian_agent_memory"), "apply_cleanup_plan"))

    def test_source_validation_is_read_only_and_gate_precedes_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            audit = audit_vault(root, PLAN_GATE)
            plan = build_cleanup_plan(root, audit, context("cleanup-source-plan"), PLAN_GATE)
            (root / "AGENTS.md").write_bytes((root / "AGENTS.md").read_bytes() + b"changed\n")
            changed = tree_hashes(root)
            with self.assertRaisesRegex(PlanInvalidatedError, "cleanup source revision changed"):
                validate_cleanup_source(root, plan, PLAN_GATE)
            self.assertEqual(changed, tree_hashes(root))

            blank_real = AuthorizationGate(OperationScope.REAL, " ")
            with mock.patch.object(
                maintenance_module,
                "audit_vault",
                side_effect=AssertionError("public audit entered before gate"),
            ) as public_audit:
                with self.assertRaisesRegex(ValidationError, "authorization reference"):
                    validate_cleanup_source(root, plan, blank_real)
            public_audit.assert_not_called()


class CleanupGuardRecoveryTests(unittest.TestCase):
    def _crashed_canonical(self, root, transaction_id):
        process = multiprocessing.Process(
            target=crash_with_root_guard,
            args=(str(root), transaction_id),
        )
        process.start()
        process.join(10)
        self.assertFalse(process.is_alive())
        self.assertEqual(23, process.exitcode)
        stale = root / ".agent-memory-root-write.lock"
        return stale.read_bytes(), hashlib.sha256(stale.read_bytes()).hexdigest()

    def _candidate(self, root, transaction_id, raw=b'{"actor":"crashed"'):
        token = hashlib.sha256(
            (str(root.resolve()) + "\0" + transaction_id).encode("utf-8")
        ).hexdigest()
        path = root / (".agent-memory-root-write.candidate-" + token)
        path.write_bytes(raw)
        return path, raw

    def _assert_result(self, root, result, target, recovery, kind, raw):
        self.assertIsInstance(result, GuardRecoveryResult)
        self.assertEqual("recovered", result.status)
        self.assertEqual(target, result.target_transaction_id)
        self.assertEqual(recovery, result.recovery_transaction_id)
        self.assertEqual(kind, result.recovered_kind)
        self.assertFalse(Path(result.evidence_path).is_absolute())
        self.assertEqual(raw, (root / result.evidence_path).read_bytes())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result.recovered_artifact_sha256)
        self.assertFalse((root / ".agent-memory-root-write.lock").exists())
        self.assertEqual([], list(root.glob(".agent-memory-root-write.candidate-*")))
        self.assertNotIn(
            "root-write-recovery-incomplete",
            _codes(audit_vault(root, FIXTURE_GATE)),
        )

    def test_recovers_canonical_and_partial_candidate_without_spending_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            canonical_root = copy_vault_fixture("v2-clean", Path(temporary) / "canonical")
            raw, expected_hash = self._crashed_canonical(canonical_root, "cleanup-dead")
            result = recover_stale_root_guard(
                canonical_root,
                "cleanup-dead",
                expected_hash,
                context("cleanup-recovery"),
                RECOVERY_GATE,
            )
            self._assert_result(
                canonical_root,
                result,
                "cleanup-dead",
                "cleanup-recovery",
                "canonical-lock",
                raw,
            )
            with root_write_guard(canonical_root, context("cleanup-later-writer")):
                pass

            candidate_root = copy_vault_fixture("v2-clean", Path(temporary) / "candidate")
            candidate, candidate_raw = self._candidate(candidate_root, "cleanup-partial")
            expected_candidate_hash = hashlib.sha256(candidate_raw).hexdigest()
            result = recover_stale_root_guard(
                candidate_root,
                "cleanup-partial",
                None,
                context("cleanup-candidate-recovery"),
                RECOVERY_GATE,
            )
            self.assertFalse(candidate.exists())
            self.assertEqual(expected_candidate_hash, result.recovered_artifact_sha256)
            self._assert_result(
                candidate_root,
                result,
                "cleanup-partial",
                "cleanup-candidate-recovery",
                "candidate-only",
                candidate_raw,
            )
            with root_write_guard(candidate_root, context("cleanup-candidate-later-writer")):
                pass

    def test_refuses_blank_wrong_reused_unknown_and_live_recovery_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            _, expected_hash = self._crashed_canonical(root, "cleanup-refuse")
            before = tree_hashes(root)
            with self.assertRaisesRegex(ValidationError, "authorization reference"):
                recover_stale_root_guard(
                    root,
                    "cleanup-refuse",
                    expected_hash,
                    context("cleanup-recovery"),
                    FIXTURE_GATE,
                )
            with self.assertRaises(ConflictError):
                recover_stale_root_guard(
                    root,
                    "cleanup-refuse",
                    "f" * 64,
                    context("cleanup-recovery"),
                    RECOVERY_GATE,
                )
            with self.assertRaisesRegex(ValidationError, "distinct"):
                recover_stale_root_guard(
                    root,
                    "cleanup-refuse",
                    expected_hash,
                    context("cleanup-refuse"),
                    RECOVERY_GATE,
                )
            self.assertEqual(before, tree_hashes(root))

        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            self._candidate(root, "cleanup-target")
            _write(root, ".agent-memory-root-write.candidate-" + "f" * 64, b"unknown\n")
            before = tree_hashes(root)
            with self.assertRaises(ConflictError):
                recover_stale_root_guard(
                    root,
                    "cleanup-target",
                    None,
                    context("cleanup-recovery"),
                    RECOVERY_GATE,
                )
            self.assertEqual(before, tree_hashes(root))

        with tempfile.TemporaryDirectory() as temporary:
            root = copy_vault_fixture("v2-clean", Path(temporary))
            ready = multiprocessing.Event()
            release = multiprocessing.Event()
            holder = multiprocessing.Process(
                target=_hold_root_guard,
                args=(str(root), ready, release),
            )
            holder.start()
            self.assertTrue(ready.wait(10))
            live = root / ".agent-memory-root-write.lock"
            before = _tree_hashes_except(root, {".agent-memory-root-write.lock"})
            try:
                with self.assertRaises(LockBusyError):
                    recover_stale_root_guard(
                        root,
                        "cleanup-live-holder",
                        "f" * 64,
                        context("cleanup-live-recovery"),
                        RECOVERY_GATE,
                    )
                self.assertTrue(live.exists())
                self.assertEqual(
                    before,
                    _tree_hashes_except(root, {".agent-memory-root-write.lock"}),
                )
            finally:
                release.set()
                holder.join(10)
            self.assertFalse(holder.is_alive())
            self.assertEqual(0, holder.exitcode)

    def test_replays_every_plan1_recovery_rotation_boundary(self):
        candidate_stages = (
            "evidence-published",
            "prepared-transition-published",
            "new-candidate-leased",
            "new-canonical-published",
            "published-transition-published",
            "before-removed-transition",
            "old-candidate-unlinked",
            "removed-transition-published",
        )
        canonical_stages = (
            "evidence-published",
            "prepared-transition-published",
            "new-candidate-leased",
            "old-canonical-unlinked",
            "new-canonical-published",
            "published-transition-published",
            "before-removed-transition",
            "old-candidate-unlinked",
            "removed-transition-published",
        )
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for index, stage in enumerate(candidate_stages):
                with self.subTest(kind="candidate", stage=stage):
                    root = copy_vault_fixture("v2-clean", parent / ("candidate-" + str(index)))
                    _, raw = self._candidate(root, "cleanup-partial", b"partial crash bytes")
                    process = multiprocessing.Process(
                        target=crash_during_recovery,
                        args=(
                            str(root),
                            "cleanup-partial",
                            None,
                            "cleanup-replay",
                            "incident-replay",
                            stage,
                        ),
                    )
                    process.start()
                    process.join(10)
                    self.assertEqual(31, process.exitcode)
                    result = recover_stale_root_guard(
                        root,
                        "cleanup-partial",
                        None,
                        context("cleanup-replay"),
                        AuthorizationGate(OperationScope.FIXTURE, "incident-replay"),
                    )
                    self._assert_result(
                        root,
                        result,
                        "cleanup-partial",
                        "cleanup-replay",
                        "candidate-only",
                        raw,
                    )

            for index, stage in enumerate(canonical_stages):
                with self.subTest(kind="canonical", stage=stage):
                    root = copy_vault_fixture("v2-clean", parent / ("canonical-" + str(index)))
                    raw, expected_hash = self._crashed_canonical(root, "cleanup-dead")
                    process = multiprocessing.Process(
                        target=crash_during_recovery,
                        args=(
                            str(root),
                            "cleanup-dead",
                            expected_hash,
                            "cleanup-replay-canonical",
                            "incident-canonical",
                            stage,
                        ),
                    )
                    process.start()
                    process.join(10)
                    self.assertEqual(31, process.exitcode)
                    result = recover_stale_root_guard(
                        root,
                        "cleanup-dead",
                        expected_hash,
                        context("cleanup-replay-canonical"),
                        AuthorizationGate(OperationScope.FIXTURE, "incident-canonical"),
                    )
                    self._assert_result(
                        root,
                        result,
                        "cleanup-dead",
                        "cleanup-replay-canonical",
                        "canonical-lock",
                        raw,
                    )


if __name__ == "__main__":
    unittest.main()
