"""Packaged fixture smoke using only caller-independent temporary roots."""

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest import mock

import obsidian_agent_memory.maintenance as maintenance_module
import obsidian_agent_memory.migration as migration_module
from obsidian_agent_memory import (
    AuthorizationGate,
    ConflictError,
    MigrationActionKind,
    MigrationBundle,
    OperationScope,
    PromotionCandidate,
    RecordCandidate,
    RecordEnvelope,
    TransactionContext,
    ValidationError,
    CodeIdentity,
    CodeIdentityProof,
    MigrationReviewProposal,
    ProposalArtifact,
    ProposalFamily,
    ProposalReviewArtifact,
    ProposalReviewContext,
    TransactionConflictProposal,
    apply_migration,
    audit_vault,
    build_cleanup_plan,
    build_global_focus,
    build_project_focus,
    build_project_views,
    build_root_views,
    bind_proposal_review,
    build_proposal_review,
    commit_record,
    compute_body_sha256,
    doctor_memory_root,
    initialize_memory_root,
    load_catalog,
    load_migration_bundle,
    load_proposal_review,
    normalize_body,
    observe_runtime_identity,
    parse_proposal_artifact,
    plan_v1_to_v2,
    preserve_promotion_candidate,
    publish_projection,
    read_accepted_record,
    resolve_binding,
    search_accepted_records,
    select_read_adapter,
    update_focus,
    validate_cleanup_source,
    verify_migration,
)

from .doctor import run_doctor
from .lifecycle import (
    apply_install,
    apply_uninstall,
    load_lifecycle_plan,
    plan_install,
    plan_uninstall,
    write_lifecycle_plan,
)
from .models import SmokeReport
from .release import build_release, verified_release_source, verify_release
from .roots import resolve_skill_roots


SMOKE_STEPS = (
    "release-built",
    "release-verified",
    "pack-installed",
    "installed-tools-verified",
    "doctor-headless",
    "memory-routed",
    "memory-initialized",
    "summary-and-add-accepted",
    "conflict-proposed",
    "accepted-record-catalog-verified",
    "promotion-candidate-preserved",
    "projection-cas-verified",
    "filesystem-query-accepted-only",
    "migration-planned",
    "migration-applied-with-archives",
    "migration-verified",
    "maintenance-planned",
    "installed-resolution-verified",
    "pack-uninstalled",
    "unrelated-sentinel-preserved",
)

_MIGRATE_VERBS = ("detect", "plan", "apply", "verify", "rollback")
_MAINTAIN_VERBS = (
    "audit", "plan", "recover-root-guard", "review-proposals",
    "plan-proposal-resolution", "apply-proposal-resolution",
    "verify-proposal-resolution", "recover-proposal-resolution",
)
_TOKEN = re.compile(r"\{\{[^{}]+\}\}")


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _tree_bytes(root):
    selected = Path(root)
    if not selected.exists():
        return ()
    return tuple(
        (path.relative_to(selected).as_posix(), path.read_bytes())
        for path in sorted(selected.rglob("*"))
        if path.is_file()
    )


def _canonical_json(path, value):
    Path(path).write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _portable_relative(value):
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return (
        isinstance(value, str)
        and bool(value)
        and not posix.is_absolute()
        and not windows.is_absolute()
        and "\\" not in value
        and posix.as_posix() == value
        and all(part not in ("", ".", "..") for part in posix.parts)
    )


def _review_lifecycle_plan(plan, path):
    written = write_lifecycle_plan(plan, path)
    digest = _sha256(written)
    return load_lifecycle_plan(written), digest


def _render_template(path, replacements):
    text = Path(path).read_text(encoding="utf-8")

    def substitute(match):
        key = match.group(0)[2:-2]
        return replacements.get(key, "fixed smoke text")

    rendered = _TOKEN.sub(substitute, text)
    _require("{{" not in rendered, "template contains an unrendered token")
    return normalize_body(rendered)


def _candidate(memory_id, record_type, revision, supersedes, body):
    if record_type not in ("session", "decision"):
        raise ValueError("smoke candidate type is not allowlisted")
    normalized = normalize_body(body)
    envelope = RecordEnvelope(
        memory_id=memory_id,
        record_type=record_type,
        schema_version=2,
        owner_scope="project.demo." + record_type,
        project="demo",
        revision=revision,
        supersedes=supersedes,
        created_at="2026-08-30T04:00:00Z",
        observed_at="2026-08-30T04:00:00Z",
        source="fixture-smoke",
        source_revision="fixture-source-1",
        body_sha256=compute_body_sha256(normalized),
    )
    return RecordCandidate(envelope=envelope, body=normalized)


def _context(transaction_id, occurred_at="2026-08-30T04:00:00Z"):
    return TransactionContext(transaction_id, "fixture-agent", occurred_at)


def _help_verbs(entrypoint, expected):
    completed = subprocess.run(
        (sys.executable, "-B", str(entrypoint), "--help"),
        check=True,
        capture_output=True,
        text=True,
    )
    match = re.search(r"\{([^{}]+)\}", completed.stdout)
    _require(match is not None, "installed help omitted its command set")
    actual = tuple(match.group(1).split(","))
    _require(actual == expected, "installed help command set changed")
    return completed.stdout


def _verify_installed_tools(source_root, installed_umbrella):
    installed_migrate = installed_umbrella / "scripts" / "vault_migrate.py"
    installed_maintain = installed_umbrella / "scripts" / "vault_maintain.py"
    for path in (installed_migrate, installed_maintain):
        _require(path.is_file(), "installed wrapper is missing")

    migrate_help = _help_verbs(installed_migrate, _MIGRATE_VERBS)
    maintain_help = _help_verbs(installed_maintain, _MAINTAIN_VERBS)
    _require("cleanup apply" not in migrate_help.casefold(), "migration help exposes cleanup apply")
    _require("cleanup execute" not in migrate_help.casefold(), "migration help exposes cleanup execute")
    _require("apply" not in _MAINTAIN_VERBS, "maintenance help exposes cleanup apply")
    _require("execute" not in _MAINTAIN_VERBS, "maintenance help exposes cleanup execute")

    pairs = (
        (
            installed_migrate,
            Path(source_root) / "tools" / "vault_migrate.py",
            "from obsidian_agent_memory.cli_migrate import main",
        ),
        (
            installed_maintain,
            Path(source_root) / "tools" / "vault_maintain.py",
            "from obsidian_agent_memory.cli_maintain import main",
        ),
    )
    for installed, wrapper, marker in pairs:
        _require(marker in installed.read_text("utf-8"), "installed wrapper module changed")
        _require(marker in wrapper.read_text("utf-8"), "root wrapper module changed")
    return installed_migrate, installed_maintain


def _record_projection_flow(temporary_root, installed_umbrella):
    memory_root = temporary_root / "memory"
    binding = resolve_binding(memory_root, "demo", {}, None, temporary_root)
    _require(binding.memory_root == memory_root, "explicit memory root was not preserved")
    _require(binding.project_id == "demo", "explicit project was not preserved")

    created = initialize_memory_root(memory_root, "demo", _context("memory-init-001"))
    relatives = tuple(path.relative_to(memory_root).as_posix() for path in created)
    for required in ("AGENTS.md", "README.md"):
        _require(required in relatives, "initial root output is missing " + required)
        raw = (memory_root / required).read_bytes()
        _require(bool(raw), required + " is empty")
        _require(raw.decode("utf-8").encode("utf-8") == raw, required + " is not UTF-8")
        _require(raw.endswith(b"\n") and not raw.endswith(b"\n\n"), required + " final newline changed")

    templates = installed_umbrella / "templates"
    session_body = _render_template(
        templates / "session-record.md",
        {
            "topic": "Packaged fixture smoke",
            "session_status": "completed",
            "primary_story_id": "none",
            "related_story_id_lines": "related_story_id: none",
            "user_goal": "Prove the installed pack in temporary roots.",
            "work_done": "Committed one session summary.",
        },
    )
    decision_body = _render_template(
        templates / "decision-record.md",
        {
            "title": "Cache policy",
            "context": "The fixture needs a stable cache policy.",
            "decision": "Rebuild the cache after its source revision changes.",
        },
    )
    competing_body = _render_template(
        templates / "decision-record.md",
        {
            "title": "Competing cache policy",
            "context": "This losing revision used stale expectations.",
            "decision": "Keep stale cache bytes.",
        },
    )

    session = _candidate("session-demo", "session", 1, None, session_body)
    decision_one = _candidate("decision-demo", "decision", 1, None, decision_body)
    decision_two = _candidate(
        "decision-demo", "decision", 2, "decision-demo@1", decision_body
    )
    competing = _candidate(
        "decision-demo", "decision", 2, "decision-demo@1", competing_body
    )
    _require(session.envelope.owner_scope == "project.demo.session", "session owner changed")
    for selected in (decision_one, decision_two, competing):
        _require(selected.envelope.owner_scope == "project.demo.decision", "decision owner changed")

    summary = commit_record(memory_root, session, 0, None, _context("record-session-001"))
    first = commit_record(memory_root, decision_one, 1, None, _context("record-decision-001"))
    accepted = commit_record(memory_root, decision_two, 2, 1, _context("record-decision-002"))
    accepted_bytes = accepted.record_path.read_bytes()
    losing = commit_record(memory_root, competing, 2, 1, _context("record-decision-losing"))
    _require(
        (summary.status, first.status, accepted.status) == ("accepted", "accepted", "accepted"),
        "expected records were not accepted",
    )
    _require(losing.status == "proposed", "stale decision was not proposed")
    _require(losing.proposal_path is not None and losing.proposal_path.is_file(), "proposal was not preserved")
    _require(bool(losing.conflict_code), "proposal conflict code is missing")
    _require(accepted.record_path.read_bytes() == accepted_bytes, "accepted record was overwritten")

    focus_context = _context("focus-smoke-001")
    focus = update_focus(
        memory_root,
        "demo",
        0,
        ("session-demo", "decision-demo"),
        "2026-08-30T04:00:00Z",
        focus_context,
    )
    _require(focus.status == "accepted", "initial focus was not accepted")

    catalog = load_catalog(memory_root)
    _require(catalog.revision == 3, "catalog revision changed")
    _require(
        tuple((entry.memory_id, entry.revision) for entry in catalog.entries)
        == (("decision-demo", 2), ("session-demo", 1)),
        "accepted catalog selection changed",
    )
    accepted_record = read_accepted_record(memory_root, "decision-demo")
    _require(accepted_record.envelope.revision == 2, "accepted decision revision changed")
    _require(accepted_record.catalog_revision == 3, "accepted catalog revision changed")
    _require(competing.body != accepted_record.body, "losing decision was selected")

    promotion_path = preserve_promotion_candidate(
        memory_root,
        PromotionCandidate(
            candidate_id="promotion-demo-cache-policy",
            source_record_ids=("decision-demo",),
            suggested_target="knowledge-base/decisions/cache-policy",
            rationale="The accepted cache policy is reusable across projects.",
        ),
        _context("promotion-smoke-001", "2026-08-30T04:02:00Z"),
    )
    _require(
        promotion_path.relative_to(memory_root).as_posix()
        == ".agent-memory/state/proposals/promotion-demo-cache-policy.json",
        "promotion path changed",
    )
    _require(not (temporary_root / "knowledge-base").exists(), "Knowledge Base was resolved")

    root_first = build_root_views(memory_root, "smoke-2.0.0")
    project_first_set = build_project_views(memory_root, "demo", "smoke-2.0.0")
    _require(
        tuple(document.relative_path for document in root_first)
        == (
            "_index/current-focus.md",
            "_index/home.md",
            "_index/memory-map.md",
            "_index/stale-or-uncertain.md",
        ),
        "root projection inventory changed",
    )
    _require(
        tuple(document.relative_path for document in project_first_set)
        == ("projects/demo/current-focus.md", "projects/demo/overview.md"),
        "project projection inventory changed",
    )
    initial_documents = root_first + project_first_set
    for index, document in enumerate(initial_documents):
        publish_projection(
            memory_root,
            document,
            _context("projection-smoke-initial-%02d" % index, "2026-08-30T04:02:00Z"),
        )

    project_first = next(
        document
        for document in project_first_set
        if document.relative_path == "projects/demo/current-focus.md"
    )
    global_first = next(
        document
        for document in root_first
        if document.relative_path == "_index/current-focus.md"
    )
    _require(project_first.expected_target_sha256 is None, "fresh project projection expected bytes")
    _require(global_first.expected_target_sha256 is None, "fresh global projection expected bytes")
    project_path = memory_root / project_first.relative_path
    global_path = memory_root / global_first.relative_path

    project_stale = build_project_focus(memory_root, "demo", "smoke-2.0.0")
    global_stale = build_global_focus(memory_root, "smoke-2.0.0")
    _require(project_first.content == project_stale.content, "project projection is nondeterministic")
    _require(global_first.content == global_stale.content, "global projection is nondeterministic")
    _require(project_stale.expected_target_sha256 is not None, "project CAS digest is missing")
    _require(global_stale.expected_target_sha256 is not None, "global CAS digest is missing")

    forbidden = replace(project_stale, relative_path="_records/forbidden.md")
    try:
        publish_projection(
            memory_root,
            forbidden,
            _context("projection-smoke-forbidden-01", "2026-08-30T04:02:30Z"),
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("forbidden projection target was accepted")
    _require(not (memory_root / "_records" / "forbidden.md").exists(), "forbidden projection was written")

    second_focus = update_focus(
        memory_root,
        "demo",
        1,
        ("session-demo", "decision-demo"),
        "2026-08-30T04:03:00Z",
        _context("focus-smoke-002", "2026-08-30T04:03:00Z"),
    )
    _require(second_focus.status == "accepted", "second focus was not accepted")
    project_before = project_path.read_bytes()
    global_before = global_path.read_bytes()
    for stale, transaction_id, occurred_at in (
        (project_stale, "projection-smoke-project-stale-01", "2026-08-30T04:04:00Z"),
        (global_stale, "projection-smoke-global-stale-01", "2026-08-30T04:04:01Z"),
    ):
        try:
            publish_projection(memory_root, stale, _context(transaction_id, occurred_at))
        except ConflictError:
            pass
        else:
            raise AssertionError("stale projection won its CAS race")
    _require(project_before == project_path.read_bytes(), "project projection changed after CAS loss")
    _require(global_before == global_path.read_bytes(), "global projection changed after CAS loss")

    final_documents = build_root_views(memory_root, "smoke-2.0.0") + build_project_views(
        memory_root, "demo", "smoke-2.0.0"
    )
    for index, document in enumerate(final_documents):
        publish_projection(
            memory_root,
            document,
            _context("projection-smoke-final-%02d" % index, "2026-08-30T04:05:00Z"),
        )
    project_after = project_path.read_bytes()
    global_after = global_path.read_bytes()
    _require(project_before != project_after, "project projection did not advance")
    _require(global_before != global_after, "global projection did not advance")
    _require(
        project_stale.source_revision
        != build_project_focus(memory_root, "demo", "smoke-2.0.0").source_revision,
        "project projection source revision did not advance",
    )
    _require(project_after == project_path.read_bytes(), "project projection bytes are unstable")
    _require(global_after == global_path.read_bytes(), "global projection bytes are unstable")
    _require(doctor_memory_root(memory_root) == (), "memory root is not healthy")

    for index in range(7):
        noise = memory_root / "_sources" / ("query-noise-%02d.md" % index)
        noise.parent.mkdir(parents=True, exist_ok=True)
        noise.write_text("cache policy losing generated orphan\n", encoding="utf-8")

    def unexpected_runner(command, timeout):
        del command, timeout
        raise AssertionError("filesystem fallback called the command runner")

    adapter_selection = select_read_adapter(
        binding,
        unexpected_runner,
        temporary_root / "missing-obsidian-cli",
    )
    _require(adapter_selection.mode == "filesystem", "filesystem fallback was not selected")

    class AcceptedOnlyAdapter:
        def read(self, relative_path):
            return adapter_selection.adapter.read(relative_path)

        def search(self, query, limit=20):
            del query, limit
            raise AssertionError("accepted-record search used raw adapter search")

        def files(self, prefix, limit=200):
            return adapter_selection.adapter.files(prefix, limit)

    matches = search_accepted_records(
        memory_root,
        AcceptedOnlyAdapter(),
        "cache policy",
        limit=5,
    )
    _require(len(matches) == 1, "accepted search returned losing or orphan bytes")
    _require(matches[0].envelope.memory_id == "decision-demo", "accepted search identity changed")
    _require(matches[0].envelope.revision == 2, "accepted search revision changed")
    _require(matches[0].catalog_revision == 3, "accepted search catalog revision changed")
    _require(matches[0].body == accepted_record.body, "accepted search body changed")
    return memory_root


def _tampered_bundle_refusal(fixture_root, bundle, temporary_root):
    original_root = _tree_bytes(fixture_root)
    for name in ("owner", "snapshot"):
        copied = temporary_root / ("tampered-" + name)
        shutil.copytree(bundle.bundle_dir, copied)
        if name == "owner":
            plan_path = copied / "plan.json"
            document = json.loads(plan_path.read_text("utf-8"))
            action = next(item for item in document["actions"] if item["kind"] == "record")
            action["owner_scope"] = "agent.runbook"
            _canonical_json(plan_path, document)
        else:
            snapshot_path = next((copied / "snapshot" / "files").rglob("*.md"))
            snapshot_path.write_bytes(snapshot_path.read_bytes() + b"tampered\n")
        untrusted = MigrationBundle(
            copied,
            bundle.detection,
            bundle.snapshot,
            bundle.plan,
            bundle.bundle_sha256,
        )
        try:
            apply_migration(
                fixture_root,
                untrusted,
                bundle.bundle_sha256,
                _context("smoke-migration-apply", "2026-08-30T04:11:00Z"),
                AuthorizationGate(OperationScope.FIXTURE, None),
            )
        except ValidationError:
            pass
        else:
            raise AssertionError("tampered migration bundle was accepted")
        _require(_tree_bytes(fixture_root) == original_root, "tampered bundle changed fixture bytes")
        _require(not (fixture_root / ".agent-memory").exists(), "tampered bundle created transaction state")


def _migration_and_maintenance_flow(temporary_root, source_root, installed_migrate, installed_maintain):
    fixture_root = temporary_root / "v1-minimal"
    shutil.copytree(Path(source_root) / "tests" / "fixtures" / "vaults" / "v1-minimal", fixture_root)
    work_dir = temporary_root / "migration-work"
    _require(work_dir != fixture_root and fixture_root not in work_dir.parents, "migration work overlaps fixture")

    fixture_gate = AuthorizationGate(OperationScope.FIXTURE, None)
    detect = subprocess.run(
        (
            sys.executable,
            "-B",
            str(installed_migrate),
            "detect",
            "--root",
            str(fixture_root),
            "--scope",
            "fixture",
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    _require('"generation":"v1"' in detect.stdout, "installed migration detect changed")

    plan_context = _context("smoke-migration-plan", "2026-08-30T04:10:00Z")
    apply_context = _context("smoke-migration-apply", "2026-08-30T04:11:00Z")
    bundle = plan_v1_to_v2(fixture_root, work_dir, plan_context, fixture_gate)
    loaded = load_migration_bundle(bundle.bundle_dir)
    _require(loaded.bundle_sha256 == bundle.bundle_sha256, "fresh strict bundle digest changed")
    decision = next(
        action
        for action in bundle.plan.actions
        if action.source_path == "projects/demo/decisions/cache-policy.md"
    )
    _require(decision.kind is MigrationActionKind.RECORD, "legacy decision is not a record action")
    _require(decision.record_type == "decision", "legacy decision type changed")
    _require(decision.owner_scope == "project.demo.decision", "legacy decision owner changed")
    _require(decision.unresolved_classification is None, "legacy decision became unresolved")
    _require(
        decision.projection_effects
        == (
            "_index/current-focus.md",
            "_index/home.md",
            "_index/memory-map.md",
            "_index/stale-or-uncertain.md",
            "projects/demo/current-focus.md",
            "projects/demo/overview.md",
        ),
        "legacy decision projection effects changed",
    )
    for action in bundle.plan.actions:
        _require(
            action.projection_effects == tuple(sorted(set(action.projection_effects))),
            "migration projection effects are not canonical",
        )
        if action.kind in (
            MigrationActionKind.FOCUS_PROPOSAL,
            MigrationActionKind.EMBEDDED_KNOWLEDGE_REVIEW,
            MigrationActionKind.UNRESOLVED_PROPOSAL,
        ):
            _require(action.unresolved_classification is not None, "unresolved action lacks its enum")

    _tampered_bundle_refusal(fixture_root, bundle, temporary_root)

    original_initialize = migration_module._transactions.initialize_memory_root
    original_commit = migration_module._transactions.commit_record
    original_focus = migration_module._transactions.update_focus
    with mock.patch.object(
        migration_module._transactions,
        "initialize_memory_root",
        wraps=original_initialize,
    ) as initialize_calls, mock.patch.object(
        migration_module._transactions,
        "commit_record",
        wraps=original_commit,
    ) as commit_calls, mock.patch.object(
        migration_module._transactions,
        "update_focus",
        wraps=original_focus,
    ) as focus_calls:
        result = apply_migration(
            fixture_root,
            bundle,
            bundle.bundle_sha256,
            apply_context,
            fixture_gate,
        )

    child_contexts = []
    for recorded in initialize_calls.call_args_list + commit_calls.call_args_list + focus_calls.call_args_list:
        values = tuple(recorded.args) + tuple(recorded.kwargs.values())
        child_contexts.extend(value for value in values if isinstance(value, TransactionContext))
    child_ids = tuple(context.transaction_id for context in child_contexts)
    _require(bool(child_ids), "migration did not pass child transaction contexts")
    _require(all(value.startswith("migration-child-") for value in child_ids), "migration child ID prefix changed")
    _require(len(child_ids) == len(set(child_ids)), "migration child IDs are not unique")
    _require(apply_context.transaction_id not in child_ids, "parent context was reused as a child")

    _require(result.status == "applied", "fixture migration was not applied")
    _require(result.reviewed_bundle_sha256 == bundle.bundle_sha256, "result lost reviewed digest")
    _require(result.plan_authorization_ref is None, "fixture plan invented authorization")
    _require(result.apply_authorization_ref is None, "fixture apply invented authorization")
    _require(result.rollback_authorization_ref is None, "fixture rollback invented authorization")
    _require(result.archived_paths == tuple(sorted(set(result.archived_paths))), "archives are not canonical")
    _require(bool(result.archived_paths), "migration did not archive legacy paths")
    _require(all(_portable_relative(path) for path in result.archived_paths), "archive path is not relative")

    journal_path = fixture_root / ".agent-memory" / "transactions" / apply_context.transaction_id / "journal.json"
    journal = json.loads(journal_path.read_text("utf-8"))
    _require(journal["reviewed_bundle_sha256"] == bundle.bundle_sha256, "journal lost reviewed digest")
    _require(journal["result"]["reviewed_bundle_sha256"] == bundle.bundle_sha256, "journal result lost digest")
    for field in ("plan_authorization_ref", "apply_authorization_ref", "rollback_authorization_ref"):
        _require(journal[field] is None, "fixture journal invented authorization")
        _require(journal["result"][field] is None, "fixture result invented authorization")

    rollback_manifest = journal_path.parent / "rollback" / "manifest.json"
    _require(rollback_manifest.is_file(), "later-process rollback manifest is missing")
    rollback_document = json.loads(rollback_manifest.read_text("utf-8"))
    combined_evidence = journal_path.read_text("utf-8") + rollback_manifest.read_text("utf-8")
    _require(str(work_dir) not in combined_evidence, "rollback evidence depends on planning work directory")
    _require(bool(rollback_document), "rollback manifest is empty")

    verification_one = verify_migration(fixture_root, bundle, fixture_gate)
    verification_two = verify_migration(fixture_root, bundle, fixture_gate)
    _require(verification_one == verification_two, "migration verification is nondeterministic")
    _require(verification_one.valid, "migration verification failed")
    _require(verification_one.bundle_sha256 == bundle.bundle_sha256, "verification lost reviewed digest")

    audit = audit_vault(fixture_root, fixture_gate)
    cleanup_plan = build_cleanup_plan(
        fixture_root,
        audit,
        _context("smoke-cleanup-plan", "2026-08-30T04:12:00Z"),
        fixture_gate,
    )
    validated_audit = validate_cleanup_source(fixture_root, cleanup_plan, fixture_gate)
    _require(validated_audit.source_revision == audit.source_revision, "cleanup source validation changed")
    _require(not hasattr(maintenance_module, "apply_cleanup"), "cleanup executor was imported")
    _require(not hasattr(maintenance_module, "execute_cleanup"), "cleanup executor was imported")
    for action in cleanup_plan.actions + cleanup_plan.blocked_actions:
        _require(all(_portable_relative(path) for path in action.source_paths), "cleanup path is not relative")

    maintenance_root = temporary_root / "maintenance-output"
    audit_path = maintenance_root / "audit.json"
    cleanup_plan_path = maintenance_root / "cleanup-plan.json"
    subprocess.run(
        (
            sys.executable,
            "-B",
            str(installed_maintain),
            "audit",
            "--root",
            str(fixture_root),
            "--output",
            str(audit_path),
            "--scope",
            "fixture",
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        (
            sys.executable,
            "-B",
            str(installed_maintain),
            "plan",
            "--root",
            str(fixture_root),
            "--audit",
            str(audit_path),
            "--output",
            str(cleanup_plan_path),
            "--scope",
            "fixture",
            "--transaction-id",
            "smoke-cleanup-plan",
            "--actor",
            "fixture-agent",
            "--occurred-at",
            "2026-08-30T04:12:00Z",
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    for path in (audit_path, cleanup_plan_path):
        _require(path.resolve().is_relative_to(maintenance_root.resolve()), "maintenance output escaped")
        _require(not path.resolve().is_relative_to(fixture_root.resolve()), "maintenance output entered fixture")
    saved_audit = json.loads(audit_path.read_text("utf-8"))
    saved_plan = json.loads(cleanup_plan_path.read_text("utf-8"))
    _require(saved_audit["source_revision"] == audit.source_revision, "CLI audit source changed")
    _require(saved_plan["source_revision"] == cleanup_plan.source_revision, "CLI plan source changed")
    for action in saved_plan["actions"] + saved_plan["blocked_actions"]:
        _require(all(_portable_relative(path) for path in action["source_paths"]), "CLI cleanup path is not relative")

    rejection_commands = (
        (
            "audit",
            "--root",
            str(fixture_root),
            "--output",
            str(fixture_root / "forbidden-audit.json"),
            "--scope",
            "fixture",
        ),
        (
            "plan",
            "--root",
            str(fixture_root),
            "--audit",
            str(audit_path),
            "--output",
            str(fixture_root / "forbidden-plan.json"),
            "--scope",
            "fixture",
            "--transaction-id",
            "smoke-rejected-output",
            "--actor",
            "fixture-agent",
            "--occurred-at",
            "2026-08-30T04:12:00Z",
        ),
        (
            "plan",
            "--root",
            str(fixture_root),
            "--audit",
            str(fixture_root / "forbidden-audit-input.json"),
            "--output",
            str(maintenance_root / "forbidden-plan.json"),
            "--scope",
            "fixture",
            "--transaction-id",
            "smoke-rejected-input",
            "--actor",
            "fixture-agent",
            "--occurred-at",
            "2026-08-30T04:12:00Z",
        ),
    )
    for arguments in rejection_commands:
        completed = subprocess.run(
            (sys.executable, "-B", str(installed_maintain)) + arguments,
            capture_output=True,
            text=True,
        )
        _require(completed.returncode != 0, "maintenance accepted an in-root artifact")
    _require(not (fixture_root / "forbidden-audit.json").exists(), "rejected audit was written")
    _require(not (fixture_root / "forbidden-plan.json").exists(), "rejected plan was written")
    return fixture_root


def run_fixture_smoke(repo_root):
    """Run the packaged fixture tracer without accepting any mutable root."""
    source_repository = Path(repo_root).resolve(strict=True)
    _require(source_repository.is_dir(), "repository root is not a directory")

    with tempfile.TemporaryDirectory(prefix="agent-memory-pack-smoke-") as temporary:
        temporary_root = Path(temporary).resolve(strict=True)
        artifacts = build_release(source_repository, temporary_root / "release")
        checked = verify_release(
            artifacts.archive_path,
            artifacts.checksum_path,
            artifacts.manifest_path,
        )
        _require(checked == artifacts, "release verification changed artifact identity")

        with verified_release_source(
            artifacts.archive_path,
            artifacts.checksum_path,
            artifacts.manifest_path,
        ) as verified:
            selection = resolve_skill_roots(
                temporary_root / "skills",
                None,
                {},
                temporary_root / "lifecycle-state",
            )
            install_plan = plan_install(
                artifacts.archive_path,
                selection,
                "smoke-pack-install-plan",
                "fixture-agent",
                "2026-08-30T03:50:00Z",
                checksum_path=artifacts.checksum_path,
                release_manifest_path=artifacts.manifest_path,
            )
            _require(install_plan.blockers == (), "fresh fixture install is blocked")
            reviewed_install, install_digest = _review_lifecycle_plan(
                install_plan,
                temporary_root / "reviewed-install.json",
            )
            install_result = apply_install(
                artifacts.archive_path,
                reviewed_install,
                install_digest,
                "fixture-agent",
                "2026-08-30T03:51:00Z",
                "fixture-pack-install-approval-001",
                checksum_path=artifacts.checksum_path,
                release_manifest_path=artifacts.manifest_path,
            )
            _require(install_result.status == "installed", "fixture pack was not installed")

            installed_umbrella = selection.skills_root / "obsidian-agent-memory"
            installed_migrate, installed_maintain = _verify_installed_tools(
                verified.source_root,
                installed_umbrella,
            )
            workspace = temporary_root / "workspace"
            workspace.mkdir()
            doctor = run_doctor(verified.source_root, selection, workspace)
            _require(doctor.ok, "headless packaged doctor failed")

            fixture = subprocess.run(
                (
                    sys.executable, "-I", "-B", "-c",
                    "import sys; sys.path[:0] = sys.argv[1:3]; "
                    "from agent_memory_pack.installed_fixture import main; "
                    "main(sys.argv[3:])",
                    str(installed_umbrella / "scripts"),
                    str(verified.source_root / "tools"),
                    str(temporary_root), str(verified.source_root),
                    str(installed_umbrella),
                ),
                capture_output=True, text=True, encoding="utf-8", timeout=600,
            )
            _require(
                fixture.returncode == 0,
                "installed fixture failed:\n" + fixture.stdout + fixture.stderr,
            )
            _require(
                fixture.stdout.strip() == "INSTALLED FIXTURE PASS resolution-tests=4",
                "installed fixture omitted its completion evidence",
            )

            sentinel = selection.skills_root / "unrelated-skill" / "sentinel.txt"
            sentinel.parent.mkdir()
            sentinel.write_text("preserve unrelated Skill\n", encoding="utf-8")
            uninstall_plan = plan_uninstall(
                selection,
                "smoke-pack-uninstall-plan",
                "fixture-agent",
                "2026-08-30T04:20:00Z",
            )
            _require(uninstall_plan.blockers == (), "managed fixture uninstall is blocked")
            _require(len(uninstall_plan.actions) == 10, "uninstall action count changed")
            _require(
                tuple(action.kind for action in uninstall_plan.actions)
                == ("archive-member",) * 9 + ("archive-installed-state",),
                "uninstall action sequence changed",
            )
            reviewed_uninstall, uninstall_digest = _review_lifecycle_plan(
                uninstall_plan,
                temporary_root / "reviewed-uninstall.json",
            )
            uninstall_result = apply_uninstall(
                reviewed_uninstall,
                uninstall_digest,
                "fixture-agent",
                "2026-08-30T04:21:00Z",
                "fixture-pack-uninstall-approval-001",
            )
            _require(uninstall_result.status == "uninstalled", "fixture pack was not uninstalled")
            _require(sentinel.read_text("utf-8") == "preserve unrelated Skill\n", "unrelated Skill changed")

        _require(not (source_repository / "dist").exists(), "smoke created repository dist output")
        return SmokeReport(ok=True, steps=SMOKE_STEPS)
