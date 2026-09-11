import hashlib
from pathlib import Path
import re
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SKILLS_ROOT = REPO_ROOT / "skills"
PACKAGE_ROOT = (
    SKILLS_ROOT / "obsidian-agent-memory" / "scripts"
)
sys.path.insert(0, str(PACKAGE_ROOT))

from obsidian_agent_memory import PackManifest, validate_skill_tree


ACTIVE_MEMBERS = (
    "obsidian-agent-memory",
    "obsidian-agent-memory-init",
    "obsidian-agent-memory-route",
    "obsidian-agent-memory-collaboration",
    "obsidian-agent-memory-query",
    "obsidian-agent-memory-add",
    "obsidian-agent-memory-summary",
    "obsidian-agent-memory-maintain",
    "obsidian-agent-memory-upgrade",
)
REFERENCE_FILES = (
    "record-ownership.md",
    "configuration-and-path-discovery.md",
    "retrieval-adapters.md",
    "write-consistency.md",
    "projection-contract.md",
    "vault-schema-2.md",
    "v1-to-v2-migration.md",
    "proposal-review.md",
    "story-session-coordination.md",
    "validation-and-target-workstation.md",
)
TEMPLATE_FILES = (
    "session-record.md",
    "story-record.md",
    "decision-record.md",
    "preference-record.md",
    "runbook-record.md",
    "migration-record.md",
    "maintenance-record.md",
)
TEMPLATE_TOKENS = {
    "session-record.md": {
        "topic", "session_status", "primary_story_id", "related_story_id_lines",
        "user_goal", "outcome", "work_done", "decision_record_references",
        "commands_verified", "files_changed", "promotion_candidates", "follow_ups",
    },
    "story-record.md": {
        "title", "situation", "current_state", "turning_points", "failure_mode",
        "resolution", "open_questions", "related_decision_ids",
    },
    "decision-record.md": {
        "title", "context", "decision", "consequences", "evidence",
        "related_record_ids",
    },
    "preference-record.md": {
        "title", "preference", "decision_test", "evidence",
    },
    "runbook-record.md": {
        "title", "preconditions", "procedure", "verification",
        "failure_handling",
    },
    "migration-record.md": {
        "title", "source_snapshot", "reviewed_plan", "applied_changes",
        "verification", "unresolved_proposals",
    },
    "maintenance-record.md": {
        "title", "audit_scope", "findings", "reviewed_actions",
        "applied_transactions", "verification",
    },
}
WORD_LIMITS = {
    "obsidian-agent-memory": 650,
    "obsidian-agent-memory-init": 320,
    "obsidian-agent-memory-route": 320,
    "obsidian-agent-memory-collaboration": 500,
    "obsidian-agent-memory-query": 320,
    "obsidian-agent-memory-add": 320,
    "obsidian-agent-memory-summary": 320,
    "obsidian-agent-memory-maintain": 320,
    "obsidian-agent-memory-upgrade": 320,
}


def skill_text(member):
    return (SKILLS_ROOT / member / "SKILL.md").read_text(encoding="utf-8")


def body_word_count(text):
    parts = text.split("---", 2)
    body = parts[2] if len(parts) == 3 else text
    return len(re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]*", body))


def markdown_targets(text):
    return tuple(re.findall(r"\[[^\]]+\]\(([^)]+)\)", text))


def assert_member_contract(testcase, member, required_targets):
    path = SKILLS_ROOT / member / "SKILL.md"
    testcase.assertTrue(path.is_file(), str(path))
    text = skill_text(member)
    testcase.assertTrue(text.startswith("---\nname: {0}\n".format(member)))
    testcase.assertLessEqual(body_word_count(text), WORD_LIMITS[member])
    targets = markdown_targets(text)
    for target in required_targets:
        testcase.assertIn(target, targets)
        testcase.assertTrue((path.parent / target).resolve().is_file(), target)


def source_manifest():
    return PackManifest(
        name="obsidian-agent-memory-skill-pack",
        version="2.0.0",
        minimum_python="3.9",
        schema_versions=(1, 2),
        active_members=ACTIVE_MEMBERS,
        removed_members=("obsidian-agent-memory-writer",),
        required_capabilities=(),
        optional_capabilities=("obsidian-cli", "obsidian-knowledge-base"),
        release_archive="obsidian-agent-memory-skill-pack-2.0.0.zip",
        release_checksum="obsidian-agent-memory-skill-pack-2.0.0.zip.sha256",
        release_manifest="obsidian-agent-memory-skill-pack-2.0.0-manifest.json",
        files=(),
    )


def assert_validator_gate(testcase, pending_members):
    unexpected = []
    for finding in validate_skill_tree(REPO_ROOT, source_manifest()):
        expected_missing = (
            finding.code in ("member-missing", "route-missing")
            and any(
                member in (finding.path + " " + finding.message)
                for member in pending_members
            )
        )
        if not expected_missing:
            unexpected.append(finding)
    testcase.assertEqual((), tuple(unexpected))


class SharedContractTests(unittest.TestCase):
    def test_reference_and_template_inventory(self):
        reference_root = SKILLS_ROOT / "obsidian-agent-memory" / "references"
        template_root = SKILLS_ROOT / "obsidian-agent-memory" / "templates"
        self.assertEqual(
            set(REFERENCE_FILES),
            {path.name for path in reference_root.glob("*.md")},
        )
        self.assertEqual(
            set(TEMPLATE_FILES),
            {path.name for path in template_root.glob("*.md")},
        )

    def test_template_render_tokens_are_exact(self):
        template_root = SKILLS_ROOT / "obsidian-agent-memory" / "templates"
        for name, expected in TEMPLATE_TOKENS.items():
            text = (template_root / name).read_text(encoding="utf-8")
            actual = set(re.findall(r"\{\{([a-z_]+)\}\}", text))
            self.assertEqual(expected, actual, name)

        story = (template_root / "story-record.md").read_text(encoding="utf-8")
        self.assertNotIn("## Decision", story)
        self.assertNotIn("Session timeline", story)

    def test_shared_references_have_no_raw_machine_fragments(self):
        reference_root = SKILLS_ROOT / "obsidian-agent-memory" / "references"
        forbidden_fragments = (
            "C:\\Users\\",
            "/Users/",
            "/home/",
            ".codex",
        )
        for name in REFERENCE_FILES:
            text = (reference_root / name).read_text(encoding="utf-8")
            for value in forbidden_fragments:
                self.assertNotIn(value, text, name)

    def test_legacy_writer_name_is_only_in_removal_reference(self):
        legacy_name = b"obsidian-agent-memory-writer"
        expected_path = Path(
            "obsidian-agent-memory/references/v1-to-v2-migration.md"
        )
        matches = tuple(
            path.relative_to(SKILLS_ROOT)
            for path in sorted(SKILLS_ROOT.rglob("*"))
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and legacy_name in path.read_bytes()
            )
        )

        self.assertEqual((expected_path,), matches)
        self.assertEqual(
            1,
            (SKILLS_ROOT / expected_path).read_bytes().count(legacy_name),
        )


class SkillContractTests(unittest.TestCase):
    def test_umbrella_contract(self):
        assert_member_contract(
            self,
            "obsidian-agent-memory",
            tuple("references/" + name for name in REFERENCE_FILES),
        )
        text = skill_text("obsidian-agent-memory")
        for member in ACTIVE_MEMBERS[1:]:
            self.assertEqual(text.count(member), 1)
        assert_validator_gate(self, ACTIVE_MEMBERS[1:])


class InitSkillContractTests(unittest.TestCase):
    def test_init_contract(self):
        assert_member_contract(self, "obsidian-agent-memory-init", (
            "../obsidian-agent-memory/references/configuration-and-path-discovery.md",
            "../obsidian-agent-memory/references/vault-schema-2.md",
            "../obsidian-agent-memory/references/validation-and-target-workstation.md",
        ))
        assert_validator_gate(self, ACTIVE_MEMBERS[2:])


class RouteSkillContractTests(unittest.TestCase):
    def test_route_contract(self):
        assert_member_contract(self, "obsidian-agent-memory-route", (
            "../obsidian-agent-memory/references/configuration-and-path-discovery.md",
            "../obsidian-agent-memory/references/retrieval-adapters.md",
            "../obsidian-agent-memory/references/projection-contract.md",
        ))
        assert_validator_gate(self, ACTIVE_MEMBERS[3:])


class CollaborationSkillContractTests(unittest.TestCase):
    def test_collaboration_contract(self):
        assert_member_contract(self, "obsidian-agent-memory-collaboration", (
            "../obsidian-agent-memory/references/record-ownership.md",
            "../obsidian-agent-memory/references/write-consistency.md",
            "../obsidian-agent-memory/references/story-session-coordination.md",
        ))
        text = skill_text("obsidian-agent-memory-collaboration")
        for value in (
            "query/status/dispatch only",
            "durable coordinator output",
            "inherited membership",
            "accepted or proposed",
            "mandatory durable classifications",
            "Never turn",
            "Unbound Session Proposal",
            "failed/cancelled",
        ):
            self.assertIn(value, text)
        assert_validator_gate(self, ACTIVE_MEMBERS[4:])


class QuerySkillContractTests(unittest.TestCase):
    def test_query_contract(self):
        assert_member_contract(self, "obsidian-agent-memory-query", (
            "../obsidian-agent-memory/references/retrieval-adapters.md",
            "../obsidian-agent-memory/references/record-ownership.md",
            "../obsidian-agent-memory/references/projection-contract.md",
        ))
        assert_validator_gate(self, ACTIVE_MEMBERS[5:])


class AddSkillContractTests(unittest.TestCase):
    def test_add_contract(self):
        assert_member_contract(self, "obsidian-agent-memory-add", (
            "../obsidian-agent-memory/references/record-ownership.md",
            "../obsidian-agent-memory/references/configuration-and-path-discovery.md",
            "../obsidian-agent-memory/references/write-consistency.md",
            "../obsidian-agent-memory/references/projection-contract.md",
        ))
        text = skill_text("obsidian-agent-memory-add")
        self.assertLess(
            text.index("preserve_promotion_candidate"),
            text.index("build_root_views"),
        )
        assert_validator_gate(self, ACTIVE_MEMBERS[6:])


class SummarySkillContractTests(unittest.TestCase):
    def test_summary_contract(self):
        assert_member_contract(self, "obsidian-agent-memory-summary", (
            "../obsidian-agent-memory/references/record-ownership.md",
            "../obsidian-agent-memory/references/configuration-and-path-discovery.md",
            "../obsidian-agent-memory/references/write-consistency.md",
            "../obsidian-agent-memory/references/projection-contract.md",
            "../obsidian-agent-memory/references/story-session-coordination.md",
            "../obsidian-agent-memory/templates/session-record.md",
        ))
        text = skill_text("obsidian-agent-memory-summary")
        self.assertIn("primary_story_id", text)
        self.assertIn("preserve_unbound_session_candidate", text)
        self.assertIn("failed or cancelled", text)
        self.assertIn("contain nothing about the proposal", text)
        self.assertIn("changes nothing and contains nothing", text)
        self.assertIn("stale/uncertain operational view", text)
        self.assertLess(
            text.index("preserve_promotion_candidate"),
            text.index("build_root_views"),
        )
        assert_validator_gate(self, ACTIVE_MEMBERS[7:])


class MaintainSkillContractTests(unittest.TestCase):
    def test_proposal_resolution_authorization_boundaries_are_documented(self):
        text = skill_text("obsidian-agent-memory-maintain")
        reference = (
            SKILLS_ROOT / "obsidian-agent-memory" / "references" / "proposal-review.md"
        ).read_text(encoding="utf-8")
        for command in (
            "plan-proposal-resolution", "apply-proposal-resolution",
            "verify-proposal-resolution", "recover-proposal-resolution",
        ):
            self.assertIn(command, text)
        for value in (
            "classification evidence -> reviewed rewrite packet",
            "do not authorize planning against the real root",
            "never edits or deletes old source files",
            "does not perform a Knowledge Base write",
        ):
            self.assertIn(value, reference)

    def test_review_proposals_contract_is_documented(self):
        text = skill_text("obsidian-agent-memory-maintain")
        self.assertIn("review-proposals", text)
        self.assertIn("references/proposal-review.md", text)
        reference = (
            SKILLS_ROOT / "obsidian-agent-memory" / "references" / "proposal-review.md"
        ).read_text(encoding="utf-8")
        for value in ("read-only", "does not", "strict", "Exit `0`", "separate authorization"):
            self.assertIn(value, reference)

    def test_maintain_contract(self):
        assert_member_contract(self, "obsidian-agent-memory-maintain", (
            "../obsidian-agent-memory/references/record-ownership.md",
            "../obsidian-agent-memory/references/write-consistency.md",
            "../obsidian-agent-memory/references/projection-contract.md",
            "../obsidian-agent-memory/references/validation-and-target-workstation.md",
            "../obsidian-agent-memory/templates/maintenance-record.md",
        ))
        assert_validator_gate(self, ACTIVE_MEMBERS[8:])
        text = (SKILLS_ROOT / "obsidian-agent-memory-maintain" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("recover-root-guard", text)
        self.assertIn("narrow", text.lower())
        self.assertNotIn("apply cleanup", text.lower())


class UpgradeSkillContractTests(unittest.TestCase):
    def test_upgrade_contract(self):
        assert_member_contract(self, "obsidian-agent-memory-upgrade", (
            "../obsidian-agent-memory/references/vault-schema-2.md",
            "../obsidian-agent-memory/references/v1-to-v2-migration.md",
            "../obsidian-agent-memory/references/write-consistency.md",
            "../obsidian-agent-memory/references/validation-and-target-workstation.md",
            "../obsidian-agent-memory/templates/migration-record.md",
        ))
        assert_validator_gate(self, ())


class FinalFamilyTests(unittest.TestCase):
    def test_exact_active_skill_directories(self):
        actual = tuple(sorted(
            path.name
            for path in SKILLS_ROOT.iterdir()
            if (path / "SKILL.md").is_file()
        ))
        self.assertEqual(tuple(sorted(ACTIVE_MEMBERS)), actual)
        self.assertFalse(
            (SKILLS_ROOT / "obsidian-agent-memory-writer").exists()
        )

    def test_all_markdown_links_resolve_inside_source(self):
        for member in ACTIVE_MEMBERS:
            skill = SKILLS_ROOT / member / "SKILL.md"
            for target in markdown_targets(skill_text(member)):
                resolved = (skill.parent / target).resolve()
                resolved.relative_to(REPO_ROOT.resolve())
                self.assertTrue(resolved.is_file(), str(resolved))

    def test_source_has_no_machine_defaults(self):
        from tests.portability import (
            KNOWN_LOCAL_LITERAL_HASHES, contains_absolute_path,
        )
        forbidden_fragments = (
            "C:\\Users\\",
            "/Users/",
            "/home/",
            ".codex",
        )
        for path in SKILLS_ROOT.rglob("*"):
            if not path.is_file() or path.suffix not in (".md", ".py", ".json"):
                continue
            text = path.read_text(encoding="utf-8")
            for value in forbidden_fragments:
                self.assertNotIn(value, text, str(path))
            for token in re.findall(r"[A-Za-z0-9._-]+", text):
                digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
                self.assertNotIn(digest, KNOWN_LOCAL_LITERAL_HASHES, str(path))

        evidence_root = REPO_ROOT / "tests" / "evaluations" / "evidence"
        for path in evidence_root.rglob("*.md") if evidence_root.exists() else ():
            text = path.read_text(encoding="utf-8")
            self.assertFalse(contains_absolute_path(text), str(path))
            for token in re.findall(r"[A-Za-z0-9._-]+", text):
                digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
                self.assertNotIn(digest, KNOWN_LOCAL_LITERAL_HASHES, str(path))

    def test_plan_one_validator_accepts_skill_tree(self):
        manifest = PackManifest(
            name="obsidian-agent-memory-skill-pack",
            version="2.0.0",
            minimum_python="3.9",
            schema_versions=(1, 2),
            active_members=ACTIVE_MEMBERS,
            removed_members=("obsidian-agent-memory-writer",),
            required_capabilities=(),
            optional_capabilities=("obsidian-cli", "obsidian-knowledge-base"),
            release_archive="obsidian-agent-memory-skill-pack-2.0.0.zip",
            release_checksum="obsidian-agent-memory-skill-pack-2.0.0.zip.sha256",
            release_manifest="obsidian-agent-memory-skill-pack-2.0.0-manifest.json",
            files=(),
        )
        findings = validate_skill_tree(REPO_ROOT, manifest)
        self.assertEqual((), findings)

    def test_optional_capability_contract_is_explicit(self):
        manifest = source_manifest()
        self.assertEqual((), manifest.required_capabilities)
        self.assertEqual(
            ("obsidian-cli", "obsidian-knowledge-base"),
            manifest.optional_capabilities,
        )
        umbrella = skill_text("obsidian-agent-memory")
        query = skill_text("obsidian-agent-memory-query")
        add = skill_text("obsidian-agent-memory-add")
        summary = skill_text("obsidian-agent-memory-summary")
        self.assertIn("optional `obsidian-cli`", umbrella)
        self.assertIn("optional `obsidian-knowledge-base`", umbrella)
        self.assertIn("named reason", umbrella)
        self.assertIn("bounded filesystem", query)
        self.assertIn("search_accepted_records", query)
        self.assertIn("promotion candidate", add)
        self.assertIn("preserve_promotion_candidate", add)
        self.assertIn("build_project_views", add)
        self.assertIn("build_root_views", add)
        self.assertIn("build_project_views", summary)
        self.assertIn("build_root_views", summary)


if __name__ == "__main__":
    unittest.main()
