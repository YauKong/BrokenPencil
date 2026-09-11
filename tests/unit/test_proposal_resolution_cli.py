import contextlib
import io
import json
import unittest

import tests.helpers
from tests.proposal_resolution_helpers import build_resolution_fixture

import obsidian_agent_memory as memory
from obsidian_agent_memory import cli_maintain
from obsidian_agent_memory.errors import ValidationError


class ProposalResolutionPublicSurfaceTests(unittest.TestCase):
    def test_required_resolution_api_is_exported(self):
        required = {
            "ProposalDecisionEnvelope",
            "bind_proposal_decisions",
            "load_proposal_decisions",
            "RewriteCandidateArtifact",
            "SemanticReviewArtifact",
            "load_rewrite_candidate",
            "load_semantic_review",
            "RewritePacket",
            "bind_rewrite_packet",
            "load_rewrite_packet",
            "seal_rewrite_packet",
            "ResolutionPlan",
            "ResolutionVerification",
            "bind_resolution_plan",
            "load_resolution_plan",
            "plan_proposal_resolution",
            "ResolutionResult",
            "apply_proposal_resolution",
            "recover_proposal_resolution",
            "verify_proposal_resolution",
        }
        self.assertEqual(set(), required - set(memory.__all__))
        self.assertTrue(all(hasattr(memory, name) for name in required))


class ProposalResolutionCliContractTests(unittest.TestCase):
    def test_fixture_cli_plans_applies_and_verifies(self):
        fixture = build_resolution_fixture(self)
        outside = fixture.packet.root.parent
        report_path = outside / "cli-report.json"
        report_path.write_bytes(fixture.report.raw)
        decisions_path = outside / "decisions.json"
        plan_path = outside / "cli-resolution-plan.json"
        common = [
            "--root", str(fixture.root), "--scope", "fixture",
            "--report", str(report_path),
            "--report-sha256", fixture.report.report_sha256,
            "--decisions", str(decisions_path),
            "--decisions-sha256", fixture.decisions.decisions_sha256,
            "--packet", str(fixture.packet.root),
            "--packet-sha256", fixture.packet.packet_sha256,
            "--bundle", str(fixture.bundle.bundle_dir),
            "--bundle-sha256", fixture.bundle.bundle_sha256,
            "--fixture-code-revision", "proposal-resolution-fixture-v1",
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = cli_maintain.main(
                ["plan-proposal-resolution"] + common + [
                    "--output", str(plan_path),
                    "--transaction-id", "tx-cli-plan",
                    "--actor", "fixture-agent",
                    "--occurred-at", "2026-08-30T02:10:00Z",
                ]
            )
        self.assertEqual(0, code)
        planned = json.loads(stdout.getvalue())

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = cli_maintain.main(
                ["apply-proposal-resolution"] + common + [
                    "--plan", str(plan_path),
                    "--resolution-plan-sha256", planned["resolution_plan_sha256"],
                    "--transaction-id", "tx-cli-apply",
                    "--actor", "fixture-agent",
                    "--occurred-at", "2026-08-30T02:11:00Z",
                ]
            )
        self.assertEqual(0, code)
        applied = json.loads(stdout.getvalue())
        self.assertEqual("applied", applied["status"])

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = cli_maintain.main(
                [
                    "verify-proposal-resolution",
                    "--root", str(fixture.root),
                    "--scope", "fixture",
                    "--plan", str(plan_path),
                    "--resolution-plan-sha256", planned["resolution_plan_sha256"],
                    "--target-transaction-id", "tx-cli-apply",
                ]
            )
        self.assertEqual(0, code)
        self.assertEqual("valid", json.loads(stdout.getvalue())["status"])

    def test_help_lists_the_four_resolution_commands(self):
        help_text = cli_maintain._parser().format_help()
        for command in (
            "plan-proposal-resolution",
            "apply-proposal-resolution",
            "verify-proposal-resolution",
            "recover-proposal-resolution",
        ):
            self.assertIn(command, help_text)

    def test_apply_requires_all_explicit_binding_and_context_arguments(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = cli_maintain.main(["apply-proposal-resolution"])
        self.assertEqual(2, code)
        for option in ("--root", "--scope", "--plan", "--resolution-plan-sha256"):
            self.assertIn(option, stderr.getvalue())

    def test_real_resolution_mutation_requires_authorization_reference(self):
        with self.assertRaisesRegex(ValidationError, "authorization reference"):
            cli_maintain._gate("real", None)


if __name__ == "__main__":
    unittest.main()
