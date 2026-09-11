import ast
import json
import unittest

from tests.helpers import REPO_ROOT


class ReleaseDocumentationTests(unittest.TestCase):
    def test_proposal_review_operator_boundaries_are_documented(self):
        reference = (
            REPO_ROOT / "skills" / "obsidian-agent-memory" / "references" / "proposal-review.md"
        ).read_text(encoding="utf-8")
        required = (
            "review-proposals", "--bundle-sha256", "--fixture-code-revision",
            "outside the memory root", "default-layout", "sensitive",
            "never replaces", "Exit `0`", "Exit `4`",
            "separate authorization boundaries",
        )
        for value in required:
            self.assertIn(value, reference)

    def test_final_local_release_policy_names_outputs_and_stops_at_every_boundary(self):
        manifest = json.loads((REPO_ROOT / "pack.json").read_text(encoding="utf-8"))
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        release = (
            REPO_ROOT / "docs" / "release-and-authorization.md"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            ".worktrees/\ndist/\n.artifacts/\n__pycache__/\n*.py[cod]\n",
            (REPO_ROOT / ".gitignore").read_text(encoding="utf-8"),
        )
        artifacts = (
            "obsidian-agent-memory-skill-pack-2.0.1.zip",
            "obsidian-agent-memory-skill-pack-2.0.1.zip.sha256",
            "obsidian-agent-memory-skill-pack-2.0.1-manifest.json",
        )
        self.assertEqual(
            artifacts,
            (
                manifest["release_archive"],
                manifest["release_checksum"],
                manifest["release_manifest"],
            ),
        )
        heading = "## Final local release stop checklist"
        boundaries = (
            "Passing local tests does not authorize installation on the current workstation.",
            "Building local release artifacts does not authorize installation, Git push, upload, or release publication.",
            "Installing on the current workstation does not authorize real-vault detection, migration planning, migration apply, verification, rollback, or cleanup.",
            "A verified real-vault migration does not authorize cleanup execution or deletion of migration or pack rollback evidence.",
            "Local commits do not authorize Git push.",
            "Creating or verifying the fixed local `v2.0.1` tag does not authorize pushing the tag or moving or deleting any existing tag.",
            "Git push does not authorize release publication.",
            "Release publication requires a new request naming the destination and the exact SHA-256 of each of the three artifacts.",
        )
        for document in (readme, release):
            section = document[document.index(heading) :]
            self.assertNotIn("```", section)
            positions = [section.index(value) for value in boundaries]
            self.assertEqual(positions, sorted(positions))
            for artifact in artifacts:
                self.assertIn(artifact, document)

    def test_readme_has_safe_archive_preflight_and_separate_operator_blocks(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        required = (
            "Python 3.9",
            "obsidian-agent-memory-skill-pack-2.0.1.zip",
            "obsidian-agent-memory-skill-pack-2.0.1.zip.sha256",
            "obsidian-agent-memory-skill-pack-2.0.1-manifest.json",
            "integrity, not publisher authenticity",
            "$safeExtractor = @'",
            "reject_duplicates",
            "PurePosixPath",
            "FILE_ATTRIBUTE_REPARSE_POINT",
            "destination.exists()",
            "destination.mkdir()",
            "output.open(\"xb\")",
            "python tools\\verify_release.py",
            "python tools\\validate.py",
            "python tools\\bootstrap.py check",
            "python tools\\bootstrap.py plan",
            "tools/bootstrap.py') apply",
            "tools/doctor.py",
            "--probe-cli",
            "tools/smoke.py",
            "Stop the host application",
            "restart",
            "does not configure or migrate memory",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, readme)
        self.assertNotIn("Expand-Archive", readme)
        self.assertNotIn("extractall", readme)
        checksum = readme.index("Get-FileHash")
        extractor = readme.index("$safeExtractor = @'")
        extraction = readme.index("destination.mkdir()")
        packaged_verify = readme.index("python tools\\verify_release.py")
        validator = readme.index("python tools\\validate.py")
        self.assertLess(checksum, extractor)
        self.assertLess(extractor, extraction)
        self.assertLess(extraction, packaged_verify)
        self.assertLess(packaged_verify, validator)
        self.assertIn("if ($LASTEXITCODE -ne 0)", readme[packaged_verify:validator])
        self.assertNotIn("C:\\Users\\", readme)

    def test_authorization_matrix_has_eleven_ordered_boundaries_and_plan3_commands(self):
        document = (REPO_ROOT / "docs" / "release-and-authorization.md").read_text(
            encoding="utf-8"
        )
        headings = (
            "## 1. Local source implementation, commits, and fixed release tag",
            "## 2. Current-workstation install dry run",
            "## 3. Current-workstation install or upgrade apply",
            "## 4. Post-install validation",
            "## 5. Current-workstation pack recovery, rollback, or uninstall",
            "## 6. Real-vault migration detect and plan",
            "## 7. Real-vault migration apply, verify, and rollback",
            "## 8. Post-migration maintenance audit, cleanup plan, and stale root-guard recovery",
            "## 9. Future cleanup execution and rollback-material deletion",
            "## 10. Git push",
            "## 11. Release publication",
        )
        positions = [document.index(heading) for heading in headings]
        self.assertEqual(sorted(positions), positions)
        required = (
            "$migrateTool = Join-Path $skillsRoot 'obsidian-agent-memory/scripts/vault_migrate.py'",
            "$maintainTool = Join-Path $skillsRoot 'obsidian-agent-memory/scripts/vault_maintain.py'",
            "detect --root $realMemoryRoot --scope real",
            "plan --root $realMemoryRoot --work-dir $migrationWorkRoot --scope real",
            "bundle_sha256",
            "--bundle-sha256 $reviewedMigrationBundleSha256",
            "verify --root $realMemoryRoot --bundle",
            "rollback --root $realMemoryRoot --apply-transaction-id $applyTransactionId",
            "--transaction-id $rollbackTransactionId",
            "audit --root $realMemoryRoot --output $cleanupAuditPath --scope real",
            "plan --root $realMemoryRoot --audit $cleanupAuditPath",
            "recover-root-guard --root $realMemoryRoot --scope real",
            "tools/install_pack.py recover",
            "tools/uninstall_pack.py recover",
            "There is no cleanup apply command",
            "Stop the host application",
            "Prior success does not continue automatically",
            "new request",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, document)
        self.assertNotIn("cleanup apply --", document)
        self.assertNotIn("C:\\Users\\", document)
        apply_block = document[document.index("--bundle-sha256"):]
        self.assertNotIn("Get-FileHash", apply_block.split("```", 1)[0])

    def test_bootstrap_is_static_dispatch_without_shell_or_fallthrough(self):
        source = (REPO_ROOT / "tools" / "bootstrap.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertNotIn("subprocess", imports)
        self.assertIn('usage="bootstrap.py {check,plan,apply,doctor} ..."', source)
        for command in ("check", "plan", "apply", "doctor"):
            self.assertIn('arguments.command == "{0}"'.format(command), source)
        self.assertGreaterEqual(source.count("return 0"), 3)


if __name__ == "__main__":
    unittest.main()
