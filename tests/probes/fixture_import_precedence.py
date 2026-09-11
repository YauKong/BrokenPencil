"""Isolated regression probe; accepts the source repository as its only argument."""
import subprocess
import sys
import tempfile
from pathlib import Path

repository = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory(prefix="fixture-import-regression-") as directory:
    temporary = Path(directory)
    source = temporary / "verified"
    foreign = temporary / "foreign-site-packages"
    for root in (source, foreign):
        (root / "tests").mkdir(parents=True)
        (root / "tests/__init__.py").write_text("", encoding="utf-8")
    (foreign / "tests/helpers.py").write_text(
        "raise AssertionError('foreign tests package selected')\n", encoding="utf-8"
    )
    (source / "tests/helpers.py").write_text("", encoding="utf-8")
    (source / "tests/fixture_case.py").write_text(
        "import unittest\n"
        "class FixtureCase(unittest.TestCase):\n"
        "    def test_selected_fixture(self):\n"
        "        self.assertIn('verified', __file__)\n", encoding="utf-8"
    )
    program = (
        "import sys; from pathlib import Path; "
        "sys.path[:0] = sys.argv[1:3]; "
        "from agent_memory_pack import installed_fixture as worker; "
        "sys.path.insert(2, sys.argv[3]); "
        "worker._record_projection_flow = lambda *args: None; "
        "worker._migration_and_maintenance_flow = lambda *args: None; "
        "worker._RESOLUTION_TESTS = ('tests.fixture_case.FixtureCase.test_selected_fixture',) * 4; "
        "worker.main(sys.argv[4:])"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program,
         str(repository / "skills/obsidian-agent-memory/scripts"), str(repository / "tools"),
         str(foreign), str(temporary), str(source),
         str(repository / "skills/obsidian-agent-memory")],
        capture_output=True, text=True, encoding="utf-8",
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    raise SystemExit(result.returncode)
