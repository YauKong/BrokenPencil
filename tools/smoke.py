"""Run the packaged Agent Memory fixture smoke in temporary roots."""

import argparse
from pathlib import Path

from _bootstrap import bootstrap


bootstrap()

from obsidian_agent_memory import AgentMemoryError
from agent_memory_pack import run_fixture_smoke


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    try:
        report = run_fixture_smoke(parser.parse_args(argv).repo_root)
    except (AgentMemoryError, AssertionError, OSError) as error:
        parser.exit(1, "SMOKE FAIL: {0}\n".format(error))
    if not report.ok:
        parser.exit(1, "SMOKE FAIL\n")
    print("SMOKE PASS steps={0} scope=fixture temporary=true".format(len(report.steps)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
