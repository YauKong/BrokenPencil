"""Repository-clone entrypoint for the portable vault migration CLI."""

import sys
from pathlib import Path


SCRIPTS_DIR = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "obsidian-agent-memory"
    / "scripts"
)
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory.cli_migrate import main


if __name__ == "__main__":
    raise SystemExit(main())
