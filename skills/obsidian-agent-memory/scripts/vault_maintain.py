"""Installed entrypoint for the portable vault maintenance CLI."""

import sys
import tempfile
import uuid
from pathlib import Path


if len(sys.argv) > 1 and sys.argv[1] == "review-proposals":
    sys.dont_write_bytecode = True
    sys.pycache_prefix = str(
        Path(tempfile.gettempdir()).resolve()
        / ("agent-memory-review-pycache-" + uuid.uuid4().hex)
    )

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from obsidian_agent_memory.cli_maintain import main


if __name__ == "__main__":
    raise SystemExit(main())
