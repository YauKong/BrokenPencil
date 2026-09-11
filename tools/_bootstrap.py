"""Bounded import bootstrap shared by clone/archive command wrappers."""

import sys
from pathlib import Path
from typing import Tuple


def bootstrap() -> Tuple[Path, Path]:
    repo_root = Path(__file__).resolve().parents[1]
    paths = (
        repo_root / "skills" / "obsidian-agent-memory" / "scripts",
        repo_root / "tools",
    )
    for path in reversed(paths):
        text = str(path)
        if text not in sys.path:
            sys.path.insert(0, text)
    return paths
