"""Build the deterministic Agent Memory Skill pack release artifacts."""

import argparse
import os
import stat
import sys
from pathlib import Path
from typing import Optional, Sequence

from _bootstrap import bootstrap


bootstrap()

from obsidian_agent_memory import AgentMemoryError
from agent_memory_pack import build_release


def _repository_root(value: str) -> Path:
    path = Path(os.path.abspath(value))
    try:
        metadata = path.lstat()
    except OSError as error:
        raise argparse.ArgumentTypeError("repository root must be a directory") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise argparse.ArgumentTypeError("repository root must be a directory")
    return path


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=_repository_root)
    parser.add_argument("--dist-dir", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        artifacts = build_release(arguments.repo_root, arguments.dist_dir)
    except (AgentMemoryError, OSError) as error:
        print("ERROR {0}".format(error), file=sys.stderr)
        return 5
    print(
        "BUILT {0} {1} {2} sha256={3}".format(
            artifacts.archive_path.name,
            artifacts.checksum_path.name,
            artifacts.manifest_path.name,
            artifacts.archive_sha256,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
