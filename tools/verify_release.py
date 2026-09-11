"""Strictly verify Agent Memory release artifacts without extracting them."""

import argparse
import os
import stat
import sys
from pathlib import Path
from typing import Optional, Sequence

from _bootstrap import bootstrap


bootstrap()

from obsidian_agent_memory import AgentMemoryError
from agent_memory_pack import verify_release


def _existing_regular(value: str) -> Path:
    path = Path(os.path.abspath(value))
    try:
        metadata = path.lstat()
    except OSError as error:
        raise argparse.ArgumentTypeError("artifact must be an existing file") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise argparse.ArgumentTypeError("artifact must be an existing file")
    return path


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=_existing_regular)
    parser.add_argument("--checksum", required=True, type=_existing_regular)
    parser.add_argument("--manifest", required=True, type=_existing_regular)
    arguments = parser.parse_args(argv)
    try:
        artifacts = verify_release(
            arguments.archive,
            arguments.checksum,
            arguments.manifest,
        )
    except (AgentMemoryError, OSError) as error:
        print("ERROR {0}".format(error), file=sys.stderr)
        return 5
    print(
        "VERIFIED obsidian-agent-memory-skill-pack 2.0.1 sha256={0}".format(
            artifacts.archive_sha256
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
