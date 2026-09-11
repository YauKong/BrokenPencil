"""Refresh or check the canonical Skill pack payload manifest."""

import argparse
import os
import stat
import sys
from pathlib import Path
from typing import Optional, Sequence

from _bootstrap import bootstrap


bootstrap()

from obsidian_agent_memory import AgentMemoryError
from agent_memory_pack import refresh_pack_manifest


def _repository_root(value: str) -> Path:
    path = Path(os.path.abspath(value))
    try:
        metadata = path.lstat()
    except OSError as error:
        raise argparse.ArgumentTypeError(
            "repository root must be an existing directory"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise argparse.ArgumentTypeError("repository root must be an existing directory")
    return path


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=_repository_root)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        manifest = refresh_pack_manifest(arguments.repo_root, check=arguments.check)
    except AgentMemoryError as error:
        print("ERROR {0}".format(error), file=sys.stderr)
        return 1
    if arguments.check:
        print("CURRENT pack.json")
    else:
        print("UPDATED pack.json files={0}".format(len(manifest.files)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
