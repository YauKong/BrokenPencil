"""Validate the source repository and fixed 2.0.1 release metadata."""

import argparse
import os
import stat
import sys
from pathlib import Path
from typing import Optional, Sequence

from _bootstrap import bootstrap


bootstrap()

from obsidian_agent_memory import AgentMemoryError, load_pack_manifest, validate_repository
from agent_memory_pack import validate_release_metadata


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
    arguments = parser.parse_args(argv)
    try:
        manifest = load_pack_manifest(arguments.repo_root / "pack.json")
        findings = validate_repository(arguments.repo_root, manifest)
        findings += validate_release_metadata(arguments.repo_root, manifest)
    except AgentMemoryError as error:
        print("ERROR manifest-invalid pack.json {0}".format(error), file=sys.stderr)
        return 1
    findings = tuple(
        sorted(
            set(findings),
            key=lambda item: (item.severity, item.code, item.path, item.message),
        )
    )
    for finding in findings:
        print(
            "{0} {1} {2} {3}".format(
                finding.severity.upper(),
                finding.code,
                finding.path,
                finding.message,
            )
        )
    if any(finding.severity == "error" for finding in findings):
        return 1
    print("VALID {0} {1} files={2}".format(manifest.name, manifest.version, len(manifest.files)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
