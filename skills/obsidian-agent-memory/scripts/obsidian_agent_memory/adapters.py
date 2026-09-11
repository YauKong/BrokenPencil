"""Bounded read-adapter selection for portable Agent Memory roots."""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterator, Optional, Sequence, Tuple

from .errors import ValidationError
from .models import AdapterSelection, CommandRunner, RootBinding, SearchHit
from .paths import resolve_inside, validate_identifier


_COMMAND_TIMEOUT_SECONDS = 2.0
_HEALTH_QUERY = "__agent_memory_health_probe__"
_MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
_REQUIRED_OPERATIONS = frozenset(("files", "read", "search"))
_COMMAND_LINE = re.compile(
    r"^[ \t]*(read|search|files)(?::[^\r\n]*|[ \t]{2,}(?!-)\S[^\r\n]*)?$"
)
_ALLOWED_READ_ROOTS = frozenset(("_index", "_records", "projects"))
_ORDERED_READ_ROOTS = tuple(sorted(_ALLOWED_READ_ROOTS))
_MAX_EXCERPT_CHARACTERS = 240
_FILESYSTEM_INSPECTION_LIMIT = 10_000
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _raw_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_redirect(metadata: object) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def _contained_raw_path(root: Path, target: Path) -> Path:
    raw_root = _raw_absolute(root)
    raw_target = _raw_absolute(target)
    try:
        raw_target.relative_to(raw_root)
    except ValueError as error:
        raise ValidationError("adapter path escapes the memory root") from error
    return raw_target


def _resolve_inside_safely(root: Path, *parts: str) -> Path:
    try:
        return resolve_inside(root, *parts)
    except ValidationError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise ValidationError("unable to resolve contained path") from error


def _plain_contained_metadata(
    root: Path,
    target: Path,
    expected_kind: Optional[str] = None,
    allow_missing: bool = False,
) -> Tuple[Path, Optional[object]]:
    raw_root = _raw_absolute(root)
    raw_target = _contained_raw_path(raw_root, target)
    relative = raw_target.relative_to(raw_root)
    current = raw_root
    paths = [raw_root]
    for component in relative.parts:
        current = current / component
        paths.append(current)

    leaf_metadata = None
    for index, path in enumerate(paths):
        try:
            metadata = path.lstat()
        except FileNotFoundError as error:
            if allow_missing:
                return raw_target, None
            raise ValidationError("plain contained path does not exist") from error
        except (OSError, RuntimeError, ValueError) as error:
            raise ValidationError("unable to inspect plain contained path") from error
        if _is_redirect(metadata):
            raise ValidationError("reparse paths are not supported")
        is_leaf = index == len(paths) - 1
        if not is_leaf and not stat.S_ISDIR(metadata.st_mode):
            raise ValidationError("plain directory path component required")
        leaf_metadata = metadata

    if leaf_metadata is None:
        raise ValidationError("plain path metadata unavailable")
    if expected_kind == "file" and not stat.S_ISREG(leaf_metadata.st_mode):
        raise ValidationError("plain regular file required")
    if expected_kind == "directory" and not stat.S_ISDIR(leaf_metadata.st_mode):
        raise ValidationError("plain directory required")

    try:
        resolved_root = raw_root.resolve(strict=True)
        resolved_target = raw_target.resolve(strict=True)
        resolved_relative = resolved_target.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise ValidationError("resolved path escapes the memory root") from error
    if os.path.normcase(os.fspath(resolved_relative)) != os.path.normcase(
        os.fspath(relative)
    ):
        raise ValidationError("resolved path differs from canonical lexical path")
    return raw_target, leaf_metadata


def _same_file_identity(before: object, after: object) -> bool:
    return (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)


def _read_plain_contained_utf8(
    root: Path,
    target: Path,
    limit: int,
    kind: str,
) -> str:
    descriptor = None
    try:
        raw_target, before = _plain_contained_metadata(
            root, target, expected_kind="file"
        )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        descriptor = os.open(os.fspath(raw_target), flags)
        after = os.fstat(descriptor)
        if _is_redirect(after) or not stat.S_ISREG(after.st_mode):
            raise ValidationError("plain regular file handle required")
        if before is None or not _same_file_identity(before, after):
            raise ValidationError("file identity changed before bounded read")
        if after.st_size > limit:
            raise ValidationError("{0} exceeds the size limit".format(kind))
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except ValidationError:
        raise
    except OSError as error:
        raise ValidationError("unable to read {0}".format(kind)) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > limit:
        raise ValidationError("{0} exceeds the size limit".format(kind))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError("{0} is not valid UTF-8".format(kind)) from error


def _validate_limit(limit: int) -> int:
    if type(limit) is not int or limit <= 0:
        raise ValidationError("limit must be a positive integer")
    return limit


def _validate_query(query: str) -> str:
    if not isinstance(query, str) or not query.strip():
        raise ValidationError("query must be non-empty text")
    return query.strip()


def _validate_portable_components(parts: Sequence[str]) -> None:
    for component in parts:
        validate_identifier(component, "adapter path component")


def _validated_relative_path(root: Path, value: str) -> Tuple[Path, str]:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValidationError("invalid adapter path")
    pure_path = PurePosixPath(value)
    if (
        pure_path.is_absolute()
        or PureWindowsPath(value).is_absolute()
        or pure_path.as_posix() != value
        or not pure_path.parts
        or pure_path.parts[0] not in _ALLOWED_READ_ROOTS
        or any(part in (".", "..") for part in pure_path.parts)
    ):
        raise ValidationError("invalid adapter path")
    _validate_portable_components(pure_path.parts[1:])
    raw_root = _raw_absolute(root)
    allowed_base = raw_root / pure_path.parts[0]
    candidate = raw_root.joinpath(*pure_path.parts)
    raw_candidate = _contained_raw_path(raw_root, candidate)
    _plain_contained_metadata(raw_root, raw_candidate, allow_missing=True)
    _resolve_inside_safely(allowed_base, *pure_path.parts[1:])
    return raw_candidate, pure_path.as_posix()


def _matching_excerpt(text: str, normalized_query: str) -> str:
    for line in text.splitlines():
        if normalized_query in line.casefold():
            return line[:_MAX_EXCERPT_CHARACTERS]
    return text.replace("\r", " ").replace("\n", " ")[:_MAX_EXCERPT_CHARACTERS]


def _help_operations(text: str) -> frozenset:
    operations = []
    for line in text.splitlines():
        matched = _COMMAND_LINE.fullmatch(line)
        if matched is not None:
            operations.append(matched.group(1))
    return frozenset(operations)


class _FilesystemReadAdapter:
    def __init__(self, root: Path):
        self._root = _raw_absolute(root)

    def read(self, relative_path: str) -> str:
        path, _ = _validated_relative_path(self._root, relative_path)
        return _read_plain_contained_utf8(
            self._root, path, _MAX_COMMAND_OUTPUT_BYTES, "adapter text"
        )

    def _iter_files(
        self, directory: Path, inspections: "_FilesystemInspectionCounter"
    ) -> Iterator[str]:
        pending = [directory]
        while pending:
            current = pending.pop()
            regular_files = []
            child_directories = []
            try:
                with os.scandir(str(current)) as iterator:
                    while True:
                        try:
                            entry = next(iterator)
                        except StopIteration:
                            break
                        inspections.inspect()
                        try:
                            relative_path = Path(entry.path).relative_to(
                                self._root
                            ).as_posix()
                        except ValueError as error:
                            raise ValidationError(
                                "adapter entry escaped the memory root"
                            ) from error
                        resolved, normalized = _validated_relative_path(
                            self._root, relative_path
                        )
                        _, metadata = _plain_contained_metadata(
                            self._root, resolved
                        )
                        if metadata is None:
                            raise ValidationError(
                                "adapter entry metadata unavailable"
                            )
                        if stat.S_ISREG(metadata.st_mode):
                            regular_files.append(normalized)
                        elif stat.S_ISDIR(metadata.st_mode):
                            child_directories.append((normalized, resolved))
            except OSError as error:
                raise ValidationError("unable to enumerate adapter files") from error

            yield from sorted(regular_files)

            pending.extend(
                path
                for _, path in sorted(
                    child_directories, key=lambda item: item[0], reverse=True
                )
            )

    def _files_inventory(
        self, prefix: str, inspections: "_FilesystemInspectionCounter"
    ) -> Tuple[str, ...]:
        path, normalized_prefix = _validated_relative_path(self._root, prefix)
        path, metadata = _plain_contained_metadata(
            self._root, path, allow_missing=True
        )
        if metadata is None:
            return ()
        if stat.S_ISREG(metadata.st_mode):
            inspections.inspect()
            return (normalized_prefix,)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValidationError("adapter prefix must be a plain file or directory")
        return tuple(sorted(self._iter_files(path, inspections)))

    def files(self, prefix: str, limit: int = 200) -> Tuple[str, ...]:
        _validate_limit(limit)
        inventory = self._files_inventory(prefix, _FilesystemInspectionCounter())
        return inventory[:limit]

    def search(self, query: str, limit: int = 20) -> Tuple[SearchHit, ...]:
        normalized_query = _validate_query(query).casefold()
        _validate_limit(limit)
        candidates = []
        inspections = _FilesystemInspectionCounter()
        for prefix in _ORDERED_READ_ROOTS:
            candidates.extend(self._files_inventory(prefix, inspections))

        hits = []
        for relative_path in sorted(candidates):
            text = self.read(relative_path)
            if normalized_query in text.casefold():
                hits.append(
                    SearchHit(relative_path, _matching_excerpt(text, normalized_query))
                )
                if len(hits) == limit:
                    break
        return tuple(hits)


class _FilesystemInspectionCounter:
    def __init__(self):
        self._count = 0

    def inspect(self) -> None:
        self._count += 1
        if self._count > _FILESYSTEM_INSPECTION_LIMIT:
            raise ValidationError("filesystem inspection limit exceeded")


class _ObsidianCliReadAdapter:
    def __init__(self, root: Path, executable: str, vault: str, runner: CommandRunner):
        self._root = _raw_absolute(root)
        self._executable = executable
        self._vault = vault
        self._runner = runner

    def _run(self, operation: str, options: Sequence[Tuple[str, object]]) -> str:
        try:
            result = self._runner(
                _cli_command(self._executable, operation, self._vault, options),
                _COMMAND_TIMEOUT_SECONDS,
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            raise ValidationError("Obsidian CLI read operation unavailable") from error
        if result.returncode != 0:
            raise ValidationError("Obsidian CLI read operation failed")
        output = _bounded_command_output(result)
        if output is None:
            raise ValidationError("Obsidian CLI output is invalid or oversized")
        return output

    def read(self, relative_path: str) -> str:
        _, normalized = _validated_relative_path(self._root, relative_path)
        return self._run("read", (("path", normalized), ("limit", 1)))

    def search(self, query: str, limit: int = 20) -> Tuple[SearchHit, ...]:
        normalized_query = _validate_query(query)
        _validate_limit(limit)
        output = self._run("search", (("query", normalized_query), ("limit", limit)))
        hits = []
        for line in output.splitlines():
            if not line:
                continue
            relative_path, separator, excerpt = line.partition("\t")
            _, normalized_path = _validated_relative_path(self._root, relative_path)
            hits.append(SearchHit(normalized_path, excerpt if separator else ""))
            if len(hits) == limit:
                break
        return tuple(hits)

    def files(self, prefix: str, limit: int = 200) -> Tuple[str, ...]:
        _validate_limit(limit)
        _, normalized_prefix = _validated_relative_path(self._root, prefix)
        output = self._run("files", (("path", normalized_prefix), ("limit", limit)))
        paths = []
        for line in output.splitlines():
            if not line:
                continue
            _, normalized_path = _validated_relative_path(self._root, line)
            paths.append(normalized_path)
            if len(paths) == limit:
                break
        return tuple(sorted(paths))


def _cli_command(
    executable: str,
    operation: str,
    vault: Optional[str] = None,
    options: Sequence[Tuple[str, object]] = (),
) -> Tuple[str, ...]:
    command = [executable]
    if vault is not None:
        command.append("vault=" + vault)
    command.append(operation)
    command.extend("{0}={1}".format(key, value) for key, value in options)
    return tuple(command)


def _bounded_command_output(process: subprocess.CompletedProcess) -> Optional[str]:
    output = process.stdout
    if output is None:
        return ""
    if isinstance(output, bytes):
        raw = output
    elif isinstance(output, str):
        try:
            raw = output.encode("utf-8")
        except UnicodeEncodeError:
            return None
    else:
        return None
    if len(raw) > _MAX_COMMAND_OUTPUT_BYTES:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _filesystem_selection(binding: RootBinding, reason: str) -> AdapterSelection:
    return AdapterSelection(_FilesystemReadAdapter(binding.memory_root), "filesystem", reason)


def select_read_adapter(
    binding: RootBinding,
    runner: CommandRunner,
    executable: Optional[Path] = None,
) -> AdapterSelection:
    """Choose a healthy explicit-vault CLI, or a bounded filesystem fallback."""
    selected_executable = (
        str(executable) if executable is not None else shutil.which("obsidian")
    )
    if not selected_executable:
        return _filesystem_selection(binding, "cli-executable-missing")

    vault = binding.obsidian_vault
    if not isinstance(vault, str) or not vault.strip():
        return _filesystem_selection(binding, "cli-vault-missing")

    try:
        help_result = runner(
            _cli_command(selected_executable, "help"), _COMMAND_TIMEOUT_SECONDS
        )
    except (subprocess.TimeoutExpired, OSError):
        return _filesystem_selection(binding, "cli-health-timeout")
    if help_result.returncode != 0:
        return _filesystem_selection(binding, "cli-help-nonzero")

    help_output = _bounded_command_output(help_result)
    if help_output is None or not _REQUIRED_OPERATIONS.issubset(
        _help_operations(help_output)
    ):
        return _filesystem_selection(binding, "cli-operation-unsupported")

    probe_command = _cli_command(
        selected_executable,
        "search",
        vault,
        (("query", _HEALTH_QUERY), ("limit", 1)),
    )
    try:
        probe_result = runner(probe_command, _COMMAND_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        return _filesystem_selection(binding, "cli-health-timeout")
    if probe_result.returncode != 0:
        return _filesystem_selection(binding, "cli-health-nonzero")

    return AdapterSelection(
        _ObsidianCliReadAdapter(
            binding.memory_root, selected_executable, vault, runner
        ),
        "obsidian-cli",
        "cli-healthy",
    )
