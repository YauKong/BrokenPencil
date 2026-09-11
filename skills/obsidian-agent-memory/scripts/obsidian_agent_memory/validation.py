"""Read-only validation for portable Skill and repository source trees."""

import hashlib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .artifact_schemas import MigrationReviewProposal, parse_proposal_artifact
from .errors import AgentMemoryError, ContainmentError, ValidationError
from .manifest import _portable_path_is_safe
from .models import (
    CatalogEntry,
    CatalogSnapshot,
    Finding,
    PackManifest,
    RecordEnvelope,
)
from .migration import index_applied_migration_proposals
from .paths import resolve_inside, validate_identifier
from .projections import build_projection_from_observed_target
from .records import parse_record, record_relative_path, render_record


_FRONTMATTER_BYTE_LIMIT = 4096
_FRONTMATTER_LINE_LIMIT = 32
_DESCRIPTION_BYTE_LIMIT = 512
_LINK_MATCH_LIMIT = 128
_LINK_TARGET_LIMIT = 1024
_FORBIDDEN_SCALAR_MARKERS = frozenset(
    ("[", "]", "{", "}", "|", ">", "&", "*", "!", "'", '"', "#", ",")
)
_LINK_OPEN_PATTERN = re.compile(r"\[[^\]\r\n]{0,1024}\]\(")
_URI_SCHEME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_HEADING_PATTERN = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$")
_ROUTE_PATTERN = re.compile(
    r"^[ \t]*-[ \t]+[^:\r\n]+:[ \t]+`([a-z0-9][a-z0-9._-]{0,127})`\.?[ \t]*$"
)
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_TEXT_SUFFIXES = frozenset((".md", ".py", ".json", ".txt"))
_EXCLUDED_PARTS = frozenset((".git", ".superpowers", "dist", "tests", "__pycache__"))
_HARD_CODED_PATH_PATTERN = re.compile(
    r"(?:(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/]"
    r"|\\\\[^\\\s]+\\[^\\\s]+"
    r"|(?<![A-Za-z0-9:/])/(?:Users|home)/)"
)
_HTTP_URL_PATTERN = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
_FILE_URI_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+.-])" + "fi" + "le:", re.IGNORECASE
)
_DEFAULT_BINDING_PATTERN = re.compile(
    r"\b(?:OBSIDIAN_VAULT|DEFAULT_MEMORY_ROOT|DEFAULT_PROJECT|DEFAULT_RUNTIME_HOME)[ \t]*="
)
_AMBIENT_HOME_PATTERN = re.compile(r"\b(?:Path\.home|os\.path\.expanduser)[ \t]*\(")
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:password|secret|api_key|apikey|authorization|credential|token)\b"
    r"[ \t]*=[ \t]*(?:\"[^\"\r\n]+\"|'[^'\r\n]+')",
    re.IGNORECASE,
)
_SENSITIVE_JSON_KEYS = frozenset(
    (
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "credential",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "token",
    )
)
_REMOVED_WRITER = "obsidian-agent-memory-" + "writer"
_REMOVED_WRITER_ALLOWED_PATHS = frozenset(
    (
        "skills/obsidian-agent-memory/references/v1-to-v2-migration.md",
        "docs/release-and-authorization.md",
    )
)
_MEMORY_DOCUMENT_LIMIT = 1024 * 1024
_MEMORY_INVENTORY_LIMIT = 10000
_ROOT_GUARD_INVENTORY_LIMIT = 10000
_MEMORY_HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_MEMORY_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_ROOT_ANCHOR_NAME = ".agent-memory-root-write.anchor"
_ROOT_ANCHOR_BYTES = b'{"purpose":"root-write-namespace","schema_version":1}\n'
_ROOT_LOCK_NAME = ".agent-memory-root-write.lock"
_ROOT_CANDIDATE_PREFIX = ".agent-memory-root-write.candidate-"
_ANCHOR_CANDIDATE_NAME = _ROOT_ANCHOR_NAME + ".candidate"
_OBSERVABLE_GUARD_LOCK_OFFSET = 1_048_576
_TRANSACTION_OPERATIONS = frozenset(
    ("commit-record", "initialize", "knowledge-promotion", "update_focus")
)
_TRANSACTION_STATUSES = frozenset(("accepted", "in-progress", "proposed"))


class _MemoryContainmentError(Exception):
    def __init__(self, path: Optional[str] = None):
        super().__init__(path)
        self.path = path


class _MemoryOversizeError(Exception):
    pass


def _windows_probe_open(path: Path) -> int:
    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(path),
        0x80000000 | 0x40000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00000080 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        if error in (2, 3):
            raise FileNotFoundError(error, "probe path not found", str(path))
        raise OSError(error, "CreateFileW probe failed", str(path))
    try:
        return msvcrt.open_osfhandle(
            handle, os.O_RDWR | getattr(os, "O_BINARY", 0)
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def _windows_memory_read_open(path: Path) -> int:
    """Open one non-following Windows read handle for bounded doctor input."""
    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(path),
        0x80000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00000080 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        if error in (2, 3):
            raise FileNotFoundError(error, "memory path not found", str(path))
        raise OSError(error, "CreateFileW memory read failed", str(path))
    try:
        return msvcrt.open_osfhandle(
            handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


class _ProbeLease:
    """Minimal nonblocking read-only observer over one lock-compatible handle."""

    def __init__(self, descriptor: int):
        self.descriptor = descriptor
        self.held = False
        self.lock_offset = 0
        self.closed = False

    @classmethod
    def open(cls, path: Path) -> "_ProbeLease":
        if os.name == "nt":
            return cls(_windows_probe_open(path))
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        return cls(os.open(str(path), flags))

    def acquire(self, offset: int) -> bool:
        os.lseek(self.descriptor, offset, os.SEEK_SET)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        self.held = True
        self.lock_offset = offset
        return True

    def release(self) -> None:
        if not self.held:
            return
        os.lseek(self.descriptor, self.lock_offset, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self.descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        self.held = False

    def read_bounded(self, start: int = 0) -> bytes:
        os.lseek(self.descriptor, start, os.SEEK_SET)
        chunks = []
        remaining = _MEMORY_DOCUMENT_LIMIT + 1
        while remaining:
            chunk = os.read(self.descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) + start > _MEMORY_DOCUMENT_LIMIT:
            raise _MemoryOversizeError()
        return raw

    def close(self) -> None:
        if self.closed:
            return
        try:
            self.release()
        finally:
            os.close(self.descriptor)
            self.closed = True


@dataclass(frozen=True)
class _ProbeResult:
    raw: Optional[bytes]
    busy: bool
    metadata: os.stat_result


def _probe_memory_file(
    root: Path,
    relative: str,
    offset: int,
    locked_expected: Optional[bytes] = None,
) -> _ProbeResult:
    try:
        candidate = _memory_candidate(root, relative)
    except _MemoryContainmentError as error:
        raise _MemoryContainmentError(relative) from error
    try:
        before = candidate.lstat()
    except FileNotFoundError:
        raise
    except OSError as error:
        raise _MemoryContainmentError(relative) from error
    if _is_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise _MemoryContainmentError(relative)
    try:
        lease = _ProbeLease.open(candidate)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise _MemoryContainmentError(relative) from error
    primary_failure_active = False
    try:
        after = os.fstat(lease.descriptor)
        if not stat.S_ISREG(after.st_mode) or not _same_file_metadata(before, after):
            raise _MemoryContainmentError(relative)
        if after.st_size > _MEMORY_DOCUMENT_LIMIT:
            raise _MemoryOversizeError()
        acquired = lease.acquire(offset)
        busy = not acquired
        try:
            raw = lease.read_bounded(0)
        except PermissionError:
            if not busy or os.name != "nt" or offset != 0:
                raise _MemoryContainmentError(relative)
            if after.st_size == 0:
                raw = b""
            else:
                tail = lease.read_bounded(1)
                if (
                    locked_expected is not None
                    and 0 < after.st_size <= len(locked_expected)
                    and tail == locked_expected[1 : after.st_size]
                ):
                    raw = locked_expected[: after.st_size]
                else:
                    raw = None
        except OSError as error:
            raise _MemoryContainmentError(relative) from error
        return _ProbeResult(raw, busy, after)
    except BaseException:
        primary_failure_active = True
        raise
    finally:
        try:
            lease.close()
        except OSError as error:
            if not primary_failure_active:
                raise _MemoryContainmentError(relative) from error


def _finding(code: str, path: str, message: str) -> Finding:
    return Finding(code=code, severity="error", path=path, message=message)


def _sorted_findings(findings: Iterable[Finding]) -> Tuple[Finding, ...]:
    return tuple(
        sorted(
            set(findings),
            key=lambda finding: (
                finding.severity,
                finding.code,
                finding.path,
                finding.message,
            ),
        )
    )


def _is_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def _resolved_root(repo_root: Path) -> Path:
    return resolve_inside(Path(repo_root))


def _contained_candidate(repo_root: Path, candidate: Path) -> Optional[Path]:
    root = _resolved_root(repo_root)
    lexical = Path(candidate)
    try:
        relative = lexical.relative_to(root)
    except ValueError:
        try:
            relative = lexical.absolute().relative_to(root)
        except ValueError:
            return None
    try:
        resolved = lexical.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None
    try:
        resolved.relative_to(root)
    except ValueError:
        return None

    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return None
        if _is_reparse(metadata):
            return None
    return resolved


def _regular_file(repo_root: Path, candidate: Path) -> Optional[Path]:
    resolved = _contained_candidate(repo_root, candidate)
    if resolved is None:
        return None
    try:
        metadata = resolved.lstat()
    except OSError:
        return None
    if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        return None
    return resolved


def _relative_posix(root: Path, candidate: Path) -> str:
    return candidate.relative_to(root).as_posix()


def _is_excluded(relative_path: str) -> bool:
    parts = Path(relative_path).parts
    return bool(
        any(part in _EXCLUDED_PARTS for part in parts)
        or any(
            part == ".agent-memory"
            or part.startswith(".agent-memory-root-write")
            for part in parts
        )
        or relative_path.endswith(".pyc")
    )


def _manifest_path_is_safe(path: str) -> bool:
    return _portable_path_is_safe(path)


def _has_reparse_component(repo_root: Path, candidate: Path) -> bool:
    root = _resolved_root(repo_root)
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if _is_reparse(metadata):
            return True
    return False


def _read_regular_file(repo_root: Path, candidate: Path) -> Optional[bytes]:
    resolved = _regular_file(repo_root, candidate)
    if resolved is None:
        return None
    try:
        return resolved.read_bytes()
    except OSError:
        return None


def _validate_scalar(value: str) -> bool:
    return bool(
        value
        and value == value.strip(" \t")
        and not any(marker in value for marker in _FORBIDDEN_SCALAR_MARKERS)
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _frontmatter(raw: bytes) -> Optional[Mapping[str, str]]:
    prefix = raw[:_FRONTMATTER_BYTE_LIMIT]
    normalized = prefix.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = normalized.split(b"\n")
    if not lines or lines[0] != b"---":
        return None
    closing_index = None
    for index in range(1, min(len(lines), _FRONTMATTER_LINE_LIMIT)):
        if lines[index] == b"---":
            closing_index = index
            break
    if closing_index is None:
        return None

    values: Dict[str, str] = {}
    for raw_line in lines[1:closing_index]:
        if raw_line.strip(b" \t") == b"":
            continue
        if b": " not in raw_line:
            return None
        raw_key, raw_value = raw_line.split(b": ", 1)
        try:
            key = raw_key.decode("ascii")
            value = raw_value.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if key not in ("name", "description") or key in values or not _validate_scalar(value):
            return None
        values[key] = value
    if set(values) != {"name", "description"}:
        return None
    if len(values["description"].encode("utf-8")) > _DESCRIPTION_BYTE_LIMIT:
        return None
    return values


def _reference_is_valid(repo_root: Path, skill_path: Path, target: str) -> bool:
    if len(target) > _LINK_TARGET_LIMIT:
        return False
    path_part = target.split("#", 1)[0]
    if path_part == "":
        candidate = skill_path
    else:
        if (
            _URI_SCHEME_PATTERN.match(path_part) is not None
            or path_part.startswith(("/", "//"))
            or "\\" in path_part
            or PureWindowsPath(path_part).is_absolute()
            or PureWindowsPath(path_part).drive
            or any(ord(character) < 32 or ord(character) == 127 for character in path_part)
        ):
            return False
        candidate = skill_path.parent / Path(path_part)
    return _regular_file(repo_root, candidate) is not None


def _broken_references(repo_root: Path, skill_path: Path, text: str) -> bool:
    for index, match in enumerate(_LINK_OPEN_PATTERN.finditer(text)):
        if index >= _LINK_MATCH_LIMIT:
            break
        target_start = match.end()
        window = text[target_start : target_start + _LINK_TARGET_LIMIT + 2]
        closing_index = None
        for offset, character in enumerate(window):
            if character in "\r\n":
                break
            if character == ")":
                closing_index = offset
                break
        if closing_index is None:
            if len(window) > _LINK_TARGET_LIMIT:
                return True
            continue
        if closing_index > _LINK_TARGET_LIMIT:
            return True
        target = window[:closing_index]
        if not _reference_is_valid(repo_root, skill_path, target):
            return True
    return False


def _route_declarations(text: str) -> Tuple[Tuple[str, ...], bool]:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    inside = False
    section_seen = False
    invalid = False
    targets = []
    for line in lines:
        heading = _HEADING_PATTERN.fullmatch(line)
        if heading is not None:
            level = len(heading.group(1))
            title = heading.group(2)
            if level == 2 and title == "Routes":
                invalid = invalid or section_seen
                section_seen = True
                inside = True
                continue
            if level <= 2:
                inside = False
        if inside:
            if line.strip(" \t") == "":
                continue
            route = _ROUTE_PATTERN.fullmatch(line)
            if route is None:
                invalid = True
                continue
            try:
                targets.append(validate_identifier(route.group(1), "route target"))
            except ValidationError:
                invalid = True
    return tuple(targets), invalid


def validate_skill_tree(repo_root: Path, manifest: PackManifest) -> Tuple[Finding, ...]:
    """Validate active Skill prompts, routes, and direct local references."""
    root = _resolved_root(Path(repo_root))
    findings: List[Finding] = []
    parsed_names: Dict[str, List[str]] = {}
    present_files: Set[str] = set()
    texts: Dict[str, str] = {}

    for member in manifest.active_members:
        try:
            validate_identifier(member, "active member")
        except ValidationError as error:
            raise ValidationError("invalid PackManifest active member") from error
        relative = "skills/{0}/SKILL.md".format(member)
        member_root = root / "skills" / member
        lexical_path = member_root / "SKILL.md"
        if _has_reparse_component(root, lexical_path):
            findings.append(
                _finding(
                    "path-containment",
                    relative,
                    "path escapes repository or is a reparse point",
                )
            )
            continue
        try:
            parent_metadata = member_root.lstat()
            file_metadata = lexical_path.lstat()
        except FileNotFoundError:
            findings.append(
                _finding("member-missing", relative, "active member SKILL.md is missing")
            )
            continue
        except OSError:
            findings.append(
                _finding("path-containment", relative, "path escapes repository or is a reparse point")
            )
            continue
        if (
            _is_reparse(parent_metadata)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or _is_reparse(file_metadata)
            or not stat.S_ISREG(file_metadata.st_mode)
            or _regular_file(root, lexical_path) is None
        ):
            findings.append(
                _finding("path-containment", relative, "path escapes repository or is a reparse point")
            )
            continue
        present_files.add(member)
        try:
            raw = lexical_path.read_bytes()
        except OSError:
            findings.append(
                _finding("frontmatter-invalid", relative, "invalid SKILL.md frontmatter")
            )
            continue
        header = _frontmatter(raw)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if header is None or text == "":
            findings.append(
                _finding("frontmatter-invalid", relative, "invalid SKILL.md frontmatter")
            )
            continue
        name = header["name"]
        try:
            validate_identifier(name, "Skill name")
        except ValidationError:
            findings.append(
                _finding("frontmatter-invalid", relative, "invalid SKILL.md frontmatter")
            )
            continue
        if name != member:
            findings.append(
                _finding("frontmatter-invalid", relative, "invalid SKILL.md frontmatter")
            )
        parsed_names.setdefault(name, []).append(relative)
        texts[member] = text

        if _broken_references(root, lexical_path, text):
            findings.append(
                _finding(
                    "reference-broken",
                    relative,
                    "local reference is missing or outside repository",
                )
            )

    for relative_paths in parsed_names.values():
        if len(relative_paths) > 1:
            for relative in relative_paths:
                findings.append(
                    _finding("frontmatter-invalid", relative, "invalid SKILL.md frontmatter")
                )

    umbrella = "obsidian-agent-memory"
    umbrella_relative = "skills/{0}/SKILL.md".format(umbrella)
    if umbrella in texts:
        targets, invalid_routes = _route_declarations(texts[umbrella])
        target_counts = Counter(targets)
        expected_targets = manifest.active_members[1:]
        expected_set = set(expected_targets)
        if (
            invalid_routes
            or umbrella in target_counts
            or any(target_counts[target] > 1 for target in expected_targets)
        ):
            findings.append(
                _finding(
                    "route-invalid",
                    umbrella_relative,
                    "invalid route declaration",
                )
            )
        for target in targets:
            if target == umbrella:
                continue
            if target not in expected_set or target not in present_files:
                findings.append(
                    _finding(
                        "route-missing",
                        umbrella_relative,
                        "route target {0} is missing or inactive".format(target),
                    )
                )
        for target in expected_targets:
            if target_counts[target] == 0:
                findings.append(
                    _finding(
                        "route-missing",
                        umbrella_relative,
                        "route target {0} is missing or inactive".format(target),
                    )
                )

    return _sorted_findings(findings)


def _discover_runtime_files(
    repo_root: Path,
) -> Tuple[Tuple[Finding, ...], Mapping[str, bytes]]:
    root = _resolved_root(repo_root)
    findings: List[Finding] = []
    files: Dict[str, bytes] = {}
    for root_name in ("skills", "tools"):
        scan_root = root / root_name
        try:
            root_metadata = scan_root.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            findings.append(
                _finding(
                    "path-containment",
                    root_name,
                    "path escapes repository or is a reparse point",
                )
            )
            continue
        if _is_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
            findings.append(
                _finding(
                    "path-containment",
                    root_name,
                    "path escapes repository or is a reparse point",
                )
            )
            continue

        for current_text, directory_names, file_names in os.walk(
            str(scan_root), topdown=True, followlinks=False
        ):
            current = Path(current_text)
            retained_directories = []
            for name in sorted(directory_names):
                candidate = current / name
                relative = _relative_posix(root, candidate)
                if _is_excluded(relative):
                    continue
                try:
                    metadata = candidate.lstat()
                except OSError:
                    findings.append(
                        _finding(
                            "path-containment",
                            relative,
                            "path escapes repository or is a reparse point",
                        )
                    )
                    continue
                if (
                    _is_reparse(metadata)
                    or not stat.S_ISDIR(metadata.st_mode)
                    or _contained_candidate(root, candidate) is None
                ):
                    findings.append(
                        _finding(
                            "path-containment",
                            relative,
                            "path escapes repository or is a reparse point",
                        )
                    )
                    continue
                retained_directories.append(name)
            directory_names[:] = retained_directories

            for name in sorted(file_names):
                candidate = current / name
                relative = _relative_posix(root, candidate)
                if _is_excluded(relative):
                    continue
                try:
                    metadata = candidate.lstat()
                except OSError:
                    findings.append(
                        _finding(
                            "path-containment",
                            relative,
                            "path escapes repository or is a reparse point",
                        )
                    )
                    continue
                if _is_reparse(metadata) or _contained_candidate(root, candidate) is None:
                    findings.append(
                        _finding(
                            "path-containment",
                            relative,
                            "path escapes repository or is a reparse point",
                        )
                    )
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                if candidate.suffix.lower() not in _TEXT_SUFFIXES:
                    files[relative] = b""
                    continue
                raw = _read_regular_file(root, candidate)
                if raw is None:
                    findings.append(
                        _finding(
                            "path-containment",
                            relative,
                            "path escapes repository or is a reparse point",
                        )
                    )
                    continue
                files[relative] = raw
    return _sorted_findings(findings), files


def _skill_member_findings(
    repo_root: Path, manifest: PackManifest
) -> Tuple[Finding, ...]:
    root = _resolved_root(repo_root)
    skills_root = root / "skills"
    try:
        root_metadata = skills_root.lstat()
    except OSError:
        return ()
    if _is_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        return ()
    try:
        with os.scandir(str(skills_root)) as iterator:
            entries = tuple(iterator)
    except OSError:
        return ()

    active_members = set(manifest.active_members)
    removed_members = set(manifest.removed_members)
    findings = []
    for entry in entries:
        candidate = Path(entry.path)
        relative = _relative_posix(root, candidate)
        if _is_excluded(relative):
            continue
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            continue
        if entry.name in active_members:
            continue
        if entry.name in removed_members:
            findings.append(
                _finding(
                    "removed-member-present",
                    relative,
                    "removed member is exposed by active source",
                )
            )
        else:
            findings.append(
                _finding(
                    "member-unexpected",
                    relative,
                    "skill member directory is not declared active",
                )
            )
    return _sorted_findings(findings)


def _contains_removed_writer(value: object) -> bool:
    if isinstance(value, str):
        return _REMOVED_WRITER in value
    if isinstance(value, list):
        return any(_contains_removed_writer(item) for item in value)
    if isinstance(value, dict):
        return any(
            _REMOVED_WRITER in str(key) or _contains_removed_writer(item)
            for key, item in value.items()
        )
    return False


def _writer_only_in_removed_metadata(text: str) -> bool:
    try:
        document = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(document, dict):
        return False
    removed = document.get("removed_members")
    if not isinstance(removed, list) or _REMOVED_WRITER not in removed:
        return False
    remainder = dict(document)
    del remainder["removed_members"]
    allowed_occurrences = sum(item == _REMOVED_WRITER for item in removed)
    return (
        not _contains_removed_writer(remainder)
        and text.count(_REMOVED_WRITER) == allowed_occurrences
    )


def _writer_is_allowed(relative: str, text: str) -> bool:
    return bool(
        relative.startswith("tests/")
        or relative == "removal-profiles.json"
        or relative in _REMOVED_WRITER_ALLOWED_PATHS
        or (
            not relative.startswith(("skills/", "tools/"))
            and _writer_only_in_removed_metadata(text)
        )
    )


def _is_removed_writer_member_path(relative: str) -> bool:
    member_root = "skills/{0}".format(_REMOVED_WRITER)
    return relative == member_root or relative.startswith(member_root + "/")


def _json_contains_sensitive_key(text: str) -> bool:
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return False

    pending = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = key.casefold().replace("-", "_")
                if (
                    normalized_key in _SENSITIVE_JSON_KEYS
                    and isinstance(item, str)
                    and item != ""
                ):
                    return True
                pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)
    return False


def _mask_http_span(match: re.Match) -> str:
    token = match.group(0)
    opening = []
    closing_to_opening = {
        ")": "(",
        "]": "[",
        "}": "{",
    }
    for index, character in enumerate(token):
        if character in "([{":
            opening.append(character)
        elif character in closing_to_opening:
            if not opening or opening[-1] != closing_to_opening[character]:
                return " " * index + token[index:]
            opening.pop()
    return " " * len(token)


def _content_findings(relative: str, raw: bytes) -> Tuple[Finding, ...]:
    text = raw.decode("utf-8", errors="ignore")
    path_scan_text = _HTTP_URL_PATTERN.sub(_mask_http_span, text)
    findings = []
    if (
        _HARD_CODED_PATH_PATTERN.search(path_scan_text)
        or _FILE_URI_PATTERN.search(path_scan_text)
        or _DEFAULT_BINDING_PATTERN.search(text)
        or _AMBIENT_HOME_PATTERN.search(text)
    ):
        findings.append(
            _finding(
                "path-hardcoded",
                relative,
                "machine-specific path or default binding detected",
            )
        )
    if _SECRET_ASSIGNMENT_PATTERN.search(text) or _json_contains_sensitive_key(text):
        findings.append(
            _finding(
                "secret-present",
                relative,
                "credential-like literal assignment detected",
            )
        )
    if (
        _REMOVED_WRITER in text
        and not _is_removed_writer_member_path(relative)
        and not _writer_is_allowed(relative, text)
    ):
        findings.append(
            _finding(
                "removed-member-present",
                relative,
                "removed member is exposed by active source",
            )
        )
    return tuple(findings)


def validate_repository(repo_root: Path, manifest: PackManifest) -> Tuple[Finding, ...]:
    """Validate a source repository without writing, repairing, printing, or exiting."""
    root = _resolved_root(Path(repo_root))
    findings: List[Finding] = list(validate_skill_tree(root, manifest))
    findings.extend(_skill_member_findings(root, manifest))
    discovery_findings, runtime_files = _discover_runtime_files(root)
    findings.extend(discovery_findings)

    declared = {item.path: item for item in manifest.files}
    for relative in runtime_files:
        if relative not in declared:
            findings.append(
                _finding(
                    "runtime-file-unmanifested",
                    relative,
                    "runtime file is not listed in manifest",
                )
            )

    manifest_text_files: Dict[str, bytes] = {}
    for item in manifest.files:
        relative = item.path
        if not _manifest_path_is_safe(relative):
            raise ValidationError("invalid PackManifest file path")
        candidate = root.joinpath(*relative.split("/"))
        if _has_reparse_component(root, candidate):
            findings.append(
                _finding(
                    "path-containment",
                    relative,
                    "path escapes repository or is a reparse point",
                )
            )
            continue
        raw = _read_regular_file(root, candidate)
        if raw is None:
            findings.append(
                _finding(
                    "hash-mismatch",
                    relative,
                    "manifest file is missing or its SHA-256 differs",
                )
            )
            continue
        if hashlib.sha256(raw).hexdigest() != item.sha256:
            findings.append(
                _finding(
                    "hash-mismatch",
                    relative,
                    "manifest file is missing or its SHA-256 differs",
                )
            )
        if Path(relative).suffix.lower() in _TEXT_SUFFIXES:
            manifest_text_files[relative] = raw

    for relative, raw in runtime_files.items():
        if Path(relative).suffix.lower() in _TEXT_SUFFIXES:
            findings.extend(_content_findings(relative, raw))

    for relative, raw in manifest_text_files.items():
        if relative in runtime_files:
            continue
        text = raw.decode("utf-8", errors="ignore")
        if _REMOVED_WRITER in text and not _writer_is_allowed(relative, text):
            findings.append(
                _finding(
                    "removed-member-present",
                    relative,
                    "removed member is exposed by active source",
                )
            )

    return _sorted_findings(findings)


def _memory_finding(code: str, severity: str, path: str, message: str) -> Finding:
    return Finding(code=code, severity=severity, path=path, message=message)


def _memory_path_is_safe(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    portable = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return bool(
        not portable.is_absolute()
        and not windows.is_absolute()
        and not windows.drive
        and portable.as_posix() == value
        and all(part not in ("", ".", "..") for part in portable.parts)
    )


def _containment_path(error: _MemoryContainmentError, fallback: str) -> str:
    return error.path if _memory_path_is_safe(error.path) else fallback


def _memory_candidate(root: Path, relative: str) -> Path:
    if not _memory_path_is_safe(relative):
        raise _MemoryContainmentError()
    raw_root = Path(os.path.abspath(os.fspath(root)))
    try:
        root_metadata = raw_root.lstat()
    except OSError as error:
        raise _MemoryContainmentError() from error
    if _is_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise _MemoryContainmentError()
    current = raw_root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise _MemoryContainmentError() from error
        if _is_reparse(metadata):
            raise _MemoryContainmentError()
    try:
        resolved_root = resolve_inside(raw_root)
        resolved_candidate = current.resolve(strict=False)
        resolved_candidate.relative_to(resolved_root)
        return resolved_candidate
    except (ContainmentError, OSError, RuntimeError, ValueError) as error:
        raise _MemoryContainmentError() from error


def _same_file_metadata(first: os.stat_result, second: os.stat_result) -> bool:
    return bool(
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
    )


def _read_memory_file(root: Path, relative: str) -> bytes:
    try:
        candidate = _memory_candidate(root, relative)
    except _MemoryContainmentError as error:
        raise _MemoryContainmentError(relative) from error
    try:
        before = candidate.lstat()
    except FileNotFoundError:
        raise
    except OSError as error:
        raise _MemoryContainmentError(relative) from error
    if _is_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise _MemoryContainmentError(relative)
    try:
        if os.name == "nt":
            descriptor = _windows_memory_read_open(candidate)
        else:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(str(candidate), flags)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise _MemoryContainmentError(relative) from error
    primary_failure_active = False
    try:
        after = os.fstat(descriptor)
        if (
            _is_reparse(after)
            or not stat.S_ISREG(after.st_mode)
            or not _same_file_metadata(before, after)
        ):
            raise _MemoryContainmentError(relative)
        chunks = []
        remaining = _MEMORY_DOCUMENT_LIMIT + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MEMORY_DOCUMENT_LIMIT:
            raise _MemoryOversizeError()
        return raw
    except BaseException as error:
        primary_failure_active = True
        if isinstance(error, OSError):
            raise _MemoryContainmentError(relative) from error
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as error:
            if not primary_failure_active:
                raise _MemoryContainmentError(relative) from error


def _reject_memory_duplicate_keys(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValidationError("duplicate memory JSON key")
        document[key] = value
    return document


def _decode_memory_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_memory_duplicate_keys)
    except (UnicodeDecodeError, ValueError, ValidationError) as error:
        raise ValidationError("invalid memory JSON") from error


def _read_canonical_memory_json(root: Path, relative: str) -> Mapping[str, object]:
    raw = _read_memory_file(root, relative)
    document = _decode_memory_json(raw)
    if not isinstance(document, dict) or raw != _canonical_memory_json(document):
        raise ValidationError("noncanonical memory JSON")
    return document


def _valid_hash(value: object) -> bool:
    return isinstance(value, str) and _MEMORY_HASH_PATTERN.fullmatch(value) is not None


def _valid_memory_timestamp(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and _MEMORY_TIMESTAMP_PATTERN.fullmatch(value) is not None
    )


def _valid_identifier(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        validate_identifier(value, "memory identifier")
    except ValidationError:
        return False
    return True


def _canonical_memory_json(value: Mapping[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def _doctor_catalog_entry(
    memory_id: object,
    value: object,
) -> CatalogEntry:
    keys = {
        "memory_id",
        "owner_scope",
        "project",
        "record_type",
        "relative_path",
        "revision",
    }
    if not isinstance(memory_id, str) or not isinstance(value, dict) or set(value) != keys:
        raise ValidationError("invalid catalog entry")
    if value.get("memory_id") != memory_id or not _valid_identifier(memory_id):
        raise ValidationError("invalid catalog entry")
    revision = value.get("revision")
    if type(revision) is not int or revision <= 0:
        raise ValidationError("invalid catalog entry")
    if not _valid_identifier(value.get("record_type")) or not _valid_identifier(
        value.get("owner_scope")
    ):
        raise ValidationError("invalid catalog entry")
    project = value.get("project")
    if project is not None and not _valid_identifier(project):
        raise ValidationError("invalid catalog entry")
    relative = value.get("relative_path")
    if not (
        _memory_path_is_safe(relative)
        and PurePosixPath(relative).parts
        and PurePosixPath(relative).parts[0] == "_records"
    ):
        raise ValidationError("invalid catalog entry")
    envelope = RecordEnvelope(
        memory_id=memory_id,
        record_type=value["record_type"],
        schema_version=2,
        owner_scope=value["owner_scope"],
        project=project,
        revision=revision,
        supersedes=None,
        created_at="2000-01-01T00:00:00Z",
        observed_at="2000-01-01T00:00:00Z",
        source="catalog",
        source_revision="schema-2",
        body_sha256="0" * 64,
    )
    if record_relative_path(envelope).as_posix() != relative:
        raise ValidationError("invalid catalog entry")
    return CatalogEntry(
        memory_id,
        revision,
        relative,
        value["record_type"],
        value["owner_scope"],
        project,
    )


def _doctor_catalog(root: Path) -> CatalogSnapshot:
    raw = _read_memory_file(root, ".agent-memory/state/catalog.json")
    document = _decode_memory_json(raw)
    if not isinstance(document, dict) or raw != _canonical_memory_json(document):
        raise ValidationError("invalid catalog")
    if set(document) != {"records", "revision", "schema_version"}:
        raise ValidationError("invalid catalog")
    revision = document.get("revision")
    records = document.get("records")
    if not (
        document.get("schema_version") == 2
        and type(document.get("schema_version")) is int
        and type(revision) is int
        and revision >= 0
        and isinstance(records, dict)
        and len(records) <= _MEMORY_INVENTORY_LIMIT
    ):
        raise ValidationError("invalid catalog")
    entries = tuple(
        _doctor_catalog_entry(memory_id, records[memory_id])
        for memory_id in sorted(records)
    )
    return CatalogSnapshot(revision, entries)


def _doctor_record_is_exact(
    root: Path,
    entry: CatalogEntry,
) -> bool:
    raw = _read_memory_file(root, entry.relative_path)
    try:
        text = raw.decode("utf-8")
        envelope, body = parse_record(text)
    except (UnicodeDecodeError, ValidationError):
        return False
    return bool(
        raw == render_record(envelope, body).encode("utf-8")
        and record_relative_path(envelope).as_posix() == entry.relative_path
        and envelope.memory_id == entry.memory_id
        and envelope.revision == entry.revision
        and envelope.record_type == entry.record_type
        and envelope.owner_scope == entry.owner_scope
        and envelope.project == entry.project
    )


def _valid_cas(value: object, revision_name: str) -> bool:
    expected_keys = {
        "desired_revision",
        "desired_sha256",
        "expected_revision",
        "expected_sha256",
        "pending_name",
    }
    return bool(
        isinstance(value, dict)
        and set(value) == expected_keys
        and type(value.get("desired_revision")) is int
        and value["desired_revision"] >= 1
        and type(value.get("expected_revision")) is int
        and value["expected_revision"] >= 0
        and value["desired_revision"] == value["expected_revision"] + 1
        and _valid_hash(value.get("desired_sha256"))
        and _valid_hash(value.get("expected_sha256"))
        and isinstance(value.get("pending_name"), str)
        and re.fullmatch(r"\.pending-[0-9a-f]{64}", value["pending_name"])
        is not None
        and revision_name in ("catalog_revision", "focus_revision")
    )


def _valid_record_desired(value: object, target: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "memory_id",
        "record_candidate",
        "record_candidate_sha256",
        "record_revision",
        "record_sha256",
        "relative_path",
    }:
        return False
    semantic = value.get("record_candidate")
    if not isinstance(semantic, dict) or set(semantic) != {"body", "envelope"}:
        return False
    envelope_value = semantic.get("envelope")
    if not isinstance(envelope_value, dict) or set(envelope_value) != {
        "body_sha256",
        "created_at",
        "memory_id",
        "observed_at",
        "owner_scope",
        "project",
        "record_type",
        "revision",
        "schema_version",
        "source",
        "source_revision",
        "supersedes",
    }:
        return False
    try:
        envelope = RecordEnvelope(**envelope_value)
        rendered = render_record(envelope, semantic.get("body")).encode("utf-8")
        relative_path = record_relative_path(envelope).as_posix()
    except (TypeError, ValidationError):
        return False
    return bool(
        value.get("memory_id") == envelope.memory_id
        and value.get("record_revision") == envelope.revision
        and value.get("relative_path") == relative_path
        and target == relative_path
        and value.get("record_sha256") == hashlib.sha256(rendered).hexdigest()
        and value.get("record_candidate_sha256")
        == hashlib.sha256(_canonical_memory_json(semantic)).hexdigest()
    )


def _valid_task4_desired(operation: str, value: object, target: object) -> bool:
    if not isinstance(value, dict):
        return False
    if operation == "initialize":
        return bool(
            set(value) == {"created_paths", "schema_version"}
            and value.get("schema_version") == 2
            and type(value.get("schema_version")) is int
            and isinstance(value.get("created_paths"), list)
            and bool(value["created_paths"])
            and all(isinstance(item, str) and item for item in value["created_paths"])
            and target == "."
        )
    if operation == "commit-record":
        return _valid_record_desired(value, target)
    if operation == "update_focus":
        record_ids = value.get("record_ids")
        return bool(
            set(value) == {"observed_at", "project_id", "record_ids"}
            and _valid_identifier(value.get("project_id"))
            and _valid_memory_timestamp(value.get("observed_at"))
            and isinstance(record_ids, list)
            and record_ids == sorted(set(record_ids))
            and all(_valid_identifier(item) for item in record_ids)
            and target
            == ".agent-memory/state/focus/{0}.json".format(value["project_id"])
        )
    if operation == "knowledge-promotion":
        source_ids = value.get("source_record_ids")
        return bool(
            set(value)
            == {"candidate_id", "rationale", "source_record_ids", "suggested_target"}
            and _valid_identifier(value.get("candidate_id"))
            and isinstance(source_ids, list)
            and bool(source_ids)
            and all(_valid_identifier(item) for item in source_ids)
            and isinstance(value.get("suggested_target"), str)
            and _memory_path_is_safe(value["suggested_target"])
            and isinstance(value.get("rationale"), str)
            and bool(value["rationale"].strip())
            and target
            == ".agent-memory/state/proposals/{0}.json".format(
                value["candidate_id"]
            )
        )
    return False


def _valid_transaction_common(document: object, transaction_id: str) -> bool:
    if not isinstance(document, dict):
        return False
    common = {
        "actor",
        "desired",
        "expected_base",
        "occurred_at",
        "operation",
        "schema_version",
        "status",
        "target",
        "transaction_id",
    }
    operation = document.get("operation")
    status = document.get("status")
    if not (
        document.get("schema_version") == 2
        and type(document.get("schema_version")) is int
        and operation in _TRANSACTION_OPERATIONS
        and status in _TRANSACTION_STATUSES
        and document.get("transaction_id") == transaction_id
        and _valid_identifier(transaction_id)
        and _valid_identifier(document.get("actor"))
        and _valid_memory_timestamp(document.get("occurred_at"))
        and isinstance(document.get("target"), str)
        and _valid_task4_desired(operation, document.get("desired"), document.get("target"))
    ):
        return False

    expected = document.get("expected_base")
    if operation == "initialize":
        return bool(
            status in ("accepted", "in-progress")
            and set(document) == common | {"created_paths"}
            and expected == {"root_empty": True}
            and document.get("created_paths") == document["desired"]["created_paths"]
        )
    if operation == "commit-record":
        if not (
            isinstance(expected, dict)
            and set(expected) == {"catalog_revision", "record_revision"}
            and type(expected.get("catalog_revision")) is int
            and expected["catalog_revision"] >= 0
            and (
                expected.get("record_revision") is None
                or (
                    type(expected.get("record_revision")) is int
                    and expected["record_revision"] >= 1
                )
            )
        ):
            return False
        if status == "in-progress":
            variants = (
                common,
                common | {"catalog_cas"},
                common
                | {
                    "catalog_cas",
                    "orphan_record_path",
                    "orphan_record_sha256",
                    "orphan_status",
                },
            )
            if set(document) not in variants:
                return False
            if "catalog_cas" in document and not _valid_cas(
                document["catalog_cas"], "catalog_revision"
            ):
                return False
            if "orphan_status" in document:
                return bool(
                    document["orphan_status"] == "published-before-catalog"
                    and document.get("orphan_record_path")
                    == document["desired"]["relative_path"]
                    and document.get("orphan_record_sha256")
                    == document["desired"]["record_sha256"]
                )
            return True
        if status == "accepted":
            return bool(
                set(document)
                == common | {"catalog_cas", "catalog_revision", "record_path"}
                and _valid_cas(document.get("catalog_cas"), "catalog_revision")
                and document.get("catalog_revision")
                == document["catalog_cas"]["desired_revision"]
                and document.get("record_path") == document["desired"]["relative_path"]
            )
        return bool(
            set(document)
            == common
            | {"catalog_revision", "conflict_code", "observed_base", "proposal_path"}
            and type(document.get("catalog_revision")) is int
            and document["catalog_revision"] >= 0
            and _valid_identifier(document.get("conflict_code"))
            and isinstance(document.get("observed_base"), dict)
            and _memory_path_is_safe(document.get("proposal_path"))
        )
    if operation == "update_focus":
        if not (
            isinstance(expected, dict)
            and set(expected) == {"focus_revision"}
            and type(expected.get("focus_revision")) is int
            and expected["focus_revision"] >= 0
        ):
            return False
        if status == "in-progress":
            return bool(
                set(document) in (common, common | {"focus_cas"})
                and (
                    "focus_cas" not in document
                    or _valid_cas(document["focus_cas"], "focus_revision")
                )
            )
        if status == "accepted":
            return bool(
                set(document) == common | {"focus_cas", "focus_revision"}
                and _valid_cas(document.get("focus_cas"), "focus_revision")
                and document.get("focus_revision")
                == document["focus_cas"]["desired_revision"]
            )
        return bool(
            set(document)
            == common
            | {"conflict_code", "focus_revision", "observed_base", "proposal_path"}
            and _valid_identifier(document.get("conflict_code"))
            and type(document.get("focus_revision")) is int
            and document["focus_revision"] >= 0
            and isinstance(document.get("observed_base"), dict)
            and _memory_path_is_safe(document.get("proposal_path"))
        )
    if expected != {}:
        return False
    if status == "in-progress":
        return set(document) == common
    return bool(
        status == "accepted"
        and set(document) == common | {"observed_base", "proposal_path"}
        and isinstance(document.get("observed_base"), dict)
        and _memory_path_is_safe(document.get("proposal_path"))
    )


def _valid_projection_transaction(
    document: object,
    context_hash: str,
    target_hash: str,
) -> bool:
    if not isinstance(document, dict):
        return False
    transaction_id = document.get("transaction_id")
    target = document.get("target")
    evidence = document.get("projection_evidence")
    desired = document.get("desired")
    expected = document.get("expected_base")
    if not _valid_identifier(transaction_id) or not _memory_path_is_safe(target):
        return False
    if (
        hashlib.sha256(transaction_id.encode("utf-8")).hexdigest() != context_hash
        or hashlib.sha256(target.encode("utf-8")).hexdigest() != target_hash
        or not isinstance(evidence, dict)
        or set(evidence) != {"context_sha256", "target_path_sha256"}
        or evidence.get("context_sha256") != context_hash
        or evidence.get("target_path_sha256") != target_hash
        or document.get("operation") != "publish_projection"
        or document.get("schema_version") != 2
        or type(document.get("schema_version")) is not int
        or document.get("status") not in ("accepted", "in-progress")
        or not _valid_identifier(document.get("actor"))
        or not _valid_memory_timestamp(document.get("occurred_at"))
        or not isinstance(desired, dict)
        or set(desired) != {"content_sha256", "source_revision", "target_sha256"}
        or not all(_valid_hash(desired.get(key)) for key in desired)
        or desired.get("content_sha256") != desired.get("target_sha256")
        or not isinstance(expected, dict)
        or set(expected) != {"source_revision", "target_sha256"}
        or not _valid_hash(expected.get("source_revision"))
        or not (expected.get("target_sha256") is None or _valid_hash(expected.get("target_sha256")))
    ):
        return False
    allowed = {
        "actor",
        "desired",
        "expected_base",
        "occurred_at",
        "operation",
        "projection_evidence",
        "schema_version",
        "status",
        "target",
        "transaction_id",
    }
    if document.get("status") == "in-progress" and "projection_recovery" in document:
        allowed.add("projection_recovery")
        recovery = document.get("projection_recovery")
        recovery_relative = ".agent-memory/transactions/projection-recovery/{0}/{1}".format(
            context_hash,
            target_hash,
        )
        observed = recovery.get("observed") if isinstance(recovery, dict) else None
        evidence_paths = (
            recovery.get("evidence_paths") if isinstance(recovery, dict) else None
        )
        if not (
            isinstance(recovery, dict)
            and set(recovery)
            == {
                "evidence_paths",
                "failure_code",
                "observed",
                "observed_sha256",
                "prior_sha256",
                "published_sha256",
                "target",
            }
            and recovery.get("failure_code") == "rollback-target-drift"
            and recovery.get("prior_sha256") == expected.get("target_sha256")
            and recovery.get("published_sha256") == desired.get("target_sha256")
            and recovery.get("target") == target
            and _recovery_namespace_description_is_exact(
                observed,
                target,
                ("absent", "directory", "regular", "reparse", "special"),
            )
            and (
                _valid_hash(recovery.get("observed_sha256"))
                if observed.get("kind") == "regular"
                else recovery.get("observed_sha256") is None
            )
            and isinstance(evidence_paths, list)
            and bool(evidence_paths)
            and len(evidence_paths) <= _MEMORY_INVENTORY_LIMIT
            and evidence_paths == sorted(set(evidence_paths))
            and all(
                _memory_path_is_safe(item)
                and (
                    item == target
                    or item == recovery_relative
                    or item.startswith(recovery_relative + "/")
                )
                for item in evidence_paths
            )
        ):
            return False
    return set(document) == allowed


def _valid_projection_claim(
    document: object,
    context_hash: str,
) -> bool:
    if not isinstance(document, dict) or set(document) != {
        "context_sha256",
        "schema_version",
        "target",
        "target_path_sha256",
        "transaction_id",
    }:
        return False
    transaction_id = document.get("transaction_id")
    target = document.get("target")
    return bool(
        document.get("schema_version") == 2
        and type(document.get("schema_version")) is int
        and _valid_identifier(transaction_id)
        and _memory_path_is_safe(target)
        and document.get("context_sha256") == context_hash
        and hashlib.sha256(transaction_id.encode("utf-8")).hexdigest() == context_hash
        and _valid_hash(document.get("target_path_sha256"))
        and hashlib.sha256(target.encode("utf-8")).hexdigest()
        == document.get("target_path_sha256")
    )


def _valid_proposal(document: object, filename_id: str) -> bool:
    required = {
        "actor",
        "conflict_code",
        "desired",
        "expected_base",
        "observed_base",
        "occurred_at",
        "operation",
        "schema_version",
        "target",
        "transaction_id",
    }
    if not (
        isinstance(document, dict)
        and set(document) == required
        and document.get("schema_version") == 2
        and type(document.get("schema_version")) is int
        and document.get("operation") in _TRANSACTION_OPERATIONS.difference({"initialize"})
        and _valid_identifier(document.get("actor"))
        and _valid_identifier(document.get("transaction_id"))
        and isinstance(document.get("conflict_code"), str)
        and bool(document.get("conflict_code"))
        and isinstance(document.get("desired"), dict)
        and isinstance(document.get("expected_base"), dict)
        and isinstance(document.get("observed_base"), dict)
        and _valid_memory_timestamp(document.get("occurred_at"))
        and isinstance(document.get("target"), str)
    ):
        return False
    operation = document["operation"]
    desired = document["desired"]
    expected = document["expected_base"]
    observed = document["observed_base"]
    transaction_id = document["transaction_id"]
    if operation == "commit-record":
        return bool(
            filename_id == transaction_id
            and _valid_record_desired(desired, document["target"])
            and set(expected) == {"catalog_revision", "record_revision"}
            and type(expected.get("catalog_revision")) is int
            and expected["catalog_revision"] >= 0
            and (
                expected.get("record_revision") is None
                or (
                    type(expected.get("record_revision")) is int
                    and expected["record_revision"] >= 1
                )
            )
            and set(observed).issubset({"catalog_revision", "record_revision"})
        )
    if operation == "update_focus":
        return bool(
            filename_id == transaction_id
            and _valid_task4_desired(operation, desired, document["target"])
            and set(expected) == {"focus_revision"}
            and type(expected.get("focus_revision")) is int
            and expected["focus_revision"] >= 0
            and set(observed).issubset({"focus_revision", "missing_record_ids"})
        )
    source_ids = desired.get("source_record_ids") if isinstance(desired, dict) else None
    return bool(
        operation == "knowledge-promotion"
        and isinstance(desired, dict)
        and set(desired)
        == {"candidate_id", "rationale", "source_record_ids", "suggested_target"}
        and filename_id == desired.get("candidate_id")
        and _valid_identifier(filename_id)
        and isinstance(source_ids, list)
        and bool(source_ids)
        and all(_valid_identifier(item) for item in source_ids)
        and isinstance(desired.get("rationale"), str)
        and bool(desired["rationale"].strip())
        and _memory_path_is_safe(desired.get("suggested_target"))
        and document["target"] == desired["suggested_target"]
        and document["conflict_code"] == "knowledge-promotion-candidate"
        and expected == {"source_record_ids": source_ids}
        and set(observed) == {"catalog_revision"}
        and type(observed.get("catalog_revision")) is int
        and observed["catalog_revision"] >= 0
    )


def _direct_regular_children(
    root: Path,
    relative: str,
    limit: Optional[int] = None,
) -> Tuple[Tuple[str, Path], ...]:
    inventory_limit = _MEMORY_INVENTORY_LIMIT if limit is None else limit
    if type(inventory_limit) is not int or inventory_limit < 0:
        raise ValueError("invalid inventory limit")
    try:
        directory = _memory_candidate(root, relative)
    except _MemoryContainmentError as error:
        raise _MemoryContainmentError(relative) from error
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        return ()
    except OSError as error:
        raise _MemoryContainmentError(relative) from error
    if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise _MemoryContainmentError(relative)
    try:
        with os.scandir(str(directory)) as iterator:
            bounded_entries = []
            for entry in iterator:
                candidate = Path(entry.path)
                child_relative = relative + "/" + entry.name
                try:
                    child_metadata = candidate.lstat()
                except OSError as error:
                    raise _MemoryContainmentError(child_relative) from error
                if _is_reparse(child_metadata):
                    raise _MemoryContainmentError(child_relative)
                bounded_entries.append((entry.name, candidate))
                if len(bounded_entries) > inventory_limit:
                    raise _MemoryOversizeError()
    except OSError as error:
        raise _MemoryContainmentError(relative) from error
    return tuple(
        (relative + "/" + name, candidate)
        for name, candidate in sorted(bounded_entries, key=lambda item: item[0])
    )


def _bounded_root_guard_candidates(root: Path) -> Tuple[Path, ...]:
    """Inventory the root before sorting or classifying its guard candidates."""
    bounded_candidates = []
    contained_failures = []
    entry_count = 0
    try:
        with os.scandir(str(root)) as iterator:
            for entry in iterator:
                entry_count += 1
                if entry.name.startswith(_ROOT_CANDIDATE_PREFIX):
                    candidate = Path(entry.path)
                    bounded_candidates.append(candidate)
                    try:
                        metadata = candidate.lstat()
                    except OSError:
                        contained_failures.append(entry.name)
                    else:
                        if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
                            contained_failures.append(entry.name)
                if entry_count > _ROOT_GUARD_INVENTORY_LIMIT:
                    if contained_failures:
                        raise _MemoryContainmentError(min(contained_failures))
                    raise _MemoryOversizeError()
    except (_MemoryContainmentError, _MemoryOversizeError):
        raise
    except OSError as error:
        raise _MemoryContainmentError() from error
    return tuple(sorted(bounded_candidates, key=lambda path: path.name))


def _bounded_outer_layout(
    root: Path,
    namespace: str,
) -> Tuple[Tuple[str, Path, Tuple[Tuple[str, Path], ...]], ...]:
    """Enumerate one Task 5 two-level layout within one aggregate bound."""
    contexts = _direct_regular_children(root, namespace)
    remaining = _MEMORY_INVENTORY_LIMIT - len(contexts)
    layout = []
    for context_relative, context_path in contexts:
        if not context_path.is_dir():
            children = ()
        else:
            children = _direct_regular_children(root, context_relative, remaining)
            remaining -= len(children)
        layout.append((context_relative, context_path, children))
    return tuple(layout)


def _projection_recovery_children(
    root: Path,
    relative: str,
) -> Tuple[Tuple[Tuple[str, Path], ...], bool, bool]:
    """Bound terminal and non-terminal inventories independently."""
    try:
        directory = _memory_candidate(root, relative)
    except _MemoryContainmentError as error:
        raise _MemoryContainmentError(relative) from error
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        return (), False, False
    except OSError as error:
        raise _MemoryContainmentError(relative) from error
    if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise _MemoryContainmentError(relative)
    entries = []
    terminal_count = 0
    nonterminal_count = 0
    terminal_overflow = False
    nonterminal_overflow = False
    try:
        with os.scandir(str(directory)) as iterator:
            for entry in iterator:
                candidate = Path(entry.path)
                child_relative = relative + "/" + entry.name
                try:
                    child_metadata = candidate.lstat()
                except OSError as error:
                    raise _MemoryContainmentError(child_relative) from error
                if _is_reparse(child_metadata):
                    raise _MemoryContainmentError(child_relative)
                terminal = entry.name.startswith("terminal-")
                if terminal:
                    terminal_count += 1
                    if terminal_count > _MEMORY_INVENTORY_LIMIT:
                        terminal_overflow = True
                        break
                else:
                    nonterminal_count += 1
                    if nonterminal_count > _MEMORY_INVENTORY_LIMIT:
                        nonterminal_overflow = True
                        continue
                entries.append((child_relative, candidate))
    except OSError as error:
        raise _MemoryContainmentError(relative) from error
    return (
        tuple(sorted(entries, key=lambda item: item[1].name)),
        terminal_overflow,
        nonterminal_overflow,
    )


def _projection_generator_version(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError("invalid projection") from error
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ValidationError("invalid projection")
    try:
        closing = lines.index("---", 1)
    except ValueError as error:
        raise ValidationError("invalid projection") from error
    fields = {}
    for line in lines[1:closing]:
        if ": " not in line:
            raise ValidationError("invalid projection")
        key, value = line.split(": ", 1)
        if key in fields:
            raise ValidationError("invalid projection")
        fields[key] = value
    generator_version = fields.get("generator_version")
    if not _valid_identifier(generator_version):
        raise ValidationError("invalid projection")
    return generator_version


def _expected_projection(
    root: Path,
    relative: str,
    generator_version: str,
    observed_target_sha256: str,
) -> bytes:
    expected = build_projection_from_observed_target(
        root,
        relative,
        generator_version,
        observed_target_sha256,
    )
    return expected.content.encode("utf-8")


def _recovery_namespace_description_is_exact(
    value: object,
    expected_path: str,
    allowed_kinds: Iterable[str],
) -> bool:
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    if kind not in frozenset(allowed_kinds) or value.get("path") != expected_path:
        return False
    if kind in ("absent", "unclassifiable"):
        return set(value) == {"kind", "path"}
    if set(value) != {"file_type", "kind", "path"}:
        return False
    file_type = value.get("file_type")
    if type(file_type) is not int:
        return False
    if kind == "regular":
        return file_type == stat.S_IFREG
    if kind == "directory":
        return file_type == stat.S_IFDIR
    if kind == "special":
        return file_type not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK)
    return kind == "reparse"


def _projection_recovery_evidence_paths(
    value: object,
    relative_target: str,
    recovery_relative: str,
) -> Optional[frozenset]:
    if not (
        isinstance(value, list)
        and bool(value)
        and len(value) <= _MEMORY_INVENTORY_LIMIT
        and value == sorted(set(value))
        and all(_memory_path_is_safe(item) for item in value)
    ):
        return None
    if any(
        item != relative_target
        and item != recovery_relative
        and not item.startswith(recovery_relative + "/")
        for item in value
    ):
        return None
    if recovery_relative + "/intent.json" not in value:
        return None
    return frozenset(value)


def _projection_recovery_intent(
    raw: bytes,
    recovery_relative: str,
    context_hash: str,
    target_hash: str,
    owner: Mapping[str, object],
) -> Optional[Mapping[str, object]]:
    document = _canonical_recovery_document(raw)
    if document is None or set(document) != {
        "displaced_path",
        "prior_path",
        "prior_sha256",
        "published_sha256",
        "schema_version",
        "status",
        "target",
        "transaction_id",
    }:
        return None
    prior_sha256 = owner["expected_base"]["target_sha256"]
    published_sha256 = owner["desired"]["target_sha256"]
    expected_prior_path = (
        recovery_relative + "/prior-" + prior_sha256 + ".bin"
        if prior_sha256 is not None
        else None
    )
    return document if (
        document.get("displaced_path") == recovery_relative + "/displaced.bin"
        and document.get("prior_path") == expected_prior_path
        and document.get("prior_sha256") == prior_sha256
        and document.get("published_sha256") == published_sha256
        and document.get("schema_version") == 2
        and type(document.get("schema_version")) is int
        and document.get("status") == "in-progress"
        and document.get("target") == owner.get("target")
        and document.get("transaction_id") == owner.get("transaction_id")
        and hashlib.sha256(document["transaction_id"].encode("utf-8")).hexdigest()
        == context_hash
        and hashlib.sha256(document["target"].encode("utf-8")).hexdigest()
        == target_hash
    ) else None


def _projection_terminal_common_is_exact(
    value: Mapping[str, object],
    owner: Mapping[str, object],
    context_hash: str,
    target_hash: str,
) -> bool:
    evidence = value.get("projection_evidence")
    return bool(
        value.get("prior_sha256") == owner["expected_base"]["target_sha256"]
        and value.get("published_sha256") == owner["desired"]["target_sha256"]
        and value.get("schema_version") == 2
        and type(value.get("schema_version")) is int
        and value.get("status") == "terminal"
        and value.get("target") == owner.get("target")
        and value.get("transaction_id") == owner.get("transaction_id")
        and isinstance(evidence, dict)
        and set(evidence) == {"context_sha256", "target_path_sha256"}
        and evidence.get("context_sha256") == context_hash
        and evidence.get("target_path_sha256") == target_hash
    )


def _projection_terminal_schema_is_exact(
    value: object,
    owner: Mapping[str, object],
    context_hash: str,
    target_hash: str,
    recovery_relative: str,
) -> bool:
    if not isinstance(value, dict) or not _projection_terminal_common_is_exact(
        value, owner, context_hash, target_hash
    ):
        return False
    target = owner["target"]
    prior_hash = owner["expected_base"]["target_sha256"]
    published_hash = owner["desired"]["target_sha256"]
    evidence = _projection_recovery_evidence_paths(
        value.get("evidence_paths"), target, recovery_relative
    )
    if evidence is None:
        return False
    base_keys = {
        "evidence_paths",
        "outcome",
        "prior_sha256",
        "projection_evidence",
        "published_sha256",
        "schema_version",
        "status",
        "target",
        "transaction_id",
    }
    base_evidence = {recovery_relative + "/intent.json"}
    if prior_hash is not None:
        base_evidence.add(recovery_relative + "/prior-" + prior_hash + ".bin")
    outcome = value.get("outcome")
    byte_keys = base_keys.union(
        {
            "displaced",
            "displaced_path",
            "displaced_sha256",
            "observed",
            "observed_sha256",
        }
    )
    if outcome in ("restored", "conflict-preserved") and set(value) == byte_keys:
        displaced_path = recovery_relative + "/displaced.bin"
        if not (
            _recovery_namespace_description_is_exact(
                value.get("displaced"), displaced_path, ("regular",)
            )
            and value.get("displaced_path") == displaced_path
            and _valid_hash(value.get("displaced_sha256"))
            and _recovery_namespace_description_is_exact(
                value.get("observed"),
                target,
                ("absent", "directory", "regular", "reparse", "special"),
            )
        ):
            return False
        observed_hash = value.get("observed_sha256")
        if value["observed"]["kind"] == "regular":
            if not _valid_hash(observed_hash):
                return False
        elif observed_hash is not None:
            return False
        expected_evidence = set(base_evidence)
        if value["displaced_sha256"] != published_hash:
            expected_evidence.add(
                recovery_relative
                + "/unexpected-"
                + value["displaced_sha256"]
                + ".bin"
            )
        if observed_hash is not None:
            expected_evidence.add(
                recovery_relative + "/observed-" + observed_hash + ".bin"
            )
        elif value["observed"]["kind"] != "absent":
            expected_evidence.add(target)
        if evidence != frozenset(expected_evidence):
            return False
        if outcome == "conflict-preserved":
            return True
        if value["displaced_sha256"] != published_hash:
            return False
        return bool(
            (
                prior_hash is None
                and value["observed"]["kind"] == "absent"
                and observed_hash is None
            )
            or (
                prior_hash is not None
                and value["observed"]["kind"] == "regular"
                and observed_hash == prior_hash
            )
        )

    namespace_keys = base_keys.union({"displaced", "observed"})
    if outcome == "conflict-preserved" and set(value) == namespace_keys:
        displaced_path = recovery_relative + "/displaced.bin"
        if not (
            _recovery_namespace_description_is_exact(
                value.get("displaced"),
                displaced_path,
                ("absent", "directory", "reparse", "special"),
            )
            and _recovery_namespace_description_is_exact(
                value.get("observed"),
                target,
                ("absent", "directory", "regular", "reparse", "special"),
            )
        ):
            return False
        expected_evidence = set(base_evidence)
        if value["observed"]["kind"] != "absent":
            expected_evidence.add(target)
            return evidence == frozenset(expected_evidence)
        return evidence in (
            frozenset(expected_evidence),
            frozenset(expected_evidence.union({displaced_path})),
        )

    quarantine_keys = base_keys.union({"endpoint_hashes"})
    if outcome == "quarantine-failed-closed" and set(value) == quarantine_keys:
        endpoint_hashes = value.get("endpoint_hashes")
        if not isinstance(endpoint_hashes, dict) or set(endpoint_hashes) != {
            "quarantine",
            "target",
        }:
            return False
        expected_evidence = set(base_evidence)
        for label in ("quarantine", "target"):
            endpoint_hash = endpoint_hashes[label]
            if endpoint_hash is not None and not _valid_hash(endpoint_hash):
                return False
            if endpoint_hash is not None:
                expected_evidence.add(
                    recovery_relative + "/" + label + "-" + endpoint_hash + ".bin"
                )
        return evidence == frozenset(expected_evidence)

    unexpected_keys = base_keys.union(
        {"endpoints", "error_type", "invalid_terminals"}
    )
    inventory = value.get("terminal_inventory")
    expected_keys = (
        unexpected_keys.union({"terminal_inventory"})
        if inventory is not None
        else unexpected_keys
    )
    if outcome != "unexpected-exception" or set(value) != expected_keys:
        return False
    endpoints = value.get("endpoints")
    invalid = value.get("invalid_terminals")
    if not (
        isinstance(value.get("error_type"), str)
        and bool(value["error_type"])
        and isinstance(endpoints, dict)
        and set(endpoints) == {"quarantine", "target"}
        and _recovery_namespace_description_is_exact(
            endpoints.get("quarantine"),
            recovery_relative + "/displaced.bin",
            ("absent", "directory", "regular", "reparse", "special", "unclassifiable"),
        )
        and _recovery_namespace_description_is_exact(
            endpoints.get("target"),
            target,
            ("absent", "directory", "regular", "reparse", "special", "unclassifiable"),
        )
        and isinstance(invalid, list)
        and len(invalid) <= 64
    ):
        return False
    invalid_paths = []
    for description in invalid:
        if not _projection_invalid_terminal_description_is_exact(
            description, recovery_relative
        ):
            return False
        invalid_paths.append(description["path"])
    if invalid_paths != sorted(set(invalid_paths)):
        return False
    if inventory is not None and not _projection_terminal_inventory_value_is_exact(
        inventory, len(invalid)
    ):
        return False
    expected_evidence = set(base_evidence)
    for endpoint in endpoints.values():
        if endpoint["kind"] not in ("absent", "unclassifiable"):
            expected_evidence.add(endpoint["path"])
    expected_evidence.update(invalid_paths)
    return evidence == frozenset(expected_evidence)


def _projection_terminal_inventory_value_is_exact(
    value: object,
    listed_invalid_count: int,
) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "count",
        "invalid_count",
        "inventory_sha256",
        "limit",
        "listed_invalid_count",
        "valid_count",
    }:
        return False
    counts = tuple(
        value.get(key)
        for key in ("count", "invalid_count", "listed_invalid_count", "valid_count")
    )
    if any(type(item) is not int for item in counts):
        return False
    return bool(
        0 < value["count"] <= _MEMORY_INVENTORY_LIMIT
        and value["count"] == value["invalid_count"] + value["valid_count"]
        and 0 <= value["listed_invalid_count"] <= min(value["invalid_count"], 64)
        and value["listed_invalid_count"] == listed_invalid_count
        and value["limit"] == _MEMORY_INVENTORY_LIMIT
        and _valid_hash(value.get("inventory_sha256"))
    )


def _projection_invalid_terminal_description_is_exact(
    value: object,
    recovery_relative: str,
) -> bool:
    if not isinstance(value, dict):
        return False
    path = value.get("path")
    if not _memory_path_is_safe(path):
        return False
    if path == recovery_relative:
        return value == {"kind": "unclassifiable", "path": recovery_relative}
    portable = PurePosixPath(path)
    if (
        portable.parent.as_posix() != recovery_relative
        or not portable.name.startswith("terminal-")
    ):
        return False
    kind = value.get("kind")
    if kind != "regular":
        return _recovery_namespace_description_is_exact(
            value,
            path,
            ("absent", "directory", "reparse", "special", "unclassifiable"),
        )
    base = {"file_type", "kind", "path"}
    if not _recovery_namespace_description_is_exact(
        {key: value[key] for key in base if key in value},
        path,
        ("regular",),
    ):
        return False
    if set(value) == base:
        return True
    if set(value) == base.union({"raw_sha256"}):
        return _valid_hash(value.get("raw_sha256"))
    if set(value) == base.union({"size"}):
        return type(value.get("size")) is int and value["size"] > _MEMORY_DOCUMENT_LIMIT
    return False


def _projection_terminal_invalid_description(
    relative: str,
    candidate: Path,
    raw: Optional[bytes],
    oversize: bool = False,
) -> Mapping[str, object]:
    try:
        metadata = candidate.lstat()
    except OSError:
        return {"kind": "unclassifiable", "path": relative}
    if _is_reparse(metadata):
        kind = "reparse"
    elif stat.S_ISREG(metadata.st_mode):
        kind = "regular"
    elif stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
    else:
        kind = "special"
    description: Dict[str, object] = {
        "file_type": stat.S_IFMT(metadata.st_mode),
        "kind": kind,
        "path": relative,
    }
    if kind == "regular":
        if oversize:
            description["size"] = metadata.st_size
        elif raw is not None:
            description["raw_sha256"] = hashlib.sha256(raw).hexdigest()
    return description


def _projection_terminal_compact_inventory(
    valid: Iterable[Tuple[str, Mapping[str, object]]],
    invalid: Iterable[Mapping[str, object]],
    excluded_relative: str,
    listed_invalid_count: int,
) -> Mapping[str, object]:
    entries = []
    valid_count = 0
    for relative, _ in valid:
        if relative == excluded_relative:
            continue
        name = PurePosixPath(relative).name
        raw_hash = name[len("terminal-") : -len(".json")]
        entries.append(
            (
                name,
                0,
                {
                    "classification": "valid",
                    "name": name,
                    "raw_sha256": raw_hash,
                },
            )
        )
        valid_count += 1
    invalid_list = list(invalid)
    for description in invalid_list:
        entries.append(
            (
                PurePosixPath(str(description["path"])).name,
                1,
                {
                    "classification": "invalid",
                    "description": description,
                },
            )
        )
    digest = hashlib.sha256()
    digest.update(b"projection-terminal-inventory-v1\n")
    for _, _, entry in sorted(entries, key=lambda item: (item[0], item[1])):
        digest.update(_canonical_memory_json(entry))
    return {
        "count": valid_count + len(invalid_list),
        "invalid_count": len(invalid_list),
        "inventory_sha256": digest.hexdigest(),
        "limit": _MEMORY_INVENTORY_LIMIT,
        "listed_invalid_count": listed_invalid_count,
        "valid_count": valid_count,
    }


def _matching_projection_terminal(
    valid: Tuple[Tuple[str, Mapping[str, object]], ...],
    invalid: Tuple[Mapping[str, object], ...],
) -> Optional[Tuple[str, Mapping[str, object]]]:
    if len(valid) == 1:
        relative, manifest = valid[0]
        if (
            manifest.get("terminal_inventory") is None
            and manifest.get("invalid_terminals", []) == list(invalid)
        ):
            return relative, manifest
    candidates = []
    expected_count = len(valid) - 1 + len(invalid)
    for relative, manifest in valid:
        inventory = manifest.get("terminal_inventory")
        listed_count = (
            inventory.get("listed_invalid_count")
            if isinstance(inventory, dict)
            else None
        )
        if not (
            isinstance(inventory, dict)
            and type(listed_count) is int
            and inventory.get("count") == expected_count
            and inventory.get("invalid_count") == len(invalid)
            and inventory.get("valid_count") == len(valid) - 1
            and manifest.get("invalid_terminals") == list(invalid[:listed_count])
        ):
            continue
        candidates.append((relative, manifest, listed_count))
    if len(candidates) != 1:
        return None
    relative, manifest, listed_count = candidates[0]
    expected = _projection_terminal_compact_inventory(
        valid,
        invalid,
        relative,
        listed_count,
    )
    return (relative, manifest) if manifest["terminal_inventory"] == expected else None


def _projection_recovery_artifact_issue(
    root: Path,
    relative: str,
    expected_hash: str,
) -> Optional[str]:
    try:
        raw = _read_memory_file(root, relative)
    except (FileNotFoundError, _MemoryContainmentError, _MemoryOversizeError):
        return relative
    return relative if hashlib.sha256(raw).hexdigest() != expected_hash else None


def _projection_namespace_issue(
    root: Path,
    description: Mapping[str, object],
    expected_hash: Optional[str] = None,
) -> Optional[str]:
    relative = str(description["path"])
    portable = PurePosixPath(relative)
    parent_relative = portable.parent.as_posix()
    try:
        if parent_relative == ".":
            parent = Path(os.path.abspath(os.fspath(root)))
        else:
            parent = _memory_candidate(root, parent_relative)
        parent_metadata = parent.lstat()
        if _is_reparse(parent_metadata) or not stat.S_ISDIR(parent_metadata.st_mode):
            return relative
        candidate = parent / portable.name
        metadata = candidate.lstat()
    except FileNotFoundError:
        return None if description.get("kind") == "absent" else relative
    except (OSError, _MemoryContainmentError):
        return relative
    if _is_reparse(metadata):
        observed_kind = "reparse"
    elif stat.S_ISREG(metadata.st_mode):
        observed_kind = "regular"
    elif stat.S_ISDIR(metadata.st_mode):
        observed_kind = "directory"
    else:
        observed_kind = "special"
    if description.get("kind") == "absent" or observed_kind != description.get("kind"):
        return relative
    if description.get("file_type") != stat.S_IFMT(metadata.st_mode):
        return relative
    if expected_hash is not None:
        return _projection_recovery_artifact_issue(root, relative, expected_hash)
    return None


def _projection_terminal_evidence_issue(
    root: Path,
    value: Mapping[str, object],
    recovery_relative: str,
    owner: Mapping[str, object],
) -> Optional[str]:
    prior_hash = owner["expected_base"]["target_sha256"]
    if prior_hash is not None:
        relative = recovery_relative + "/prior-" + prior_hash + ".bin"
        issue = _projection_recovery_artifact_issue(root, relative, prior_hash)
        if issue is not None:
            return issue
    outcome = value["outcome"]
    if outcome in ("restored", "conflict-preserved") and "displaced_sha256" in value:
        relative = recovery_relative + "/displaced.bin"
        issue = _projection_recovery_artifact_issue(
            root, relative, value["displaced_sha256"]
        )
        if issue is not None:
            return issue
        if value["displaced_sha256"] != owner["desired"]["target_sha256"]:
            relative = (
                recovery_relative
                + "/unexpected-"
                + value["displaced_sha256"]
                + ".bin"
            )
            issue = _projection_recovery_artifact_issue(
                root, relative, value["displaced_sha256"]
            )
            if issue is not None:
                return issue
        observed = value["observed"]
        observed_hash = value.get("observed_sha256")
        issue = _projection_namespace_issue(root, observed, observed_hash)
        if issue is not None:
            return issue
        if observed_hash is not None:
            relative = recovery_relative + "/observed-" + observed_hash + ".bin"
            issue = _projection_recovery_artifact_issue(root, relative, observed_hash)
            if issue is not None:
                return issue
    elif outcome == "conflict-preserved":
        descriptions = [value["observed"]]
        if value["displaced"]["path"] in value["evidence_paths"]:
            descriptions.append(value["displaced"])
        for description in descriptions:
            issue = _projection_namespace_issue(root, description)
            if issue is not None:
                return issue
    elif outcome == "quarantine-failed-closed":
        for label in ("quarantine", "target"):
            endpoint_hash = value["endpoint_hashes"][label]
            endpoint_relative = (
                recovery_relative + "/displaced.bin"
                if label == "quarantine"
                else owner["target"]
            )
            endpoint_description = (
                {"kind": "absent", "path": endpoint_relative}
                if endpoint_hash is None
                else {
                    "file_type": stat.S_IFREG,
                    "kind": "regular",
                    "path": endpoint_relative,
                }
            )
            issue = _projection_namespace_issue(
                root, endpoint_description, endpoint_hash
            )
            if issue is not None:
                return issue
            if endpoint_hash is not None:
                relative = (
                    recovery_relative + "/" + label + "-" + endpoint_hash + ".bin"
                )
                issue = _projection_recovery_artifact_issue(root, relative, endpoint_hash)
                if issue is not None:
                    return issue
    elif outcome == "unexpected-exception":
        for description in value["endpoints"].values():
            if description.get("kind") == "unclassifiable":
                continue
            issue = _projection_namespace_issue(root, description)
            if issue is not None:
                return issue
    return None


def _validate_projection_recoveries(
    root: Path,
    owners: Mapping[Tuple[str, str], Tuple[str, Mapping[str, object]]],
) -> Tuple[Tuple[Finding, ...], Set[str]]:
    recovery_root = ".agent-memory/transactions/projection-recovery"
    findings: List[Finding] = []
    suppressed: Set[str] = set()

    def invalid(path: str) -> None:
        findings.append(
            _memory_finding(
                "transaction-invalid",
                "error",
                path,
                "invalid canonical transaction JSON or operation schema",
            )
        )

    def contained(error: _MemoryContainmentError, fallback: str) -> None:
        findings.append(
            _memory_finding(
                "path-containment",
                "error",
                _containment_path(error, fallback),
                "candidate path is invalid, escaping, or a reparse point",
            )
        )

    def pending(path: str, owner_relative: str) -> None:
        findings.append(
            _memory_finding(
                "transaction-pending-invalid",
                "error",
                path,
                "transaction-bound pending or recovery evidence is unknown, incomplete, malformed, or mismatched",
            )
        )
        suppressed.add(owner_relative)

    try:
        recovery_layout = _bounded_outer_layout(root, recovery_root)
    except _MemoryContainmentError as error:
        contained(error, recovery_root)
        return _sorted_findings(findings), suppressed
    except _MemoryOversizeError:
        invalid(recovery_root)
        return _sorted_findings(findings), suppressed
    for context_relative, context_path, targets in recovery_layout:
        context_hash = context_path.name
        if not _valid_hash(context_hash) or not context_path.is_dir():
            invalid(recovery_root)
            continue
        for recovery_relative, recovery_path in targets:
            target_hash = recovery_path.name
            owner_entry = owners.get((context_hash, target_hash))
            if not _valid_hash(target_hash) or not recovery_path.is_dir() or owner_entry is None:
                invalid(recovery_root)
                continue
            owner_relative, owner = owner_entry
            if owner.get("status") != "in-progress":
                invalid(recovery_relative)
                suppressed.add(owner_relative)
                continue
            try:
                (
                    children,
                    terminal_overflow,
                    nonterminal_overflow,
                ) = _projection_recovery_children(root, recovery_relative)
            except _MemoryContainmentError as error:
                contained(error, recovery_relative)
                suppressed.add(owner_relative)
                continue
            if terminal_overflow:
                invalid(recovery_relative)
                suppressed.add(owner_relative)
                continue
            by_name = {path.name: (relative, path) for relative, path in children}
            intent_relative = recovery_relative + "/intent.json"
            try:
                intent_raw = _read_memory_file(root, intent_relative)
            except _MemoryContainmentError as error:
                contained(error, intent_relative)
                suppressed.add(owner_relative)
                continue
            except (FileNotFoundError, _MemoryOversizeError):
                invalid(intent_relative)
                suppressed.add(owner_relative)
                continue
            intent = _projection_recovery_intent(
                intent_raw,
                recovery_relative,
                context_hash,
                target_hash,
                owner,
            )
            if intent is None:
                invalid(intent_relative)
                suppressed.add(owner_relative)
                continue
            if nonterminal_overflow:
                pending(recovery_relative, owner_relative)
                continue
            terminal_names = sorted(
                name
                for name in by_name
                if name.startswith("terminal-")
            )
            if not terminal_names:
                pending(recovery_relative, owner_relative)
                continue
            valid_terminals: List[Tuple[str, Mapping[str, object]]] = []
            invalid_terminals: List[Mapping[str, object]] = []
            for name in terminal_names:
                relative, candidate = by_name[name]
                raw = None
                try:
                    raw = _read_memory_file(root, relative)
                except _MemoryOversizeError:
                    invalid_terminals.append(
                        _projection_terminal_invalid_description(
                            relative, candidate, None, oversize=True
                        )
                    )
                    continue
                except (FileNotFoundError, _MemoryContainmentError):
                    invalid_terminals.append(
                        _projection_terminal_invalid_description(
                            relative, candidate, None
                        )
                    )
                    continue
                document = _canonical_recovery_document(raw)
                expected_name = "terminal-" + hashlib.sha256(raw).hexdigest() + ".json"
                if (
                    name != expected_name
                    or document is None
                    or not _projection_terminal_schema_is_exact(
                        document,
                        owner,
                        context_hash,
                        target_hash,
                        recovery_relative,
                    )
                ):
                    invalid_terminals.append(
                        _projection_terminal_invalid_description(
                            relative, candidate, raw
                        )
                    )
                else:
                    valid_terminals.append((relative, document))
            valid_terminal_tuple = tuple(valid_terminals)
            invalid_terminal_tuple = tuple(invalid_terminals)
            semantic_terminal = _matching_projection_terminal(
                valid_terminal_tuple,
                invalid_terminal_tuple,
            )
            if semantic_terminal is None:
                candidate_path = (
                    valid_terminal_tuple[0][0]
                    if valid_terminal_tuple
                    else str(invalid_terminal_tuple[0].get("path", recovery_relative))
                    if invalid_terminal_tuple
                    else recovery_relative
                )
                invalid(
                    candidate_path
                )
                suppressed.add(owner_relative)
                continue
            terminal_relative, terminal = semantic_terminal
            allowed_nonterminal = {"intent.json", "displaced.bin"}
            prior_hash = owner["expected_base"]["target_sha256"]
            if prior_hash is not None:
                allowed_nonterminal.add("prior-" + prior_hash + ".bin")
            for evidence_relative in terminal["evidence_paths"]:
                if evidence_relative.startswith(recovery_relative + "/"):
                    allowed_nonterminal.add(PurePosixPath(evidence_relative).name)
            unknown = sorted(
                name
                for name in by_name
                if name not in allowed_nonterminal and name not in terminal_names
            )
            if unknown:
                pending(by_name[unknown[0]][0], owner_relative)
                continue
            issue = _projection_terminal_evidence_issue(
                root, terminal, recovery_relative, owner
            )
            if issue is not None:
                pending(issue, owner_relative)
    return _sorted_findings(findings), suppressed


def _root_lock_transaction_id(raw: Optional[bytes]) -> Optional[str]:
    if raw is None:
        return None
    try:
        document = _decode_memory_json(raw)
    except ValidationError:
        return None
    if not isinstance(document, dict) or raw != _canonical_memory_json(document):
        return None
    allowed = {"actor", "created_at", "target", "transaction_id"}
    if "process_id" in document:
        allowed.add("process_id")
        if type(document.get("process_id")) is not int or document["process_id"] <= 0:
            return None
    if (
        set(document) != allowed
        or not _valid_identifier(document.get("actor"))
        or not _valid_identifier(document.get("transaction_id"))
        or not isinstance(document.get("created_at"), str)
        or not document["created_at"]
        or document.get("target") != "."
    ):
        return None
    return document["transaction_id"]


def _guard_string_line(
    line: str,
    prefix: str,
    suffix: str,
    identifier: bool,
) -> bool:
    if not line.startswith(prefix) or not line.endswith(suffix):
        return False
    encoded = line[len(prefix) : len(line) - len(suffix)]
    try:
        value = json.loads(encoded)
    except ValueError:
        return False
    return bool(
        isinstance(value, str)
        and value
        and (not identifier or _valid_identifier(value))
    )


def _guard_complete_line(index: int, line: str) -> bool:
    if index == 0:
        return line == "{\n"
    if index == 1:
        return _guard_string_line(line, '  "actor": ', ",\n", True)
    if index == 2:
        return _guard_string_line(line, '  "created_at": ', ",\n", False)
    if index == 3:
        return re.fullmatch(r'  "process_id": [1-9][0-9]*,\n', line) is not None
    if index == 4:
        return line == '  "target": ".",\n'
    if index == 5:
        return _guard_string_line(line, '  "transaction_id": ', "\n", True)
    return index == 6 and line == "}\n"


def _identifier_json_prefix(value: str) -> bool:
    if not value.startswith('"'):
        return '"'.startswith(value)
    remainder = value[1:]
    quote_index = remainder.find('"')
    if quote_index < 0:
        return bool(
            len(remainder) <= 128
            and (not remainder or remainder[0].isalnum())
            and all(
                character.isascii()
                and (character.islower() or character.isdigit() or character in "._-")
                for character in remainder
            )
        )
    scalar = remainder[:quote_index]
    suffix = remainder[quote_index + 1 :]
    return _valid_identifier(scalar) and ",\n".startswith(suffix)


def _guard_partial_line(index: int, line: str) -> bool:
    fixed = {
        0: "{\n",
        1: '  "actor": ',
        2: '  "created_at": ',
        3: '  "process_id": ',
        4: '  "target": ".",\n',
        5: '  "transaction_id": ',
        6: "}\n",
    }[index]
    if fixed.startswith(line):
        return True
    if not line.startswith(fixed):
        return False
    value = line[len(fixed) :]
    if index in (1, 5):
        return _identifier_json_prefix(value)
    if index == 2:
        if not value.startswith('"'):
            return '"'.startswith(value)
        return "\n" not in value and "\r" not in value
    if index == 3:
        return bool(not value or (value.isdigit() and not value.startswith("0")))
    return False


def _normal_guard_prefix_is_possible(raw: Optional[bytes]) -> bool:
    if raw is None:
        return False
    if raw == b"":
        return True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lines = text.splitlines(keepends=True)
    if not lines or len(lines) > 7:
        return False
    for index, line in enumerate(lines):
        last = index == len(lines) - 1
        if line.endswith("\n"):
            if not _guard_complete_line(index, line):
                return False
            continue
        return last and _guard_partial_line(index, line)
    return len(lines) < 7


def _root_candidate_name(root: Path, transaction_id: str) -> str:
    binding = (str(root.resolve(strict=False)) + "\0" + transaction_id).encode("utf-8")
    return _ROOT_CANDIDATE_PREFIX + hashlib.sha256(binding).hexdigest()


def _canonical_recovery_document(raw: bytes) -> Optional[Mapping[str, object]]:
    try:
        document = _decode_memory_json(raw)
    except ValidationError:
        return None
    if not isinstance(document, dict) or raw != _canonical_memory_json(document):
        return None
    return document


def _root_recovery_incomplete_path(
    root: Path,
    operation_relative: str,
) -> Optional[str]:
    """Return the first offending path in one completed immutable recovery event."""
    required_names = (
        "000-prepared.json",
        "010-new-guard-published.json",
        "020-old-artifact-removed.json",
        "old-artifact.bin",
    )
    try:
        children = _direct_regular_children(root, operation_relative)
    except _MemoryContainmentError:
        raise
    except _MemoryOversizeError:
        return operation_relative
    by_name = {candidate.name: (relative, candidate) for relative, candidate in children}
    if len(by_name) != len(children):
        return operation_relative
    unknown = sorted(set(by_name).difference(required_names))
    if unknown:
        return by_name[unknown[0]][0]
    if set(by_name) != set(required_names):
        return operation_relative
    for name in required_names:
        relative, candidate = by_name[name]
        try:
            metadata = candidate.lstat()
        except OSError:
            return relative
        if _is_reparse(metadata):
            raise _MemoryContainmentError(relative)
        if not stat.S_ISREG(metadata.st_mode):
            return relative

    operation_id = PurePosixPath(operation_relative).name
    if not _valid_hash(operation_id):
        return operation_relative
    prepared_relative = by_name["000-prepared.json"][0]
    published_relative = by_name["010-new-guard-published.json"][0]
    removed_relative = by_name["020-old-artifact-removed.json"][0]
    evidence_relative = by_name["old-artifact.bin"][0]
    try:
        prepared_raw = _read_memory_file(root, prepared_relative)
        published_raw = _read_memory_file(root, published_relative)
        removed_raw = _read_memory_file(root, removed_relative)
        evidence_probe = _probe_memory_file(root, evidence_relative, 0)
    except _MemoryContainmentError as error:
        raise _MemoryContainmentError(
            _containment_path(error, evidence_relative)
        ) from error
    except (FileNotFoundError, _MemoryOversizeError):
        return operation_relative
    prepared = _canonical_recovery_document(prepared_raw)
    if prepared is None:
        return prepared_relative
    published = _canonical_recovery_document(published_raw)
    if published is None:
        return published_relative
    removed = _canonical_recovery_document(removed_raw)
    if removed is None:
        return removed_relative
    evidence_raw = evidence_probe.raw
    if evidence_raw is None:
        return evidence_relative

    prepared_keys = {
        "authorization_ref",
        "new_guard",
        "old_artifact",
        "operation_id",
        "operation_tuple",
        "previous_transition_sha256",
        "recovered_kind",
        "schema_version",
        "step",
    }
    operation_tuple = prepared.get("operation_tuple")
    tuple_keys = {
        "authorization_ref",
        "expected_lock_sha256",
        "recovery_transaction_id",
        "target_transaction_id",
    }
    if not (
        set(prepared) == prepared_keys
        and prepared.get("schema_version") == 1
        and type(prepared.get("schema_version")) is int
        and prepared.get("step") == "prepared"
        and prepared.get("previous_transition_sha256") is None
        and prepared.get("operation_id") == operation_id
        and isinstance(operation_tuple, dict)
        and set(operation_tuple) == tuple_keys
        and isinstance(operation_tuple.get("authorization_ref"), str)
        and bool(operation_tuple["authorization_ref"].strip())
        and prepared.get("authorization_ref")
        == operation_tuple.get("authorization_ref")
        and _valid_identifier(operation_tuple.get("recovery_transaction_id"))
        and _valid_identifier(operation_tuple.get("target_transaction_id"))
        and operation_tuple.get("recovery_transaction_id")
        != operation_tuple.get("target_transaction_id")
        and (
            operation_tuple.get("expected_lock_sha256") is None
            or _valid_hash(operation_tuple.get("expected_lock_sha256"))
        )
        and hashlib.sha256(_canonical_memory_json(operation_tuple)).hexdigest()
        == operation_id
    ):
        return prepared_relative

    expected_lock_sha256 = operation_tuple["expected_lock_sha256"]
    recovered_kind = (
        "canonical-lock" if expected_lock_sha256 is not None else "candidate-only"
    )
    recovery_transaction_id = operation_tuple["recovery_transaction_id"]
    target_transaction_id = operation_tuple["target_transaction_id"]
    expected_new_candidate = _root_candidate_name(root, recovery_transaction_id)
    expected_old_candidate = _root_candidate_name(root, target_transaction_id)
    new_guard = prepared.get("new_guard")
    old_artifact = prepared.get("old_artifact")
    if not (
        prepared.get("recovered_kind") == recovered_kind
        and isinstance(new_guard, dict)
        and set(new_guard) == {"candidate", "canonical", "sha256", "size"}
        and new_guard.get("candidate") == expected_new_candidate
        and new_guard.get("canonical") == _ROOT_LOCK_NAME
        and _valid_hash(new_guard.get("sha256"))
        and type(new_guard.get("size")) is int
        and 0 < new_guard["size"] <= _MEMORY_DOCUMENT_LIMIT
        and isinstance(old_artifact, dict)
        and set(old_artifact)
        == {
            "candidate",
            "candidate_present",
            "canonical_present",
            "device",
            "evidence",
            "inode",
            "sha256",
            "size",
        }
        and old_artifact.get("candidate") == expected_old_candidate
        and type(old_artifact.get("candidate_present")) is bool
        and type(old_artifact.get("canonical_present")) is bool
        and old_artifact.get("canonical_present")
        == (recovered_kind == "canonical-lock")
        and old_artifact.get("evidence") == evidence_relative
        and _valid_hash(old_artifact.get("sha256"))
        and type(old_artifact.get("size")) is int
        and old_artifact.get("size") == len(evidence_raw)
        and type(old_artifact.get("device")) is int
        and old_artifact.get("device") == evidence_probe.metadata.st_dev
        and type(old_artifact.get("inode")) is int
        and old_artifact.get("inode") == evidence_probe.metadata.st_ino
        and hashlib.sha256(evidence_raw).hexdigest() == old_artifact.get("sha256")
        and (
            expected_lock_sha256 is None
            or expected_lock_sha256 == old_artifact.get("sha256")
        )
    ):
        return evidence_relative if isinstance(old_artifact, dict) else prepared_relative

    transition_keys = {
        "endpoints",
        "operation_id",
        "previous_transition_sha256",
        "schema_version",
        "step",
    }
    endpoint_keys = {
        "new_candidate",
        "new_canonical",
        "new_device",
        "new_inode",
        "new_sha256",
        "old_candidate_present",
        "old_device",
        "old_evidence",
        "old_inode",
        "old_sha256",
    }
    published_endpoints = published.get("endpoints")
    if not (
        set(published) == transition_keys
        and published.get("operation_id") == operation_id
        and published.get("previous_transition_sha256")
        == hashlib.sha256(prepared_raw).hexdigest()
        and published.get("schema_version") == 1
        and type(published.get("schema_version")) is int
        and published.get("step") == "new-guard-published"
        and isinstance(published_endpoints, dict)
        and set(published_endpoints) == endpoint_keys
        and published_endpoints.get("new_candidate") == expected_new_candidate
        and published_endpoints.get("new_canonical") == _ROOT_LOCK_NAME
        and published_endpoints.get("new_sha256") == new_guard.get("sha256")
        and type(published_endpoints.get("new_device")) is int
        and type(published_endpoints.get("new_inode")) is int
        and published_endpoints.get("old_candidate_present")
        == old_artifact.get("candidate_present")
        and published_endpoints.get("old_evidence") == evidence_relative
        and published_endpoints.get("old_sha256") == old_artifact.get("sha256")
        and published_endpoints.get("old_device") == old_artifact.get("device")
        and published_endpoints.get("old_inode") == old_artifact.get("inode")
    ):
        return published_relative

    expected_removed_endpoints = dict(published_endpoints)
    expected_removed_endpoints["old_candidate_present"] = False
    if not (
        set(removed) == transition_keys
        and removed.get("operation_id") == operation_id
        and removed.get("previous_transition_sha256")
        == hashlib.sha256(published_raw).hexdigest()
        and removed.get("schema_version") == 1
        and type(removed.get("schema_version")) is int
        and removed.get("step") == "old-artifact-removed"
        and removed.get("endpoints") == expected_removed_endpoints
    ):
        return removed_relative
    return None


def _task4_reconciled_state(
    root: Path,
    document: Mapping[str, object],
) -> Tuple[Optional[str], Optional[str]]:
    operation = document["operation"]
    if operation == "update_focus" and "focus_cas" in document:
        target = document["target"]
        state = document["focus_cas"]
    elif operation == "update_focus":
        target = document["target"]
        expected_revision = document["expected_base"]["focus_revision"]
        desired = document["desired"]
        try:
            raw = _read_memory_file(root, target)
        except FileNotFoundError:
            return (
                ("not-run", target)
                if expected_revision == 0
                else ("ambiguous", target)
            )
        except _MemoryOversizeError:
            return "ambiguous", target
        try:
            observed = _decode_memory_json(raw)
        except ValidationError:
            return "ambiguous", target
        desired_document = {
            "observed_at": desired["observed_at"],
            "project_id": desired["project_id"],
            "record_ids": desired["record_ids"],
            "revision": expected_revision + 1,
            "schema_version": 2,
        }
        if raw == _canonical_memory_json(desired_document):
            return "ran", target
        if (
            isinstance(observed, dict)
            and raw == _canonical_memory_json(observed)
            and observed.get("project_id") == desired["project_id"]
            and observed.get("revision") == expected_revision
        ):
            return "not-run", target
        return "ambiguous", target
    elif operation == "commit-record" and "catalog_cas" in document:
        target = ".agent-memory/state/catalog.json"
        state = document["catalog_cas"]
    elif operation == "commit-record":
        target = document["target"]
        state = {
            "expected_sha256": None,
            "desired_sha256": document["desired"]["record_sha256"],
        }
    elif operation == "knowledge-promotion":
        target = document["target"]
        try:
            raw = _read_memory_file(root, target)
        except FileNotFoundError:
            return "not-run", target
        except _MemoryOversizeError:
            return "ambiguous", target
        try:
            proposal = _decode_memory_json(raw)
        except ValidationError:
            return "ambiguous", target
        candidate_id = document["desired"]["candidate_id"]
        if (
            isinstance(proposal, dict)
            and raw == _canonical_memory_json(proposal)
            and _valid_proposal(proposal, candidate_id)
            and proposal.get("transaction_id") == document["transaction_id"]
            and proposal.get("desired") == document["desired"]
        ):
            return "ran", target
        return "ambiguous", target
    else:
        return None, None
    try:
        raw = _read_memory_file(root, target)
    except FileNotFoundError:
        observed = None
    except _MemoryOversizeError:
        observed = "oversize"
    else:
        observed = hashlib.sha256(raw).hexdigest()

    pending_name = state.get("pending_name")
    if pending_name is not None:
        pending_relative = PurePosixPath(target).parent.joinpath(pending_name).as_posix()
        try:
            pending_raw = _read_memory_file(root, pending_relative)
        except FileNotFoundError:
            pass
        except (_MemoryContainmentError, _MemoryOversizeError):
            return "pending-invalid:" + pending_relative, None
        else:
            if hashlib.sha256(pending_raw).hexdigest() != state["desired_sha256"]:
                return "pending-invalid:" + pending_relative, None
    if observed == state["expected_sha256"]:
        return "not-run", target
    if observed == state["desired_sha256"]:
        return "ran", target
    return "ambiguous", target


def doctor_memory_root(root: Path) -> Tuple[Finding, ...]:
    """Return deterministic read-only findings for one explicit memory root."""
    memory_root = Path(os.path.abspath(os.fspath(root)))
    findings: List[Finding] = []

    def add(code: str, severity: str, path: str, message: str) -> None:
        findings.append(_memory_finding(code, severity, path, message))

    try:
        root_metadata = memory_root.lstat()
        if _is_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
            raise _MemoryContainmentError()
    except (OSError, _MemoryContainmentError):
        add(
            "path-containment",
            "error",
            "<root>",
            "candidate path is invalid, escaping, or a reparse point",
        )
        return _sorted_findings(findings)

    initialized = (memory_root / ".agent-memory").exists()
    for relative in (".agent-memory/config.json", ".agent-memory/schema.json"):
        try:
            document = _read_canonical_memory_json(memory_root, relative)
            if not (
                isinstance(document, dict)
                and set(document) == {"schema_version"}
                and type(document.get("schema_version")) is int
                and document.get("schema_version") == 2
            ):
                raise ValidationError("invalid schema")
        except _MemoryContainmentError:
            add(
                "path-containment",
                "error",
                relative,
                "candidate path is invalid, escaping, or a reparse point",
            )
        except (FileNotFoundError, _MemoryOversizeError, ValidationError):
            add("schema-invalid", "error", relative, "invalid Schema 2 JSON document")

    catalog = None
    try:
        catalog = _doctor_catalog(memory_root)
    except _MemoryContainmentError:
        add(
            "path-containment",
            "error",
            ".agent-memory/state/catalog.json",
            "candidate path is invalid, escaping, or a reparse point",
        )
    except (FileNotFoundError, _MemoryOversizeError, ValidationError):
        add(
            "catalog-invalid",
            "error",
            ".agent-memory/state/catalog.json",
            "invalid canonical catalog JSON or schema",
        )
    if catalog is not None:
        for entry in catalog.entries:
            try:
                record_valid = _doctor_record_is_exact(memory_root, entry)
            except FileNotFoundError:
                add(
                    "catalog-record-missing",
                    "error",
                    ".agent-memory/state/catalog.json",
                    "catalog-selected record is missing: {0}".format(entry.relative_path),
                )
                continue
            except _MemoryContainmentError:
                add(
                    "path-containment",
                    "error",
                    entry.relative_path,
                    "candidate path is invalid, escaping, or a reparse point",
                )
                continue
            except _MemoryOversizeError:
                record_valid = False
            if not record_valid:
                add(
                    "catalog-record-mismatch",
                    "error",
                    entry.relative_path,
                    "catalog-selected record envelope, hash, or canonical path does not match",
                )

    catalog_ids = set(entry.memory_id for entry in catalog.entries) if catalog else set()
    project_ids = set(
        entry.project
        for entry in catalog.entries
        if entry.project is not None
    ) if catalog else set()
    focus_root = ".agent-memory/state/focus"
    deferred_focus_pending: List[str] = []
    try:
        focus_children = _direct_regular_children(memory_root, focus_root)
    except _MemoryContainmentError as error:
        add(
            "path-containment",
            "error",
            _containment_path(error, focus_root),
            "candidate path is invalid, escaping, or a reparse point",
        )
        focus_children = ()
    except _MemoryOversizeError:
        add(
            "focus-invalid",
            "error",
            focus_root,
            "invalid canonical focus JSON or schema",
        )
        focus_children = ()
    for relative, candidate in focus_children:
        if re.fullmatch(r"\.pending-[0-9a-f]{64}", candidate.name):
            deferred_focus_pending.append(relative)
            continue
        if candidate.suffix != ".json" or not stat.S_ISREG(candidate.lstat().st_mode):
            add("focus-invalid", "error", relative, "invalid canonical focus JSON or schema")
            continue
        try:
            document = _read_canonical_memory_json(memory_root, relative)
            project_id = candidate.stem
            record_ids = document.get("record_ids") if isinstance(document, dict) else None
            if not (
                isinstance(document, dict)
                and set(document)
                == {"observed_at", "project_id", "record_ids", "revision", "schema_version"}
                and document.get("schema_version") == 2
                and type(document.get("schema_version")) is int
                and document.get("project_id") == project_id
                and _valid_identifier(project_id)
                and type(document.get("revision")) is int
                and document.get("revision") >= 0
                and _valid_memory_timestamp(document.get("observed_at"))
                and isinstance(record_ids, list)
                and len(record_ids) <= _MEMORY_INVENTORY_LIMIT
                and record_ids == sorted(set(record_ids))
                and all(_valid_identifier(item) for item in record_ids)
            ):
                raise ValidationError("invalid focus")
        except _MemoryContainmentError:
            add(
                "path-containment",
                "error",
                relative,
                "candidate path is invalid, escaping, or a reparse point",
            )
            continue
        except (FileNotFoundError, _MemoryOversizeError, ValidationError):
            add("focus-invalid", "error", relative, "invalid canonical focus JSON or schema")
            continue
        for memory_id in record_ids:
            if memory_id not in catalog_ids:
                add(
                    "focus-record-not-current",
                    "error",
                    relative,
                    "focus references a record that is not current in the catalog: {0}".format(
                        memory_id
                    ),
                )
        project_ids.add(project_id)

    transaction_root = ".agent-memory/transactions"
    valid_task4_transactions: Dict[str, Mapping[str, object]] = {}
    try:
        transaction_children = _direct_regular_children(memory_root, transaction_root)
    except _MemoryContainmentError as error:
        add(
            "path-containment",
            "error",
            _containment_path(error, transaction_root),
            "candidate path is invalid, escaping, or a reparse point",
        )
        transaction_children = ()
    except _MemoryOversizeError:
        add(
            "transaction-invalid",
            "error",
            transaction_root,
            "invalid canonical transaction JSON or operation schema",
        )
        transaction_children = ()
    for relative, candidate in transaction_children:
        if candidate.is_dir():
            if candidate.name not in ("projections", "projection-recovery"):
                add(
                    "transaction-invalid",
                    "error",
                    relative,
                    "invalid canonical transaction JSON or operation schema",
                )
            continue
        if candidate.suffix != ".json":
            add(
                "transaction-invalid",
                "error",
                relative,
                "invalid canonical transaction JSON or operation schema",
            )
            continue
        try:
            document = _read_canonical_memory_json(memory_root, relative)
        except _MemoryContainmentError:
            add(
                "path-containment",
                "error",
                relative,
                "candidate path is invalid, escaping, or a reparse point",
            )
            continue
        except (FileNotFoundError, _MemoryOversizeError, ValidationError):
            document = None
        if not _valid_transaction_common(document, candidate.stem):
            add(
                "transaction-invalid",
                "error",
                relative,
                "invalid canonical transaction JSON or operation schema",
            )
        else:
            valid_task4_transactions[relative] = document

    bound_focus_pending = set()
    for document in valid_task4_transactions.values():
        if (
            document.get("status") == "in-progress"
            and document.get("operation") == "update_focus"
            and isinstance(document.get("focus_cas"), dict)
        ):
            bound_focus_pending.add(
                PurePosixPath(document["target"])
                .parent.joinpath(document["focus_cas"]["pending_name"])
                .as_posix()
            )
    for relative in deferred_focus_pending:
        if relative not in bound_focus_pending:
            add(
                "focus-invalid",
                "error",
                relative,
                "invalid canonical focus JSON or schema",
            )

    for relative, document in valid_task4_transactions.items():
        if document["status"] != "in-progress":
            continue
        try:
            state, _ = _task4_reconciled_state(memory_root, document)
        except _MemoryContainmentError:
            add(
                "path-containment",
                "error",
                document["target"] if _memory_path_is_safe(document["target"]) else "<root>",
                "candidate path is invalid, escaping, or a reparse point",
            )
            continue
        if state is None:
            add(
                "transaction-incomplete-ambiguous",
                "error",
                relative,
                "in-progress transaction has no single reconciled canonical outcome",
            )
        elif state.startswith("pending-invalid:"):
            add(
                "transaction-pending-invalid",
                "error",
                state.split(":", 1)[1],
                "transaction-bound pending or recovery evidence is unknown, incomplete, malformed, or mismatched",
            )
        elif state == "not-run":
            add(
                "transaction-incomplete-not-run",
                "warning",
                relative,
                "transaction or pre-intent claim has not applied a canonical mutation",
            )
        elif state == "ran":
            add(
                "transaction-incomplete-ran",
                "error",
                relative,
                "in-progress transaction canonical target is at the recorded desired state but was not finalized",
            )
        else:
            add(
                "transaction-incomplete-ambiguous",
                "error",
                relative,
                "in-progress transaction has no single reconciled canonical outcome",
            )

    projection_root = ".agent-memory/transactions/projections"
    projection_owners: Dict[
        Tuple[str, str], Tuple[str, Mapping[str, object]]
    ] = {}
    try:
        projection_layout = _bounded_outer_layout(memory_root, projection_root)
    except _MemoryContainmentError as error:
        add(
            "path-containment",
            "error",
            _containment_path(error, projection_root),
            "candidate path is invalid, escaping, or a reparse point",
        )
        projection_layout = ()
    except _MemoryOversizeError:
        add(
            "transaction-invalid",
            "error",
            projection_root,
            "invalid canonical transaction JSON or operation schema",
        )
        projection_layout = ()
    for context_relative, context_path, children in projection_layout:
        context_hash = context_path.name
        if not _valid_hash(context_hash) or not context_path.is_dir():
            add(
                "transaction-invalid",
                "error",
                projection_root,
                "invalid canonical transaction JSON or operation schema",
            )
            continue
        claim_relative = None
        claim_document = None
        valid_journals: Dict[str, Mapping[str, object]] = {}
        context_invalid = False
        for relative, child in children:
            if child.name == "unguarded-target.claim":
                claim_relative = relative
                try:
                    claim_document = _read_canonical_memory_json(memory_root, relative)
                except _MemoryContainmentError:
                    add(
                        "path-containment",
                        "error",
                        relative,
                        "candidate path is invalid, escaping, or a reparse point",
                    )
                    context_invalid = True
                    continue
                except (_MemoryOversizeError, ValidationError):
                    claim_document = None
                if not _valid_projection_claim(claim_document, context_hash):
                    add(
                        "transaction-invalid",
                        "error",
                        relative,
                        "invalid canonical transaction JSON or operation schema",
                    )
                    context_invalid = True
                continue
            if child.suffix != ".json" or not _valid_hash(child.stem):
                add(
                    "transaction-invalid",
                    "error",
                    projection_root,
                    "invalid canonical transaction JSON or operation schema",
                )
                context_invalid = True
                continue
            try:
                document = _read_canonical_memory_json(memory_root, relative)
            except _MemoryContainmentError:
                add(
                    "path-containment",
                    "error",
                    relative,
                    "candidate path is invalid, escaping, or a reparse point",
                )
                context_invalid = True
                continue
            except (_MemoryOversizeError, ValidationError):
                document = None
            if not _valid_projection_transaction(document, context_hash, child.stem):
                add(
                    "transaction-invalid",
                    "error",
                    relative,
                    "invalid canonical transaction JSON or operation schema",
                )
                context_invalid = True
                continue
            valid_journals[child.stem] = document
            projection_owners[(context_hash, child.stem)] = (relative, document)
        if claim_relative is not None and claim_document is not None and not context_invalid:
            target_hash = claim_document["target_path_sha256"]
            journal = valid_journals.get(target_hash)
            if valid_journals and (
                len(valid_journals) != 1
                or journal is None
                or journal.get("transaction_id")
                != claim_document.get("transaction_id")
                or journal.get("target") != claim_document.get("target")
            ):
                add(
                    "transaction-invalid",
                    "error",
                    claim_relative,
                    "invalid canonical transaction JSON or operation schema",
                )
            elif journal is None:
                add(
                    "transaction-incomplete-not-run",
                    "warning",
                    claim_relative,
                    "transaction or pre-intent claim has not applied a canonical mutation",
                )
        if not context_invalid:
            for target_hash, document in valid_journals.items():
                relative = context_relative + "/" + target_hash + ".json"
                if document["status"] == "accepted":
                    continue
                target = document["target"]
                try:
                    target_raw = _read_memory_file(memory_root, target)
                except FileNotFoundError:
                    observed_hash = None
                except _MemoryContainmentError:
                    add(
                        "path-containment",
                        "error",
                        target,
                        "candidate path is invalid, escaping, or a reparse point",
                    )
                    continue
                except _MemoryOversizeError:
                    observed_hash = "oversize"
                else:
                    observed_hash = hashlib.sha256(target_raw).hexdigest()
                desired_hash = document["desired"]["target_sha256"]
                expected_hash = document["expected_base"]["target_sha256"]
                if observed_hash == expected_hash:
                    add(
                        "transaction-incomplete-not-run",
                        "warning",
                        relative,
                        "transaction or pre-intent claim has not applied a canonical mutation",
                    )
                elif observed_hash == desired_hash:
                    add(
                        "transaction-incomplete-ran",
                        "error",
                        relative,
                        "in-progress transaction canonical target is at the recorded desired state but was not finalized",
                    )
                else:
                    add(
                        "transaction-incomplete-ambiguous",
                        "error",
                        relative,
                        "in-progress transaction has no single reconciled canonical outcome",
                    )

    recovery_findings, suppressed_projection_owners = _validate_projection_recoveries(
        memory_root,
        projection_owners,
    )
    if suppressed_projection_owners:
        findings = [
            finding
            for finding in findings
            if not (
                finding.path in suppressed_projection_owners
                and finding.code.startswith("transaction-incomplete-")
            )
        ]
    findings.extend(recovery_findings)

    proposal_root = ".agent-memory/state/proposals"
    try:
        migration_proposal_bindings = index_applied_migration_proposals(memory_root)
    except AgentMemoryError:
        migration_proposal_bindings = {}
    try:
        proposal_children = _direct_regular_children(memory_root, proposal_root)
    except _MemoryContainmentError as error:
        add(
            "path-containment",
            "error",
            _containment_path(error, proposal_root),
            "candidate path is invalid, escaping, or a reparse point",
        )
        proposal_children = ()
    except _MemoryOversizeError:
        add(
            "proposal-invalid",
            "error",
            proposal_root,
            "invalid canonical proposal JSON or schema",
        )
        proposal_children = ()
    for relative, candidate in proposal_children:
        try:
            raw = _read_memory_file(memory_root, relative)
            artifact = parse_proposal_artifact(relative, raw)
        except _MemoryContainmentError:
            add(
                "path-containment",
                "error",
                relative,
                "candidate path is invalid, escaping, or a reparse point",
            )
            continue
        except (FileNotFoundError, _MemoryOversizeError, ValidationError):
            artifact = None
        if candidate.suffix != ".json" or artifact is None:
            add(
                "proposal-invalid",
                "error",
                relative,
                "invalid canonical proposal JSON or schema",
            )
            continue
        if isinstance(artifact, MigrationReviewProposal):
            bindings = migration_proposal_bindings.get(relative, ())
            if not (
                len(bindings) == 1
                and bindings[0].proposal_after_sha256 == artifact.sha256
                and bindings[0].source_revision == artifact.source_revision
            ):
                add(
                    "proposal-unbound",
                    "error",
                    relative,
                    "migration review proposal lacks one exact applied journal binding",
                )
            continue
        if artifact.operation == "knowledge-promotion":
            desired = artifact.desired
            source_ids = desired.get("source_record_ids") if isinstance(desired, dict) else None
            if not (
                isinstance(desired, dict)
                and set(desired)
                == {"candidate_id", "rationale", "source_record_ids", "suggested_target"}
                and desired.get("candidate_id") == candidate.stem
                and _valid_identifier(candidate.stem)
                and isinstance(source_ids, list)
                and bool(source_ids)
                and all(_valid_identifier(item) for item in source_ids)
                and all(item in catalog_ids for item in source_ids)
                and _memory_path_is_safe(desired.get("suggested_target"))
                and isinstance(desired.get("rationale"), str)
                and bool(desired.get("rationale").strip())
            ):
                add(
                    "promotion-candidate-invalid",
                    "warning",
                    relative,
                    "knowledge promotion candidate is invalid or its source records are not current",
                )

    projection_candidates = set() if catalog is None else {
        "_index/current-focus.md",
        "_index/home.md",
        "_index/memory-map.md",
        "_index/stale-or-uncertain.md",
    }
    for project_id in sorted(project_ids):
        projection_candidates.update(
            {
                "projects/{0}/current-focus.md".format(project_id),
                "projects/{0}/overview.md".format(project_id),
            }
        )
        if catalog is not None:
            projection_candidates.update(
                "projects/{0}/stories/{1}.md".format(project_id, entry.memory_id)
                for entry in catalog.entries
                if entry.project == project_id and entry.record_type == "story"
            )
    if catalog is not None:
        try:
            filesystem_projects = _direct_regular_children(memory_root, "projects")
        except _MemoryContainmentError as error:
            add(
                "path-containment",
                "error",
                _containment_path(error, "projects"),
                "candidate path is invalid, escaping, or a reparse point",
            )
            filesystem_projects = ()
        except _MemoryOversizeError:
            filesystem_projects = ()
        for project_relative, project_path in filesystem_projects:
            project_id = project_path.name
            if not project_path.is_dir() or not _valid_identifier(project_id):
                continue
            projection_candidates.update(
                {
                    project_relative + "/current-focus.md",
                    project_relative + "/overview.md",
                }
            )
            stories_relative = project_relative + "/stories"
            try:
                stories = _direct_regular_children(memory_root, stories_relative)
            except _MemoryContainmentError as error:
                add(
                    "path-containment",
                    "error",
                    _containment_path(error, stories_relative),
                    "candidate path is invalid, escaping, or a reparse point",
                )
                continue
            except _MemoryOversizeError:
                continue
            projection_candidates.update(
                relative
                for relative, story_path in stories
                if story_path.is_file()
                and story_path.suffix == ".md"
                and _valid_identifier(story_path.stem)
            )
    for relative in sorted(projection_candidates):
        try:
            raw = _read_memory_file(memory_root, relative)
            generator_version = _projection_generator_version(raw)
            expected = _expected_projection(
                memory_root,
                relative,
                generator_version,
                hashlib.sha256(raw).hexdigest(),
            )
            if raw != expected:
                raise ValidationError("projection drift")
        except _MemoryContainmentError:
            add(
                "path-containment",
                "error",
                relative,
                "candidate path is invalid, escaping, or a reparse point",
            )
        except FileNotFoundError:
            continue
        except (_MemoryOversizeError, ValidationError):
            add(
                "projection-drift",
                "warning",
                relative,
                "generated projection differs from deterministic canonical output",
            )
        except AgentMemoryError:
            continue

    anchor_result = None
    anchor_valid = False
    anchor_state = "absent"
    if initialized:
        try:
            anchor_result = _probe_memory_file(
                memory_root,
                _ROOT_ANCHOR_NAME,
                0,
                locked_expected=_ROOT_ANCHOR_BYTES,
            )
        except _MemoryContainmentError:
            anchor_state = "invalid"
            add(
                "path-containment",
                "error",
                _ROOT_ANCHOR_NAME,
                "candidate path is invalid, escaping, or a reparse point",
            )
        except FileNotFoundError:
            add(
                "root-write-anchor-missing",
                "error",
                _ROOT_ANCHOR_NAME,
                "initialized root is missing the root-write namespace anchor",
            )
        except _MemoryOversizeError:
            anchor_state = "invalid"
            add(
                "root-write-anchor-malformed",
                "error",
                _ROOT_ANCHOR_NAME,
                "root-write namespace anchor bytes are malformed",
            )
        else:
            anchor_state = "present"
            if anchor_result.raw != _ROOT_ANCHOR_BYTES:
                add(
                    "root-write-anchor-malformed",
                    "error",
                    _ROOT_ANCHOR_NAME,
                    "root-write namespace anchor bytes are malformed",
                )
            else:
                anchor_valid = True

    anchor_candidate_result = None
    try:
        anchor_candidate_result = _probe_memory_file(
            memory_root,
            _ANCHOR_CANDIDATE_NAME,
            0,
            locked_expected=_ROOT_ANCHOR_BYTES,
        )
    except FileNotFoundError:
        pass
    except (_MemoryContainmentError, _MemoryOversizeError):
        add(
            "root-write-anchor-candidate-malformed",
            "error",
            _ANCHOR_CANDIDATE_NAME,
            "root-write namespace bootstrap candidate bytes or identity are malformed",
        )
    else:
        candidate_raw = anchor_candidate_result.raw
        candidate_valid = bool(
            candidate_raw is not None
            and _ROOT_ANCHOR_BYTES.startswith(candidate_raw)
        )
        if anchor_state == "present":
            candidate_valid = bool(
                candidate_valid
                and anchor_valid
                and candidate_raw == _ROOT_ANCHOR_BYTES
                and anchor_result is not None
                and _same_file_metadata(
                    anchor_candidate_result.metadata,
                    anchor_result.metadata,
                )
                and anchor_candidate_result.busy == anchor_result.busy
            )
        elif anchor_state == "invalid":
            candidate_valid = False
        if candidate_valid:
            if anchor_candidate_result.busy:
                add(
                    "root-write-anchor-candidate-active",
                    "warning",
                    _ANCHOR_CANDIDATE_NAME,
                    "root-write namespace bootstrap candidate has a live lease",
                )
            else:
                add(
                    "root-write-anchor-candidate-stale",
                    "warning",
                    _ANCHOR_CANDIDATE_NAME,
                    "root-write namespace bootstrap candidate is stale-resumable",
                )
        else:
            add(
                "root-write-anchor-candidate-malformed",
                "error",
                _ANCHOR_CANDIDATE_NAME,
                "root-write namespace bootstrap candidate bytes or identity are malformed",
            )

    guard_inventory_invalid = False
    try:
        guard_candidates = _bounded_root_guard_candidates(memory_root)
    except _MemoryContainmentError as error:
        add(
            "path-containment",
            "error",
            _containment_path(error, "<root>"),
            "candidate path is invalid, escaping, or a reparse point",
        )
        guard_candidates = ()
        guard_inventory_invalid = True
    except _MemoryOversizeError:
        add(
            "root-write-malformed",
            "error",
            _ROOT_LOCK_NAME,
            "root-write guard bytes, identity, or candidate inventory are malformed",
        )
        guard_candidates = ()
        guard_inventory_invalid = True
    canonical_guard = memory_root / _ROOT_LOCK_NAME
    try:
        canonical_guard.lstat()
    except FileNotFoundError:
        canonical_exists = False
    except OSError:
        canonical_exists = True
    else:
        canonical_exists = True

    canonical_probe = None
    canonical_transaction_id = None
    canonical_containment = False
    if canonical_exists:
        try:
            canonical_probe = _probe_memory_file(
                memory_root, _ROOT_LOCK_NAME, _OBSERVABLE_GUARD_LOCK_OFFSET
            )
            canonical_transaction_id = _root_lock_transaction_id(canonical_probe.raw)
        except _MemoryContainmentError as error:
            add(
                "path-containment",
                "error",
                _containment_path(error, _ROOT_LOCK_NAME),
                "candidate path is invalid, escaping, or a reparse point",
            )
            canonical_containment = True
        except (_MemoryOversizeError, FileNotFoundError):
            pass

    expected_candidate_name = (
        _root_candidate_name(memory_root, canonical_transaction_id)
        if canonical_transaction_id is not None
        else None
    )
    candidate_containment: Set[str] = set()
    candidate_unreadable: Set[str] = set()
    candidate_summaries: Dict[str, Tuple[Optional[str], bool]] = {}
    expected_candidate_probe = None
    for candidate_path in guard_candidates:
        candidate_relative = candidate_path.name
        try:
            observed_candidate_probe = _probe_memory_file(
                memory_root,
                candidate_relative,
                _OBSERVABLE_GUARD_LOCK_OFFSET,
            )
        except _MemoryContainmentError as error:
            candidate_containment.add(candidate_relative)
            add(
                "path-containment",
                "error",
                _containment_path(error, candidate_relative),
                "candidate path is invalid, escaping, or a reparse point",
            )
        except (_MemoryOversizeError, FileNotFoundError):
            candidate_unreadable.add(candidate_relative)
        else:
            candidate_summaries[candidate_relative] = (
                _root_lock_transaction_id(observed_candidate_probe.raw),
                _normal_guard_prefix_is_possible(observed_candidate_probe.raw),
            )
            if candidate_relative == expected_candidate_name:
                expected_candidate_probe = observed_candidate_probe

    safe_guard_candidates = tuple(
        path
        for path in guard_candidates
        if path.name not in candidate_containment
    )

    def classify_candidate_only() -> None:
        if len(safe_guard_candidates) != 1:
            for candidate_path in safe_guard_candidates:
                add(
                    "root-write-malformed",
                    "error",
                    candidate_path.name,
                    "root-write guard bytes, identity, or candidate inventory are malformed",
                )
            return
        candidate_path = safe_guard_candidates[0]
        candidate_summary = candidate_summaries.get(candidate_path.name)
        if candidate_path.name in candidate_unreadable or candidate_summary is None:
            valid_candidate = False
        else:
            transaction_id, prefix_is_possible = candidate_summary
            candidate_suffix = candidate_path.name[len(_ROOT_CANDIDATE_PREFIX) :]
            valid_candidate = bool(
                _valid_hash(candidate_suffix)
                and (
                    candidate_path.name
                    == _root_candidate_name(memory_root, transaction_id)
                    if transaction_id is not None
                    else prefix_is_possible
                )
            )
        if valid_candidate:
            add(
                "root-write-candidate",
                "warning",
                candidate_path.name,
                "candidate-only root-write guard evidence requires explicit recovery review",
            )
        else:
            add(
                "root-write-malformed",
                "error",
                candidate_path.name,
                "root-write guard bytes, identity, or candidate inventory are malformed",
            )

    if guard_inventory_invalid:
        pass
    elif canonical_exists and not canonical_containment:
        matching_candidates = tuple(
            path
            for path in safe_guard_candidates
            if path.name == expected_candidate_name
        )
        guard_is_valid = bool(
            canonical_probe is not None
            and canonical_transaction_id is not None
            and len(matching_candidates) == 1
            and len(safe_guard_candidates) == 1
            and expected_candidate_probe is not None
            and expected_candidate_probe.raw == canonical_probe.raw
            and _same_file_metadata(
                expected_candidate_probe.metadata, canonical_probe.metadata
            )
        )
        if guard_is_valid and anchor_valid and anchor_result is not None:
            busy_tuple = (
                anchor_result.busy,
                canonical_probe.busy,
                expected_candidate_probe.busy,
            )
            if busy_tuple == (True, True, True):
                add(
                    "root-write-active",
                    "warning",
                    _ROOT_LOCK_NAME,
                    "root-write guard has a live lease",
                )
            elif busy_tuple == (False, False, False):
                add(
                    "root-write-stale",
                    "warning",
                    _ROOT_LOCK_NAME,
                    "root-write guard lease is acquirable and requires explicit recovery review",
                )
            else:
                guard_is_valid = False
        if not guard_is_valid:
            if expected_candidate_name not in candidate_containment:
                add(
                    "root-write-malformed",
                    "error",
                    _ROOT_LOCK_NAME,
                    "root-write guard bytes, identity, or candidate inventory are malformed",
                )
            for candidate_path in safe_guard_candidates:
                if candidate_path.name != expected_candidate_name:
                    add(
                        "root-write-malformed",
                        "error",
                        candidate_path.name,
                        "root-write guard bytes, identity, or candidate inventory are malformed",
                    )
    elif guard_candidates:
        classify_candidate_only()

    recovery_root = ".agent-memory-root-write-recoveries"
    try:
        recovery_operations = _direct_regular_children(memory_root, recovery_root)
    except _MemoryContainmentError as error:
        add(
            "path-containment",
            "error",
            _containment_path(error, recovery_root),
            "candidate path is invalid, escaping, or a reparse point",
        )
        recovery_operations = ()
    except _MemoryOversizeError:
        add(
            "root-write-recovery-incomplete",
            "error",
            recovery_root,
            "root-write recovery transition chain is incomplete, missing, duplicate, unknown, reordered, or hash-divergent",
        )
        recovery_operations = ()
    for operation_relative, operation_path in recovery_operations:
        try:
            operation_metadata = operation_path.lstat()
        except OSError:
            operation_metadata = None
        if (
            operation_metadata is None
            or _is_reparse(operation_metadata)
            or not stat.S_ISDIR(operation_metadata.st_mode)
            or not _valid_hash(operation_path.name)
        ):
            offending = recovery_root
        else:
            try:
                offending = _root_recovery_incomplete_path(
                    memory_root, operation_relative
                )
            except _MemoryContainmentError as error:
                add(
                    "path-containment",
                    "error",
                    _containment_path(error, operation_relative),
                    "candidate path is invalid, escaping, or a reparse point",
                )
                continue
        if offending is not None:
            add(
                "root-write-recovery-incomplete",
                "error",
                offending,
                "root-write recovery transition chain is incomplete, missing, duplicate, unknown, reordered, or hash-divergent",
            )

    return _sorted_findings(findings)
