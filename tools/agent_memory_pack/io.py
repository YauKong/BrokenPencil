"""Crash-safe byte publication helpers for release and lifecycle metadata."""

import ctypes
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Optional

from obsidian_agent_memory import ConflictError, ValidationError, validate_identifier


_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_sha256(value: Optional[str], field: str) -> Optional[str]:
    if value is not None and not _SHA256_PATTERN.fullmatch(value):
        raise ValidationError("invalid {0}".format(field))
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def _raw_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _assert_plain_components(path: Path, allow_missing: bool) -> None:
    absolute = _raw_absolute(path)
    current = Path(absolute.anchor)
    missing = False
    for component in absolute.parts[1:]:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if not allow_missing:
                raise ValidationError("publication path is missing")
            missing = True
            continue
        except OSError as error:
            raise ValidationError("publication path cannot be inspected") from error
        if missing:
            raise ValidationError("publication path changed during inspection")
        if _is_reparse(metadata):
            raise ValidationError("publication path contains a reparse point")


def _read_hash(path: Path) -> Optional[str]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ValidationError("publication endpoint cannot be inspected") from error
    if _is_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise ValidationError("publication endpoint is not a regular file")
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise ValidationError("publication endpoint cannot be read") from error
    if (
        _is_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
    ):
        raise ConflictError("publication endpoint changed during inspection")
    return _sha256(raw)


def _require_current_hash(path: Path, expected_sha256: Optional[str]) -> None:
    actual = _read_hash(path)
    if actual != expected_sha256:
        raise ConflictError("publication target revision changed")


def _fsync_directory(directory: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return

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
        str(directory),
        0x40000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise OSError(ctypes.get_last_error(), "cannot open directory for durability flush")
    try:
        flush = kernel32.FlushFileBuffers
        flush.argtypes = (ctypes.c_void_p,)
        flush.restype = ctypes.c_int
        if not flush(handle):
            raise OSError(ctypes.get_last_error(), "cannot flush directory metadata")
    finally:
        kernel32.CloseHandle(handle)


def _checkpoint(stage: str) -> None:
    del stage


def _pending_path(
    path: Path,
    data: bytes,
    operation_id: str,
    transition_id: str,
    expected_sha256: Optional[str],
) -> Path:
    validate_identifier(operation_id, "operation_id")
    validate_identifier(transition_id, "transition_id")
    _validate_sha256(expected_sha256, "expected_sha256")
    desired_sha256 = _sha256(data)
    intent = canonical_json_bytes(
        {
            "desired_sha256": desired_sha256,
            "expected_sha256": expected_sha256,
            "operation_id": operation_id,
            "path": path.name,
            "transition_id": transition_id,
        }
    )
    token = _sha256(intent)
    return path.with_name("." + path.name + ".pending-" + token)


def _pending_inventory(path: Path, expected_pending: Path):
    if not path.parent.exists():
        return (), False
    prefix = "." + path.name + ".pending-"
    matches = tuple(
        entry
        for entry in path.parent.iterdir()
        if entry.name.startswith(prefix)
    )
    return matches, any(entry != expected_pending for entry in matches)


def _classify_atomic_write(
    path: Path,
    data: bytes,
    operation_id: str,
    transition_id: str,
    expected_sha256: Optional[str],
) -> str:
    """Classify caller-bound mutable publication evidence without mutating it."""
    target = _raw_absolute(Path(path))
    pending = _pending_path(
        target, data, operation_id, transition_id, expected_sha256
    )
    _assert_plain_components(target.parent, allow_missing=True)
    desired_sha256 = _sha256(data)
    current_sha256 = _read_hash(target)
    pending_paths, unknown_pending = _pending_inventory(target, pending)
    if unknown_pending:
        return "ambiguous"
    pending_sha256 = _read_hash(pending) if pending in pending_paths else None

    if pending_sha256 is not None and pending_sha256 != desired_sha256:
        if current_sha256 in (expected_sha256, desired_sha256):
            return "incomplete-owned"
        return "ambiguous"
    if current_sha256 == desired_sha256:
        return "ran"
    if current_sha256 == expected_sha256:
        return "not-run"
    return "ambiguous"


def atomic_write(
    path: Path,
    data: bytes,
    operation_id: str,
    transition_id: str,
    expected_sha256: Optional[str],
) -> None:
    """Replace one mutable canonical file through caller-bound pending evidence."""
    if not isinstance(data, bytes):
        raise ValidationError("publication data must be bytes")
    target = _raw_absolute(Path(path))
    pending = _pending_path(
        target, data, operation_id, transition_id, expected_sha256
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_plain_components(target.parent, allow_missing=False)
    state = _classify_atomic_write(
        target, data, operation_id, transition_id, expected_sha256
    )
    if state in ("incomplete-owned", "ambiguous"):
        raise ConflictError("publication evidence is {0}".format(state))

    desired_sha256 = _sha256(data)
    pending_sha256 = _read_hash(pending)
    if state == "ran":
        if pending_sha256 is not None:
            if pending_sha256 != desired_sha256:
                raise ConflictError("publication evidence is incomplete-owned")
            _checkpoint("before-candidate-unlink")
            pending.unlink()
            _checkpoint("after-candidate-unlink")
        _checkpoint("before-directory-fsync")
        _fsync_directory(target.parent)
        _checkpoint("after-directory-fsync")
        if _read_hash(target) != desired_sha256:
            raise ConflictError("published bytes changed before success")
        return

    if pending_sha256 is None:
        _require_current_hash(target, expected_sha256)
        _checkpoint("before-candidate-open")
        with pending.open("xb") as handle:
            _checkpoint("after-candidate-open")
            handle.write(data)
            _checkpoint("after-candidate-write")
            _checkpoint("before-candidate-fsync")
            handle.flush()
            os.fsync(handle.fileno())
            _checkpoint("after-candidate-fsync")
        pending_sha256 = _read_hash(pending)
    if pending_sha256 != desired_sha256:
        raise ConflictError("publication evidence is incomplete-owned")

    _require_current_hash(target, expected_sha256)
    _checkpoint("before-replace")
    os.replace(str(pending), str(target))
    _checkpoint("after-replace")
    _checkpoint("before-directory-fsync")
    _fsync_directory(target.parent)
    _checkpoint("after-directory-fsync")
    if _read_hash(target) != desired_sha256:
        raise ConflictError("published bytes changed before success")


def atomic_publish_exclusive(path: Path, data: bytes, candidate: Path) -> None:
    """Publish immutable bytes with a same-directory hardlink and no overwrite."""
    if not isinstance(data, bytes):
        raise ValidationError("publication data must be bytes")
    target = _raw_absolute(Path(path))
    prepared = _raw_absolute(Path(candidate))
    if target == prepared or target.parent != prepared.parent:
        raise ValidationError("exclusive candidate must be a distinct sibling")
    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_plain_components(target.parent, allow_missing=False)

    desired_sha256 = _sha256(data)
    target_sha256 = _read_hash(target)
    candidate_sha256 = _read_hash(prepared)
    if target_sha256 not in (None, desired_sha256):
        raise ConflictError("exclusive publication target is occupied")
    if candidate_sha256 not in (None, desired_sha256):
        raise ConflictError("exclusive publication candidate is incomplete")

    if target_sha256 == desired_sha256:
        _checkpoint("before-directory-fsync")
        _fsync_directory(target.parent)
        _checkpoint("after-directory-fsync")
        if candidate_sha256 is not None:
            _checkpoint("before-candidate-unlink")
            prepared.unlink()
            _checkpoint("after-candidate-unlink")
            _fsync_directory(target.parent)
        return

    if candidate_sha256 is None:
        _checkpoint("before-candidate-open")
        with prepared.open("xb") as handle:
            _checkpoint("after-candidate-open")
            handle.write(data)
            _checkpoint("after-candidate-write")
            _checkpoint("before-candidate-fsync")
            handle.flush()
            os.fsync(handle.fileno())
            _checkpoint("after-candidate-fsync")
        candidate_sha256 = _read_hash(prepared)
    if candidate_sha256 != desired_sha256:
        raise ConflictError("exclusive publication candidate is incomplete")

    _checkpoint("before-hardlink")
    try:
        os.link(str(prepared), str(target))
    except FileExistsError as error:
        raise ConflictError("exclusive publication target is occupied") from error
    except OSError as error:
        raise ConflictError("exclusive hardlink publication failed") from error
    _checkpoint("after-hardlink")
    if _read_hash(target) != desired_sha256:
        raise ConflictError("exclusive published bytes changed")
    _checkpoint("before-directory-fsync")
    _fsync_directory(target.parent)
    _checkpoint("after-directory-fsync")
    _checkpoint("before-candidate-unlink")
    prepared.unlink()
    _checkpoint("after-candidate-unlink")
    _fsync_directory(target.parent)
