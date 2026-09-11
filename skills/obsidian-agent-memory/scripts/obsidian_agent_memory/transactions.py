"""Crash-safe Schema-2 initialization and conflict-preserving transactions."""

import contextlib
import ctypes
import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass, replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import ContextManager, Dict, Iterator, Mapping, Optional, Sequence, Tuple

from .errors import AgentMemoryError, ConflictError, LockBusyError, ValidationError
from .models import (
    CommitOutcome,
    FocusUpdateOutcome,
    PromotionCandidate,
    RecordCandidate,
    RecordEnvelope,
    RootGuardRecovery,
    RootWriteGuard,
    TransactionContext,
    UnboundSessionCandidate,
)
from .coordination import _validate_unbound_session_candidate
from .paths import validate_identifier
from .records import (
    _validate_timestamp,
    normalize_body,
    parse_record,
    record_relative_path,
    render_record,
)
from .session_relationships import parse_session_relationship


_ANCHOR_NAME = ".agent-memory-root-write.anchor"
_ANCHOR_CANDIDATE_NAME = _ANCHOR_NAME + ".candidate"
_ANCHOR_BYTES = b'{"purpose":"root-write-namespace","schema_version":1}\n'
_ROOT_LOCK_NAME = ".agent-memory-root-write.lock"
_ROOT_CANDIDATE_PREFIX = ".agent-memory-root-write.candidate-"
_OBSERVABLE_GUARD_LOCK_OFFSET = 1024 * 1024
_HASH_HEX = frozenset("0123456789abcdef")


def _json_bytes(value: Mapping[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fsync_directory(directory: Path) -> None:
    """Flush directory metadata when the platform exposes a usable primitive."""
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
            error = ctypes.get_last_error()
            raise OSError(error, "cannot flush directory metadata")
    finally:
        kernel32.CloseHandle(handle)


def _raw_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _assert_plain_path(path: Path, allow_missing: bool = False) -> None:
    """Walk the raw absolute path and reject every redirect/special component."""
    absolute = _raw_absolute(path)
    current = Path(absolute.anchor)
    missing = False
    for component in absolute.parts[1:]:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if allow_missing:
                missing = True
                continue
            raise
        if missing:
            raise ValidationError("path inventory changed during raw component walk")
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
        ):
            raise ValidationError("reparse paths are not supported")
        if current != absolute and not stat.S_ISDIR(metadata.st_mode):
            raise ValidationError("non-directory path component is not supported")
        if current == absolute and not stat.S_ISDIR(metadata.st_mode):
            raise ValidationError("plain directory path required")
    if not missing:
        resolved = absolute.resolve(strict=True)
        if os.path.normcase(str(resolved)) != os.path.normcase(str(absolute)):
            raise ValidationError("resolved path differs from checked raw path")


def _assert_checked_parent(root: Path, target: Path, allow_missing: bool = False) -> None:
    raw_root = _raw_absolute(root)
    raw_parent = _raw_absolute(target).parent
    _assert_plain_path(raw_root, allow_missing=allow_missing)
    _assert_plain_path(raw_parent, allow_missing=allow_missing)
    try:
        raw_parent.relative_to(raw_root)
    except ValueError as error:
        raise ValidationError("mutation target escapes memory root") from error
    resolved_root = raw_root.resolve(strict=False)
    resolved_parent = raw_parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(resolved_root)
    except ValueError as error:
        raise ValidationError("resolved mutation target escapes memory root") from error


def _assert_plain_file(path: Path) -> None:
    absolute = _raw_absolute(path)
    _assert_plain_path(absolute.parent)
    metadata = absolute.lstat()
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
    ):
        raise ValidationError("reparse files are not supported")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValidationError("plain regular file required")
    if os.path.normcase(str(absolute.resolve(strict=True))) != os.path.normcase(str(absolute)):
        raise ValidationError("resolved file differs from checked raw path")


def _read_plain_text(path: Path) -> str:
    _assert_plain_file(path)
    return path.read_text("utf-8")


def _prepare_root(root: Path, allow_missing: bool = False) -> Path:
    raw_root = _raw_absolute(Path(root))
    _assert_plain_path(raw_root, allow_missing=allow_missing)
    return raw_root.resolve(strict=False)


def _validate_context(context: TransactionContext) -> TransactionContext:
    if not isinstance(context, TransactionContext):
        raise ValidationError("invalid transaction context")
    validate_identifier(context.transaction_id, "transaction_id")
    validate_identifier(context.actor, "actor")
    if not isinstance(context.occurred_at, str) or not context.occurred_at.strip():
        raise ValidationError("invalid occurred_at")
    return context


def _candidate_for(target: Path, token: str) -> Path:
    return target.with_name(target.name + ".candidate-" + token)


def _write_complete_file(root: Path, path: Path, content: bytes) -> None:
    _assert_checked_parent(root, path)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publication_checkpoint(stage: str, target: Path) -> None:
    """Private crash-injection seam for no-replace publication tests."""


def _cas_checkpoint(stage: str, target: Path) -> None:
    """Private crash-injection seam for mutable replacement tests."""


def _move_no_replace(root: Path, source: Path, destination: Path) -> None:
    """Atomically move one namespace entry without replacing an occupied path."""
    checked_root = _prepare_root(root)
    for path in (source, destination):
        _assert_checked_parent(checked_root, path)
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file = kernel32.MoveFileExW
        move_file.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
        move_file.restype = ctypes.c_int
        if not move_file(str(source), str(destination), 0):
            error = ctypes.get_last_error()
            if error in (80, 183):
                raise ConflictError("no-replace destination is occupied")
            raise AgentMemoryError(
                "atomic no-replace move is unavailable (Windows error {0})".format(error)
            )
    else:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            renameat2.restype = ctypes.c_int
            result = renameat2(
                -100,
                os.fsencode(source),
                -100,
                os.fsencode(destination),
                0x00000001,
            )
        else:
            renamex_np = getattr(libc, "renamex_np", None)
            if renamex_np is None:
                raise AgentMemoryError("atomic no-replace move is unavailable")
            renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
            renamex_np.restype = ctypes.c_int
            result = renamex_np(
                os.fsencode(source),
                os.fsencode(destination),
                0x00000004,
            )
        if result != 0:
            error = ctypes.get_errno()
            if error == getattr(os, "EEXIST", 17):
                raise ConflictError("no-replace destination is occupied")
            raise AgentMemoryError("atomic no-replace move is unavailable")
    _fsync_directory(source.parent)
    if destination.parent != source.parent:
        _fsync_directory(destination.parent)


def _publish_exclusive(
    target: Path,
    content: bytes,
    token: str,
    root: Optional[Path] = None,
) -> Path:
    """Publish complete bytes by same-volume hardlink without replacement."""
    checked_root = _prepare_root(root if root is not None else target.parent)
    _assert_checked_parent(checked_root, target, allow_missing=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_checked_parent(checked_root, target)
    candidate = _candidate_for(target, token)
    _write_complete_file(checked_root, candidate, content)
    _publication_checkpoint("candidate-fsynced", target)
    published = False
    try:
        _assert_checked_parent(checked_root, candidate)
        _assert_checked_parent(checked_root, target)
        os.link(str(candidate), str(target))
        published = True
        _publication_checkpoint("canonical-linked", target)
        _fsync_directory(target.parent)
        _publication_checkpoint("canonical-directory-synced", target)
    except FileExistsError:
        raise ConflictError("canonical target is occupied")
    except OSError as error:
        raise AgentMemoryError("safe no-replace publication is unavailable") from error
    finally:
        if not published or target.exists():
            try:
                _publication_checkpoint("before-candidate-unlink", target)
                _assert_checked_parent(checked_root, candidate)
                candidate.unlink()
                _publication_checkpoint("candidate-unlinked", target)
                _fsync_directory(target.parent)
                _publication_checkpoint("cleanup-directory-synced", target)
            except FileNotFoundError:
                pass
    return target


def _replace_cas(
    target: Path,
    expected: bytes,
    content: bytes,
    token: str,
    root: Optional[Path] = None,
) -> Path:
    checked_root = _prepare_root(root if root is not None else target.parent)
    _assert_checked_parent(checked_root, target)
    if not target.exists():
        raise ConflictError("mutable target changed before replacement")
    _assert_plain_file(target)
    if target.read_bytes() != expected:
        raise ConflictError("mutable target changed before replacement")
    _assert_checked_parent(checked_root, target, allow_missing=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_checked_parent(checked_root, target)
    pending = target.with_name(".pending-" + token)
    _write_complete_file(checked_root, pending, content)
    _cas_checkpoint("pending-fsynced", target)
    if target.read_bytes() != expected:
        raise ConflictError("mutable target changed before replacement")
    _cas_checkpoint("before-replace", target)
    _assert_checked_parent(checked_root, pending)
    _assert_checked_parent(checked_root, target)
    os.replace(str(pending), str(target))
    _cas_checkpoint("after-replace", target)
    _fsync_directory(target.parent)
    _cas_checkpoint("directory-synced", target)
    return target


class _Lease:
    """One-byte nonblocking advisory lease with exact handle ownership."""

    def __init__(self, descriptor: int):
        self.descriptor = descriptor
        self.closed = False
        self.held = False
        self.lock_offset = 0
        self.probe_failure_path: Optional[Path] = None

    @classmethod
    def create(cls, path: Path) -> "_Lease":
        if os.name == "nt":
            return cls(_windows_open(path, 1))
        descriptor = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        return cls(descriptor)

    @classmethod
    def open(cls, path: Path) -> "_Lease":
        if os.name == "nt":
            return cls(_windows_open(path, 3))
        return cls(os.open(str(path), os.O_RDWR))

    def acquire(self, offset: int = 0) -> bool:
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

    def write_all(self, content: bytes) -> None:
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        os.ftruncate(self.descriptor, 0)
        view = memoryview(content)
        while view:
            written = os.write(self.descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(self.descriptor)

    def read_all(self) -> bytes:
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        chunks = []
        while True:
            chunk = os.read(self.descriptor, 65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    def release(self) -> None:
        if self.held:
            os.lseek(self.descriptor, self.lock_offset, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            self.held = False

    def close(self) -> None:
        if not self.closed:
            try:
                self.release()
            finally:
                os.close(self.descriptor)
                self.closed = True


def _prove_live_unlink(
    root: Path,
    candidate: Path,
    lease: _Lease,
    expected_bytes: bytes,
) -> None:
    """Fail closed unless a leased hardlink alias can be deleted durably."""
    probe = candidate.with_name(candidate.name + ".live-unlink-probe")
    _assert_checked_parent(root, candidate)
    _assert_checked_parent(root, probe)
    if probe.exists():
        raise AgentMemoryError("live-unlink capability probe is occupied")
    probe_linked = False
    try:
        os.link(str(candidate), str(probe))
        probe_linked = True
        _fsync_directory(candidate.parent)
        _assert_checked_parent(root, probe)
        probe.unlink()
        _fsync_directory(candidate.parent)
    except OSError as error:
        if probe_linked:
            lease.probe_failure_path = probe
        raise AgentMemoryError("lease-bearing alias unlink is unavailable") from error
    if (
        not lease.held
        or not candidate.exists()
        or lease.read_all() != expected_bytes
    ):
        raise AgentMemoryError("live-unlink capability probe changed the leased candidate")


def _windows_open(path: Path, disposition: int) -> int:
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
        disposition,
        0x00000080,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        if error in (80, 183):
            raise FileExistsError(error, "path already exists", str(path))
        if error in (2, 3):
            raise FileNotFoundError(error, "path not found", str(path))
        raise OSError(error, "CreateFileW failed", str(path))
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDWR | getattr(os, "O_BINARY", 0))
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def _same_file(first: Path, second: Path) -> bool:
    try:
        return os.path.samefile(str(first), str(second))
    except (FileNotFoundError, OSError):
        return False


def _anchor_checkpoint(stage: str) -> None:
    """Private deterministic crash-injection seam for anchor bootstrap tests."""


def _ensure_anchor(root: Path) -> Path:
    anchor = root / _ANCHOR_NAME
    candidate = root / _ANCHOR_CANDIDATE_NAME
    _assert_checked_parent(root, anchor)
    _assert_checked_parent(root, candidate)
    if anchor.exists():
        _assert_plain_file(anchor)
        try:
            anchor_bytes = anchor.read_bytes()
        except PermissionError as error:
            raise LockBusyError("root-write-busy") from error
        if anchor_bytes != _ANCHOR_BYTES:
            raise ConflictError("malformed root-write namespace anchor")
        if candidate.exists():
            _assert_plain_file(candidate)
            lease = _Lease.open(candidate)
            try:
                if not lease.acquire():
                    raise LockBusyError("root-write namespace bootstrap is busy")
                if lease.read_all() != _ANCHOR_BYTES or not _same_file(anchor, candidate):
                    raise ConflictError("ambiguous root-write namespace bootstrap")
                _assert_checked_parent(root, candidate)
                candidate.unlink()
                _fsync_directory(root)
            finally:
                lease.close()
        return anchor


    permitted_root_names = {
        _ANCHOR_CANDIDATE_NAME,
        "AGENTS.md",
        "README.md",
        ".agent-memory",
        "_records",
        ".agent-memory-root-write-recoveries",
    }
    if any(path.name not in permitted_root_names for path in root.iterdir()):
        raise ConflictError("unknown root inventory during anchor bootstrap")

    try:
        lease = _Lease.create(candidate)
        _anchor_checkpoint("candidate-created")
    except FileExistsError:
        lease = _Lease.open(candidate)
    try:
        if not lease.acquire():
            raise LockBusyError("root-write namespace bootstrap is busy")
        _anchor_checkpoint("candidate-leased")
        existing = lease.read_all()
        if not _ANCHOR_BYTES.startswith(existing):
            raise ConflictError("invalid root-write namespace candidate")
        os.lseek(lease.descriptor, len(existing), os.SEEK_SET)
        for offset, byte in enumerate(_ANCHOR_BYTES[len(existing) :], start=len(existing) + 1):
            if os.write(lease.descriptor, bytes((byte,))) != 1:
                raise OSError("short anchor write")
            os.fsync(lease.descriptor)
            _anchor_checkpoint("prefix-{0}".format(offset))
        try:
            _assert_checked_parent(root, candidate)
            _assert_checked_parent(root, anchor)
            os.link(str(candidate), str(anchor))
            _anchor_checkpoint("canonical-linked")
            _fsync_directory(root)
            _anchor_checkpoint("canonical-directory-synced")
        except FileExistsError:
            if anchor.read_bytes() != _ANCHOR_BYTES or not _same_file(anchor, candidate):
                raise ConflictError("ambiguous root-write namespace bootstrap")
        if lease.read_all() != _ANCHOR_BYTES or not _same_file(anchor, candidate):
            raise ConflictError("invalid root-write namespace anchor")
        _anchor_checkpoint("before-candidate-unlink")
        _assert_checked_parent(root, candidate)
        candidate.unlink()
        _anchor_checkpoint("candidate-unlinked")
        _fsync_directory(root)
        _anchor_checkpoint("cleanup-directory-synced")
    finally:
        lease.close()
    return anchor


@dataclass
class _ActiveGuard:
    guard: RootWriteGuard
    guard_lease: _Lease
    anchor_lease: _Lease
    candidate_path: Path
    lock_bytes: bytes
    process_id: int


_ACTIVE_GUARDS: Dict[int, _ActiveGuard] = {}


def _root_candidate(root: Path, transaction_id: str) -> Path:
    binding = (str(root.resolve(strict=False)) + "\0" + transaction_id).encode("utf-8")
    return root / (_ROOT_CANDIDATE_PREFIX + _sha256(binding))


def _lock_document(
    context: TransactionContext,
    target: str,
    include_process: bool = True,
) -> bytes:
    document = {
        "actor": context.actor,
        "created_at": context.occurred_at,
        "target": target,
        "transaction_id": context.transaction_id,
    }
    if include_process:
        document["process_id"] = os.getpid()
    return _json_bytes(document)


@contextlib.contextmanager
def root_write_guard(root: Path, context: TransactionContext) -> ContextManager[RootWriteGuard]:
    """Acquire the permanent namespace lease and one observable root guard."""
    _validate_context(context)
    root = _prepare_root(root, allow_missing=True)
    _assert_checked_parent(root, root / _ANCHOR_NAME, allow_missing=True)
    root.mkdir(parents=True, exist_ok=True)
    _assert_plain_path(root)
    anchor = _ensure_anchor(root)
    _assert_plain_file(anchor)
    anchor_lease = _Lease.open(anchor)
    if not anchor_lease.acquire():
        anchor_lease.close()
        raise LockBusyError("root-write-busy")

    candidate = _root_candidate(root, context.transaction_id)
    canonical = root / _ROOT_LOCK_NAME
    _assert_checked_parent(root, candidate)
    _assert_checked_parent(root, canonical)
    guard_lease: Optional[_Lease] = None
    registered_guard: Optional[RootWriteGuard] = None
    try:
        if canonical.exists():
            _assert_plain_file(canonical)
            raise LockBusyError("stale-root-write-guard")
        try:
            guard_lease = _Lease.create(candidate)
        except FileExistsError as error:
            raise LockBusyError("stale-root-write-candidate") from error
        # The anchor lease serializes the namespace. Keep the guard candidate's
        # exact descriptor lease beyond the JSON bytes so observers can read
        # the complete canonical lock document without acquiring ownership.
        if not guard_lease.acquire(offset=_OBSERVABLE_GUARD_LOCK_OFFSET):
            raise LockBusyError("root-write-busy")
        lock_bytes = _lock_document(context, ".")
        guard_lease.write_all(lock_bytes)
        _prove_live_unlink(root, candidate, guard_lease, lock_bytes)
        try:
            _assert_checked_parent(root, candidate)
            _assert_checked_parent(root, canonical)
            os.link(str(candidate), str(canonical))
        except FileExistsError as error:
            raise LockBusyError("root-write-busy") from error
        _fsync_directory(root)
        if not _same_file(candidate, canonical) or guard_lease.read_all() != lock_bytes:
            raise AgentMemoryError("root guard publication verification failed")
        registered_guard = RootWriteGuard(root, canonical, _sha256(lock_bytes), context.transaction_id)
        _ACTIVE_GUARDS[id(registered_guard)] = _ActiveGuard(
            registered_guard,
            guard_lease,
            anchor_lease,
            candidate,
            lock_bytes,
            os.getpid(),
        )
        yield registered_guard
    finally:
        if registered_guard is not None:
            active = _ACTIVE_GUARDS.pop(id(registered_guard), None)
            if active is not None:
                try:
                    if (
                        canonical.exists()
                        and _same_file(canonical, candidate)
                        and active.guard_lease.read_all() == active.lock_bytes
                    ):
                        _assert_checked_parent(root, canonical)
                        canonical.unlink()
                        _fsync_directory(root)
                    if candidate.exists() and active.guard_lease.read_all() == active.lock_bytes:
                        _assert_checked_parent(root, candidate)
                        candidate.unlink()
                        _fsync_directory(root)
                finally:
                    active.guard_lease.close()
        elif guard_lease is not None:
            guard_lease.close()
        anchor_lease.close()


def _require_guard(root: Path, context: TransactionContext, guard: RootWriteGuard) -> _ActiveGuard:
    active = _ACTIVE_GUARDS.get(id(guard))
    resolved_root = _prepare_root(root)
    try:
        lock_document = json.loads(active.lock_bytes.decode("utf-8")) if active is not None else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        lock_document = None
    if (
        active is None
        or active.guard is not guard
        or active.process_id != os.getpid()
        or not active.guard_lease.held
        or not active.anchor_lease.held
        or guard.root != resolved_root
        or guard.transaction_id != context.transaction_id
        or not isinstance(lock_document, dict)
        or lock_document.get("actor") != context.actor
        or lock_document.get("created_at") != context.occurred_at
        or lock_document.get("transaction_id") != context.transaction_id
        or guard.lock_path != resolved_root / _ROOT_LOCK_NAME
        or guard.token != _sha256(active.lock_bytes)
        or not guard.lock_path.exists()
        or active.guard_lease.read_all() != active.lock_bytes
        or not _same_file(guard.lock_path, active.candidate_path)
    ):
        raise LockBusyError("invalid-root-write-guard")
    _assert_plain_file(guard.lock_path)
    return active


def _with_guard(root: Path, context: TransactionContext, guard: Optional[RootWriteGuard]):
    if guard is None:
        return root_write_guard(root, context)

    @contextlib.contextmanager
    def supplied() -> Iterator[RootWriteGuard]:
        _require_guard(root, context, guard)
        yield guard

    return supplied()


@contextlib.contextmanager
def _narrow_lock(
    root: Path,
    name: str,
    context: TransactionContext,
    relative_directory: Path = Path(".agent-memory/locks"),
) -> Iterator[None]:
    lock_directory = root / relative_directory
    _assert_checked_parent(root, lock_directory / "placeholder", allow_missing=True)
    lock_directory.mkdir(parents=True, exist_ok=True)
    _assert_plain_path(lock_directory)
    canonical = lock_directory / (name + ".lock")
    token = _sha256((context.transaction_id + "\0" + canonical.as_posix()).encode("utf-8"))
    candidate = _candidate_for(canonical, token)
    _assert_checked_parent(root, canonical)
    _assert_checked_parent(root, candidate)
    if canonical.exists() or candidate.exists():
        if canonical.exists():
            _assert_plain_file(canonical)
        if candidate.exists():
            _assert_plain_file(candidate)
        raise LockBusyError("occupied-lock")
    lease = _Lease.create(candidate)
    lock_bytes = _lock_document(context, canonical.relative_to(root).as_posix())
    published = False
    try:
        if not lease.acquire():
            raise LockBusyError("occupied-lock")
        lease.write_all(lock_bytes)
        _prove_live_unlink(root, candidate, lease, lock_bytes)
        try:
            _assert_checked_parent(root, candidate)
            _assert_checked_parent(root, canonical)
            os.link(str(candidate), str(canonical))
        except FileExistsError as error:
            raise LockBusyError("occupied-lock") from error
        published = True
        _fsync_directory(lock_directory)
        yield
    finally:
        try:
            if published and canonical.exists() and _same_file(canonical, candidate):
                _assert_checked_parent(root, canonical)
                canonical.unlink()
                _fsync_directory(lock_directory)
            if (
                lease.probe_failure_path is None
                and candidate.exists()
                and lease.read_all() == lock_bytes
            ):
                _assert_checked_parent(root, candidate)
                candidate.unlink()
                _fsync_directory(lock_directory)
        finally:
            lease.close()


_AGENTS = """# Agent Memory Schema 2\n\nImmutable records are canonical facts. Canonical focus JSON owns working focus. Generated views are projections only. Every mutable write requires an expected revision, and every path must remain contained beneath this root.\n"""
_README = """# Portable Agent Memory\n\nSchema 2 separates four layers: immutable records, revisioned canonical state, generated Markdown views, and append-only operational evidence. Obsidian and a reusable Knowledge Base are optional integrations, not canonical owners.\n"""


def _initial_documents(project_id: Optional[str], context: TransactionContext) -> Tuple[Tuple[Path, bytes], ...]:
    documents = [
        (Path("AGENTS.md"), _AGENTS.encode("utf-8")),
        (Path("README.md"), _README.encode("utf-8")),
        (Path(".agent-memory/config.json"), _json_bytes({"schema_version": 2})),
        (Path(".agent-memory/schema.json"), _json_bytes({"schema_version": 2})),
        (
            Path(".agent-memory/state/catalog.json"),
            _json_bytes({"records": {}, "revision": 0, "schema_version": 2}),
        ),
    ]
    if project_id is not None:
        documents.append(
            (
                Path(".agent-memory/state/focus") / (project_id + ".json"),
                _json_bytes(
                    {
                        "observed_at": context.occurred_at,
                        "project_id": project_id,
                        "record_ids": [],
                        "revision": 0,
                        "schema_version": 2,
                    }
                ),
            )
        )
    return tuple(documents)


def initialize_memory_root(
    root: Path,
    project_id: Optional[str],
    context: TransactionContext,
    guard: Optional[RootWriteGuard] = None,
) -> Tuple[Path, ...]:
    """Exclusively initialize one empty root with Schema-2 canonical files."""
    _validate_context(context)
    if project_id is not None:
        validate_identifier(project_id, "project_id")
    root = _prepare_root(root, allow_missing=True)
    existed = root.exists()
    if existed:
        _assert_plain_path(root)
        if guard is None:
            permitted_pre_guard = {_ANCHOR_NAME, _ANCHOR_CANDIDATE_NAME}
            if any(path.name not in permitted_pre_guard for path in root.iterdir()):
                raise ConflictError("memory root is not empty")

    created_files = []
    try:
        with _with_guard(root, context, guard):
            allowed = {
                _ANCHOR_NAME,
                _ROOT_LOCK_NAME,
                _root_candidate(root, context.transaction_id).name,
                ".agent-memory-root-write-recoveries",
            }
            if any(path.name not in allowed for path in root.iterdir()):
                raise ConflictError("memory root changed during initialization")
            documents = _initial_documents(project_id, context)
            relative_paths = [_ANCHOR_NAME]
            relative_paths.extend(relative.as_posix() for relative, _ in documents)
            relative_paths.append(".agent-memory/transactions/{0}.json".format(context.transaction_id))
            transaction_path = root / ".agent-memory/transactions" / (context.transaction_id + ".json")
            intent = {
                "actor": context.actor,
                "created_paths": relative_paths,
                "desired": {"created_paths": relative_paths, "schema_version": 2},
                "expected_base": {"root_empty": True},
                "occurred_at": context.occurred_at,
                "operation": "initialize",
                "schema_version": 2,
                "status": "in-progress",
                "target": ".",
                "transaction_id": context.transaction_id,
            }
            intent_bytes = _json_bytes(intent)
            _publish_exclusive(
                transaction_path,
                intent_bytes,
                _sha256((context.transaction_id + "\0initialize-intent").encode("utf-8")),
                root=root,
            )
            for relative, content in documents:
                target = root / relative
                token = _sha256((context.transaction_id + "\0" + relative.as_posix()).encode("utf-8"))
                _publish_exclusive(target, content, token, root=root)
                created_files.append(target)
            transaction = dict(intent)
            transaction["status"] = "accepted"
            _finalize_transaction(
                transaction_path,
                intent_bytes,
                _json_bytes(transaction),
                context.transaction_id,
            )
            created_files.append(transaction_path)
    except BaseException:
        if not created_files and not existed:
            try:
                if root.exists() and not any(root.iterdir()):
                    _assert_checked_parent(root.parent, root / "placeholder")
                    root.rmdir()
            except OSError:
                pass
        raise
    return (root / _ANCHOR_NAME,) + tuple(created_files)


def commit_record(
    root: Path,
    candidate: RecordCandidate,
    expected_catalog_revision: int,
    expected_record_revision: Optional[int],
    context: TransactionContext,
    guard: Optional[RootWriteGuard] = None,
) -> CommitOutcome:
    return _commit_record(
        root,
        candidate,
        expected_catalog_revision,
        expected_record_revision,
        context,
        guard=guard,
        allow_legacy_migration_session=False,
    )


def _commit_record(
    root: Path,
    candidate: RecordCandidate,
    expected_catalog_revision: int,
    expected_record_revision: Optional[int],
    context: TransactionContext,
    guard: Optional[RootWriteGuard] = None,
    allow_legacy_migration_session: bool = False,
) -> CommitOutcome:
    _validate_context(context)
    if not isinstance(candidate, RecordCandidate):
        raise ValidationError("invalid record candidate")
    if type(expected_catalog_revision) is not int or expected_catalog_revision < 0:
        raise ValidationError("invalid expected catalog revision")
    if expected_record_revision is not None and (
        type(expected_record_revision) is not int or expected_record_revision <= 0
    ):
        raise ValidationError("invalid expected record revision")
    invalid_supersedes_identity = False
    try:
        rendered = render_record(candidate.envelope, candidate.body).encode("utf-8")
        parsed_envelope, _ = parse_record(rendered.decode("utf-8"))
    except ValidationError:
        supersedes = candidate.envelope.supersedes
        if (
            isinstance(supersedes, str)
            and "@" in supersedes
            and supersedes.rsplit("@", 1)[0] != candidate.envelope.memory_id
        ):
            invalid_supersedes_identity = True
            validation_envelope = replace(candidate.envelope, supersedes=None)
            render_record(validation_envelope, candidate.body)
            parsed_envelope = validation_envelope
            rendered = _json_bytes(
                {"body": candidate.body, "envelope": asdict(candidate.envelope)}
            )
        else:
            raise
    root = _prepare_root(root)
    if guard is not None:
        _require_guard(root, context, guard)
    relative_record = record_relative_path(parsed_envelope)
    record_path = root / relative_record
    transaction_path = root / ".agent-memory" / "transactions" / (context.transaction_id + ".json")
    proposal_path = root / ".agent-memory" / "state" / "proposals" / (context.transaction_id + ".json")
    semantic_candidate = {
        "body": normalize_body(candidate.body),
        "envelope": asdict(candidate.envelope),
    }
    desired = {
        "memory_id": parsed_envelope.memory_id,
        "record_candidate": semantic_candidate,
        "record_candidate_sha256": _sha256(_json_bytes(semantic_candidate)),
        "record_revision": parsed_envelope.revision,
        "record_sha256": _sha256(rendered),
        "relative_path": relative_record.as_posix(),
    }
    intent = {
        "actor": context.actor,
        "desired": desired,
        "expected_base": {
            "catalog_revision": expected_catalog_revision,
            "record_revision": expected_record_revision,
        },
        "occurred_at": context.occurred_at,
        "operation": "commit-record",
        "schema_version": 2,
        "status": "in-progress",
        "target": relative_record.as_posix(),
        "transaction_id": context.transaction_id,
    }
    intent_bytes = _json_bytes(intent)
    intent_token = _sha256((context.transaction_id + "\0intent").encode("utf-8"))
    _publish_exclusive(transaction_path, intent_bytes, intent_token, root=root)

    def propose(code: str, observed: Mapping[str, object], catalog_revision: int) -> CommitOutcome:
        proposal = {
            "actor": context.actor,
            "conflict_code": code,
            "desired": desired,
            "expected_base": intent["expected_base"],
            "observed_base": dict(observed),
            "occurred_at": context.occurred_at,
            "operation": "commit-record",
            "schema_version": 2,
            "target": relative_record.as_posix(),
            "transaction_id": context.transaction_id,
        }
        proposal_bytes = _json_bytes(proposal)
        _publish_exclusive(
            proposal_path,
            proposal_bytes,
            _sha256((context.transaction_id + "\0proposal").encode("utf-8")),
            root=root,
        )
        final = dict(intent)
        final.update(
            {
                "catalog_revision": catalog_revision,
                "conflict_code": code,
                "observed_base": dict(observed),
                "proposal_path": proposal_path.relative_to(root).as_posix(),
                "status": "proposed",
            }
        )
        _finalize_transaction(transaction_path, intent_bytes, _json_bytes(final), context.transaction_id)
        return CommitOutcome("proposed", context.transaction_id, catalog_revision, None, proposal_path, code)

    try:
        guard_manager = _with_guard(root, context, guard)
        with guard_manager:
            try:
                with _narrow_lock(root, "catalog", context):
                    catalog_path = root / ".agent-memory" / "state" / "catalog.json"
                    _assert_plain_file(catalog_path)
                    old_catalog_bytes = catalog_path.read_bytes()
                    catalog = json.loads(old_catalog_bytes.decode("utf-8"))
                    observed_revision = catalog.get("revision")
                    records = catalog.get("records")
                    if type(observed_revision) is not int or not isinstance(records, dict):
                        raise AgentMemoryError("invalid catalog")
                    existing = records.get(parsed_envelope.memory_id)
                    observed_record_revision = existing.get("revision") if isinstance(existing, dict) else None
                    observed = {
                        "catalog_revision": observed_revision,
                        "record_revision": observed_record_revision,
                    }
                    if observed_revision != expected_catalog_revision:
                        return propose("stale-catalog-revision", observed, observed_revision)
                    if invalid_supersedes_identity:
                        return propose("revision-chain-mismatch", observed, observed_revision)
                    if existing is None:
                        if expected_record_revision is not None:
                            return propose("stale-record-revision", observed, observed_revision)
                        if parsed_envelope.revision != 1 or parsed_envelope.supersedes is not None:
                            return propose("revision-chain-mismatch", observed, observed_revision)
                    else:
                        if expected_record_revision is None:
                            return propose("duplicate-memory-id", observed, observed_revision)
                        if observed_record_revision != expected_record_revision:
                            return propose("stale-record-revision", observed, observed_revision)
                        if (
                            parsed_envelope.revision != observed_record_revision + 1
                            or parsed_envelope.supersedes
                            != "{0}@{1}".format(parsed_envelope.memory_id, observed_record_revision)
                        ):
                            return propose("revision-chain-mismatch", observed, observed_revision)
                        semantic_keys = ("memory_id", "record_type", "owner_scope", "project")
                        current_identity = tuple(existing.get(key) for key in semantic_keys)
                        candidate_identity = tuple(getattr(parsed_envelope, key) for key in semantic_keys)
                        if current_identity != candidate_identity:
                            return propose("owner-identity-mismatch", observed, observed_revision)
                    membership_conflict = _session_membership_conflict(
                        parsed_envelope,
                        candidate.body,
                        records,
                        allow_legacy_migration_session,
                    )
                    if membership_conflict is not None:
                        return propose(membership_conflict, observed, observed_revision)
                    if record_path.exists():
                        _assert_plain_file(record_path)
                        return propose("occupied-target", observed, observed_revision)
                    new_records = dict(records)
                    new_records[parsed_envelope.memory_id] = {
                        "memory_id": parsed_envelope.memory_id,
                        "owner_scope": parsed_envelope.owner_scope,
                        "project": parsed_envelope.project,
                        "record_type": parsed_envelope.record_type,
                        "relative_path": relative_record.as_posix(),
                        "revision": parsed_envelope.revision,
                    }
                    new_catalog = {
                        "records": new_records,
                        "revision": observed_revision + 1,
                        "schema_version": 2,
                    }
                    new_catalog_bytes = _json_bytes(new_catalog)
                    catalog_token = _sha256(
                        (
                            context.transaction_id
                            + "\0"
                            + _sha256(old_catalog_bytes)
                            + "\0"
                            + _sha256(new_catalog_bytes)
                        ).encode("utf-8")
                    )
                    cas_intent = dict(intent)
                    cas_intent["catalog_cas"] = {
                        "desired_sha256": _sha256(new_catalog_bytes),
                        "desired_revision": observed_revision + 1,
                        "expected_sha256": _sha256(old_catalog_bytes),
                        "expected_revision": observed_revision,
                        "pending_name": ".pending-" + catalog_token,
                    }
                    cas_intent_bytes = _json_bytes(cas_intent)
                    _finalize_transaction(
                        transaction_path,
                        intent_bytes,
                        cas_intent_bytes,
                        context.transaction_id,
                    )
                    intent = cas_intent
                    intent_bytes = cas_intent_bytes
                    try:
                        _publish_exclusive(
                            record_path,
                            rendered,
                            _sha256((context.transaction_id + "\0record").encode("utf-8")),
                            root=root,
                        )
                    except BaseException as error:
                        if record_path.exists() and record_path.read_bytes() == rendered:
                            orphan = dict(intent)
                            orphan.update(
                                {
                                    "orphan_record_path": relative_record.as_posix(),
                                    "orphan_record_sha256": _sha256(rendered),
                                    "orphan_status": "published-before-catalog",
                                }
                            )
                            try:
                                _finalize_transaction(
                                    transaction_path,
                                    intent_bytes,
                                    _json_bytes(orphan),
                                    context.transaction_id,
                                )
                            except BaseException:
                                pass
                        raise AgentMemoryError("record publication did not complete durably") from error
                    try:
                        _replace_cas(
                            catalog_path,
                            old_catalog_bytes,
                            new_catalog_bytes,
                            catalog_token,
                            root=root,
                        )
                    except BaseException as error:
                        orphan = dict(intent)
                        orphan.update(
                            {
                                "orphan_record_path": relative_record.as_posix(),
                                "orphan_record_sha256": _sha256(rendered),
                                "orphan_status": "published-before-catalog",
                            }
                        )
                        try:
                            _finalize_transaction(
                                transaction_path,
                                intent_bytes,
                                _json_bytes(orphan),
                                context.transaction_id,
                            )
                        except BaseException:
                            pass
                        raise AgentMemoryError("record published before catalog CAS failed") from error
                    final = dict(intent)
                    final.update(
                        {
                            "catalog_revision": observed_revision + 1,
                            "record_path": relative_record.as_posix(),
                            "status": "accepted",
                        }
                    )
                    _finalize_transaction(
                        transaction_path,
                        intent_bytes,
                        _json_bytes(final),
                        context.transaction_id,
                    )
                    return CommitOutcome(
                        "accepted",
                        context.transaction_id,
                        observed_revision + 1,
                        record_path,
                        None,
                        None,
                    )
            except LockBusyError:
                return propose("occupied-lock", {}, expected_catalog_revision)
    except LockBusyError:
        return propose("root-write-busy", {}, expected_catalog_revision)


def _session_membership_conflict(
    envelope: RecordEnvelope,
    body: str,
    catalog_records: Mapping[str, object],
    allow_legacy_migration_session: bool,
) -> Optional[str]:
    if envelope.record_type != "session":
        return None
    try:
        relationship = parse_session_relationship(body)
    except ValidationError as error:
        code = str(error)
        if allow_legacy_migration_session and code == "session-relationship-required":
            return None
        if code == "session-relationship-required":
            return code
        return "session-relationship-invalid"

    story_ids = tuple(
        item
        for item in (relationship.primary_story_id,) + relationship.related_story_ids
        if item is not None
    )
    for story_id in story_ids:
        entry = catalog_records.get(story_id)
        if not isinstance(entry, dict):
            return "session-story-missing"
        if entry.get("record_type") != "story":
            return "session-story-type-mismatch"
        if entry.get("project") != envelope.project:
            return "session-story-project-mismatch"
    return None


def _finalize_transaction(
    transaction_path: Path,
    expected_bytes: bytes,
    final_bytes: bytes,
    transaction_id: str,
) -> None:
    token = _sha256(
        (transaction_id + "\0" + _sha256(expected_bytes) + "\0" + _sha256(final_bytes)).encode("utf-8")
    )
    _replace_cas(
        transaction_path,
        expected_bytes,
        final_bytes,
        token,
        root=transaction_path.parents[2],
    )


def update_focus(
    root: Path,
    project_id: str,
    expected_revision: int,
    record_ids: Sequence[str],
    observed_at: str,
    context: TransactionContext,
    guard: Optional[RootWriteGuard] = None,
) -> FocusUpdateOutcome:
    """CAS one project's canonical focus while preserving conflicting intent."""
    _validate_context(context)
    validate_identifier(project_id, "project_id")
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValidationError("invalid expected focus revision")
    if isinstance(record_ids, (str, bytes)) or not isinstance(record_ids, Sequence):
        raise ValidationError("record_ids must be a sequence")
    normalized_ids = []
    for record_id in record_ids:
        normalized_ids.append(validate_identifier(record_id, "record_id"))
    selected_ids = tuple(sorted(set(normalized_ids)))
    _validate_timestamp(observed_at, "observed_at")

    root = _prepare_root(root)
    if guard is not None:
        _require_guard(root, context, guard)
    focus_path = root / ".agent-memory" / "state" / "focus" / (project_id + ".json")
    transaction_path = root / ".agent-memory" / "transactions" / (context.transaction_id + ".json")
    proposal_path = root / ".agent-memory" / "state" / "proposals" / (context.transaction_id + ".json")
    desired = {
        "observed_at": observed_at,
        "project_id": project_id,
        "record_ids": list(selected_ids),
    }
    expected_base = {"focus_revision": expected_revision}
    intent = {
        "actor": context.actor,
        "desired": desired,
        "expected_base": expected_base,
        "occurred_at": context.occurred_at,
        "operation": "update_focus",
        "schema_version": 2,
        "status": "in-progress",
        "target": focus_path.relative_to(root).as_posix(),
        "transaction_id": context.transaction_id,
    }
    intent_bytes = _json_bytes(intent)
    _publish_exclusive(
        transaction_path,
        intent_bytes,
        _sha256((context.transaction_id + "\0focus-intent").encode("utf-8")),
        root=root,
    )

    def propose(
        code: str,
        observed: Mapping[str, object],
        focus_revision: int,
    ) -> FocusUpdateOutcome:
        proposal = {
            "actor": context.actor,
            "conflict_code": code,
            "desired": desired,
            "expected_base": expected_base,
            "observed_base": dict(observed),
            "occurred_at": context.occurred_at,
            "operation": "update_focus",
            "schema_version": 2,
            "target": focus_path.relative_to(root).as_posix(),
            "transaction_id": context.transaction_id,
        }
        _publish_exclusive(
            proposal_path,
            _json_bytes(proposal),
            _sha256((context.transaction_id + "\0focus-proposal").encode("utf-8")),
            root=root,
        )
        final = dict(intent)
        final.update(
            {
                "conflict_code": code,
                "focus_revision": focus_revision,
                "observed_base": dict(observed),
                "proposal_path": proposal_path.relative_to(root).as_posix(),
                "status": "proposed",
            }
        )
        _finalize_transaction(
            transaction_path,
            intent_bytes,
            _json_bytes(final),
            context.transaction_id,
        )
        return FocusUpdateOutcome(
            "proposed",
            context.transaction_id,
            focus_revision,
            proposal_path,
            code,
        )

    def observe_focus_revision() -> int:
        _assert_plain_file(focus_path)
        try:
            current_focus = json.loads(focus_path.read_text("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AgentMemoryError("invalid focus state") from error
        current_revision = current_focus.get("revision") if isinstance(current_focus, dict) else None
        if type(current_revision) is not int or current_revision < 0:
            raise AgentMemoryError("invalid focus state")
        return current_revision

    try:
        with _with_guard(root, context, guard):
            try:
                with _narrow_lock(
                    root,
                    "focus--" + project_id,
                    context,
                    Path(".agent-memory/state/locks"),
                ):
                    _assert_plain_file(focus_path)
                    old_focus_bytes = focus_path.read_bytes()
                    try:
                        focus = json.loads(old_focus_bytes.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        raise AgentMemoryError("invalid focus state") from error
                    if (
                        not isinstance(focus, dict)
                        or focus.get("schema_version") != 2
                        or focus.get("project_id") != project_id
                        or type(focus.get("revision")) is not int
                        or focus["revision"] < 0
                        or not isinstance(focus.get("record_ids"), list)
                        or not isinstance(focus.get("observed_at"), str)
                    ):
                        raise AgentMemoryError("invalid focus state")
                    observed_revision = focus["revision"]
                    observed_base = {"focus_revision": observed_revision}
                    if observed_revision != expected_revision:
                        return propose(
                            "stale-focus-revision",
                            observed_base,
                            observed_revision,
                        )

                    catalog_path = root / ".agent-memory" / "state" / "catalog.json"
                    _assert_plain_file(catalog_path)
                    try:
                        catalog = json.loads(catalog_path.read_text("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        raise AgentMemoryError("invalid catalog") from error
                    records = catalog.get("records") if isinstance(catalog, dict) else None
                    if not isinstance(records, dict) or type(catalog.get("revision")) is not int:
                        raise AgentMemoryError("invalid catalog")
                    missing_ids = [record_id for record_id in selected_ids if record_id not in records]
                    if missing_ids:
                        observed_base["missing_record_ids"] = missing_ids
                        return propose(
                            "missing-record-id",
                            observed_base,
                            observed_revision,
                        )

                    new_focus = {
                        "observed_at": observed_at,
                        "project_id": project_id,
                        "record_ids": list(selected_ids),
                        "revision": observed_revision + 1,
                        "schema_version": 2,
                    }
                    new_focus_bytes = _json_bytes(new_focus)
                    focus_token = _sha256(
                        (
                            context.transaction_id
                            + "\0"
                            + _sha256(old_focus_bytes)
                            + "\0"
                            + _sha256(new_focus_bytes)
                        ).encode("utf-8")
                    )
                    cas_intent = dict(intent)
                    cas_intent["focus_cas"] = {
                        "desired_revision": observed_revision + 1,
                        "desired_sha256": _sha256(new_focus_bytes),
                        "expected_revision": observed_revision,
                        "expected_sha256": _sha256(old_focus_bytes),
                        "pending_name": ".pending-" + focus_token,
                    }
                    cas_intent_bytes = _json_bytes(cas_intent)
                    _finalize_transaction(
                        transaction_path,
                        intent_bytes,
                        cas_intent_bytes,
                        context.transaction_id,
                    )
                    intent = cas_intent
                    intent_bytes = cas_intent_bytes
                    _replace_cas(
                        focus_path,
                        old_focus_bytes,
                        new_focus_bytes,
                        focus_token,
                        root=root,
                    )
                    final = dict(intent)
                    final.update(
                        {
                            "focus_revision": observed_revision + 1,
                            "status": "accepted",
                        }
                    )
                    _finalize_transaction(
                        transaction_path,
                        intent_bytes,
                        _json_bytes(final),
                        context.transaction_id,
                    )
                    return FocusUpdateOutcome(
                        "accepted",
                        context.transaction_id,
                        observed_revision + 1,
                        None,
                        None,
                    )
            except LockBusyError:
                busy_revision = observe_focus_revision()
                return propose(
                    "occupied-lock",
                    {"focus_revision": busy_revision},
                    busy_revision,
                )
    except LockBusyError:
        busy_revision = observe_focus_revision()
        return propose(
            "root-write-busy",
            {"focus_revision": busy_revision},
            busy_revision,
        )


def preserve_promotion_candidate(
    root: Path,
    candidate: PromotionCandidate,
    context: TransactionContext,
    guard: Optional[RootWriteGuard] = None,
) -> Path:
    _validate_context(context)
    if not isinstance(candidate, PromotionCandidate):
        raise ValidationError("invalid promotion candidate")
    validate_identifier(candidate.candidate_id, "candidate_id")
    if not candidate.source_record_ids:
        raise ValidationError("promotion candidate requires sources")
    for source_id in candidate.source_record_ids:
        validate_identifier(source_id, "source_record_id")
    suggested = PurePosixPath(candidate.suggested_target)
    windows_suggested = PureWindowsPath(candidate.suggested_target)
    if (
        not isinstance(candidate.suggested_target, str)
        or not candidate.suggested_target
        or suggested.is_absolute()
        or windows_suggested.is_absolute()
        or "\\" in candidate.suggested_target
        or any(part in ("", ".", "..") for part in suggested.parts)
        or len(suggested.parts) < 2
    ):
        raise ValidationError("suggested target must be a portable relative Knowledge Base hint")
    if not isinstance(candidate.rationale, str) or not candidate.rationale.strip():
        raise ValidationError("promotion candidate requires rationale")
    root = _prepare_root(root)
    if guard is not None:
        _require_guard(root, context, guard)
    transaction_path = root / ".agent-memory" / "transactions" / (context.transaction_id + ".json")
    proposal_path = root / ".agent-memory" / "state" / "proposals" / (candidate.candidate_id + ".json")
    desired = {
        "candidate_id": candidate.candidate_id,
        "rationale": candidate.rationale,
        "source_record_ids": list(candidate.source_record_ids),
        "suggested_target": candidate.suggested_target,
    }
    intent = {
        "actor": context.actor,
        "desired": desired,
        "expected_base": {},
        "occurred_at": context.occurred_at,
        "operation": "knowledge-promotion",
        "schema_version": 2,
        "status": "in-progress",
        "target": proposal_path.relative_to(root).as_posix(),
        "transaction_id": context.transaction_id,
    }
    intent_bytes = _json_bytes(intent)
    _publish_exclusive(
        transaction_path,
        intent_bytes,
        _sha256((context.transaction_id + "\0promotion-intent").encode("utf-8")),
        root=root,
    )

    def preserve(catalog: Mapping[str, object]) -> Path:
        records = catalog.get("records")
        revision = catalog.get("revision")
        if not isinstance(records, dict) or type(revision) is not int:
            raise AgentMemoryError("invalid catalog")
        if any(source_id not in records for source_id in candidate.source_record_ids):
            raise ConflictError("promotion source is not current")
        proposal = {
            "actor": context.actor,
            "conflict_code": "knowledge-promotion-candidate",
            "desired": desired,
            "expected_base": {"source_record_ids": list(candidate.source_record_ids)},
            "observed_base": {"catalog_revision": revision},
            "occurred_at": context.occurred_at,
            "operation": "knowledge-promotion",
            "schema_version": 2,
            "target": candidate.suggested_target,
            "transaction_id": context.transaction_id,
        }
        _publish_exclusive(
            proposal_path,
            _json_bytes(proposal),
            _sha256((context.transaction_id + "\0" + candidate.candidate_id).encode("utf-8")),
            root=root,
        )
        final = dict(intent)
        final.update(
            {
                "observed_base": {"catalog_revision": revision},
                "proposal_path": proposal_path.relative_to(root).as_posix(),
                "status": "accepted",
            }
        )
        _finalize_transaction(transaction_path, intent_bytes, _json_bytes(final), context.transaction_id)
        return proposal_path

    try:
        with _with_guard(root, context, guard):
            with _narrow_lock(root, "catalog", context):
                catalog = json.loads(
                    _read_plain_text(root / ".agent-memory" / "state" / "catalog.json")
                )
                return preserve(catalog)
    except LockBusyError:
        # Append-only promotion evidence survives a busy canonical writer. Read
        # one complete catalog snapshot and preserve it without cross-root I/O.
        catalog = json.loads(
            _read_plain_text(root / ".agent-memory" / "state" / "catalog.json")
        )
        return preserve(catalog)


def preserve_unbound_session_candidate(
    root: Path,
    candidate: UnboundSessionCandidate,
    context: TransactionContext,
    guard: Optional[RootWriteGuard] = None,
) -> Path:
    """Preserve an unconfirmed Session as append-only operational evidence."""
    _validate_context(context)
    _validate_unbound_session_candidate(candidate)
    if candidate.session_candidate.envelope.project != candidate.project_id:
        raise ValidationError("unbound Session project does not match proposal project")
    root = _prepare_root(root)
    if guard is not None:
        _require_guard(root, context, guard)
    transaction_path = root / ".agent-memory" / "transactions" / (context.transaction_id + ".json")
    proposal_path = root / ".agent-memory" / "state" / "proposals" / (context.transaction_id + ".json")
    semantic_candidate = {
        "body": normalize_body(candidate.session_candidate.body),
        "envelope": asdict(candidate.session_candidate.envelope),
    }
    primary = None
    if candidate.candidate_primary_story_id is not None:
        primary = {
            "evidence": candidate.candidate_primary_evidence,
            "story_id": candidate.candidate_primary_story_id,
        }
    related = [
        {"evidence": evidence, "story_id": story_id}
        for story_id, evidence in zip(
            candidate.candidate_related_story_ids,
            candidate.candidate_related_evidence,
        )
    ]
    desired = {
        "candidate_primary_story": primary,
        "candidate_related_stories": related,
        "coordinator_task_id": candidate.coordinator_task_id,
        "intended_story_delta": (
            asdict(candidate.intended_story_delta)
            if candidate.intended_story_delta is not None
            else None
        ),
        "origin_task_id": candidate.origin_task_id,
        "project_id": candidate.project_id,
        "session_candidate": semantic_candidate,
        "session_candidate_sha256": _sha256(_json_bytes(semantic_candidate)),
    }
    target = proposal_path.relative_to(root).as_posix()
    intent = {
        "actor": context.actor,
        "desired": desired,
        "expected_base": {},
        "occurred_at": context.occurred_at,
        "operation": "unbound-session",
        "schema_version": 2,
        "status": "in-progress",
        "target": target,
        "transaction_id": context.transaction_id,
    }
    intent_bytes = _json_bytes(intent)
    _publish_exclusive(
        transaction_path,
        intent_bytes,
        _sha256((context.transaction_id + "\0unbound-session-intent").encode("utf-8")),
        root=root,
    )
    proposal = dict(intent)
    proposal.update(
        {
            "observed_base": {},
            "status": "proposed",
        }
    )
    proposal_bytes = _json_bytes(proposal)
    with _with_guard(root, context, guard):
        _publish_exclusive(
            proposal_path,
            proposal_bytes,
            _sha256((context.transaction_id + "\0unbound-session-proposal").encode("utf-8")),
            root=root,
        )
        final = dict(intent)
        final.update(
            {
                "observed_base": {},
                "proposal_path": target,
                "status": "proposed",
            }
        )
        _finalize_transaction(
            transaction_path,
            intent_bytes,
            _json_bytes(final),
            context.transaction_id,
        )
    return proposal_path


def recover_root_write_guard(
    root: Path,
    target_transaction_id: str,
    expected_lock_sha256: Optional[str],
    context: TransactionContext,
    authorization_ref: str,
) -> ContextManager[RootGuardRecovery]:
    return _recover_root_write_guard(
        root,
        target_transaction_id,
        expected_lock_sha256,
        context,
        authorization_ref,
    )


def _recovery_checkpoint(stage: str) -> None:
    """Private deterministic crash-injection seam used by durability tests."""


def _publish_transition(
    root: Path,
    path: Path,
    document: Mapping[str, object],
    operation_id: str,
) -> bytes:
    content = _json_bytes(document)
    _publish_exclusive(
        path,
        content,
        _sha256((operation_id + "\0" + path.name).encode("utf-8")),
        root=root,
    )
    return content


@contextlib.contextmanager
def _recover_root_write_guard(
    root: Path,
    target_transaction_id: str,
    expected_lock_sha256: Optional[str],
    context: TransactionContext,
    authorization_ref: str,
) -> Iterator[RootGuardRecovery]:
    _validate_context(context)
    validate_identifier(target_transaction_id, "target_transaction_id")
    if target_transaction_id == context.transaction_id:
        raise ValidationError("recovery context must be distinct")
    if not isinstance(authorization_ref, str) or not authorization_ref.strip():
        raise ValidationError("authorization reference is required")
    if expected_lock_sha256 is not None and (
        len(expected_lock_sha256) != 64
        or any(character not in _HASH_HEX for character in expected_lock_sha256)
    ):
        raise ValidationError("expected lock hash must be lowercase sha256")
    root = _prepare_root(root)
    _assert_plain_path(root)
    anchor = _ensure_anchor(root)
    anchor_lease = _Lease.open(anchor)
    if not anchor_lease.acquire():
        anchor_lease.close()
        raise LockBusyError("root-write-busy")

    canonical = root / _ROOT_LOCK_NAME
    old_candidate = _root_candidate(root, target_transaction_id)
    new_candidate = _root_candidate(root, context.transaction_id)
    operation_tuple = {
        "authorization_ref": authorization_ref,
        "expected_lock_sha256": expected_lock_sha256,
        "recovery_transaction_id": context.transaction_id,
        "target_transaction_id": target_transaction_id,
    }
    operation_id = _sha256(_json_bytes(operation_tuple))
    operation_directory = root / ".agent-memory-root-write-recoveries" / operation_id
    evidence_path = operation_directory / "old-artifact.bin"
    prepared_path = operation_directory / "000-prepared.json"
    published_path = operation_directory / "010-new-guard-published.json"
    removed_path = operation_directory / "020-old-artifact-removed.json"
    old_lease: Optional[_Lease] = None
    new_lease: Optional[_Lease] = None
    registered_guard: Optional[RootWriteGuard] = None
    old_source: Optional[Path] = None
    try:
        if operation_directory.exists():
            with _resume_recovery_operation(
                root,
                canonical,
                old_candidate,
                new_candidate,
                operation_directory,
                evidence_path,
                prepared_path,
                published_path,
                removed_path,
                operation_id,
                operation_tuple,
                context,
                anchor_lease,
            ) as recovery:
                yield recovery
            return
        root_candidates = set(root.glob(_ROOT_CANDIDATE_PREFIX + "*"))
        permitted_candidates = {old_candidate}
        extras = root_candidates - permitted_candidates
        if extras:
            raise ConflictError("unknown root guard candidate inventory")

        if canonical.exists():
            recovered_kind = "canonical-lock"
            if expected_lock_sha256 is None:
                raise ValidationError("canonical recovery requires expected hash")
            old_source = old_candidate if old_candidate.exists() else canonical
        else:
            recovered_kind = "candidate-only"
            if expected_lock_sha256 is not None:
                raise ValidationError("candidate-only recovery does not accept canonical hash")
            if not old_candidate.exists():
                raise ConflictError("candidate-only artifact is absent")
            old_source = old_candidate

        _assert_plain_file(old_source)
        old_lease = _Lease.open(old_source)
        if not old_lease.acquire():
            raise LockBusyError("stale root guard still has a live lease")
        old_bytes = old_lease.read_all()
        old_hash = _sha256(old_bytes)
        old_metadata = os.fstat(old_lease.descriptor)
        if recovered_kind == "canonical-lock":
            if old_hash != expected_lock_sha256:
                raise ConflictError("canonical root guard hash changed")
            if old_candidate.exists() and not _same_file(canonical, old_candidate):
                raise ConflictError("canonical and candidate guard differ")
            try:
                lock_document = json.loads(old_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ConflictError("malformed canonical root guard") from error
            if (
                not isinstance(lock_document, dict)
                or lock_document.get("transaction_id") != target_transaction_id
                or lock_document.get("target") != "."
                or set(lock_document) - {"actor", "created_at", "process_id", "target", "transaction_id"}
            ):
                raise ConflictError("canonical root guard identity mismatch")

        _assert_checked_parent(root, evidence_path, allow_missing=True)
        operation_directory.mkdir(parents=True, exist_ok=False)
        _assert_plain_path(operation_directory)
        _assert_checked_parent(root, old_source)
        _assert_checked_parent(root, evidence_path)
        os.link(str(old_source), str(evidence_path))
        _fsync_directory(operation_directory)
        if not _same_file(old_source, evidence_path):
            raise AgentMemoryError("recovery evidence publication failed")
        _recovery_checkpoint("evidence-published")

        new_lock_bytes = _lock_document(context, ".", include_process=False)
        prepared_document = {
            "authorization_ref": authorization_ref,
            "new_guard": {
                "candidate": new_candidate.relative_to(root).as_posix(),
                "canonical": canonical.relative_to(root).as_posix(),
                "sha256": _sha256(new_lock_bytes),
                "size": len(new_lock_bytes),
            },
            "old_artifact": {
                "candidate": old_candidate.relative_to(root).as_posix(),
                "candidate_present": old_candidate.exists(),
                "canonical_present": canonical.exists(),
                "evidence": evidence_path.relative_to(root).as_posix(),
                "sha256": old_hash,
                "size": len(old_bytes),
                "device": old_metadata.st_dev,
                "inode": old_metadata.st_ino,
            },
            "operation_id": operation_id,
            "operation_tuple": operation_tuple,
            "previous_transition_sha256": None,
            "recovered_kind": recovered_kind,
            "schema_version": 1,
            "step": "prepared",
        }
        prepared_bytes = _publish_transition(root, prepared_path, prepared_document, operation_id)
        _recovery_checkpoint("prepared-transition-published")

        _assert_checked_parent(root, new_candidate)
        new_lease = _Lease.create(new_candidate)
        if not new_lease.acquire(offset=_OBSERVABLE_GUARD_LOCK_OFFSET):
            raise LockBusyError("recovery guard candidate is busy")
        new_lease.write_all(new_lock_bytes)
        _prove_live_unlink(root, new_candidate, new_lease, new_lock_bytes)
        new_metadata = os.fstat(new_lease.descriptor)
        _recovery_checkpoint("new-candidate-leased")

        if recovered_kind == "canonical-lock":
            _assert_checked_parent(root, canonical)
            canonical.unlink()
            _fsync_directory(root)
            _recovery_checkpoint("old-canonical-unlinked")
        _assert_checked_parent(root, new_candidate)
        _assert_checked_parent(root, canonical)
        os.link(str(new_candidate), str(canonical))
        _fsync_directory(root)
        _recovery_checkpoint("new-canonical-published")
        if not _same_file(new_candidate, canonical) or new_lease.read_all() != new_lock_bytes:
            raise AgentMemoryError("new recovery guard publication failed")
        published_document = {
            "endpoints": {
                "new_candidate": new_candidate.relative_to(root).as_posix(),
                "new_canonical": canonical.relative_to(root).as_posix(),
                "new_sha256": _sha256(new_lock_bytes),
                "new_device": new_metadata.st_dev,
                "new_inode": new_metadata.st_ino,
                "old_candidate_present": old_candidate.exists(),
                "old_evidence": evidence_path.relative_to(root).as_posix(),
                "old_sha256": old_hash,
                "old_device": old_metadata.st_dev,
                "old_inode": old_metadata.st_ino,
            },
            "operation_id": operation_id,
            "previous_transition_sha256": _sha256(prepared_bytes),
            "schema_version": 1,
            "step": "new-guard-published",
        }
        published_bytes = _publish_transition(root, published_path, published_document, operation_id)
        _recovery_checkpoint("published-transition-published")

        if old_candidate.exists():
            _assert_checked_parent(root, old_candidate)
            old_candidate.unlink()
            _fsync_directory(root)
            _recovery_checkpoint("old-candidate-unlinked")
        removed_document = {
            "endpoints": {
                "new_candidate": new_candidate.relative_to(root).as_posix(),
                "new_canonical": canonical.relative_to(root).as_posix(),
                "new_sha256": _sha256(new_lock_bytes),
                "new_device": new_metadata.st_dev,
                "new_inode": new_metadata.st_ino,
                "old_candidate_present": False,
                "old_evidence": evidence_path.relative_to(root).as_posix(),
                "old_sha256": old_hash,
                "old_device": old_metadata.st_dev,
                "old_inode": old_metadata.st_ino,
            },
            "operation_id": operation_id,
            "previous_transition_sha256": _sha256(published_bytes),
            "schema_version": 1,
            "step": "old-artifact-removed",
        }
        _publish_transition(root, removed_path, removed_document, operation_id)
        _recovery_checkpoint("removed-transition-published")
        old_lease.close()
        old_lease = None

        registered_guard = RootWriteGuard(
            root,
            canonical,
            _sha256(new_lock_bytes),
            context.transaction_id,
        )
        _ACTIVE_GUARDS[id(registered_guard)] = _ActiveGuard(
            registered_guard,
            new_lease,
            anchor_lease,
            new_candidate,
            new_lock_bytes,
            os.getpid(),
        )
        recovery = RootGuardRecovery(
            registered_guard,
            evidence_path,
            recovered_kind,
            old_hash,
        )
        yield recovery
    finally:
        if old_lease is not None:
            old_lease.close()
        if registered_guard is not None:
            active = _ACTIVE_GUARDS.pop(id(registered_guard), None)
            if active is not None:
                try:
                    if canonical.exists() and _same_file(canonical, new_candidate):
                        _assert_checked_parent(root, canonical)
                        canonical.unlink()
                        _fsync_directory(root)
                    if new_candidate.exists() and active.guard_lease.read_all() == active.lock_bytes:
                        _assert_checked_parent(root, new_candidate)
                        new_candidate.unlink()
                        _fsync_directory(root)
                finally:
                    active.guard_lease.close()
        elif new_lease is not None:
            new_lease.close()
        anchor_lease.close()


def _load_recovery_transition(path: Path, label: str) -> Tuple[bytes, Mapping[str, object]]:
    _assert_plain_file(path)
    content = path.read_bytes()
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConflictError("malformed {0} recovery transition".format(label)) from error
    if not isinstance(document, dict):
        raise ConflictError("invalid {0} recovery transition".format(label))
    return content, document


def _validate_recovery_prefix_before_mutation(
    root: Path,
    canonical: Path,
    old_candidate: Path,
    new_candidate: Path,
    evidence_path: Path,
    prepared_path: Path,
    published_path: Path,
    removed_path: Path,
    operation_id: str,
    operation_tuple: Mapping[str, object],
    old_hash: str,
    old_metadata: object,
    new_lock_bytes: bytes,
) -> None:
    """Validate the complete immutable replay prefix and current endpoints."""
    for endpoint in (
        canonical,
        old_candidate,
        new_candidate,
        evidence_path,
        prepared_path,
        published_path,
        removed_path,
    ):
        _assert_checked_parent(root, endpoint)
    _assert_plain_file(evidence_path)
    for existing_endpoint in (canonical, old_candidate, new_candidate):
        if existing_endpoint.exists():
            _assert_plain_file(existing_endpoint)
    prepared_exists = prepared_path.exists()
    published_exists = published_path.exists()
    removed_exists = removed_path.exists()
    if (published_exists and not prepared_exists) or (removed_exists and not published_exists):
        raise ConflictError("recovery transition chain is noncontiguous")

    prepared_bytes = None
    prepared = None
    recovered_kind = "canonical-lock" if operation_tuple["expected_lock_sha256"] is not None else "candidate-only"
    expected_new_guard = {
        "candidate": new_candidate.relative_to(root).as_posix(),
        "canonical": canonical.relative_to(root).as_posix(),
        "sha256": _sha256(new_lock_bytes),
        "size": len(new_lock_bytes),
    }
    if not prepared_exists:
        if new_candidate.exists():
            raise ConflictError("unrecorded recovery guard candidate")
        if recovered_kind == "candidate-only":
            if canonical.exists() or not old_candidate.exists() or not _same_file(
                old_candidate, evidence_path
            ):
                raise ConflictError("candidate-only prepared endpoint drift")
        elif not canonical.exists() or not _same_file(canonical, evidence_path):
            raise ConflictError("canonical prepared endpoint drift")
        if old_candidate.exists() and not _same_file(old_candidate, evidence_path):
            raise ConflictError("prepared old-candidate inode drift")
    if prepared_exists:
        prepared_bytes, prepared = _load_recovery_transition(prepared_path, "prepared")
        old_artifact = prepared.get("old_artifact")
        if (
            set(prepared) != {
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
            or not isinstance(prepared.get("new_guard"), dict)
            or set(prepared["new_guard"]) != {"candidate", "canonical", "sha256", "size"}
            or prepared.get("authorization_ref") != operation_tuple["authorization_ref"]
            or prepared.get("new_guard") != expected_new_guard
            or not isinstance(old_artifact, dict)
            or set(old_artifact) != {
                "candidate",
                "candidate_present",
                "canonical_present",
                "device",
                "evidence",
                "inode",
                "sha256",
                "size",
            }
            or old_artifact.get("candidate") != old_candidate.relative_to(root).as_posix()
            or type(old_artifact.get("candidate_present")) is not bool
            or type(old_artifact.get("canonical_present")) is not bool
            or old_artifact.get("canonical_present") != (recovered_kind == "canonical-lock")
            or old_artifact.get("evidence") != evidence_path.relative_to(root).as_posix()
            or old_artifact.get("sha256") != old_hash
            or old_artifact.get("size") != old_metadata.st_size
            or old_artifact.get("device") != old_metadata.st_dev
            or old_artifact.get("inode") != old_metadata.st_ino
            or prepared.get("operation_id") != operation_id
            or prepared.get("operation_tuple") != operation_tuple
            or prepared.get("previous_transition_sha256") is not None
            or prepared.get("recovered_kind") != recovered_kind
            or prepared.get("schema_version") != 1
            or prepared.get("step") != "prepared"
        ):
            raise ConflictError("prepared recovery transition drift")
        for recorded, expected in (
            (old_artifact["candidate"], old_candidate),
            (old_artifact["evidence"], evidence_path),
            (expected_new_guard["candidate"], new_candidate),
            (expected_new_guard["canonical"], canonical),
        ):
            if root / Path(recorded) != expected:
                raise ConflictError("recorded recovery path drift")
            _assert_checked_parent(root, expected)

    published_bytes = None
    published = None
    if published_exists:
        published_bytes, published = _load_recovery_transition(published_path, "published")
        endpoints = published.get("endpoints")
        if (
            set(published) != {
                "endpoints",
                "operation_id",
                "previous_transition_sha256",
                "schema_version",
                "step",
            }
            or not isinstance(endpoints, dict)
            or set(endpoints) != {
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
            or published.get("operation_id") != operation_id
            or published.get("previous_transition_sha256") != _sha256(prepared_bytes)
            or published.get("schema_version") != 1
            or published.get("step") != "new-guard-published"
            or endpoints.get("new_candidate") != new_candidate.relative_to(root).as_posix()
            or endpoints.get("new_canonical") != canonical.relative_to(root).as_posix()
            or endpoints.get("old_evidence") != evidence_path.relative_to(root).as_posix()
            or endpoints.get("new_sha256") != _sha256(new_lock_bytes)
            or endpoints.get("old_sha256") != old_hash
            or endpoints.get("old_device") != old_metadata.st_dev
            or endpoints.get("old_inode") != old_metadata.st_ino
            or type(endpoints.get("old_candidate_present")) is not bool
            or endpoints.get("old_candidate_present") != old_artifact.get("candidate_present")
        ):
            raise ConflictError("published recovery transition drift")
        if not new_candidate.exists() or not canonical.exists():
            raise ConflictError("published recovery endpoint is missing")
        _assert_plain_file(new_candidate)
        _assert_plain_file(canonical)
        if not _same_file(new_candidate, canonical) or new_candidate.read_bytes() != new_lock_bytes:
            raise ConflictError("published recovery endpoint drift")
        new_metadata = new_candidate.stat()
        if (
            endpoints.get("new_device") != new_metadata.st_dev
            or endpoints.get("new_inode") != new_metadata.st_ino
        ):
            raise ConflictError("published recovery inode drift")
        recorded_old_present = endpoints["old_candidate_present"]
        removal_marker_pending = (
            not removed_exists
            and recorded_old_present is True
            and not old_candidate.exists()
        )
        if (
            not removed_exists
            and old_candidate.exists() != recorded_old_present
            and not removal_marker_pending
        ):
            raise ConflictError("published old-candidate presence drift")
        if old_candidate.exists():
            _assert_plain_file(old_candidate)
            if not _same_file(old_candidate, evidence_path):
                raise ConflictError("published old-candidate inode drift")

    if removed_exists:
        _, removed = _load_recovery_transition(removed_path, "removed")
        expected_endpoints = dict(published["endpoints"])
        expected_endpoints["old_candidate_present"] = False
        if (
            set(removed) != {
                "endpoints",
                "operation_id",
                "previous_transition_sha256",
                "schema_version",
                "step",
            }
            or removed.get("operation_id") != operation_id
            or removed.get("previous_transition_sha256") != _sha256(published_bytes)
            or removed.get("schema_version") != 1
            or removed.get("step") != "old-artifact-removed"
            or removed.get("endpoints") != expected_endpoints
            or old_candidate.exists()
        ):
            raise ConflictError("removed recovery transition drift")
    elif prepared_exists and not published_exists:
        old_artifact = prepared["old_artifact"]
        if old_candidate.exists() != old_artifact["candidate_present"]:
            raise ConflictError("prepared old-candidate presence drift")
        if old_candidate.exists() and not _same_file(old_candidate, evidence_path):
            raise ConflictError("prepared old-candidate inode drift")
        if canonical.exists():
            if not _same_file(canonical, evidence_path) and not (
                new_candidate.exists() and _same_file(canonical, new_candidate)
            ):
                raise ConflictError("prepared canonical endpoint drift")


@contextlib.contextmanager
def _resume_recovery_operation(
    root: Path,
    canonical: Path,
    old_candidate: Path,
    new_candidate: Path,
    operation_directory: Path,
    evidence_path: Path,
    prepared_path: Path,
    published_path: Path,
    removed_path: Path,
    operation_id: str,
    operation_tuple: Mapping[str, object],
    context: TransactionContext,
    anchor_lease: _Lease,
) -> Iterator[RootGuardRecovery]:
    _assert_plain_path(operation_directory)
    _assert_checked_parent(root, evidence_path)
    permitted_names = {
        "old-artifact.bin",
        "000-prepared.json",
        "010-new-guard-published.json",
        "020-old-artifact-removed.json",
    }
    if any(path.name not in permitted_names for path in operation_directory.iterdir()):
        raise ConflictError("unknown recovery operation inventory")
    if not evidence_path.exists():
        raise ConflictError("recovery evidence is incomplete")
    old_lease = _Lease.open(evidence_path)
    if not old_lease.acquire():
        old_lease.close()
        raise LockBusyError("recovery evidence lease is busy")
    new_lease: Optional[_Lease] = None
    registered_guard: Optional[RootWriteGuard] = None
    try:
        old_bytes = old_lease.read_all()
        old_hash = _sha256(old_bytes)
        old_metadata = os.fstat(old_lease.descriptor)
        expected_hash = operation_tuple["expected_lock_sha256"]
        recovered_kind = "canonical-lock" if expected_hash is not None else "candidate-only"
        if expected_hash is not None and old_hash != expected_hash:
            raise ConflictError("recovery evidence hash drift")
        if old_candidate.exists() and not _same_file(old_candidate, evidence_path):
            raise ConflictError("old recovery candidate endpoint drift")

        new_lock_bytes = _lock_document(context, ".", include_process=False)
        _validate_recovery_prefix_before_mutation(
            root,
            canonical,
            old_candidate,
            new_candidate,
            evidence_path,
            prepared_path,
            published_path,
            removed_path,
            operation_id,
            operation_tuple,
            old_hash,
            old_metadata,
            new_lock_bytes,
        )
        if prepared_path.exists():
            prepared_bytes = prepared_path.read_bytes()
            prepared = json.loads(prepared_bytes.decode("utf-8"))
            if (
                prepared.get("operation_id") != operation_id
                or prepared.get("operation_tuple") != operation_tuple
                or prepared.get("previous_transition_sha256") is not None
                or prepared.get("old_artifact", {}).get("sha256") != old_hash
                or prepared.get("old_artifact", {}).get("device") != old_metadata.st_dev
                or prepared.get("old_artifact", {}).get("inode") != old_metadata.st_ino
                or prepared.get("new_guard", {}).get("sha256") != _sha256(new_lock_bytes)
            ):
                raise ConflictError("prepared recovery transition drift")
        else:
            if published_path.exists() or removed_path.exists() or canonical.exists() and not _same_file(canonical, evidence_path):
                raise ConflictError("recovery transition chain is noncontiguous")
            prepared_document = {
                "authorization_ref": operation_tuple["authorization_ref"],
                "new_guard": {
                    "candidate": new_candidate.relative_to(root).as_posix(),
                    "canonical": canonical.relative_to(root).as_posix(),
                    "sha256": _sha256(new_lock_bytes),
                    "size": len(new_lock_bytes),
                },
                "old_artifact": {
                    "candidate": old_candidate.relative_to(root).as_posix(),
                    "candidate_present": old_candidate.exists(),
                    "canonical_present": canonical.exists(),
                    "evidence": evidence_path.relative_to(root).as_posix(),
                    "sha256": old_hash,
                    "size": len(old_bytes),
                    "device": old_metadata.st_dev,
                    "inode": old_metadata.st_ino,
                },
                "operation_id": operation_id,
                "operation_tuple": dict(operation_tuple),
                "previous_transition_sha256": None,
                "recovered_kind": recovered_kind,
                "schema_version": 1,
                "step": "prepared",
            }
            prepared_bytes = _publish_transition(root, prepared_path, prepared_document, operation_id)

        if new_candidate.exists():
            new_lease = _Lease.open(new_candidate)
            if not new_lease.acquire(offset=_OBSERVABLE_GUARD_LOCK_OFFSET):
                raise LockBusyError("recovery guard candidate is busy")
            if new_lease.read_all() != new_lock_bytes:
                raise ConflictError("new recovery candidate hash drift")
        else:
            new_lease = _Lease.create(new_candidate)
            if not new_lease.acquire(offset=_OBSERVABLE_GUARD_LOCK_OFFSET):
                raise LockBusyError("recovery guard candidate is busy")
            new_lease.write_all(new_lock_bytes)
        _prove_live_unlink(root, new_candidate, new_lease, new_lock_bytes)
        new_metadata = os.fstat(new_lease.descriptor)

        if canonical.exists():
            if _same_file(canonical, evidence_path):
                _assert_checked_parent(root, canonical)
                canonical.unlink()
                _fsync_directory(root)
            elif not _same_file(canonical, new_candidate):
                raise ConflictError("canonical recovery endpoint drift")
        if not canonical.exists():
            _assert_checked_parent(root, new_candidate)
            _assert_checked_parent(root, canonical)
            os.link(str(new_candidate), str(canonical))
            _fsync_directory(root)
        if not _same_file(canonical, new_candidate):
            raise ConflictError("new canonical recovery endpoint drift")

        expected_published_document = {
            "endpoints": {
                "new_candidate": new_candidate.relative_to(root).as_posix(),
                "new_canonical": canonical.relative_to(root).as_posix(),
                "new_sha256": _sha256(new_lock_bytes),
                "new_device": new_metadata.st_dev,
                "new_inode": new_metadata.st_ino,
                "old_candidate_present": old_candidate.exists(),
                "old_evidence": evidence_path.relative_to(root).as_posix(),
                "old_sha256": old_hash,
                "old_device": old_metadata.st_dev,
                "old_inode": old_metadata.st_ino,
            },
            "operation_id": operation_id,
            "previous_transition_sha256": _sha256(prepared_bytes),
            "schema_version": 1,
            "step": "new-guard-published",
        }
        if published_path.exists():
            published_bytes = published_path.read_bytes()
            published = json.loads(published_bytes.decode("utf-8"))
            if (
                published.get("operation_id") != operation_id
                or published.get("previous_transition_sha256") != _sha256(prepared_bytes)
                or published.get("endpoints", {}).get("new_sha256") != _sha256(new_lock_bytes)
                or published.get("endpoints", {}).get("old_sha256") != old_hash
                or published.get("endpoints", {}).get("new_device") != new_metadata.st_dev
                or published.get("endpoints", {}).get("new_inode") != new_metadata.st_ino
                or published.get("endpoints", {}).get("old_device") != old_metadata.st_dev
                or published.get("endpoints", {}).get("old_inode") != old_metadata.st_ino
            ):
                raise ConflictError("published recovery transition drift")
        else:
            if removed_path.exists():
                raise ConflictError("recovery transition chain is noncontiguous")
            published_bytes = _publish_transition(
                root,
                published_path,
                expected_published_document,
                operation_id,
            )

        if old_candidate.exists():
            if not _same_file(old_candidate, evidence_path):
                raise ConflictError("old recovery candidate endpoint drift")
            _assert_checked_parent(root, old_candidate)
            old_candidate.unlink()
            _fsync_directory(root)
            _recovery_checkpoint("old-candidate-unlinked")
        expected_removed_document = {
            "endpoints": {
                "new_candidate": new_candidate.relative_to(root).as_posix(),
                "new_canonical": canonical.relative_to(root).as_posix(),
                "new_sha256": _sha256(new_lock_bytes),
                "new_device": new_metadata.st_dev,
                "new_inode": new_metadata.st_ino,
                "old_candidate_present": False,
                "old_evidence": evidence_path.relative_to(root).as_posix(),
                "old_sha256": old_hash,
                "old_device": old_metadata.st_dev,
                "old_inode": old_metadata.st_ino,
            },
            "operation_id": operation_id,
            "previous_transition_sha256": _sha256(published_bytes),
            "schema_version": 1,
            "step": "old-artifact-removed",
        }
        if removed_path.exists():
            removed = json.loads(removed_path.read_text("utf-8"))
            if (
                removed.get("operation_id") != operation_id
                or removed.get("previous_transition_sha256") != _sha256(published_bytes)
                or removed.get("endpoints") != expected_removed_document["endpoints"]
            ):
                raise ConflictError("removed recovery transition drift")
        else:
            _publish_transition(root, removed_path, expected_removed_document, operation_id)
        old_lease.close()
        old_lease = None

        registered_guard = RootWriteGuard(root, canonical, _sha256(new_lock_bytes), context.transaction_id)
        _ACTIVE_GUARDS[id(registered_guard)] = _ActiveGuard(
            registered_guard,
            new_lease,
            anchor_lease,
            new_candidate,
            new_lock_bytes,
            os.getpid(),
        )
        yield RootGuardRecovery(
            registered_guard,
            evidence_path,
            recovered_kind,
            old_hash,
        )
    finally:
        if old_lease is not None:
            old_lease.close()
        if registered_guard is not None:
            active = _ACTIVE_GUARDS.pop(id(registered_guard), None)
            if active is not None:
                try:
                    if canonical.exists() and _same_file(canonical, new_candidate):
                        _assert_checked_parent(root, canonical)
                        canonical.unlink()
                        _fsync_directory(root)
                    if new_candidate.exists() and active.guard_lease.read_all() == active.lock_bytes:
                        _assert_checked_parent(root, new_candidate)
                        new_candidate.unlink()
                        _fsync_directory(root)
                finally:
                    active.guard_lease.close()
        elif new_lease is not None:
            new_lease.close()
