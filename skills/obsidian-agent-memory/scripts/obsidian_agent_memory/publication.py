"""No-replace external publication for bounded, strictly validated reports."""

import ctypes
import os
import re
import secrets
import stat
from pathlib import Path, PureWindowsPath
from typing import Callable, Tuple

from .errors import ValidationError


_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_DEVICE_NAMES = {
    "con", "prn", "aux", "nul",
    *("com{0}".format(value) for value in range(1, 10)),
    *("lpt{0}".format(value) for value in range(1, 10)),
}
_FORBIDDEN = re.compile(r'[<>"|?*\x00-\x1f]')


def _publication_checkpoint(stage: str, path: Path) -> None:
    """Narrow race-injection seam for publication tests."""


def _lexical_absolute(path: Path) -> Path:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw:
        raise ValidationError("output path must be explicit absolute text")
    lowered = raw.lower()
    if lowered.startswith(("\\\\?\\", "\\\\.\\", "\\??\\", "\\device\\")):
        raise ValidationError("device namespace output is forbidden")
    pure = PureWindowsPath(raw)
    if not pure.is_absolute() or not pure.drive or pure.root != "\\":
        raise ValidationError("output path must be absolute")
    if pure.drive.startswith("\\"):
        raise ValidationError("UNC output is unsupported")
    for index, component in enumerate(pure.parts):
        if index == 0:
            continue
        if component in ("", ".", "..") or component.endswith((".", " ")):
            raise ValidationError("invalid output path component")
        if _FORBIDDEN.search(component) or ":" in component:
            raise ValidationError("invalid output path component")
        stem = component.split(".", 1)[0].lower()
        if stem in _DEVICE_NAMES:
            raise ValidationError("reserved output path component")
    return Path(raw)


def _require_windows_ntfs(path: Path) -> None:
    if os.name != "nt":
        raise ValidationError("immutable publication backend is unsupported")
    drive = PureWindowsPath(str(path)).drive + "\\"
    kernel32 = ctypes.windll.kernel32
    if kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive)) != 3:
        raise ValidationError("output requires a fixed local volume")
    filesystem = ctypes.create_unicode_buffer(64)
    if not kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(drive), None, 0, None, None, None, filesystem, len(filesystem)
    ):
        raise OSError(ctypes.get_last_error(), "volume identity query failed")
    if filesystem.value.upper() != "NTFS":
        raise ValidationError("output requires local NTFS")


def _plain_metadata(path: Path, allow_directory=True):
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & _REPARSE_FLAG:
        raise ValidationError("output path contains a link or reparse point")
    if not stat.S_ISREG(metadata.st_mode) and not (allow_directory and stat.S_ISDIR(metadata.st_mode)):
        raise ValidationError("output path contains a special node")
    return metadata


def _identity(metadata):
    return (getattr(metadata, "st_dev", None), getattr(metadata, "st_ino", None))


def _reject_protected(output: Path, protected_roots: Tuple[Path, ...]) -> None:
    output_text = os.path.normcase(os.path.abspath(str(output)))
    for value in protected_roots:
        protected = _lexical_absolute(Path(value))
        protected_text = os.path.normcase(os.path.abspath(str(protected)))
        try:
            if os.path.commonpath((output_text, protected_text)) == protected_text:
                raise ValidationError("output overlaps a protected root")
        except ValueError:
            continue

        try:
            protected_identity = _identity(_plain_metadata(protected))
        except OSError as error:
            raise ValidationError("protected root cannot be inspected") from error
        current = output.parent
        while True:
            try:
                if _identity(_plain_metadata(current)) == protected_identity:
                    raise ValidationError("output overlaps a protected root")
            except FileNotFoundError:
                pass
            if current.parent == current:
                break
            current = current.parent


def _prepare_parents(parent: Path):
    missing = []
    current = parent
    while True:
        try:
            metadata = _plain_metadata(current)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValidationError("output parent is not a directory")
            break
        except FileNotFoundError:
            missing.append(current)
            current = current.parent
    created = []
    try:
        for directory in reversed(missing):
            directory.mkdir()
            created.append(directory)
            _plain_metadata(directory)
            _publication_checkpoint("parent-created", directory)
    except BaseException:
        for directory in reversed(created):
            try:
                directory.rmdir()
            except OSError:
                pass
        raise
    return created


def publish_immutable_report(
    final_path: Path,
    raw: bytes,
    candidate_prefix: str,
    protected_roots: Tuple[Path, ...],
    strict_validator: Callable[[bytes], object],
) -> str:
    """Publish one validated report without replacing an occupied final path."""
    output = _lexical_absolute(Path(final_path))
    if (
        not isinstance(raw, bytes)
        or len(raw) > 64 * 1024 * 1024
        or not isinstance(candidate_prefix, str)
        or not re.fullmatch(r"[.a-z0-9_-]{1,64}", candidate_prefix)
        or not callable(strict_validator)
        or not isinstance(protected_roots, tuple)
    ):
        raise ValidationError("invalid immutable publication request")
    _require_windows_ntfs(output)
    _reject_protected(output, protected_roots)

    current = output.parent
    while current.parent != current:
        try:
            _plain_metadata(current)
        except FileNotFoundError:
            pass
        current = current.parent
    try:
        endpoint = _plain_metadata(output, allow_directory=False)
    except FileNotFoundError:
        endpoint = None
    if endpoint is not None:
        return "occupied"

    created = _prepare_parents(output.parent)
    candidate = output.parent / (candidate_prefix + secrets.token_hex(16))
    renamed = False
    handle = None
    try:
        _publication_checkpoint("before-candidate", candidate)
        handle = open(candidate, "x+b", buffering=0)
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        reread = handle.read(len(raw) + 1)
        if reread != raw:
            raise OSError("candidate content changed")
        _publication_checkpoint("candidate-flushed", candidate)
        strict_validator(reread)
        _publication_checkpoint("candidate-validated", candidate)
        _publication_checkpoint("before-rename", candidate)
        handle.close()
        handle = None
        try:
            os.rename(candidate, output)
        except FileExistsError:
            return "occupied"
        renamed = True
        _publication_checkpoint("after-rename", output)
        final_raw = output.read_bytes()
        if final_raw != raw:
            raise OSError("published report content changed")
        strict_validator(final_raw)
        with open(output, "r+b") as final_handle:
            os.fsync(final_handle.fileno())
        _publication_checkpoint("after-durability", output)
        return "created"
    finally:
        if handle is not None:
            handle.close()
        if not renamed:
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
            for directory in reversed(created):
                try:
                    directory.rmdir()
                except OSError:
                    pass
