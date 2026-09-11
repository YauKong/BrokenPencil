"""Byte-reproducible release archives and strict no-extraction verification."""

import contextlib
import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, Iterator, List, Mapping, Tuple

from obsidian_agent_memory import (
    Finding,
    PackManifest,
    ValidationError,
    load_pack_manifest,
    resolve_inside,
    validate_repository,
)
from obsidian_agent_memory.manifest import _convert_manifest, _portable_path_is_safe

from .io import _assert_plain_components, _fsync_directory, canonical_json_bytes
from .metadata import refresh_pack_manifest, validate_release_metadata
from .models import ReleaseArtifacts, VerifiedReleaseSource


ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_RELEASE_KEYS = frozenset(
    (
        "archive",
        "archive_sha256",
        "content_revision",
        "files",
        "pack_name",
        "pack_version",
        "schema_version",
    )
)
_FILE_KEYS = frozenset(("path", "sha256", "size"))
_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class _VerifiedDetails:
    artifacts: ReleaseArtifacts
    document: Mapping[str, object]
    records: Tuple[Mapping[str, object], ...]
    prefix: str


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.flag_bits = 0x800
    return info


def _pairs_object(pairs: Iterable[Tuple[str, object]]) -> Dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("duplicate release JSON key")
        result[key] = value
    return result


def _json_document(raw: bytes, name: str) -> Mapping[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_object)
    except ValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("invalid {0} JSON".format(name)) from error
    if not isinstance(value, dict):
        raise ValidationError("invalid {0} document".format(name))
    return value


def _pack_manifest_bytes(raw: bytes) -> PackManifest:
    document = _json_document(raw, "pack manifest")
    return _convert_manifest(document)


def _is_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def _regular_bytes(path: Path, name: str) -> bytes:
    source = Path(os.path.abspath(os.fspath(path)))
    try:
        _assert_plain_components(source, allow_missing=False)
        before = source.lstat()
        if _is_reparse(before) or not stat.S_ISREG(before.st_mode):
            raise ValidationError("invalid {0} path".format(name))
        raw = source.read_bytes()
        after = source.lstat()
    except ValidationError:
        raise
    except OSError as error:
        raise ValidationError("cannot read {0}".format(name)) from error
    if (
        _is_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
    ):
        raise ValidationError("{0} changed during read".format(name))
    return raw


def _sha256_path(path: Path, name: str) -> str:
    source = Path(os.path.abspath(os.fspath(path)))
    try:
        _assert_plain_components(source, allow_missing=False)
        metadata = source.lstat()
        if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("invalid {0} path".format(name))
        digest = hashlib.sha256()
        size = 0
        with source.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        after = source.lstat()
    except ValidationError:
        raise
    except OSError as error:
        raise ValidationError("cannot hash {0}".format(name)) from error
    if (
        _is_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or size != metadata.st_size
        or (metadata.st_dev, metadata.st_ino, metadata.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
    ):
        raise ValidationError("{0} changed during hash".format(name))
    return digest.hexdigest()


@contextlib.contextmanager
def _open_archive(path: Path) -> Iterator[object]:
    source = Path(os.path.abspath(os.fspath(path)))
    _assert_plain_components(source, allow_missing=False)
    try:
        before = source.lstat()
        if _is_reparse(before) or not stat.S_ISREG(before.st_mode):
            raise ValidationError("invalid release archive path")
        with source.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (before.st_dev, before.st_ino, before.st_size)
                != (opened.st_dev, opened.st_ino, opened.st_size)
            ):
                raise ValidationError("release archive changed before open")
            yield handle
            after_handle = os.fstat(handle.fileno())
        after_path = source.lstat()
    except ValidationError:
        raise
    except OSError as error:
        raise ValidationError("cannot open release archive") from error
    if (
        _is_reparse(after_path)
        or not stat.S_ISREG(after_path.st_mode)
        or (opened.st_dev, opened.st_ino, opened.st_size)
        != (after_handle.st_dev, after_handle.st_ino, after_handle.st_size)
        or (opened.st_dev, opened.st_ino, opened.st_size)
        != (after_path.st_dev, after_path.st_ino, after_path.st_size)
    ):
        raise ValidationError("release archive changed during verification")


def _hash_handle(handle: object) -> str:
    handle.seek(0)
    digest = hashlib.sha256()
    while True:
        chunk = handle.read(_CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _raise_findings(findings: Tuple[Finding, ...]) -> None:
    errors = tuple(item for item in findings if item.severity == "error")
    if errors:
        raise ValidationError("release source validation failed")


def _source_files(
    repo_root: Path, manifest: PackManifest
) -> Tuple[Tuple[str, bytes], ...]:
    release_paths = tuple(sorted(("pack.json",) + tuple(item.path for item in manifest.files)))
    expected_hashes = {item.path: item.sha256 for item in manifest.files}
    result = []
    for relative_path in release_paths:
        if not _portable_path_is_safe(relative_path):
            raise ValidationError("invalid release source path")
        candidate = repo_root.joinpath(*relative_path.split("/"))
        raw = _regular_bytes(candidate, "release source")
        expected = expected_hashes.get(relative_path)
        if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
            raise ValidationError("release source hash drift")
        result.append((relative_path, raw))
    return tuple(result)


def _unique_candidate(target: Path, purpose: str) -> Path:
    for unused in range(100):
        del unused
        candidate = target.with_name(
            ".{0}.{1}-{2}".format(target.name, purpose, uuid.uuid4().hex)
        )
        if not candidate.exists():
            return candidate
    raise ValidationError("could not allocate unique release candidate")


def _publish_bytes(path: Path, raw: bytes, purpose: str) -> None:
    candidate = _unique_candidate(path, purpose)
    try:
        with candidate.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(candidate), str(path))
        _fsync_directory(path.parent)
    except OSError as error:
        raise ValidationError("could not publish release artifact") from error


def build_release(repo_root: Path, dist_dir: Path) -> ReleaseArtifacts:
    """Build the fixed release artifacts from one already-current source tree."""
    root = Path(os.path.abspath(os.fspath(repo_root)))
    _assert_plain_components(root, allow_missing=False)
    manifest = refresh_pack_manifest(root, check=True)
    _raise_findings(validate_repository(root, manifest))
    _raise_findings(validate_release_metadata(root, manifest))
    source_files = _source_files(root, manifest)

    destination = Path(os.path.abspath(os.fspath(dist_dir)))
    destination.mkdir(parents=True, exist_ok=True)
    _assert_plain_components(destination, allow_missing=False)
    try:
        metadata = destination.lstat()
    except OSError as error:
        raise ValidationError("invalid release output directory") from error
    if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValidationError("invalid release output directory")

    archive_path = destination / manifest.release_archive
    checksum_path = destination / manifest.release_checksum
    release_manifest_path = destination / manifest.release_manifest
    temporary_archive = _unique_candidate(archive_path, "archive")
    prefix = "{0}-{1}".format(manifest.name, manifest.version)
    try:
        with zipfile.ZipFile(
            temporary_archive,
            mode="x",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            for relative_path, raw in source_files:
                name = prefix + "/" + relative_path
                archive.writestr(
                    zip_info(name),
                    raw,
                    compress_type=zipfile.ZIP_STORED,
                )
        with temporary_archive.open("r+b") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary_archive), str(archive_path))
        _fsync_directory(destination)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        raise ValidationError("could not build release archive") from error

    archive_sha256 = _sha256_path(archive_path, "release archive")
    file_records = []
    for relative_path, raw in source_files:
        file_records.append(
            {
                "path": relative_path,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        )
    file_records.sort(key=lambda item: item["path"])
    content_revision = hashlib.sha256(canonical_json_bytes(file_records)).hexdigest()
    release_document = {
        "archive": manifest.release_archive,
        "archive_sha256": archive_sha256,
        "content_revision": content_revision,
        "files": file_records,
        "pack_name": manifest.name,
        "pack_version": manifest.version,
        "schema_version": 1,
    }
    checksum_bytes = (
        archive_sha256 + "  " + manifest.release_archive + "\n"
    ).encode("ascii")
    _publish_bytes(
        release_manifest_path,
        canonical_json_bytes(release_document),
        "manifest",
    )
    _publish_bytes(checksum_path, checksum_bytes, "checksum")
    return ReleaseArtifacts(
        archive_path=archive_path,
        checksum_path=checksum_path,
        manifest_path=release_manifest_path,
        archive_sha256=archive_sha256,
        content_revision=content_revision,
    )


def _release_records(value: object) -> Tuple[Mapping[str, object], ...]:
    if not isinstance(value, list) or not value:
        raise ValidationError("invalid release file inventory")
    result: List[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _FILE_KEYS:
            raise ValidationError("invalid release file record")
        path = item["path"]
        sha256 = item["sha256"]
        size = item["size"]
        if not isinstance(path, str) or not _portable_path_is_safe(path):
            raise ValidationError("unsafe release file path")
        if not isinstance(sha256, str) or not _SHA256_PATTERN.fullmatch(sha256):
            raise ValidationError("invalid release file hash")
        if type(size) is not int or size < 0:
            raise ValidationError("invalid release file size")
        result.append(item)
    paths = tuple(item["path"] for item in result)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise ValidationError("invalid release file order")
    return tuple(result)


def _release_document(raw: bytes) -> Tuple[Mapping[str, object], Tuple[Mapping[str, object], ...]]:
    document = _json_document(raw, "release manifest")
    if set(document) != _RELEASE_KEYS or document["schema_version"] != 1:
        raise ValidationError("invalid release manifest keys or schema")
    for field in (
        "archive",
        "archive_sha256",
        "content_revision",
        "pack_name",
        "pack_version",
    ):
        if not isinstance(document[field], str):
            raise ValidationError("invalid release manifest {0}".format(field))
    if not _SHA256_PATTERN.fullmatch(document["archive_sha256"]):
        raise ValidationError("invalid release archive hash")
    if not _SHA256_PATTERN.fullmatch(document["content_revision"]):
        raise ValidationError("invalid release content revision")
    records = _release_records(document["files"])
    if hashlib.sha256(canonical_json_bytes(list(records))).hexdigest() != document[
        "content_revision"
    ]:
        raise ValidationError("release content revision mismatch")
    return document, records


def _member_path_is_safe(name: str, prefix: str) -> bool:
    if not isinstance(name, str) or "\\" in name or name.startswith("/"):
        return False
    path = PurePosixPath(name)
    if path.as_posix() != name or path.is_absolute():
        return False
    if any(part in ("", ".", "..") for part in path.parts):
        return False
    if not path.parts or path.parts[0] != prefix or ":" in path.parts[0]:
        return False
    relative = "/".join(path.parts[1:])
    return _portable_path_is_safe(relative)


def _member_metadata_is_canonical(info: zipfile.ZipInfo, expected_size: int) -> bool:
    return bool(
        not (info.flag_bits & 1)
        and not (info.flag_bits & ~0x800)
        and info.date_time == ZIP_EPOCH
        and info.compress_type == zipfile.ZIP_STORED
        and info.create_system == 3
        and info.external_attr >> 16 == 0o100644
        and info.internal_attr == 0
        and info.extra == b""
        and info.comment == b""
        and info.file_size == expected_size
        and info.compress_size == expected_size
    )


def _verify_release_details(
    archive_path: Path,
    checksum_path: Path,
    manifest_path: Path,
) -> _VerifiedDetails:
    archive = Path(os.path.abspath(os.fspath(archive_path)))
    checksum = Path(os.path.abspath(os.fspath(checksum_path)))
    release_manifest = Path(os.path.abspath(os.fspath(manifest_path)))
    checksum_raw = _regular_bytes(checksum, "release checksum")
    release_raw = _regular_bytes(release_manifest, "release manifest")
    document, records = _release_document(release_raw)

    pack_name = document["pack_name"]
    pack_version = document["pack_version"]
    prefix = "{0}-{1}".format(pack_name, pack_version)
    expected_archive = prefix + ".zip"
    expected_checksum = expected_archive + ".sha256"
    expected_manifest = prefix + "-manifest.json"
    if (
        document["archive"] != expected_archive
        or archive.name != expected_archive
        or checksum.name != expected_checksum
        or release_manifest.name != expected_manifest
    ):
        raise ValidationError("release artifact basename mismatch")

    expected_checksum_bytes = (
        document["archive_sha256"] + "  " + archive.name + "\n"
    ).encode("ascii")
    if checksum_raw != expected_checksum_bytes:
        raise ValidationError("invalid release checksum sidecar")
    expected_names = tuple(prefix + "/" + item["path"] for item in records)
    pack_raw = None
    try:
        with _open_archive(archive) as archive_handle:
            archive_sha256 = _hash_handle(archive_handle)
            if archive_sha256 != document["archive_sha256"]:
                raise ValidationError("release archive checksum mismatch")
            archive_handle.seek(0)
            with zipfile.ZipFile(archive_handle, "r") as archive_reader:
                if archive_reader.comment != b"":
                    raise ValidationError("archive comment is not canonical")
                infos = tuple(archive_reader.infolist())
                names = tuple(info.filename for info in infos)
                if (
                    names != tuple(sorted(names))
                    or names != expected_names
                    or len(names) != len(set(names))
                ):
                    raise ValidationError("archive member set or order mismatch")
                for info, record in zip(infos, records):
                    if not _member_path_is_safe(info.filename, prefix):
                        raise ValidationError("unsafe archive member path")
                    if not _member_metadata_is_canonical(info, record["size"]):
                        raise ValidationError("archive member metadata mismatch")
                    digest = hashlib.sha256()
                    size = 0
                    chunks = [] if record["path"] == "pack.json" else None
                    with archive_reader.open(info, "r") as member:
                        while True:
                            chunk = member.read(_CHUNK_SIZE)
                            if not chunk:
                                break
                            digest.update(chunk)
                            size += len(chunk)
                            if chunks is not None:
                                chunks.append(chunk)
                    if size != record["size"] or digest.hexdigest() != record["sha256"]:
                        raise ValidationError("archive member content mismatch")
                    if chunks is not None:
                        pack_raw = b"".join(chunks)
    except ValidationError:
        raise
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        raise ValidationError("invalid release archive") from error

    if pack_raw is None:
        raise ValidationError("pack manifest member is missing")
    pack_manifest = _pack_manifest_bytes(pack_raw)
    if (
        pack_manifest.name != pack_name
        or pack_manifest.version != pack_version
        or pack_manifest.release_archive != archive.name
        or pack_manifest.release_checksum != checksum.name
        or pack_manifest.release_manifest != release_manifest.name
    ):
        raise ValidationError("pack and release manifest identity mismatch")
    expected_paths = tuple(
        sorted(("pack.json",) + tuple(item.path for item in pack_manifest.files))
    )
    if tuple(item["path"] for item in records) != expected_paths:
        raise ValidationError("pack and release file inventories differ")
    record_by_path = {item["path"]: item for item in records}
    for item in pack_manifest.files:
        if record_by_path[item.path]["sha256"] != item.sha256:
            raise ValidationError("pack and release file hashes differ")

    artifacts = ReleaseArtifacts(
        archive_path=archive,
        checksum_path=checksum,
        manifest_path=release_manifest,
        archive_sha256=archive_sha256,
        content_revision=document["content_revision"],
    )
    return _VerifiedDetails(artifacts, document, records, prefix)


def verify_release(
    archive_path: Path,
    checksum_path: Path,
    manifest_path: Path,
) -> ReleaseArtifacts:
    """Strictly verify all release bytes without extracting any member."""
    return _verify_release_details(archive_path, checksum_path, manifest_path).artifacts


def _extraction_parent(source_root: Path, relative_path: str) -> Tuple[Path, str]:
    parts = PurePosixPath(relative_path).parts
    if not parts:
        raise ValidationError("invalid extraction path")
    if len(parts) == 1:
        return source_root, parts[0]
    try:
        resolved_root = resolve_inside(source_root)
        parent = resolved_root.joinpath(*parts[:-1])
        parent.resolve(strict=False).relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise ValidationError("invalid extraction path") from error
    return parent, parts[-1]


@contextlib.contextmanager
def verified_release_source(
    archive_path: Path,
    checksum_path: Path,
    manifest_path: Path,
) -> Iterator[VerifiedReleaseSource]:
    """Yield one validated temporary source tree for the context lifetime."""
    artifacts = verify_release(archive_path, checksum_path, manifest_path)
    details = _verify_release_details(archive_path, checksum_path, manifest_path)
    if artifacts != details.artifacts:
        raise ValidationError("release artifacts changed before extraction")

    with tempfile.TemporaryDirectory(prefix="agent-memory-release-source-") as temporary:
        base = Path(temporary).resolve(strict=True)
        try:
            source_root = resolve_inside(base, details.prefix)
        except Exception as error:
            raise ValidationError("invalid extracted source root") from error
        source_root.mkdir()
        try:
            with _open_archive(details.artifacts.archive_path) as archive_handle:
                if _hash_handle(archive_handle) != details.artifacts.archive_sha256:
                    raise ValidationError("archive changed before extraction")
                archive_handle.seek(0)
                with zipfile.ZipFile(archive_handle, "r") as archive_reader:
                    infos = tuple(archive_reader.infolist())
                    expected_names = tuple(
                        details.prefix + "/" + item["path"] for item in details.records
                    )
                    if tuple(item.filename for item in infos) != expected_names:
                        raise ValidationError("archive changed before extraction")
                    for info, record in zip(infos, details.records):
                        if not _member_metadata_is_canonical(info, record["size"]):
                            raise ValidationError("archive changed before extraction")
                        parent, basename = _extraction_parent(source_root, record["path"])
                        parent.mkdir(parents=True, exist_ok=True)
                        output = parent / basename
                        try:
                            output.resolve(strict=False).relative_to(
                                source_root.resolve(strict=True)
                            )
                        except (OSError, ValueError) as error:
                            raise ValidationError("extraction path escaped source root") from error
                        digest = hashlib.sha256()
                        size = 0
                        with archive_reader.open(info, "r") as member, output.open("xb") as handle:
                            while True:
                                chunk = member.read(_CHUNK_SIZE)
                                if not chunk:
                                    break
                                handle.write(chunk)
                                digest.update(chunk)
                                size += len(chunk)
                            handle.flush()
                            os.fsync(handle.fileno())
                        if size != record["size"] or digest.hexdigest() != record["sha256"]:
                            raise ValidationError("post-write member verification failed")
                        os.chmod(str(output), 0o644)
        except ValidationError:
            raise
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
            raise ValidationError("safe release extraction failed") from error

        extracted_manifest = load_pack_manifest(source_root / "pack.json")
        _raise_findings(validate_repository(source_root, extracted_manifest))
        _raise_findings(validate_release_metadata(source_root, extracted_manifest))
        yield VerifiedReleaseSource(artifacts, source_root)
