"""Fail-closed runtime provenance for proposal-review reports."""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Optional, Sequence, Tuple

from .errors import ValidationError
from .operation_scope import OperationScope
from .paths import validate_identifier


_MAX_COMMAND_BYTES = 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_INSTALLED_KEYS = {
    "actor", "authorization_ref", "directories", "files", "occurred_at",
    "pack_name", "pack_version", "schema_version", "skills_root",
    "source_revision", "target_digest", "transaction_id",
}
_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True)
class CodeIdentity:
    document: Mapping[str, object]


@dataclass(frozen=True)
class CodeIdentityProof:
    identity: CodeIdentity
    proof_sha256: str
    protected_roots: Tuple[Path, ...]


def _canonical(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _proof(document, material, protected=()):
    digest = hashlib.sha256(_canonical({"identity": document, "material": material})).hexdigest()
    return CodeIdentityProof(CodeIdentity(document), digest, tuple(protected))


def _cache_isolated(dont_write_bytecode, pycache_prefix, cached_paths):
    if dont_write_bytecode is not True or pycache_prefix is None:
        raise ValidationError("runtime bytecode cache is not isolated")
    prefix = Path(pycache_prefix)
    if not prefix.is_absolute() or prefix.exists():
        raise ValidationError("runtime bytecode cache is not fresh")
    normalized = os.path.normcase(str(prefix))
    for cached in cached_paths:
        if cached is None:
            continue
        candidate = os.path.normcase(str(Path(cached)))
        try:
            if os.path.commonpath((normalized, candidate)) != normalized:
                raise ValidationError("managed module cache escapes isolated prefix")
        except ValueError as error:
            raise ValidationError("managed module cache escapes isolated prefix") from error
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _git_ancestor(module_path: Path):
    for parent in (module_path.parent,) + tuple(module_path.parents):
        if (parent / ".git").exists():
            return parent.resolve()
    return None


def _run_git(runner, arguments, environment):
    try:
        result = runner(arguments, environment)
    except Exception as error:
        raise ValidationError("Git identity command failed") from error
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if (
        getattr(result, "returncode", None) != 0
        or not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or len(stdout) > _MAX_COMMAND_BYTES
        or len(stderr) > _MAX_COMMAND_BYTES
    ):
        raise ValidationError("Git identity command failed")
    return stdout


def _git_identity(module_path, repository_root, env, runner, cache_digest):
    environment = dict(env)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    prefix = ["git", "-C", str(repository_root)]
    shown = _run_git(runner, prefix + ["rev-parse", "--show-toplevel"], environment)
    try:
        shown_root = Path(shown.decode("utf-8", errors="strict").strip()).resolve()
    except (UnicodeDecodeError, OSError, RuntimeError) as error:
        raise ValidationError("invalid Git repository identity") from error
    if shown_root != repository_root:
        raise ValidationError("Git repository root mismatch")
    head = _run_git(
        runner, prefix + ["rev-parse", "--verify", "HEAD^{commit}"], environment
    ).decode("ascii", errors="strict").strip()
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise ValidationError("invalid Git revision")
    status = _run_git(
        runner, prefix + ["status", "--porcelain=v1", "-z", "--untracked-files=all"], environment
    )
    if status:
        raise ValidationError("Git working tree is not clean")
    document = {"kind": "git-commit", "revision": head, "tree_state": "clean"}
    material = {
        "cache_isolation": cache_digest,
        "module": module_path.resolve().relative_to(repository_root).as_posix(),
        "repository_root": os.path.normcase(str(repository_root)),
    }
    return _proof(document, material, (repository_root,))


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError("duplicate installed state key")
        value[key] = item
    return value


def _plain_file(path, maximum=64 * 1024 * 1024):
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0) & _REPARSE_FLAG
        or metadata.st_size > maximum
    ):
        raise ValidationError("invalid managed file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ValidationError("managed file changed during read")
    return raw


def _installed_identity(module_path, env, cache_digest):
    suffix = PurePosixPath("obsidian-agent-memory/scripts/obsidian_agent_memory/runtime_identity.py")
    normalized = PurePosixPath(module_path.as_posix())
    if tuple(normalized.parts[-len(suffix.parts):]) != suffix.parts:
        raise ValidationError("runtime is neither source Git nor default installed pack")
    skills_root = module_path.parents[3].resolve()
    target_digest = hashlib.sha256(os.path.normcase(str(skills_root)).encode("utf-8")).hexdigest()
    state_root = skills_root.parent / ".obsidian-agent-memory-pack-state" / target_digest
    installed_path = state_root / "installed.json"
    try:
        raw = _plain_file(installed_path)
        document = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("invalid installed state") from error
    canonical = (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if raw != canonical or not isinstance(document, dict) or set(document) != _INSTALLED_KEYS:
        raise ValidationError("invalid installed state")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise ValidationError("invalid installed state")
    if (
        document["pack_name"] != "obsidian-agent-memory-skill-pack"
        or document["pack_version"] not in ("2.0.0", "2.0.1")
    ):
        raise ValidationError("invalid installed pack identity")
    if document["skills_root"] != str(skills_root) or document["target_digest"] != target_digest:
        raise ValidationError("installed target binding mismatch")
    for field in ("actor", "transaction_id"):
        validate_identifier(document[field], "installed " + field)
    if not isinstance(document["authorization_ref"], str) or not document["authorization_ref"].strip():
        raise ValidationError("invalid installed authorization")
    if not isinstance(document["occurred_at"], str) or _TIMESTAMP.fullmatch(document["occurred_at"]) is None:
        raise ValidationError("invalid installed timestamp")
    if not isinstance(document["source_revision"], str) or _DIGEST.fullmatch(document["source_revision"]) is None:
        raise ValidationError("invalid installed source revision")
    directories = document["directories"]
    files = document["files"]
    if not isinstance(directories, list) or directories != sorted(set(directories)):
        raise ValidationError("invalid installed directories")
    if not isinstance(files, list):
        raise ValidationError("invalid installed files")
    expected_files = {}
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValidationError("invalid installed files")
        path = item["path"]
        if not isinstance(path, str) or PurePosixPath(path).is_absolute() or "\\" in path:
            raise ValidationError("invalid installed file path")
        if not isinstance(item["sha256"], str) or _DIGEST.fullmatch(item["sha256"]) is None:
            raise ValidationError("invalid installed file hash")
        expected_files[path] = item["sha256"]
    if list(expected_files) != sorted(expected_files) or len(expected_files) != len(files):
        raise ValidationError("invalid installed file ordering")
    expected_directories = set(directories)
    members = sorted({PurePosixPath(path).parts[0] for path in tuple(directories) + tuple(expected_files)})
    actual_directories = set()
    actual_files = {}
    for member in members:
        start = skills_root / member
        stack = [start]
        while stack:
            directory = stack.pop()
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & _REPARSE_FLAG:
                raise ValidationError("invalid managed directory")
            relative_directory = directory.relative_to(skills_root).as_posix()
            actual_directories.add(relative_directory)
            for child in sorted(directory.iterdir(), key=lambda item: item.name, reverse=True):
                if child.name == "__pycache__":
                    if any(grandchild.suffix != ".pyc" for grandchild in child.iterdir()):
                        raise ValidationError("invalid managed cache directory")
                    continue
                child_metadata = child.lstat()
                if stat.S_ISLNK(child_metadata.st_mode) or getattr(child_metadata, "st_file_attributes", 0) & _REPARSE_FLAG:
                    raise ValidationError("unsafe managed node")
                if stat.S_ISDIR(child_metadata.st_mode):
                    stack.append(child)
                elif stat.S_ISREG(child_metadata.st_mode):
                    relative = child.relative_to(skills_root).as_posix()
                    actual_files[relative] = hashlib.sha256(_plain_file(child)).hexdigest()
                else:
                    raise ValidationError("unsafe managed node")
    if actual_directories != expected_directories or actual_files != expected_files:
        raise ValidationError("active family differs from installed state")
    identity = {
        "kind": "pack-manifest",
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "verification_status": "managed-valid",
        "version": document["pack_version"],
    }
    material = {
        "cache_isolation": cache_digest,
        "files": files,
        "source_revision": document["source_revision"],
        "target_digest": target_digest,
    }
    return _proof(identity, material, (skills_root, state_root))


def _default_runner(arguments, environment):
    return subprocess.run(
        arguments,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )


def _managed_cached_paths():
    values = []
    for name, module in tuple(sys.modules.items()):
        if name == "obsidian_agent_memory" or name.startswith("obsidian_agent_memory."):
            values.append(getattr(module, "__cached__", None))
    return tuple(values)


def _observe_runtime_identity(
    scope: OperationScope,
    fixture_code_revision: Optional[str],
    module_path: Path,
    env: Mapping[str, str],
    runner: Optional[Callable],
    dont_write_bytecode: bool,
    pycache_prefix: Optional[Path],
    cached_paths: Sequence[Optional[Path]],
) -> CodeIdentityProof:
    if not isinstance(scope, OperationScope):
        raise ValidationError("invalid runtime identity scope")
    if scope is OperationScope.FIXTURE:
        if fixture_code_revision is None:
            raise ValidationError("fixture code revision is required")
        validate_identifier(fixture_code_revision, "fixture code revision")
        return _proof({"kind": "fixture", "revision": fixture_code_revision}, {"scope": "fixture"})
    if fixture_code_revision is not None:
        raise ValidationError("fixture code revision is forbidden for real scope")
    cache_digest = _cache_isolated(dont_write_bytecode, pycache_prefix, cached_paths)
    selected_module = Path(module_path).resolve(strict=True)
    repository_root = _git_ancestor(selected_module)
    if repository_root is not None:
        return _git_identity(selected_module, repository_root, env, runner or _default_runner, cache_digest)
    return _installed_identity(selected_module, env, cache_digest)


def observe_runtime_identity(
    scope: OperationScope,
    fixture_code_revision: Optional[str],
) -> CodeIdentityProof:
    """Resolve fixture, clean source Git, or managed-valid installed identity."""
    return _observe_runtime_identity(
        scope,
        fixture_code_revision,
        Path(__file__),
        os.environ,
        _default_runner,
        sys.dont_write_bytecode,
        None if sys.pycache_prefix is None else Path(sys.pycache_prefix),
        _managed_cached_paths(),
    )
