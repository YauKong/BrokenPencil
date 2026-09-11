# Portable Agent Memory Skill Pack 2.0.1

This repository is the source of truth for the portable Agent Memory Skill
family. It requires Python 3.9 or newer and installs exactly these nine members:

- `obsidian-agent-memory`
- `obsidian-agent-memory-init`
- `obsidian-agent-memory-route`
- `obsidian-agent-memory-collaboration`
- `obsidian-agent-memory-query`
- `obsidian-agent-memory-add`
- `obsidian-agent-memory-summary`
- `obsidian-agent-memory-maintain`
- `obsidian-agent-memory-upgrade`

`obsidian-cli` and the Knowledge Base Skills are optional capabilities. Pack
installation does not configure or migrate memory. Every Skill root, state
root, workspace, memory root, actor, time, reviewed digest, and authorization
is explicit; the tools do not search a home directory or select a vault.

Version 2.0.1 supports reviewed managed upgrades from 2.0.0. Its lifecycle
reader retains 2.0.0 plans and owned installation state for recovery, uninstall,
and exact rollback; unknown managed versions are refused. Use the new verified
source to create a new upgrade plan rather than reusing an earlier plan with
different source bytes. This release does not migrate memory automatically.

## Downloaded archive: verify before executing

Download all three artifacts into an otherwise reviewed directory:

- `obsidian-agent-memory-skill-pack-2.0.1.zip`
- `obsidian-agent-memory-skill-pack-2.0.1.zip.sha256`
- `obsidian-agent-memory-skill-pack-2.0.1-manifest.json`

The checksum sidecar proves integrity, not publisher authenticity. Compare the
reviewed release/tag hash through a trusted channel before running this block.
The block validates every archive member with inline standard-library code
before creating a unique extraction directory, keeps the same archive handle
open for exclusive extraction, and leaves an incomplete unique directory for
explicit review if a later write fails.

```powershell
$archive = Resolve-Path -LiteralPath .\obsidian-agent-memory-skill-pack-2.0.1.zip
$checksum = Resolve-Path -LiteralPath .\obsidian-agent-memory-skill-pack-2.0.1.zip.sha256
$releaseManifest = Resolve-Path -LiteralPath .\obsidian-agent-memory-skill-pack-2.0.1-manifest.json
$checksumLine = (Get-Content -LiteralPath $checksum -Raw).TrimEnd("`r", "`n")
$tokens = $checksumLine -split '  ', 2
if ($tokens.Count -ne 2 -or $tokens[1] -ne $archive.Path.Split([IO.Path]::DirectorySeparatorChar)[-1]) { throw 'Invalid checksum sidecar' }
$actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $tokens[0]) { throw 'Archive SHA-256 mismatch' }
$extractBase = [IO.Path]::GetFullPath((Get-Location).Path)
$extractRoot = [IO.Path]::GetFullPath((Join-Path $extractBase ("pack-unpacked-" + [Guid]::NewGuid().ToString("N"))))
if (Test-Path -LiteralPath $extractRoot) { throw 'Unique extraction target already exists' }
$safeExtractor = @'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


archive_path = Path(sys.argv[1]).resolve(strict=True)
manifest_path = Path(sys.argv[2]).resolve(strict=True)
base = Path(sys.argv[3]).resolve(strict=True)
destination = Path(sys.argv[4]).resolve(strict=False)
if destination.parent.resolve(strict=True) != base or destination.exists():
    raise ValueError("unsafe extraction destination")
base_stat = os.lstat(str(base))
reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
if stat.S_ISLNK(base_stat.st_mode) or (
    os.name == "nt" and getattr(base_stat, "st_file_attributes", 0) & reparse
):
    raise ValueError("extraction base is a link or reparse point")
document = json.loads(
    manifest_path.read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicates,
)
if set(document) != {
    "archive", "archive_sha256", "content_revision", "files",
    "pack_name", "pack_version", "schema_version",
}:
    raise ValueError("invalid release manifest keys")
if document["archive"] != archive_path.name or document["schema_version"] != 1:
    raise ValueError("release identity mismatch")
if document["pack_name"] != "obsidian-agent-memory-skill-pack" or document["pack_version"] != "2.0.1":
    raise ValueError("release pack mismatch")
records = document["files"]
if not isinstance(records, list) or not records:
    raise ValueError("empty release inventory")
validated = []
for record in records:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
        raise ValueError("invalid file record")
    relative = PurePosixPath(record["path"])
    if (
        relative.as_posix() != record["path"]
        or relative.is_absolute()
        or any(part in ("", ".", "..") for part in relative.parts)
        or ":" in relative.parts[0]
        or "\\" in record["path"]
    ):
        raise ValueError("unsafe member path")
    digest = record["sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ValueError("invalid member hash")
    if not isinstance(record["size"], int) or record["size"] < 0:
        raise ValueError("invalid member size")
    validated.append(record)
if [item["path"] for item in validated] != sorted(item["path"] for item in validated):
    raise ValueError("unsorted inventory")
if len({item["path"] for item in validated}) != len(validated):
    raise ValueError("duplicate inventory")
canonical = (json.dumps(
    validated, sort_keys=True, indent=2, ensure_ascii=False
) + "\n").encode("utf-8")
if hashlib.sha256(canonical).hexdigest() != document["content_revision"]:
    raise ValueError("content revision mismatch")
prefix = "obsidian-agent-memory-skill-pack-2.0.1"
expected_names = tuple(prefix + "/" + item["path"] for item in validated)
with archive_path.open("rb") as archive_file:
    archive_hash = hashlib.sha256()
    while True:
        chunk = archive_file.read(1024 * 1024)
        if not chunk:
            break
        archive_hash.update(chunk)
    if archive_hash.hexdigest() != document["archive_sha256"]:
        raise ValueError("manifest archive hash mismatch")
    archive_file.seek(0)
    with zipfile.ZipFile(archive_file, "r") as archive:
        infos = archive.infolist()
        names = tuple(info.filename for info in infos)
        if names != tuple(sorted(names)) or names != expected_names or len(set(names)) != len(names):
            raise ValueError("archive member set or order mismatch")
        for info, record in zip(infos, validated):
            if (
                info.flag_bits & 1
                or info.date_time != (1980, 1, 1, 0, 0, 0)
                or info.compress_type != zipfile.ZIP_STORED
                or info.create_system != 3
                or info.external_attr >> 16 != 0o100644
                or info.file_size != record["size"]
            ):
                raise ValueError("archive member metadata mismatch")
            digest = hashlib.sha256()
            size = 0
            with archive.open(info, "r") as member:
                while True:
                    chunk = member.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
            if size != record["size"] or digest.hexdigest() != record["sha256"]:
                raise ValueError("archive member content mismatch")
        destination.mkdir()
        source_root = destination / prefix
        source_root.mkdir()
        for info, record in zip(infos, validated):
            output = source_root.joinpath(*PurePosixPath(record["path"]).parts)
            output.resolve(strict=False).relative_to(source_root.resolve(strict=True))
            output.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with archive.open(info, "r") as member, output.open("xb") as handle:
                while True:
                    chunk = member.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    digest.update(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            if digest.hexdigest() != record["sha256"]:
                raise ValueError("post-write member hash mismatch")
            os.chmod(str(output), 0o644)
print(str(source_root.resolve(strict=True)))
'@
$sourceRoot = ($safeExtractor | python - $archive.Path $releaseManifest.Path $extractBase $extractRoot).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($sourceRoot)) { throw 'Safe archive preflight/extraction failed' }
Set-Location -LiteralPath $sourceRoot
python tools\verify_release.py --archive $archive --checksum $checksum --manifest $releaseManifest
if ($LASTEXITCODE -ne 0) { throw 'Packaged release verification failed' }
python tools\validate.py --repo-root .
if ($LASTEXITCODE -ne 0) { throw 'Extracted repository validation failed' }
```

## Explicit dry run: stop after reviewing the plan

The clone and extracted-archive flows use the same explicit values. A stale
plan is never reused or displayed after a failed planner.

```powershell
if ([string]::IsNullOrWhiteSpace($env:AGENT_SKILLS_ROOT)) { throw 'Set AGENT_SKILLS_ROOT explicitly' }
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_STATE_ROOT)) { throw 'Set AGENT_PACK_STATE_ROOT explicitly' }
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_PLAN)) { throw 'Set AGENT_PACK_PLAN explicitly' }
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_ACTOR)) { throw 'Set AGENT_PACK_ACTOR explicitly' }
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_OCCURRED_AT)) { throw 'Set AGENT_PACK_OCCURRED_AT explicitly as RFC-3339' }
$skillsRoot = [IO.Path]::GetFullPath($env:AGENT_SKILLS_ROOT)
$stateRoot = [IO.Path]::GetFullPath($env:AGENT_PACK_STATE_ROOT)
$planPath = [IO.Path]::GetFullPath($env:AGENT_PACK_PLAN)
if (Test-Path -LiteralPath $planPath) { throw 'Plan output path must be absent' }
python tools\bootstrap.py check --source . --skills-root $skillsRoot --state-root $stateRoot
if ($LASTEXITCODE -ne 0) { throw 'Pack preflight check failed' }
python tools\bootstrap.py plan --source . --skills-root $skillsRoot --state-root $stateRoot --transaction-id workstation-pack-001 --actor $env:AGENT_PACK_ACTOR --occurred-at $env:AGENT_PACK_OCCURRED_AT --plan-out $planPath
if ($LASTEXITCODE -ne 0) { throw 'Pack planning failed; do not inspect or hash a prior plan' }
if (-not (Test-Path -LiteralPath $planPath -PathType Leaf)) { throw 'Pack plan was not created' }
Get-Content -LiteralPath $planPath -Raw
(Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
return
```

## Separately authorized installation

Stop the host application before this block. Run exactly one apply, inspect its
terminal result, and restart the host only after the block has ended.

```powershell
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_SOURCE_ROOT)) { throw 'Set AGENT_PACK_SOURCE_ROOT explicitly' }
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_PLAN)) { throw 'Set AGENT_PACK_PLAN explicitly' }
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_PLAN_SHA256)) { throw 'Set AGENT_PACK_PLAN_SHA256 explicitly' }
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_APPLY_ACTOR)) { throw 'Set AGENT_PACK_APPLY_ACTOR explicitly' }
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_APPLY_OCCURRED_AT)) { throw 'Set AGENT_PACK_APPLY_OCCURRED_AT explicitly as RFC-3339' }
if ([string]::IsNullOrWhiteSpace($env:AGENT_PACK_INSTALL_AUTHORIZATION)) { throw 'Set AGENT_PACK_INSTALL_AUTHORIZATION explicitly' }
$sourceRoot = [IO.Path]::GetFullPath($env:AGENT_PACK_SOURCE_ROOT)
$planPath = [IO.Path]::GetFullPath($env:AGENT_PACK_PLAN)
python (Join-Path $sourceRoot 'tools/bootstrap.py') apply --source $sourceRoot --plan $planPath --plan-sha256 $env:AGENT_PACK_PLAN_SHA256 --actor $env:AGENT_PACK_APPLY_ACTOR --occurred-at $env:AGENT_PACK_APPLY_OCCURRED_AT --authorization-ref $env:AGENT_PACK_INSTALL_AUTHORIZATION
if ($LASTEXITCODE -ne 0) { throw 'Install apply failed' }
return
```

Install rollback, uninstall apply, and uninstall rollback also rename active
members: Stop the host application, run one authorized command, inspect the
result, then restart. `install_pack.py recover` and `uninstall_pack.py recover`
only finalize a proven terminal lifecycle; recovery does not mutate active
members and does not authorize rollback, uninstall, vault access, or deletion.

## Separate post-install checks

Fixture smoke never reads a real memory root:

```powershell
python (Join-Path $sourceRoot 'tools/smoke.py') --repo-root $sourceRoot
if ($LASTEXITCODE -ne 0) { throw 'Fixture smoke failed' }
return
```

Headless doctor requires its own explicit read authorization for a selected
memory root. Omit memory options for the pre-configuration warning-only mode.

```powershell
python (Join-Path $sourceRoot 'tools/doctor.py') --source $sourceRoot --skills-root $skillsRoot --state-root $stateRoot --workspace $workspace --memory-root $memoryRoot --project-id $projectId --authorization-ref $doctorAuthorization
if ($LASTEXITCODE -ne 0) { throw 'Headless doctor failed' }
return
```

The optional live probe is another invocation and requires all explicit inputs:

```powershell
python (Join-Path $sourceRoot 'tools/doctor.py') --source $sourceRoot --skills-root $skillsRoot --state-root $stateRoot --workspace $workspace --memory-root $memoryRoot --project-id $projectId --authorization-ref $cliAuthorization --probe-cli --cli-executable $cliExecutable --obsidian-vault $obsidianVault
if ($LASTEXITCODE -ne 0) { throw 'Optional CLI doctor failed' }
return
```

See `docs/release-and-authorization.md` before any lifecycle recovery,
real-vault migration, maintenance recovery, push, or publication.

## Final local release stop checklist

The retained local release artifact names are:

- `obsidian-agent-memory-skill-pack-2.0.1.zip`
- `obsidian-agent-memory-skill-pack-2.0.1.zip.sha256`
- `obsidian-agent-memory-skill-pack-2.0.1-manifest.json`

- Passing local tests does not authorize installation on the current workstation.
- Building local release artifacts does not authorize installation, Git push, upload, or release publication.
- Installing on the current workstation does not authorize real-vault detection, migration planning, migration apply, verification, rollback, or cleanup.
- A verified real-vault migration does not authorize cleanup execution or deletion of migration or pack rollback evidence.
- Local commits do not authorize Git push.
- Creating or verifying the fixed local `v2.0.1` tag does not authorize pushing the tag or moving or deleting any existing tag.
- Git push does not authorize release publication.
- Release publication requires a new request naming the destination and the exact SHA-256 of each of the three artifacts.
