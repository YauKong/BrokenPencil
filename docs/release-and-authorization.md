# Release and authorization boundaries

Every section below is a separate approval boundary. Record the concrete
authorization reference before an action. Prior success does not continue
automatically; every later action needs a new request. No example contains a
real workstation or vault path.

The installed Plan 3 entrypoints are selected only from an explicit Skill root:

```powershell
if ([string]::IsNullOrWhiteSpace($env:AGENT_SKILLS_ROOT)) { throw 'Set AGENT_SKILLS_ROOT explicitly' }
$skillsRoot = [IO.Path]::GetFullPath($env:AGENT_SKILLS_ROOT)
$migrateTool = Join-Path $skillsRoot 'obsidian-agent-memory/scripts/vault_migrate.py'
$maintainTool = Join-Path $skillsRoot 'obsidian-agent-memory/scripts/vault_maintain.py'
```

## 1. Local source implementation, commits, and fixed release tag

Prior success does not continue automatically. Record the local-work
authorization reference; tag creation needs a new request. This boundary covers
repository files, local commits, and creation and verification of a fixed local
`v2.0.2` tag. It never authorizes moving an existing tag, pushing, or publishing.

## 2. Current-workstation install dry run

Prior success does not continue automatically. Record a dry-run authorization
reference; apply needs a new request. This permits read-only source and target
inventory plus one new explicit plan file. It does not permit active mutation,
vault access, migration, recovery, or cleanup. Stop after reviewing the plan's
canonical bytes and lowercase SHA-256.

## 3. Current-workstation install or upgrade apply

Prior success does not continue automatically. Record a new apply authorization
reference before the action. Approval names one reviewed plan SHA-256, source
revision, Skill root, state root, operation actor, and RFC-3339 time. Stop the
host application, run one apply command, inspect the terminal result, then
restart. This does not authorize vault access.

## 4. Post-install validation

Prior success does not continue automatically. Fixture smoke, real-memory
doctor, and live CLI probe each need a new request and a separate invocation.
Fixture smoke uses no real root. Doctor names one explicit root and read
authorization. CLI probing additionally names an explicit executable and vault;
it never follows apply automatically.

## 5. Current-workstation pack recovery, rollback, or uninstall

Prior success does not continue automatically. Every recovery finalization,
rollback, uninstall, and uninstall recovery needs a new request, actor, time,
and nonempty authorization distinct from earlier lifecycle operations. An exact
persisted operation tuple may be retried only to finish idempotent cleanup.

Stop the host application before rollback or uninstall apply, run one command,
inspect its result, then restart. Pure recovery finalization does not rename
active members and never implies rollback, uninstall, vault access, cleanup, or
deletion. No command deletes retained rollback material.

```powershell
python tools/install_pack.py recover --skills-root $skillsRoot --state-root $stateRoot --transaction-id $installTransactionId --actor $installRecoveryActor --occurred-at $installRecoveryOccurredAt --authorization-ref $installRecoveryAuthorization
return
```

```powershell
python tools/uninstall_pack.py recover --skills-root $skillsRoot --state-root $stateRoot --transaction-id $uninstallTransactionId --actor $uninstallRecoveryActor --occurred-at $uninstallRecoveryOccurredAt --authorization-ref $uninstallRecoveryAuthorization
return
```

## 6. Real-vault migration detect and plan

Prior success does not continue automatically. Record distinct detect and
planning references; apply needs a new request. Validate every value before use:

```powershell
$required = 'REAL_MEMORY_ROOT','MIGRATION_WORK_ROOT','MIGRATION_ACTOR','MIGRATION_PLAN_OCCURRED_AT','MIGRATION_DETECT_AUTHORIZATION','MIGRATION_PLAN_AUTHORIZATION','MIGRATION_PLAN_TRANSACTION_ID'
foreach ($name in $required) { if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) { throw "Set $name explicitly" } }
$realMemoryRoot = [IO.Path]::GetFullPath($env:REAL_MEMORY_ROOT)
$migrationWorkRoot = [IO.Path]::GetFullPath($env:MIGRATION_WORK_ROOT)
$migrationActor = $env:MIGRATION_ACTOR
$planOccurredAt = $env:MIGRATION_PLAN_OCCURRED_AT
$detectAuthorization = $env:MIGRATION_DETECT_AUTHORIZATION
$planAuthorization = $env:MIGRATION_PLAN_AUTHORIZATION
$planTransactionId = $env:MIGRATION_PLAN_TRANSACTION_ID
$relativeWork = [IO.Path]::GetRelativePath($realMemoryRoot, $migrationWorkRoot)
if ($relativeWork -eq '.' -or (-not $relativeWork.StartsWith('..' + [IO.Path]::DirectorySeparatorChar) -and $relativeWork -ne '..')) { throw 'Migration work root must remain outside the real memory root' }
python $migrateTool detect --root $realMemoryRoot --scope real --authorization-ref $detectAuthorization
if ($LASTEXITCODE -ne 0) { throw 'Migration detection failed' }
return
```

```powershell
python $migrateTool plan --root $realMemoryRoot --work-dir $migrationWorkRoot --scope real --transaction-id $planTransactionId --actor $migrationActor --occurred-at $planOccurredAt --authorization-ref $planAuthorization
if ($LASTEXITCODE -ne 0) { throw 'Migration planning failed' }
```

Stop after the plan prints canonical JSON. Copy its `bundle_sha256`, review the
complete bundle at that digest, and begin a new approval block. Do not derive or
recompute the reviewed value during apply.

## 7. Real-vault migration apply, verify, and rollback

Prior success does not continue automatically. Apply, verify, and rollback each
need a new request and distinct authorization. Apply requires the exact reviewed
bundle digest and an authorization different from planning:

```powershell
$reviewedMigrationBundleSha256 = $env:REVIEWED_MIGRATION_BUNDLE_SHA256
$applyAuthorization = $env:MIGRATION_APPLY_AUTHORIZATION
$applyTransactionId = $env:MIGRATION_APPLY_TRANSACTION_ID
$applyOccurredAt = $env:MIGRATION_APPLY_OCCURRED_AT
if ($reviewedMigrationBundleSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Reviewed bundle SHA-256 must be lowercase hexadecimal' }
if ([string]::IsNullOrWhiteSpace($applyAuthorization) -or $planAuthorization -eq $applyAuthorization) { throw 'Apply authorization must be explicit and distinct' }
if ($planTransactionId -eq $applyTransactionId) { throw 'Apply transaction must be distinct' }
python $migrateTool apply --root $realMemoryRoot --bundle (Join-Path $migrationWorkRoot $planTransactionId) --bundle-sha256 $reviewedMigrationBundleSha256 --scope real --transaction-id $applyTransactionId --actor $migrationActor --occurred-at $applyOccurredAt --authorization-ref $applyAuthorization
if ($LASTEXITCODE -ne 0) { throw 'Migration apply failed' }
return
```

```powershell
$verifyAuthorization = $env:MIGRATION_VERIFY_AUTHORIZATION
python $migrateTool verify --root $realMemoryRoot --bundle (Join-Path $migrationWorkRoot $planTransactionId) --scope real --authorization-ref $verifyAuthorization
if ($LASTEXITCODE -ne 0) { throw 'Migration verify failed' }
return
```

```powershell
$rollbackTransactionId = $env:MIGRATION_ROLLBACK_TRANSACTION_ID
$rollbackAuthorization = $env:MIGRATION_ROLLBACK_AUTHORIZATION
$rollbackOccurredAt = $env:MIGRATION_ROLLBACK_OCCURRED_AT
if ($rollbackTransactionId -eq $applyTransactionId) { throw 'Rollback transaction must be distinct' }
python $migrateTool rollback --root $realMemoryRoot --apply-transaction-id $applyTransactionId --scope real --transaction-id $rollbackTransactionId --actor $migrationActor --occurred-at $rollbackOccurredAt --authorization-ref $rollbackAuthorization
if ($LASTEXITCODE -ne 0) { throw 'Migration rollback failed' }
return
```

Rollback resolves its hash-checked source journal from the retained apply
transaction; it accepts neither a work-directory flag nor a bundle flag.

## 8. Post-migration maintenance audit, cleanup plan, and stale root-guard recovery

Prior success does not continue automatically. Audit, cleanup planning, and
stale-guard recovery each need a new request. Cleanup remains read-only
audit/plan. Validate `$cleanupAuditPath` and `$cleanupPlanPath` as explicit full
paths outside `$realMemoryRoot` using the same relative-path containment test as
`$migrationWorkRoot`.

```powershell
python $maintainTool audit --root $realMemoryRoot --output $cleanupAuditPath --scope real --authorization-ref $cleanupAuditAuthorization
if ($LASTEXITCODE -ne 0) { throw 'Maintenance audit failed' }
return
```

```powershell
python $maintainTool plan --root $realMemoryRoot --audit $cleanupAuditPath --output $cleanupPlanPath --scope real --transaction-id $cleanupPlanTransactionId --actor $migrationActor --occurred-at $cleanupPlanOccurredAt --authorization-ref $cleanupPlanAuthorization
if ($LASTEXITCODE -ne 0) { throw 'Cleanup planning failed' }
return
```

Stale root-guard recovery requires the exact root, stale transaction, lock hash
or candidate-only mode, a distinct recovery transaction, actor/time, and new
authorization. It proves the lease owner is gone and preserves immutable
evidence; it changes no record, focus, proposal, projection, or cleanup target.

```powershell
if ($rootGuardRecoveryTransactionId -eq $staleWriterTransactionId) { throw 'Recovery transaction must be distinct' }
python $maintainTool recover-root-guard --root $realMemoryRoot --scope real --target-transaction-id $staleWriterTransactionId --expected-lock-sha256 $staleRootGuardSha256 --transaction-id $rootGuardRecoveryTransactionId --actor $rootGuardRecoveryActor --occurred-at $rootGuardRecoveryOccurredAt --authorization-ref $rootGuardRecoveryAuthorization
if ($LASTEXITCODE -ne 0) { throw 'Root-guard recovery failed' }
return
```

The reviewed candidate-only form substitutes `--candidate-only` for the exact
lock-hash pair. There is no cleanup apply command.

## 9. Future cleanup execution and rollback-material deletion

Prior success does not continue automatically. A future executor or deletion
needs a new request. Neither capability exists in this release, and no audit,
plan, apply, rollback, recovery, push, or publication implies it.

## 10. Git push

Prior success does not continue automatically. A push needs a new request that
names the remote, branch, and exact revision. Local commits and a local fixed tag
do not imply push authorization.

## 11. Release publication

Prior success does not continue automatically. Publication needs a new request
that names the destination and exact artifact hashes. A local `dist/` build,
local tag, or Git push does not imply publication authorization.

## Final local release stop checklist

The retained local release artifact names are:

- `obsidian-agent-memory-skill-pack-2.0.2.zip`
- `obsidian-agent-memory-skill-pack-2.0.2.zip.sha256`
- `obsidian-agent-memory-skill-pack-2.0.2-manifest.json`

- Passing local tests does not authorize installation on the current workstation.
- Building local release artifacts does not authorize installation, Git push, upload, or release publication.
- Installing on the current workstation does not authorize real-vault detection, migration planning, migration apply, verification, rollback, or cleanup.
- A verified real-vault migration does not authorize cleanup execution or deletion of migration or pack rollback evidence.
- Local commits do not authorize Git push.
- Creating or verifying the fixed local `v2.0.2` tag does not authorize pushing the tag or moving or deleting any existing tag.
- Git push does not authorize release publication.
- Release publication requires a new request naming the destination and the exact SHA-256 of each of the three artifacts.
