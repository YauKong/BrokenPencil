# Vault Migration Operations

This document summarizes the reviewed Plan 3 operational boundary. It does not
replace the installed Skill guidance and does not authorize work on a real
vault.

## Entry points

Packaged installations run these stable entrypoints:

- `skills/obsidian-agent-memory/scripts/vault_migrate.py`
- `skills/obsidian-agent-memory/scripts/vault_maintain.py`

A repository clone provides aliases over the same shared CLI modules:

- `tools/vault_migrate.py`
- `tools/vault_maintain.py`

Migration exposes `detect`, `plan`, `apply`, `verify`, and `rollback`.
Maintenance exposes `audit`, `plan`, `recover-root-guard`, `review-proposals`,
`plan-proposal-resolution`, `apply-proposal-resolution`,
`verify-proposal-resolution`, and `recover-proposal-resolution`. The scoped
proposal-resolution workflow is described in the installed `proposal-review.md`
reference. Maintenance has no generic cleanup `apply` or `execute` command,
and the Python package has no cleanup executor.

## Public types and functions

The operation gate and transaction inputs are `OperationScope`,
`AuthorizationGate`, and `TransactionContext`.

Migration uses these locked public values:

- `VaultGeneration`, `VaultDetection`, `SourceEntry`, and `SourceCategory`
- `MigrationSnapshot` and `SnapshotEntry`
- `MigrationActionKind`, `MigrationAction`, `MigrationPlan`, and
  `UnresolvedClassification`
- `MigrationBundle`, `MigrationResult`, and `MigrationVerification`

The corresponding functions are `detect_vault`, `plan_v1_to_v2`,
`load_migration_bundle`, `validate_migration_source`, `apply_migration`,
`verify_migration`, and `rollback_migration`.

Maintenance uses `MaintenanceAudit`, `CleanupDisposition`, `CleanupAction`,
`CleanupPlan`, and `GuardRecoveryResult`. Its functions are `audit_vault`,
`build_cleanup_plan`, `validate_cleanup_source`, and
`recover_stale_root_guard`.

## Command results

The wrappers write safe JSON results to standard output and diagnostics to
standard error. Their process exit policy is:

| Exit | Meaning |
| --- | --- |
| 0 | Successful operation, verified result, or idempotent no-op |
| 2 | Invalid argument, scope, fixture marker, or authorization gate |
| 3 | Changed source revision or invalidated reviewed plan/bundle |
| 4 | Lock or compare-and-swap conflict, including a preserved proposal result |
| 5 | Verification failure or hash-safe rollback refusal |

No nonzero result authorizes retry, rebase, overwrite, or a different action.

## Reviewed bundle

`plan` writes one external bundle directory. Its canonical JSON files are
`detection.json`, `snapshot.json`, and `plan.json`; exact source bytes are under
`snapshot/files/` at their recorded paths. Every source, snapshot, target,
projection, proposal, and evidence path stored in the bundle is a portable
root-relative POSIX path. No selected-root absolute path belongs in bundle
JSON.

The complete bundle has one canonical `bundle_sha256`. Plan prints that digest.
Review records the printed value without recomputing or changing it, and apply
requires the same value through `--bundle-sha256`. Apply validates the strict
bundle before staging, checks the source revision, and rechecks the complete
bundle digest while holding the root guard. The reviewed digest is persisted in
the apply journal, `MigrationResult`, and `MigrationVerification` provenance.

Any change to a source byte/path/hash, snapshot byte, owner, target, action,
projection effect, or bundle inventory invalidates the reviewed plan before
mutation. A changed plan is never rebased onto current content and is never
silently regenerated under the old approval.

Old focus Markdown is migration input, not fact ownership. Duplicate or
ambiguous facts remain proposals. Embedded legacy knowledge stops for a
separate Knowledge Base decision and is not moved by migration.

## Scope and authorization

Fixture operations require an explicit `--root`, `--scope fixture`, and the
checked `.agent-memory-fixture.json` marker. Tests and packaging smoke operate
only on checked-in fixtures or temporary copies.

A real operation requires `--scope real` and a nonblank, operation-specific
`--authorization-ref`. A real plan authorization does not continue into real
apply. Real apply requires a distinct reviewed authorization, and real rollback
must differ from both plan and apply authorization. Successful migration does
not authorize real cleanup. A future real cleanup campaign needs its own
authorization and must begin with a separately authorized read-only audit.

Mutation commands also require explicit actor, occurrence time, and transaction
identity. Plan, apply, and rollback use a distinct transaction ID for each
phase. Prior success never grants authority for the next phase.

## Verification, idempotence, and rollback

After apply, verify the same strict bundle and digest. Reapplying the exact
reviewed bundle is an idempotence check: it returns `already-applied`, selects
the original accepted apply transaction, and changes no byte. A different
digest or source revision is refused.

Apply owns a complete journal at
`.agent-memory/transactions/<apply-transaction-id>/journal.json` and persisted
rollback material below that transaction's `rollback/` directory. The
persisted rollback manifest and bytes bind every replaced or archived endpoint
to its reviewed hash. Rollback names the apply transaction with
`--apply-transaction-id` and uses a distinct transaction identity for the
restore operation. It preflights the entire journal and rollback set before the
first reverse action, restores only hash-matching reviewed bytes, preserves
apply/rollback evidence, and refuses unknown edits with exit 5.

Rollback evidence is operational history; it is not cleanup material and is
not automatically removed.

## Maintenance and root-guard recovery

`vault_maintain.py audit` is deterministic and read-only. Its report path must
be outside the selected root. `vault_maintain.py plan` reads that external
audit, revalidates its source revision, and writes an external approval-only
cleanup plan. The plan may classify reviewed future actions as merge,
supersede, archive, regenerate, delete, or review, but it cannot execute them.
A future real cleanup plan must be derived from the separately authorized audit
before any cleanup executor is designed or authorized.

`recover-root-guard` is a separately authorized operational recovery. It binds
to exactly one target transaction and either an exact stale canonical-lock hash
or the `--candidate-only` condition. It requires a new transaction context and
nonblank authorization even for fixture scope. Recovery must prove the old
owner lease is dead, refuses live/malformed/unknown ownership, and preserves
immutable root-relative recovery evidence. Candidate-only recovery follows the
same evidence and dead-owner rules. Root-guard recovery authorizes neither
cleanup execution nor any record, focus, proposal, projection, migration, or
Knowledge Base mutation.
