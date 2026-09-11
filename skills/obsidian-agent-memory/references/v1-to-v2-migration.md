# V1 to V2 Migration

After a verified apply, unresolved migration proposals may be classified with
the read-only workflow in [Proposal review](proposal-review.md). The report is
external evidence only: it does not resolve proposals or change migration
artifacts, and it must bind the exact applied journal and reviewed bundle.

Migration uses the bundled installed entrypoint
[`../scripts/vault_migrate.py`](../scripts/vault_migrate.py). A repository
clone also provides `tools/vault_migrate.py` as an alias over the same shared
CLI implementation. The commands are:

~~~text
detect
plan
apply
verify
rollback
~~~

Every command requires an explicit `--root` and `--scope fixture|real`.
Planning also requires an external `--work-dir`. Mutation-capable commands
require explicit `--transaction-id`, `--actor`, and `--occurred-at` values.
Real scope additionally requires a nonempty `--authorization-ref` tied to the
specific reviewed operation.

The six-stage migration sequence is `detect -> snapshot -> plan -> review ->
apply -> verify`. `plan` creates the snapshot and reviewed bundle outside the
source root. The snapshot contains the exact source inventory and bytes; the
plan binds every source path/hash to its target owner/path, projection effects,
and any unresolved classification. Plan output exposes the canonical
`bundle_sha256` of the complete strict bundle inventory. The reviewer must copy
that exact 64-lowercase-hex value to apply as `--bundle-sha256`; recomputing a
new digest after review is not authorization.

`_index/*.base` files are active, non-owning auxiliary views. Migration keeps
each such view at its exact source path with its reviewed bytes rather than
treating it as a projection or rewriting its Bases definition. A view does not
own the files it selects: story inputs are classified and migrated by their own
story rules, and knowledge inputs retain an independent Knowledge Base
migration decision.

Only `plan` accepts the repeatable explicit mapping option
`--project-id-map LEGACY_ID=TARGET_ID`. The mapping is never inferred and does
not belong to detect, apply, verify, or rollback. For the reviewed legacy
shape, `JustDanceMobile=just-dance-mobile` maps the exact detected legacy
directory to the approved portable target. A case-only or no-op mapping,
duplicate source, unused source, or target collision is rejected before a
bundle is retained. Schema 2 plans serialize the sorted mapping list, so the
reviewed plan and canonical bundle digest bind the mappings together with their
actions. Existing Schema 1 bundles remain compatible and load with an empty
mapping list.

Apply is a compare-and-swap operation against both the observed source revision
and the canonical reviewed bundle digest. A changed source, plan, snapshot,
action owner/target, or bundle inventory exits nonzero before staging or root
mutation. A lock/CAS conflict also exits nonzero and preserves any proposal
instead of silently selecting a winner.

Old focus pages are inputs, not owners. Ambiguous or competing content becomes a
proposal. Raw provenance is preserved. Embedded legacy knowledge is reported as
a separate Knowledge Base migration decision and is never moved automatically.

After apply, run `verify` against the same reviewed bundle, then repeat the
exact apply as the idempotence check: it must report the original accepted
transaction without changing a byte. Keep the persisted rollback set and apply
journal. `rollback` names the original apply through
`--apply-transaction-id`, uses a distinct new `--transaction-id`, and refuses
with a nonzero hash-safe result if live endpoints or rollback evidence changed.
Fixture rollback may omit authorization only for a fresh guard; stale guard
recovery needs a new explicit authorization. Real plan, apply, and rollback
each require distinct authorization references.

The installed 1.x `obsidian-agent-memory-writer` directory is historical
removal inventory, not a 2.0 Skill. Pack removal/rollback belongs to Plan 4 and
vault migration never depends on its prompt or script.

Successful migration authorizes neither post-upgrade cleanup nor any Knowledge
Base move. Those are separate reviewed decisions.
