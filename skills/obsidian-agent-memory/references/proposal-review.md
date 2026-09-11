# Migration proposal review

`review-proposals` is a read-only post-migration classifier. It consumes one
applied Schema 1-to-2 migration, its exact reviewed bundle digest, and the
current accepted catalog. It emits a canonical Report Schema 1 file at an
explicit external path. It does not accept, reject, resolve, edit, or delete a
proposal.

```text
python vault_maintain.py review-proposals --root <schema-2-root> --bundle <reviewed-bundle-directory> --bundle-sha256 <64-lowercase-hex> --output <absolute-external-path> --scope fixture|real --actor <identifier> --observed-at <RFC3339-timestamp> [--authorization-ref <required-for-real>] [--fixture-code-revision <fixture-only-identifier>]
```

The output must be outside the memory root, reviewed bundle, clean Git
repository, installed Skill root, and installed lifecycle state root. Both
wrappers isolate bytecode cache paths before importing managed modules. Fixture
scope requires an explicit fixture revision. Real scope forbids fixture
identity and requires a nonblank authorization reference plus either a clean
Git commit identity or the default-layout, target-bound, managed-valid installed state.
Installations using a custom lifecycle state root are not discoverable by this
command and fail closed.

The report may reveal filenames, owner candidates, source categories, line
ranges, hashes, and migration/runtime metadata. Treat it as sensitive even
though source prose and authorization content are not printed. Statuses mean:

- `path-owner-candidate`: one path-derived owner is available;
- `manual-owner-review`: identical fact bytes occur under distinct owners;
- `manual-parse-review`: the source could not be safely classified;
- the remaining routing statuses preserve the original migration-review class.

Legacy mixed-content files remain proposals until a reviewed decomposition
supplies separately owned rewritten records. Report generation never performs
that decomposition. The 225-item real review set remains outside fixture
verification and is not auto-resolved.

Publication never replaces an existing file. An existing report is reused only
after strict loading and a fresh complete root/bundle/runtime binding proves it
is identical. Exit `0` means created or strictly reused. Exit `2` means usage,
authorization, containment, schema, capability, or I/O failure. Exit `3` means
the reviewed input set was already invalid. Exit `4` means a concurrent change
or a different occupied output.

A real-root review, pack installation, report publication, and any later
proposal resolution are separate authorization boundaries. Success at one does
not authorize the next.

## Reviewed resolution progression

Resolution follows this fixed sequence:

```text
classification evidence -> reviewed rewrite packet -> read-only resolution plan -> separately authorized apply
```

The decision envelope must remain non-authorizing. A rewrite packet contains
only accepted candidates with an independent semantic review; sealing the
packet still does not authorize root mutation. Planning rebinds the exact
report, decision, packet, bundle, code identity, proposal bytes, snapshot bytes,
and catalog revision, then publishes a canonical plan outside every protected
root. Applying requires the exact plan and packet hashes plus a fresh explicit
operation gate and transaction context.

Apply writes a new record for each accepted rewrite and one immutable outcome
document for every decision. It updates the accepted catalog last, retains the
staged bytes and journal for deterministic recovery, and regenerates only the
declared projections. It never edits or deletes old source files, proposals,
snapshots, bundles, or earlier journals. `sources-only`, `keep-unresolved`, and
`knowledge-base-candidate` create outcome evidence but no Agent Memory record;
the last of these also does not perform a Knowledge Base write.

The current 225-item decision set and any packet produced from it are review
evidence only. They do not authorize planning against the real root or applying
there. Real planning and real apply remain separate, explicit user decisions.
