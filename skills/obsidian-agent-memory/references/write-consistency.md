# Write Consistency

All write inputs use validated identifiers, a resolved root, and a
`TransactionContext`.

New records and revisions use `commit_record`. Supply both the expected catalog
revision and expected record revision. Focus changes use `update_focus` with an
expected focus revision and accepted record IDs.

Every mutation predeclares a recoverable transaction intent. An accepted
outcome advances exactly one canonical revision and finalizes that result. A
proposed outcome preserves one append-only proposal, reports its conflict code,
and is surfaced as non-success. An incomplete post-CAS result remains
reconcilable by doctor/maintain. There is no automatic retry, lock breaking,
overwrite, merge, or last-writer-wins.

Canonical and generated-view writers acquire the root-wide write guard before
their narrower catalog/focus/view lock. A migration may acquire it once through
`root_write_guard` and pass the verified `RootWriteGuard` token to live writers;
callers never forge or infer ownership. Root-guard contention may append only
unique intent/proposal evidence; it never changes accepted state. Migration
activation preserves those operational files instead of replacing their
directories.

Markdown current-focus and index pages never receive direct writes. Build them
with `build_project_focus` or `build_global_focus`; use `build_root_views` and
`build_project_views` when every affected browse view must be refreshed. Then
call `publish_projection` for each returned document with a fresh, unique
`TransactionContext`. Publication accepts
generated-view paths only and uses the builder-captured target hash under a
per-view lock. A changed hash is a non-success conflict. Manual drift is
preserved; replacement requires a separately authorized maintain decision with
`replace_drift=True` and the same target-hash CAS.

Installation, source commits, vault writes, migration apply, cleanup, Knowledge
Base actions, push, and publication are separately authorized operations.
