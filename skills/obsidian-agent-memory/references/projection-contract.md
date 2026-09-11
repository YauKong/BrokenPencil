# Projection Contract

Canonical project focus is revisioned JSON that references accepted record IDs.
Root and project current-focus Markdown, indexes, and graph pages are generated
views and never fact owners.

Use `update_focus` for canonical focus changes. Use
`build_project_focus(root, project_id, "2.0.0")` and
`build_global_focus(root, "2.0.0")` to create `ProjectionDocument` values.
For a complete deterministic refresh, use `build_project_views` and
`build_root_views`; they return views named `overview`, `home`, `map`, `stale`,
and `current-focus`, plus accepted-story browse documents in lexical path
order. Publish each with
`publish_projection` and a fresh, unique `TransactionContext`; never infer a
lock identity from document bytes or reuse another operation's context.

Generated frontmatter contains `generated: true`, projection version 2,
aggregate source revision, latest input observation time, generator version,
and projection body hash. Builders do not inject wall-clock time. Identical
inputs produce identical bytes. A builder captures the existing target's
whole-file hash before reading canonical inputs. Publication permits only the
declared `_index/` and `projects/` generated-view paths, locks the target, and
rechecks that expected hash before replacement. Under the root write guard it
also rebuilds the exact view input snapshot and requires the document's
`source_revision` and content to remain current; a canonical-only change is a
conflict even when the target page itself has not changed. Because operational
proposals may append concurrently, stale/uncertain publication rechecks its
input revision after replacement while still holding the target lock and
restores the captured prior page/absence on mismatch only after the target still
hashes to this publisher's exact bytes. Target drift instead preserves the
unexpected edit and transaction recovery evidence. That post-check is the
publication linearization point; it does not retry.

An accepted Story browse page reverses same-project Session relationship
blocks into a timeline sorted by observation time and Session ID. It derives
the time range only from those links and shows primary/related role plus
completed/failed/cancelled status. A pending Story revision proposal may be
shown as pending reconciliation without exposing or applying its candidate
body. Legacy Sessions without a relationship are reported as
`legacy-session-unbound`; Unbound Session Proposals never enter a Story
timeline before explicit confirmation.

If the current file is manually changed, normal publication stops with drift.
If another publisher changed it, publication stops with a revision conflict.
Maintain may preserve the unexpected bytes and explicitly replace the view
only under the same CAS; no workflow silently discards or last-writer-wins over
an edit.
