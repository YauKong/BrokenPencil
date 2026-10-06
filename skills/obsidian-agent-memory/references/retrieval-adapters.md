# Retrieval Adapters

Call `select_read_adapter(binding, runner, executable=None)`.

`obsidian-cli` is an optional pack capability. CLI mode is selected only when an
executable is available, an Obsidian vault binding exists, bounded `obsidian
help` output lists `read`, `search`, and `files`, and a two-second vault-targeted
search health probe succeeds. Every CLI request carries the explicit vault and
bounded output. Search uses explicit `path` and `limit` per allowed root;
file listing uses the CLI's `folder` and `ext=md` options, then applies the
result limit locally after validating every returned path.
If a saturated CLI search includes excluded legacy entries, the adapter reports
incomplete results instead of implying that a shortened result is exhaustive.
Use a narrower query or catalog-selected accepted-record search.

Otherwise use the returned filesystem adapter and report
`AdapterSelection.reason`. Filesystem reads are contained and bounded to
`_records`, `_index`, and `projects`; they exclude `_sources` and
`.agent-memory`.

Filesystem discovery skips plain non-note attachments (such as code and
images), after containment/reparse checks; it never decodes those files as
memory. Project browsing also ignores noncanonical legacy display names,
including old Markdown references, without changing or deleting them. Direct
reads and canonical `_records` paths retain strict identifier validation.

Adapters never expose arbitrary operational state. Use `load_catalog`,
`read_accepted_record`, or `search_accepted_records` to follow only the
catalog-selected current revision; orphan and losing immutable revisions are
not accepted evidence. Accepted records and catalog state outrank generated
views. A manually changed projection is reported as drift and preserved for
maintain review.

Adapters are read-only. Canonical records, focus state, projections, migration,
and maintenance never write through Obsidian CLI.
