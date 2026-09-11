# Retrieval Adapters

Call `select_read_adapter(binding, runner, executable=None)`.

`obsidian-cli` is an optional pack capability. CLI mode is selected only when an
executable is available, an Obsidian vault binding exists, bounded `obsidian
help` output lists `read`, `search`, and `files`, and a two-second vault-targeted
search health probe succeeds. Every CLI request carries the explicit vault and
a result limit.

Otherwise use the returned filesystem adapter and report
`AdapterSelection.reason`. Filesystem reads are contained and bounded to
`_records`, `_index`, and `projects`; they exclude `_sources` and
`.agent-memory`.

Adapters never expose arbitrary operational state. Use `load_catalog`,
`read_accepted_record`, or `search_accepted_records` to follow only the
catalog-selected current revision; orphan and losing immutable revisions are
not accepted evidence. Accepted records and catalog state outrank generated
views. A manually changed projection is reported as drift and preserved for
maintain review.

Adapters are read-only. Canonical records, focus state, projections, migration,
and maintenance never write through Obsidian CLI.
