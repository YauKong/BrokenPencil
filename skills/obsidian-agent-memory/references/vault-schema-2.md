# Vault Schema 2

Schema 2 separates canonical records, operational JSON, raw sources, and
generated views.

~~~text
AGENTS.md
README.md
.agent-memory-root-write.anchor
.agent-memory/config.json
.agent-memory/schema.json
.agent-memory/state/catalog.json
.agent-memory/state/focus/{project_id}.json
.agent-memory/state/proposals/
.agent-memory/state/locks/
.agent-memory/transactions/
_records/projects/{project_id}/sessions/
_records/projects/{project_id}/stories/
_records/projects/{project_id}/decisions/
_records/preferences/
_records/runbooks/
_records/meta/migrations/
_records/meta/maintenance/
_sources/projects/{project_id}/
_sources/meta/
_index/
projects/{project_id}/
~~~

`_records/` contains immutable accepted revisions. `.agent-memory/state/`
contains tool-managed JSON. `_sources/` preserves provenance. `_index/` and
`projects/` contain generated Markdown, except that `_index/*.base` may be an
active Obsidian Bases auxiliary view. A Base view is preserved at the same path
and byte-for-byte as a non-owner, non-projection artifact; it is not parsed or
rewritten as a generated view. Files selected by that view keep their own
classification and action: story inputs retain their independent story
ownership, while knowledge inputs remain subject to their separate Knowledge
Base migration decision. `.agent-memory-root-write.anchor` is the fixed
portable operational namespace anchor used by every cooperating writer; its
exact constant bytes contain no user, machine, path, transaction, actor, fact,
or current status, and it is neither a generated view nor a fact owner.

Initialize an explicit fixture or authorized empty root with
`initialize_memory_root(root, project_id, context)`. It exclusively creates the
Schema 2 skeleton, fixed operational namespace anchor, stable `AGENTS.md`
operating contract, and human-facing `README.md`, then returns the created
paths. Neither top-level document nor the anchor contains current status or
durable facts. Initialization does not install Skills,
migrate v1 content, create a Knowledge Base root, or search for a default root.
