---
name: obsidian-agent-memory-query
description: Use only after obsidian-agent-memory routes a read-only question about accepted project history or decisions or preferences or runbooks or evidence or focus.
---

# Obsidian Agent Memory Query

## Contracts

- [Retrieval adapters](../obsidian-agent-memory/references/retrieval-adapters.md)
- [Record ownership](../obsidian-agent-memory/references/record-ownership.md)
- [Projection contract](../obsidian-agent-memory/references/projection-contract.md)

## Workflow

1. State the selected root and, for project-scoped retrieval, the project and
   selection reason. If the project is unknown, use the route subskill first
   for bounded discovery; do not demand a project ID before that discovery.
   Global-memory reads require only the root.
2. Use the adapter selected by `select_read_adapter`; if optional `obsidian-cli`
   is unavailable, report its reason and use the bounded filesystem adapter.
3. Use `search_accepted_records` and `read_accepted_record` so only
   catalog-selected revisions are evidence; ignore orphan/losing files.
4. Read the smallest accepted records and generated views needed.
5. Follow current user, live verification, accepted owner record, preference or
   runbook, generated view, and old-session priority.
6. Name record IDs/pages used and state memory-derived uncertainty or age.
7. Verify current checkout facts when the answer depends on them.

## Read-Only Boundary

Do not write a record, focus state, projection, index, promotion, or maintenance
result. Do not trust a manually changed projection over accepted state. Report
projection drift and preserve it for maintain review.
