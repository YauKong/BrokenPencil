---
name: obsidian-agent-memory-init
description: Use only after obsidian-agent-memory routes a request to initialize one explicit empty Agent Memory root optionally with its first Schema 2 project focus state.
---

# Obsidian Agent Memory Init

## Contracts

- [Configuration and path discovery](../obsidian-agent-memory/references/configuration-and-path-discovery.md)
- [Vault Schema 2](../obsidian-agent-memory/references/vault-schema-2.md)
- [Validation and target workstation](../obsidian-agent-memory/references/validation-and-target-workstation.md)

## Workflow

1. Require one explicit resolved root and optional validated project ID.
2. Show only the exact root-relative paths `initialize_memory_root` returns:
   the fixed anchor; `AGENTS.md`; `README.md`; config, schema, catalog, and
   optional project-focus JSON; and the accepted transaction JSON at
   `.agent-memory/transactions/<transaction_id>.json`.
3. Confirm authorization applies to this empty root, not installation,
   migration, cleanup, or a Knowledge Base.
4. Call `initialize_memory_root(root, project_id, context)`.
5. Verify those returned paths, stable `AGENTS.md`/`README.md`, the exact constant
   `.agent-memory-root-write.anchor`, Schema 2 JSON, empty catalog/focus state,
   the accepted initialization transaction, and containment.
6. Return without building projections. A separately authorized operation may
   build them only after accepted state exists.

## Stop Conditions

Stop if the root is absent, ambiguous, non-empty without a reviewed migration,
outside containment, or already uses an unsupported schema. Never infer or
create a Knowledge Base root. Never overwrite an existing file.
