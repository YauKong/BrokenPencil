---
name: obsidian-agent-memory-route
description: Use only after obsidian-agent-memory routes a task that needs the smallest safe Agent Memory root and project and source and read-adapter context.
---

# Obsidian Agent Memory Route

## Contracts

- [Configuration and path discovery](../obsidian-agent-memory/references/configuration-and-path-discovery.md)
- [Retrieval adapters](../obsidian-agent-memory/references/retrieval-adapters.md)
- [Projection contract](../obsidian-agent-memory/references/projection-contract.md)

## Workflow

1. Pass explicit operation root/project and cwd. If no higher-precedence root
   is available, call `select_local_config_path` with the explicit config path,
   platform, and allowlisted environment mapping, then pass only that result to
   `resolve_binding`.
2. Stop on a missing, ambiguous, invalid, or escaping binding.
3. Call `select_read_adapter`; report its mode and reason.
4. Read only the bounded records/views needed for the task.
5. Treat accepted records as truth and generated views as retrieval aids.
6. Verify drift-prone checkout facts live when cheap.

The cwd basename is only a hint among configured projects. It never overrides
the current user's explicit root or project.

## Stop Conditions

Do not search a home directory, assume a vault name, require a running GUI,
bulk-read `_sources`, expose `.agent-memory`, or mutate during routing.
