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

1. Resolve root and project separately using the configuration contract. Pass
   the user's explicit inputs and cwd. Select a local config path even with a
   known root and project; same-root bindings can still supply the vault.
   A root-only `RootBinding` is a valid routing state.
2. Call `select_read_adapter` for that root; report its mode and reason.
3. If the project is unknown, follow the contract's bounded project discovery:
   use project IDs and browse metadata with the user's request, confirmed
   conversation context and workspace evidence. A clear match continues;
   ambiguous candidates require one concrete choice. No match leads to a
   project choice or new-project confirmation, not automatic creation.
4. State the selected root/project and the evidence for that choice. Pass the
   chosen ID explicitly to `resolve_binding` before project-scoped retrieval
   or writes. Root-wide discovery or global-memory reads need no project ID.
5. Read only the bounded records/views needed. Accepted records are truth;
   generated views are retrieval aids, not owners or routing instructions.
6. Re-evaluate the project when the user changes topic or workspace; a previous
   task's binding is not a global default. Verify drift-prone facts live.

The cwd basename is only a hint among configured projects. It never overrides
the current user's explicit root or project.

## Stop Conditions

Do not search a home directory, assume a vault name, require a running GUI,
bulk-read `_sources`, expose `.agent-memory`, or mutate during routing.
Reject invalid or escaping paths before access. Stop project-scoped work when
the project remains ambiguous after discovery; do not stop discovery merely
because the project is initially unknown. Routing never grants write authority.
