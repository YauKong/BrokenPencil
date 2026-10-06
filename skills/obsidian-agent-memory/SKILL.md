---
name: obsidian-agent-memory
description: Use first whenever a task may depend on agent-facing Obsidian or Markdown memory for routing or retrieval or durable writes or summaries or maintenance or schema migration. This is the only entrypoint to the family.
---

# Obsidian Agent Memory

## Entrypoint

Use this Skill first. Invoke one routed subskill after resolving the task type.
Current user instruction and explicit operation inputs outrank every stored
source.

Resolve the memory root separately from the task's project. If only the root
is known, use the route subskill for bounded project discovery
and context-based selection before project-scoped work. A missing project at
this stage is not an error and does not require a global default project.

## Boundaries

- Agent Memory and the optional Knowledge Base use separately configured roots.
- No user path, project, vault, runtime home, or GUI is a compiled default.
- Accepted records are immutable revisions with one semantic owner.
- Focus and index Markdown are generated projections, never canonical owners.
- Read routing must state both outcomes: use optional `obsidian-cli` only after
  a healthy explicit capability check; on failure report the named reason and
  use the bounded filesystem adapter.
- Writes use expected revisions and preserve conflicts as proposals.
- Source edits, commits, pack install, vault mutation, migration, cleanup,
  Knowledge Base actions, push, and publication are separately authorized.
- This family supplies memory mechanics, not a scheduler, queue, worker, lease,
  polling loop, or general agent runtime.

## Routes

- Create an empty Schema 2 root: `obsidian-agent-memory-init`.
- Resolve context and project binding: `obsidian-agent-memory-route`.
- Choose a collaboration/approval path: `obsidian-agent-memory-collaboration`.
- Answer from accepted memory: `obsidian-agent-memory-query`.
- Add or revise one durable fact: `obsidian-agent-memory-add`.
- Record a reviewed session: `obsidian-agent-memory-summary`.
- Audit or plan repairs: `obsidian-agent-memory-maintain`.
- Plan or perform a reviewed schema migration: `obsidian-agent-memory-upgrade`.

## Shared Contracts

- [Record ownership](references/record-ownership.md)
- [Configuration and path discovery](references/configuration-and-path-discovery.md)
- [Retrieval adapters](references/retrieval-adapters.md)
- [Write consistency](references/write-consistency.md)
- [Projection contract](references/projection-contract.md)
- [Vault Schema 2](references/vault-schema-2.md)
- [V1 to V2 migration](references/v1-to-v2-migration.md)
- [Proposal review](references/proposal-review.md)
- [Story and Session coordination](references/story-session-coordination.md)
- [Validation and target workstation](references/validation-and-target-workstation.md)

## Stop Conditions

When stating stop conditions, enumerate every category below. A decision-only
read does not allow omitting the mutation category.

- Stop and request one concrete choice when the root is absent or ambiguous,
  or a required project remains absent or ambiguous after bounded routing.
- Reject an invalid or escaping path before access.
- Stop a mutation when authorization or expected revision is missing.
- Preserve a proposal on conflict.
- If optional `obsidian-knowledge-base` is unavailable, preserve the promotion
  candidate and stop only that cross-root action with a named reason.
