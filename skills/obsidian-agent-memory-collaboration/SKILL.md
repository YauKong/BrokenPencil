---
name: obsidian-agent-memory-collaboration
description: Use only after obsidian-agent-memory routes non-trivial work that needs one explicit collaboration contract for ownership or persistence or migration or verification or Git or external-action choices.
---

# Obsidian Agent Memory Collaboration

## Contracts

- [Record ownership](../obsidian-agent-memory/references/record-ownership.md)
- [Configuration and path discovery](../obsidian-agent-memory/references/configuration-and-path-discovery.md)
- [Write consistency](../obsidian-agent-memory/references/write-consistency.md)
- [Story and Session coordination](../obsidian-agent-memory/references/story-session-coordination.md)

## Choose the Path

- **Direct Plan:** locally reversible result, exact acceptance, unchanged durable
  owner/persistence/migration/lifecycle/external contract.
- **Spec Then Plan:** durable owner, compatibility, migration, lifecycle,
  irreversible result, or external contract changes.
- **Decision Packet:** unresolved material choices determine the path.

Bundle material choices once. Decide reversible private details inside the
authorized scope. Classify independent work separately: new evidence changes
only the affected slice's path. Skip this protocol for a simple self-contained
task.

## Reopen the Decision

Reopen only when evidence changes a durable owner, canonical state, migration,
external contract, verification gate, irreversible result, or externally
visible action. A proposed direct projection edit, overwrite of an accepted
revision, or bypass of expected revisions is such a change.

When an authorized reversible source refactor exposes one of these memory
changes, keep the source refactor on Direct Plan and reopen only the durable
memory slice as Spec Then Plan.

`backend-first` and `function-first` describe implementation order, not a new
service, CLI, manager, schema, or runtime.

## Action Boundaries

Source edit, commit, pack installation, vault write, migration, cleanup,
Knowledge Base action, push, publication, and external message are separate.
Memory writes require explicit authorization through the routed subskill.

## Coordinator and Task Branches

- query/status/dispatch only -> no Session.
- durable coordinator output -> Session; optional Story delta.
- delegated child -> inherited membership is already confirmed; when its work
  changes the Story, it may attempt a Story delta against the inherited expected
  revision. The commit result is accepted or proposed; never call the delta
  accepted before that result.
- child changes membership -> coordinator/user confirmation required. Story
  title, date, focus, similarity, and ancestry are not confirmation.
- direct task without binding -> preserve an Unbound Session Proposal; it is
  neither accepted membership nor a Story timeline event.
- failed/cancelled child -> preserve the terminal linked Session; the Story does
  not become complete.

These are mandatory durable classifications even when a scenario asks only for
an explanation and forbids performing the write: a child's terminal run creates
a linked Session, durable coordinator analysis creates a Session, and a separate
Story delta is optional with an accepted-or-proposed commit result.

Never turn “durable work” into an accepted Story revision. Classify it exactly:
child durable output -> linked Session plus optional delta attempt; coordinator
durable analysis -> Session plus optional delta attempt; each attempted delta ->
accepted or proposed only after CAS.

The current controller is an adapter for supplying `CoordinationContext`, not a
new durable owner. A future Harness or heartbeat may propagate or audit the
same contract, but this Skill does not poll, discover tasks, or guess links.
