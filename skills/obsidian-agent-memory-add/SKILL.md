---
name: obsidian-agent-memory-add
description: Use only after obsidian-agent-memory routes an explicitly authorized request to add or revise one durable project fact or decision or preference or runbook or provenance-backed record.
---

# Obsidian Agent Memory Add

## Contracts

- [Record ownership](../obsidian-agent-memory/references/record-ownership.md)
- [Configuration and path discovery](../obsidian-agent-memory/references/configuration-and-path-discovery.md)
- [Write consistency](../obsidian-agent-memory/references/write-consistency.md)
- [Projection contract](../obsidian-agent-memory/references/projection-contract.md)

## Workflow

1. Resolve the explicit root/project and verify write authorization.
2. Classify exactly one semantic owner and search accepted records for it. A
   product decision's sole owner is its decision record; sessions and focus
   reference that record ID only.
3. If unchanged, link the accepted owner with no new revision or write.
4. For a correction, build a strict `RecordEnvelope` and `RecordCandidate`
   with provenance, current+1/supersedes, and expected catalog and record
   revisions.
5. Call `commit_record`. A stale CAS preserves a proposal/conflict as
   non-success; never reread-and-merge, retry, or overwrite.
6. If human/domain knowledge is identified, build a typed promotion candidate
   with accepted source record IDs and preserve it through
   `preserve_promotion_candidate`; a matching Knowledge Base Skill alone owns
   later materialization, and unavailability leaves the candidate preserved.
7. Update focus only through `update_focus` with its expected revision and
   accepted record IDs. After every accepted write and append-only
   candidate/proposal exists, rebuild affected views with
   `build_project_views` and `build_root_views`, then publish each through its
   CAS using a fresh projection context.

## Stop Conditions

Never append to an accepted record, write current-focus/index Markdown, create a
second owner, infer a root/project, retry a conflict, or perform an unauthorized
cross-root action.
