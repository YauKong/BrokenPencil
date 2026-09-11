---
name: obsidian-agent-memory-summary
description: Use only after obsidian-agent-memory routes an explicitly authorized request to preserve one reviewed session as immutable chronology with owner-record references.
---

# Obsidian Agent Memory Summary

## Contracts

- [Record ownership](../obsidian-agent-memory/references/record-ownership.md)
- [Configuration and path discovery](../obsidian-agent-memory/references/configuration-and-path-discovery.md)
- [Write consistency](../obsidian-agent-memory/references/write-consistency.md)
- [Projection contract](../obsidian-agent-memory/references/projection-contract.md)
- [Story and Session coordination](../obsidian-agent-memory/references/story-session-coordination.md)
- [Session record body](../obsidian-agent-memory/templates/session-record.md)

## Workflow

1. Resolve one root/project and write authorization. If ambiguous, ask one
   choice. Migration/maintenance uses its meta record, never a Session.
2. Classify the task branch before rendering. A query/status/dispatch-only turn
   creates no Session. Durable coordinator output creates a Session; a Story
   delta is optional. A child's terminal run creates a linked Session, including
   failure/cancellation. Inherited membership changes only with confirmation.
3. Render chronology/outcome without raw chat. Preserve a failed or cancelled
   child as a terminal linked Session; it does not complete the Story.
4. Commit each new Decision/Story first with its expected revisions.
   Preserve conflicts; never cite a proposal as accepted.
5. Render the Session relationship with exact `primary_story_id` and related
   IDs. For a direct task without confirmed binding, call
   `preserve_unbound_session_candidate`; do not commit the Session, infer from
   focus/title/date, or place it in a Story timeline. Generated Story timeline
   and browse views contain nothing about the proposal. The stale/uncertain operational view
   alone may show its metadata.
6. Commit a bound Session and report its accepted revision or proposal.
7. Use `preserve_promotion_candidate` with accepted source IDs; do not infer a
   Knowledge Base root.
8. Apply authorized focus through `update_focus`; rebuild affected views with
   `build_project_views` and `build_root_views`, then publish through CAS.

## Verification

Confirm body hash/envelope, owner references, transaction result, no secret
reproduction, and no direct current-focus/index write. For unbound work, answer
the Story timeline question explicitly: it changes nothing and contains nothing
about the proposal. An unresolved root/project produces no artifact or view.
