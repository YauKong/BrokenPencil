# Story and Session Coordination

Story membership is explicit Session content. A coordinator or Harness adapter
may supply it; Agent Memory validates and preserves it. Title, date, current
focus, text similarity, and task ancestry never establish membership.

## Task branches

| Observed branch | Durable result |
| --- | --- |
| query/status/dispatch only | no Session |
| durable coordinator output | Session; optional Story delta |
| delegated child | inherited membership is already confirmed |
| child requests a new or changed relation | coordinator or user confirmation required |
| direct task without binding | Unbound Session Proposal only |
| failed/cancelled delegated task | terminal linked Session; Story stays incomplete |

This table classifies durable results; a prompt that says not to perform the
write does not make the classification optional. The child's terminal run
creates a linked Session, including failure or cancellation. Durable coordinator
analysis creates a Session. A Story delta is separate and optional; its commit
result is accepted or proposed.

A `CoordinationContext` carries `project_id`, `coordinator_task_id`, zero or one
primary Story, zero or more related Stories, the expected primary Story
revision, and allowed scope. `relationship_from_context` converts that already
confirmed binding into the Session relationship block. It does not discover or
dispatch tasks.

Each accepted Session has exactly one status: `completed`, `failed`, or
`cancelled`. It may have zero or one primary Story and zero or more related
Stories. Every referenced Story must already be accepted in the same project.
The Session owns this relationship; the Story never stores an editable Session
list.

If an already-bound child changes durable Story state, it may attempt a Story
delta against the inherited expected revision. The result is `accepted` or
`proposed`; never describe the delta as accepted before the commit result.
`accepted` advances the Story. `proposed` preserves a conflict for coordinator
reconciliation while the linked Session remains accepted.

A directly opened task without binding uses
`build_unbound_session_candidate` and `preserve_unbound_session_candidate`.
Candidate Story IDs require explicit evidence and remain suggestions. An
intended Story delta may travel inside the proposal but is not applied. The
proposal is operational evidence, never an accepted Session or Story.

Generated Story timelines reverse only accepted Session relationships.

Before confirmation, generated Story timeline and Story browse views include
only accepted Session links:

- Story timeline and Story browse view: nothing about the unbound proposal--no
  entry, candidate ID, evidence, time-range endpoint, pending marker, progress
  claim, or completion claim.
- Stale/uncertain operational view: may list Unbound Session Proposal metadata.

A future heartbeat may audit pending proposals; Skills do not poll or infer
relationships.
