# Record Ownership

One fact has one durable owner.

| Information | Owner |
| --- | --- |
| Session chronology and command evidence | session record |
| Session status and Story membership | session relationship block |
| Project fact or failure/resolution case | story record |
| Project or product decision | decision record |
| User preference or decision habit | preference record |
| Reusable agent procedure | runbook record |
| Reusable human/domain knowledge | separate Knowledge Base |
| Active routing/focus | project focus JSON |
| Catalog and Markdown views | structured state or generated projection |
| Raw imported material | `_sources/` provenance |

Sessions and generated views may summarize an owner only with its record ID.
They never become a second owner. A correction creates an immutable revision
whose `supersedes` value names the prior revision. New owners start at revision
1 with no supersedes; an update is exactly current+1, supersedes the same ID's
current revision, and cannot change record type, project, or owner scope.

A Story is a narrative across one or more accepted Sessions, but it does not
own an editable Session list. Its timeline and time range are reverse
projections of explicit Session relationships. An unbound proposal is not
membership and cannot appear as an accepted Story event.

Owner scopes are exact: project records use
`project.<project>.session|story|decision`; global records use
`user.preference` or `agent.runbook`; meta records use `meta.migration` or
`meta.maintenance`. A syntactically safe but mismatched scope is invalid.

Build a `RecordCandidate`, then call `commit_record` with expected catalog and
record revisions. `accepted` means the catalog selected the revision.
`proposed` means a conflict preserved the desired operation; it is not success.

Knowledge promotion produces a typed `PromotionCandidate` with accepted source
record IDs and a suggested target hint. Preserve it through
`preserve_promotion_candidate` as an append-only operational proposal.
`obsidian-knowledge-base` is optional for the pack; only that matching Skill may
materialize a candidate. If it is unavailable, the candidate remains preserved
and only the requested cross-root action stops.
