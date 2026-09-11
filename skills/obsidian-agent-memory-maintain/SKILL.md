---
name: obsidian-agent-memory-maintain
description: Use only after obsidian-agent-memory routes Agent Memory work involving consistency or projections or proposals or locks or links or ownership when the requested operation is a read-only audit or an explicitly authorized cleanup plan or separately authorized narrow stale root-guard recovery.
---

# Obsidian Agent Memory Maintain

## Contracts

- [Record ownership](../obsidian-agent-memory/references/record-ownership.md)
- [Write consistency](../obsidian-agent-memory/references/write-consistency.md)
- [Projection contract](../obsidian-agent-memory/references/projection-contract.md)
- [Validation and target workstation](../obsidian-agent-memory/references/validation-and-target-workstation.md)
- [Proposal review](../obsidian-agent-memory/references/proposal-review.md)
- [Maintenance record body](../obsidian-agent-memory/templates/maintenance-record.md)

## Commands

Use the installed maintenance entrypoint named by [Validation and target
workstation](../obsidian-agent-memory/references/validation-and-target-workstation.md).
It exposes `audit`, `plan`, read-only `review-proposals`, narrow
`recover-root-guard`, and the proposal-resolution progression
`plan-proposal-resolution`, `apply-proposal-resolution`,
`verify-proposal-resolution`, and `recover-proposal-resolution`. All require an explicit `--root` and
`--scope fixture|real`; `audit` writes a named report, and `plan` consumes that
report plus explicit output and transaction context. Real scope requires a
separately approved authorization reference. `recover-root-guard` also requires
the target transaction and lock hash or candidate-only binding, plus a distinct
authorized recovery context. These commands do not execute cleanup.

For unresolved proposals after an applied migration, read [Proposal
review](../obsidian-agent-memory/references/proposal-review.md) before running
`review-proposals`. It writes one canonical report outside the memory root,
reviewed bundle, and runtime-identity protected roots. It classifies evidence
but never resolves or writes a proposal.

Resolution is `classification evidence -> reviewed rewrite packet -> read-only
plan -> separately authorized apply`. Apply binds every reviewed input and
hash. Recovery follows one validated journal with a distinct context;
verification is read-only.

## Safety

Audit before planning. Preserve proposals, raw provenance, unexpected projection
edits, uncertain facts, and rollback data. Audit/plan never break a lock. Invoke
the narrow recovery only after an explicit request names the expected lock or
candidate binding; it must prove the old advisory lease is acquirable, preserve
immutable recovery evidence, and refuse live/malformed/unknown ownership. Report
a secret's location without reproducing its value.

A repair plan distinguishes supersede, merge-by-new-revision, regenerate,
archive, and delete. No action is applied without a future reviewed plan and
transactional implementation.

Resolution creates new records and per-decision evidence without editing or
deleting legacy evidence. `knowledge-base-candidate` records intent only; it
does not write to a Knowledge Base.
