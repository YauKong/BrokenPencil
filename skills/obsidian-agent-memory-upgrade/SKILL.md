---
name: obsidian-agent-memory-upgrade
description: Use only after obsidian-agent-memory routes a reviewed Agent Memory schema migration.
---

# Obsidian Agent Memory Upgrade

## Contracts

- [Vault Schema 2](../obsidian-agent-memory/references/vault-schema-2.md)
- [V1 to V2 migration](../obsidian-agent-memory/references/v1-to-v2-migration.md)
- [Write consistency](../obsidian-agent-memory/references/write-consistency.md)
- [Validation and target workstation](../obsidian-agent-memory/references/validation-and-target-workstation.md)
- [Migration record body](../obsidian-agent-memory/templates/migration-record.md)

## Workflow

The conceptual phase order is
`detect -> snapshot -> plan -> review -> apply -> verify`.
The wrapper exposes only `detect|plan|apply|verify|rollback`; `plan` first
captures and binds the hashed snapshot, then emits the review artifact. Snapshot
and review are phases, not subcommands. Every command requires
`--scope fixture|real`; real additionally requires
`--authorization-ref AUTHORIZATION_REF`.
Dry-run plan and apply are separately authorized.

The reviewed plan binds source paths/hashes and root revision to target owners,
paths, and projection effects. A changed source invalidates it. Ambiguous or
competing content becomes a proposal. Embedded knowledge is reported for a
separate Knowledge Base decision and is not moved.

## Boundaries

Pack installation/removal, vault apply, cleanup, rollback deletion, Knowledge
Base migration, push, and publication are separate actions. No real-vault
operation occurs during repository validation.
