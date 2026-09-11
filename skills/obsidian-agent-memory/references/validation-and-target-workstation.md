# Validation and Target Workstation

The installed maintenance wrapper advertises `review-proposals`. Before that
verb imports managed modules, it disables bytecode writes and selects a fresh,
nonexistent external cache prefix. Real review accepts only a clean source Git
identity or a managed-valid default-layout installation; a custom lifecycle
state root is intentionally unsupported. See [Proposal review](proposal-review.md)
for syntax, protected output roots, sensitivity, idempotence, and exit codes.

Deterministic validation uses Python 3.9 or newer and the standard library. It
does not require PyYAML, a network connection, a known user path, a running
Obsidian GUI, or a real vault.

Plan 2 calls `validate_skill_tree(repo_root, manifest)` directly. Plan 4 owns:

~~~text
python tools/validate.py --repo-root .
~~~

Validation checks exact active members, frontmatter, routes, relative links,
portable content, release membership/hashes, and absence of removed active
members. Behavior evidence is reviewed separately and is not converted into a
deterministic model test.

Windows and PowerShell are the first target gate. A target smoke uses a
temporary Skill root and fixture vault. Configure the real Agent Memory root
only after installation, restart the host when discovery requires it, and run
a headless doctor check before optional live CLI verification.

## Gated vault tools

Installed migration and maintenance use
[`../scripts/vault_migrate.py`](../scripts/vault_migrate.py) and
[`../scripts/vault_maintain.py`](../scripts/vault_maintain.py). The
`tools/*.py` files are repository-clone aliases over those same shared CLI
modules; installed guidance must not depend on a clone layout.

Repository development, packaged smoke, and fixture evidence use `--scope
fixture`. Any real root requires a new explicit user authorization for that
exact phase and a concrete argument such as `--scope real --authorization-ref
approval-2026-08-30-migration-plan`. Prior success never continues authority
automatically: record a new authorization before plan, apply, rollback, audit,
or recovery whenever the operation contract requires one.

A successful migration does not authorize cleanup. A real cleanup campaign
begins with a separately authorized, read-only `vault_maintain.py audit` whose
JSON output is outside the selected root. Derive the approval-only cleanup plan
from that saved audit using `vault_maintain.py plan`; source-revision drift
invalidates it. The maintenance CLI deliberately provides no cleanup `apply`
or `execute` command, so a later cleanup mutation needs its own reviewed design
and authorization.

`recover-root-guard` is a narrow operational recovery, not cleanup. It binds to
one exact stale canonical-lock hash or one candidate-only transaction, requires
a distinct new transaction context and an explicit authorization even for a
fixture, and preserves immutable relative-path recovery evidence. It authorizes
neither record/focus/proposal/projection changes nor any other memory-content
mutation.
