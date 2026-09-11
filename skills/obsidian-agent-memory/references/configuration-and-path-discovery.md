# Configuration and Path Discovery

Resolve roots in this order:

1. the path explicitly named by the current user and passed to the operation;
2. an explicit command argument;
3. `OBSIDIAN_AGENT_MEMORY_ROOT`;
4. an explicitly selected local config binding;
5. one unambiguous platform registry binding selected by
   `select_local_config_path` from explicit platform/environment inputs.

Call `select_local_config_path(explicit_config_path, platform, env)` before
`resolve_binding(explicit_root, explicit_project, env, config_path, cwd)` when
no higher-precedence root is available. Windows uses `APPDATA`; macOS uses
`HOME/Library/Application Support`; Linux uses `XDG_CONFIG_HOME` or
`HOME/.config`. The selector receives an allowlisted mapping and never reads the
process environment itself.
The core never searches a home directory. The cwd basename is only a hint among
configured projects and cannot override an explicit project.

Validate every identifier with `validate_identifier`. Resolve every target with
`resolve_inside` before reading or mutating. Missing, ambiguous, invalid, or
escaping bindings stop the operation and request one concrete choice.

Machine-specific paths belong only in local configuration outside source,
release archives, and vault records. Configuration contains no credentials.
