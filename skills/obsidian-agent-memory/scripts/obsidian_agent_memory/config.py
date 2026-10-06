"""Explicit configuration loading and portable Agent Memory root selection."""

import json
import os
import unicodedata
from pathlib import Path
from typing import Mapping, Optional

from .errors import ConfigurationError, ValidationError
from .models import RootBinding
from .paths import validate_identifier


_TOP_LEVEL_KEYS = frozenset(("schema_version", "bindings"))
_BINDING_KEYS = frozenset(("workspace", "memory_root", "project_id", "obsidian_vault"))
_CREDENTIAL_KEY_FRAGMENTS = ("credential", "password", "secret", "token", "api_key", "apikey", "authorization")


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("invalid configuration: duplicate key {0}".format(key))
        result[key] = value
    return result


def _read_json(path: Path):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ConfigurationError("missing configuration file") from error
    except OSError as error:
        raise ConfigurationError("invalid configuration file") from error
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ConfigurationError) as error:
        if isinstance(error, ConfigurationError):
            raise
        raise ConfigurationError("invalid configuration JSON") from error


def _contains_credential_key(value) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if any(fragment in normalized_key for fragment in _CREDENTIAL_KEY_FRAGMENTS):
                return True
            if _contains_credential_key(child):
                return True
    elif isinstance(value, list):
        return any(_contains_credential_key(child) for child in value)
    return False


def _require_mapping(value, label: str):
    if not isinstance(value, dict):
        raise ConfigurationError("invalid {0}".format(label))
    return value


def _require_absolute_path(value, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ConfigurationError("invalid {0}".format(field))
    path = Path(value)
    if not path.is_absolute():
        raise ConfigurationError("invalid {0}: must be absolute".format(field))
    return path.resolve(strict=False)


def _validate_binding(binding):
    binding = _require_mapping(binding, "binding")
    unknown_keys = set(binding).difference(_BINDING_KEYS)
    if unknown_keys:
        raise ConfigurationError("invalid binding: unknown key")
    required_keys = {"workspace", "memory_root", "project_id"}
    if set(binding).intersection(required_keys) != required_keys:
        raise ConfigurationError("invalid binding: missing required key")

    workspace = _require_absolute_path(binding["workspace"], "workspace")
    memory_root = _require_absolute_path(binding["memory_root"], "memory_root")
    try:
        project_id = (
            validate_identifier(binding["project_id"], "project_id")
            if binding["project_id"] is not None else None
        )
    except ValidationError as error:
        raise ConfigurationError("invalid project_id") from error

    obsidian_vault = binding.get("obsidian_vault")
    if obsidian_vault is not None:
        if (
            not isinstance(obsidian_vault, str)
            or not obsidian_vault.strip()
            or len(obsidian_vault) > 255
            or any(unicodedata.category(char).startswith("C") for char in obsidian_vault)
        ):
            raise ConfigurationError("invalid obsidian_vault")
    return {
        "workspace": workspace,
        "memory_root": memory_root,
        "project_id": project_id,
        "obsidian_vault": obsidian_vault,
    }


def load_local_config(path: Path) -> Mapping[str, object]:
    """Load one explicitly named configuration file without ambient discovery."""
    config = _require_mapping(_read_json(Path(path)), "configuration")
    if _contains_credential_key(config):
        raise ConfigurationError("invalid configuration: credentials are not permitted")
    unknown_keys = set(config).difference(_TOP_LEVEL_KEYS)
    if unknown_keys:
        raise ConfigurationError("invalid configuration: unknown key")
    if set(config) != _TOP_LEVEL_KEYS:
        raise ConfigurationError("invalid configuration: missing required key")
    if config["schema_version"] != 1 or isinstance(config["schema_version"], bool):
        raise ConfigurationError("invalid configuration: unsupported schema_version")
    if not isinstance(config["bindings"], list):
        raise ConfigurationError("invalid configuration: bindings")

    bindings = []
    workspaces = set()
    for binding in config["bindings"]:
        validated = _validate_binding(binding)
        workspace_key = _normalise_path(validated["workspace"])
        if workspace_key in workspaces:
            raise ConfigurationError("invalid configuration: duplicate binding")
        workspaces.add(workspace_key)
        bindings.append(validated)
    return {"schema_version": 1, "bindings": bindings}


def _absolute_env_path(env: Mapping[str, str], name: str) -> Optional[Path]:
    value = env.get(name)
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        return None
    return path


def select_local_config_path(
    explicit_config_path: Optional[Path], platform: str, env: Mapping[str, str]
) -> Optional[Path]:
    """Select a registry location solely from supplied values, never ambient state."""
    if explicit_config_path is not None:
        if not explicit_config_path.is_absolute():
            raise ConfigurationError("invalid explicit configuration path: must be absolute")
        return explicit_config_path

    if platform == "win32":
        base = _absolute_env_path(env, "APPDATA")
        suffix = ("obsidian-agent-memory", "config.json")
    elif platform == "darwin":
        home = _absolute_env_path(env, "HOME")
        if home is None:
            return None
        return home / "Library" / "Application Support" / "obsidian-agent-memory" / "config.json"
    elif platform.startswith("linux"):
        base = _absolute_env_path(env, "XDG_CONFIG_HOME")
        if base is None:
            home = _absolute_env_path(env, "HOME")
            if home is None:
                return None
            return home / ".config" / "obsidian-agent-memory" / "config.json"
        suffix = ("obsidian-agent-memory", "config.json")
    else:
        return None

    if base is None:
        return None
    return base.joinpath(*suffix)


def _normalise_path(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(Path(path).resolve(strict=False))))


def _is_workspace_ancestor(workspace: Path, cwd: Path) -> bool:
    workspace_text = _normalise_path(workspace)
    cwd_text = _normalise_path(cwd)
    try:
        return os.path.commonpath((workspace_text, cwd_text)) == workspace_text
    except ValueError:
        return False


def _resolve_root(value, source: str) -> Path:
    try:
        return _require_absolute_path(str(value), "{0} memory root".format(source))
    except (TypeError, ValueError) as error:
        raise ConfigurationError("invalid {0} memory root".format(source)) from error


def _validate_explicit_project(explicit_project: Optional[str]) -> Optional[str]:
    if explicit_project is None:
        return None
    try:
        return validate_identifier(explicit_project, "explicit_project")
    except ValidationError as error:
        raise ConfigurationError("invalid explicit_project") from error


def _vault_for_root(bindings, root):
    vaults = {
        binding["obsidian_vault"] for binding in bindings
        if _normalise_path(binding["memory_root"]) == _normalise_path(root)
        and binding["obsidian_vault"] is not None
    }
    if len(vaults) > 1:
        raise ConfigurationError("ambiguous vault binding for selected memory root")
    return next(iter(vaults), None)


def resolve_binding(
    explicit_root: Optional[Path],
    explicit_project: Optional[str],
    env: Mapping[str, str],
    config_path: Optional[Path],
    cwd: Path,
) -> RootBinding:
    """Resolve the root first, then a project within that root when available.

    A root-only binding permits bounded project discovery by the caller; it
    does not select a default project or authorize a project-scoped operation.
    """
    project_id = _validate_explicit_project(explicit_project)
    selected_root = None
    if explicit_root is not None:
        selected_root = _resolve_root(explicit_root, "explicit")
    elif env.get("OBSIDIAN_AGENT_MEMORY_ROOT") is not None:
        selected_root = _resolve_root(env["OBSIDIAN_AGENT_MEMORY_ROOT"], "environment")

    if config_path is None:
        if selected_root is not None:
            return RootBinding(selected_root, project_id, None)
        raise ConfigurationError("missing configuration binding")
    try:
        config = load_local_config(config_path)
    except ConfigurationError as error:
        # A selected platform registry location need not have been configured.
        # Only absence is optional; malformed/unreadable configuration fails.
        if selected_root is not None and isinstance(error.__cause__, FileNotFoundError):
            return RootBinding(selected_root, project_id, None)
        raise
    bindings = config["bindings"]
    if selected_root is not None:
        bindings = [
            binding for binding in bindings
            if _normalise_path(binding["memory_root"]) == _normalise_path(selected_root)
        ]
        selected_vault = _vault_for_root(bindings, selected_root)
        if project_id is not None:
            return RootBinding(selected_root, project_id, selected_vault)
    workspace_matches = [binding for binding in bindings if _is_workspace_ancestor(binding["workspace"], cwd)]
    if workspace_matches:
        longest_length = max(len(_normalise_path(binding["workspace"])) for binding in workspace_matches)
        best_matches = [
            binding
            for binding in workspace_matches
            if len(_normalise_path(binding["workspace"])) == longest_length
        ]
        if len(best_matches) != 1:
            raise ConfigurationError("ambiguous configuration binding")
        selected = best_matches[0]
    else:
        cwd_name = Path(cwd).name
        project_matches = [binding for binding in bindings if binding["project_id"] == cwd_name]
        if not project_matches:
            if selected_root is not None:
                return RootBinding(selected_root, None, selected_vault)
            raise ConfigurationError("missing configuration binding")
        if len(project_matches) != 1:
            raise ConfigurationError("ambiguous configuration binding")
        selected = project_matches[0]

    return RootBinding(
        selected["memory_root"],
        project_id if project_id is not None else selected["project_id"],
        _vault_for_root(bindings, selected["memory_root"]),
    )
