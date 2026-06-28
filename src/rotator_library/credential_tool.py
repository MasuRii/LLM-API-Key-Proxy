# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Mirrowel

# src/rotator_library/credential_tool.py

import asyncio
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from dotenv import set_key, get_key

# NOTE: Heavy imports (provider_factory, PROVIDER_PLUGINS) are deferred
# to avoid 6-7 second delay before showing loading screen
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text

from .utils.paths import get_oauth_dir, get_data_file
from .provider_config import LITELLM_PROVIDERS, PROVIDER_CATEGORIES, PROVIDER_BLACKLIST
from .litellm_providers import (
    SCRAPED_PROVIDERS,
)
from .providers.utilities.gemini_shared_utils import format_tier_for_display
from .providers.utilities.codex_credential_formats import (
    CODEX_EXPORT_FORMATS,
    CodexImportResult,
    import_codex_credentials_from_path,
    load_codex_credentials_from_directory,
    write_codex_export_file,
)


def _get_oauth_base_dir() -> Path:
    """Get the OAuth base directory (lazy, respects EXE vs script mode)."""
    oauth_dir = get_oauth_dir()
    oauth_dir.mkdir(parents=True, exist_ok=True)
    return oauth_dir


def _get_env_file() -> Path:
    """Get the .env file path (lazy, respects EXE vs script mode)."""
    return get_data_file(".env")


console = Console()

# Global variables for lazily loaded modules
_provider_factory = None
_provider_plugins = None


def _ensure_providers_loaded():
    """Lazy load provider modules only when needed"""
    global _provider_factory, _provider_plugins
    if _provider_factory is None:
        from . import provider_factory as pf
        from .providers import PROVIDER_PLUGINS as pp

        _provider_factory = pf
        _provider_plugins = pp
    return _provider_factory, _provider_plugins


# OAuth provider display names mapping (no "(OAuth)" suffix - context makes it clear)
OAUTH_FRIENDLY_NAMES = {
    "gemini_cli": "Gemini CLI",
    "codex": "OpenAI Codex",
    "anthropic": "Claude / Claude Code (Pro & Max)",
    "copilot": "GitHub Copilot",
    "x-ai": "xAI Grok",
}

DEFAULT_OAUTH_CLEANUP_STATUSES = ("needs_reauth", "cooldown", "exhausted")
OAUTH_CLEANUP_STATUS_CHOICES = (*DEFAULT_OAUTH_CLEANUP_STATUSES, "active")
OAUTH_CLEANUP_STATUS_PRIORITY = {
    "needs_reauth": 0,
    "exhausted": 1,
    "cooldown": 2,
    "active": 3,
    "unknown": 4,
    "error": 5,
}


def _extract_key_number(key_name: str) -> int:
    """Extract the numeric suffix from a key name for proper sorting.

    Examples:
        GEMINI_API_KEY_1 -> 1
        GEMINI_API_KEY_10 -> 10
        GEMINI_API_KEY -> 0
    """
    match = re.search(r"_(\d+)$", key_name)
    return int(match.group(1)) if match else 0


# Note: _normalize_tier_name was replaced with format_tier_for_display
# from providers.utilities.gemini_shared_utils for centralized tier handling


def _count_tiers(credentials: list) -> dict:
    """Count credentials by tier.

    Args:
        credentials: List of credential info dicts with optional 'tier' key

    Returns:
        Dict mapping normalized tier names to counts, e.g. {"free": 15, "paid": 2}
    """
    tier_counts = {}
    for cred in credentials:
        tier = cred.get("tier")
        if tier:
            normalized = format_tier_for_display(tier)
            tier_counts[normalized] = tier_counts.get(normalized, 0) + 1
    return tier_counts


def _format_tier_counts(tier_counts: dict) -> str:
    """Format tier counts as a compact string.

    Examples:
        {"free": 15, "paid": 2} -> "(15 free, 2 paid)"
        {"free": 5} -> "(5 free)"
        {} -> ""
    """
    if not tier_counts:
        return ""

    # Sort by count descending, then alphabetically
    sorted_tiers = sorted(tier_counts.items(), key=lambda x: (-x[1], x[0]))
    parts = [f"{count} {tier}" for tier, count in sorted_tiers]
    return f"({', '.join(parts)})"


def _get_api_keys_from_env() -> dict:
    """
    Parse the .env file and return a dictionary of API keys grouped by provider.
    Keys are sorted numerically within each provider.

    Returns:
        Dict mapping provider names to lists of (key_name, key_value) tuples.
        Example: {"GEMINI": [("GEMINI_API_KEY_1", "abc123"), ("GEMINI_API_KEY_2", "def456")]}
    """
    api_keys = {}
    env_file = _get_env_file()

    if not env_file.is_file():
        return api_keys

    try:
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Look for lines with API_KEY pattern
                if "_API_KEY" in line and "=" in line:
                    key_name, _, key_value = line.partition("=")
                    key_name = key_name.strip()
                    key_value = key_value.strip().strip('"').strip("'")

                    # Skip PROXY_API_KEY and empty values
                    if key_name == "PROXY_API_KEY" or not key_value:
                        continue

                    # Skip placeholder values
                    if key_value.startswith("YOUR_") or key_value == "":
                        continue

                    # Extract provider name (everything before _API_KEY)
                    # Handle cases like GEMINI_API_KEY_1 -> GEMINI
                    parts = key_name.split("_API_KEY")
                    if parts:
                        provider_name = parts[0]
                        if provider_name not in api_keys:
                            api_keys[provider_name] = []
                        api_keys[provider_name].append((key_name, key_value))

        # Sort keys numerically within each provider
        for provider_name in api_keys:
            api_keys[provider_name].sort(key=lambda x: _extract_key_number(x[0]))

    except Exception as e:
        console.print(f"[bold red]Error reading .env file: {e}[/bold red]")

    return api_keys


def _api_key_provider_from_name(key_name: str) -> str | None:
    """Return the provider prefix for a .env API key name."""
    if key_name.startswith("PROXY_"):
        return None
    match = re.fullmatch(r"(.+?)_API_KEY(?:_\d+)?", key_name)
    if not match:
        return None
    return match.group(1).lower()


def _oauth_provider_from_filename(filename: str) -> str | None:
    """Return the provider prefix for an OAuth credential filename."""
    match = re.fullmatch(r"(.+?)_oauth_\d+\.json", filename)
    if not match:
        return None
    return match.group(1).lower()


def _delete_api_key_from_env(key_name: str) -> bool:
    """
    Delete an API key from the .env file with safety backup and comparison.

    This function creates a backup of all API keys before deletion,
    performs the deletion, and then verifies no unintended keys were lost.

    Args:
        key_name: The exact key name to delete (e.g., "GEMINI_API_KEY_2")

    Returns:
        True if deletion was successful and verified, False otherwise
    """
    env_file = _get_env_file()

    if not env_file.is_file():
        console.print("[bold red]Error: .env file not found[/bold red]")
        return False

    try:
        # Step 1: Read all lines and backup all API keys
        with open(env_file, "r") as f:
            original_lines = f.readlines()

        # Create backup of all API keys before modification
        api_keys_before = _get_api_keys_from_env()
        all_keys_before = set()
        for provider_keys in api_keys_before.values():
            for kn, kv in provider_keys:
                all_keys_before.add((kn, kv))

        # Step 2: Find and remove the target key
        new_lines = []
        key_found = False
        deleted_key_value = None

        for line in original_lines:
            stripped = line.strip()
            # Check if this line contains our target key
            if stripped.startswith(f"{key_name}="):
                key_found = True
                # Store the value being deleted for verification
                _, _, deleted_key_value = stripped.partition("=")
                deleted_key_value = deleted_key_value.strip().strip('"').strip("'")
                continue  # Skip this line (delete it)
            new_lines.append(line)

        if not key_found:
            console.print(
                f"[bold red]Error: Key '{key_name}' not found in .env file[/bold red]"
            )
            return False

        # Step 3: Write the modified content
        with open(env_file, "w") as f:
            f.writelines(new_lines)

        # Step 4: Verify the deletion - compare before and after
        api_keys_after = _get_api_keys_from_env()
        all_keys_after = set()
        for provider_keys in api_keys_after.values():
            for kn, kv in provider_keys:
                all_keys_after.add((kn, kv))

        # Check that only the intended key was removed
        expected_remaining = all_keys_before - {(key_name, deleted_key_value)}

        if all_keys_after != expected_remaining:
            # Something went wrong - restore from backup
            console.print(
                "[bold red]Error: Unexpected keys were affected during deletion![/bold red]"
            )
            console.print("[bold yellow]Restoring original file...[/bold yellow]")
            with open(env_file, "w") as f:
                f.writelines(original_lines)
            return False

        return True

    except Exception as e:
        console.print(f"[bold red]Error during API key deletion: {e}[/bold red]")
        return False


def _normalize_oauth_status_value(status: Any) -> str:
    """Normalize an OAuth/usage status token for cleanup filtering."""
    normalized = str(status or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "needs_reauthentication": "needs_reauth",
        "reauth_required": "needs_reauth",
        "requires_reauth": "needs_reauth",
        "rate_limited": "cooldown",
        "rate_limit": "cooldown",
    }
    return aliases.get(normalized, normalized)


def _prefer_oauth_cleanup_status(existing: str | None, new_status: str) -> str:
    """Keep the most cleanup-relevant status when multiple usage scopes disagree."""
    if not existing:
        return new_status
    if not new_status:
        return existing
    existing_priority = OAUTH_CLEANUP_STATUS_PRIORITY.get(existing, 99)
    new_priority = OAUTH_CLEANUP_STATUS_PRIORITY.get(new_status, 99)
    return new_status if new_priority < existing_priority else existing


def _usage_index_key(value: Any) -> str:
    """Return a case-insensitive key for status indexes."""
    return str(value or "").strip().lower()


def _usage_accessor_index_keys(accessor: Any) -> set[str]:
    """Build lookup keys for a usage accessor/path without exposing its value."""
    raw = str(accessor or "").strip()
    if not raw or (not raw.endswith(".json") and "/" not in raw and "\\" not in raw):
        return set()

    variants = {raw, raw.replace("\\", "/")}
    try:
        path = Path(raw)
        if path.name:
            variants.add(path.name)
        if path.exists():
            resolved = str(path.resolve())
            variants.add(resolved)
            variants.add(resolved.replace("\\", "/"))
    except Exception:
        pass

    return {_usage_index_key(variant) for variant in variants if variant}


def _remember_usage_status(mapping: dict[str, str], key: Any, status: str) -> None:
    """Store a status in an index, preserving the most cleanup-relevant status."""
    normalized_key = _usage_index_key(key)
    if not normalized_key:
        return
    mapping[normalized_key] = _prefer_oauth_cleanup_status(
        mapping.get(normalized_key),
        status,
    )


def _usage_provider_from_filename(filename: str) -> str | None:
    """Extract a provider name from a usage_<provider>.json file."""
    match = re.fullmatch(r"usage_(.+)\.json", filename)
    if not match:
        return None
    return match.group(1).lower()


def _provider_quota_group_context(provider: str) -> tuple[frozenset[str], frozenset[str]]:
    """Return hidden and defined quota groups for status derivation."""
    try:
        _, provider_plugins = _ensure_providers_loaded()
        plugin_class = provider_plugins.get(provider)
        if not plugin_class:
            return frozenset(), frozenset()

        hidden_groups = frozenset(
            str(group) for group in (getattr(plugin_class, "hidden_quota_groups", None) or ())
        )
        model_quota_groups = getattr(plugin_class, "model_quota_groups", None) or {}
        if isinstance(model_quota_groups, dict):
            defined_groups = frozenset(str(group) for group in model_quota_groups.keys())
        else:
            defined_groups = frozenset(str(group) for group in model_quota_groups)
        return hidden_groups, defined_groups
    except Exception:
        return frozenset(), frozenset()


def _timestamp_is_future(value: Any, now: float) -> bool:
    """Return True when a serialized timestamp is still active."""
    try:
        return float(value or 0) > now
    except (TypeError, ValueError):
        return False


def _resolve_usage_credential_state_status(
    state: dict[str, Any],
    *,
    now: float,
    hidden_groups: frozenset[str],
    defined_groups: frozenset[str],
) -> str:
    """Resolve cleanup status from persisted usage/cooldown health state."""
    snapshot = state.get("status_snapshot")
    if isinstance(snapshot, dict) and snapshot.get("status"):
        return _normalize_oauth_status_value(snapshot["status"])

    health = state.get("credential_health") or state.get("health_block")
    if isinstance(health, dict):
        health_status = _normalize_oauth_status_value(health.get("status"))
        if bool(health.get("blocked")) and health_status == "needs_reauth":
            return "needs_reauth"

    cooldowns = state.get("cooldowns") or {}
    if not isinstance(cooldowns, dict):
        cooldowns = {}

    active_cooldowns = {
        str(key): cooldown
        for key, cooldown in cooldowns.items()
        if isinstance(cooldown, dict)
        and _timestamp_is_future(cooldown.get("until"), now)
    }
    if not active_cooldowns:
        return "active"

    if "_global_" in active_cooldowns:
        return "cooldown"

    cooldown_groups = set(active_cooldowns)
    if hidden_groups and cooldown_groups & hidden_groups:
        return "exhausted"

    group_usage = state.get("group_usage") or {}
    known_groups = set(str(group) for group in group_usage.keys()) if isinstance(group_usage, dict) else set()
    if defined_groups:
        known_groups &= defined_groups
    visible_known_groups = known_groups - hidden_groups if hidden_groups else known_groups

    if visible_known_groups and cooldown_groups >= visible_known_groups:
        return "exhausted"

    return "cooldown"


def _oauth_stable_id_from_payload(data: dict[str, Any]) -> str:
    """Build the OAuth stable ID used by usage storage from a credential payload."""
    metadata = data.get("_proxy_metadata", {}) if isinstance(data, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}

    stable = metadata.get("login") or metadata.get("email")
    if not stable:
        for field in ("login", "email", "client_email", "account"):
            if data.get(field):
                stable = data[field]
                break
    if not stable:
        return ""

    account_id = data.get("account_id") or metadata.get("account_id")
    return f"{stable}::{account_id}" if account_id else str(stable)


def _get_oauth_usage_status_index() -> dict[str, dict[str, dict[str, str]]]:
    """Load persisted usage statuses keyed by provider, stable ID, and accessor."""
    usage_dir = get_data_file("usage")
    if not usage_dir.exists() or not usage_dir.is_dir():
        return {}

    status_index: dict[str, dict[str, dict[str, str]]] = {}
    provider_contexts: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
    now = time.time()

    for usage_file in sorted(usage_dir.rglob("usage_*.json")):
        provider = _usage_provider_from_filename(usage_file.name)
        if not provider:
            continue

        try:
            with open(usage_file, "r", encoding="utf-8") as f:
                usage_data = json.load(f)
        except Exception:
            continue

        credentials = usage_data.get("credentials", {})
        if not isinstance(credentials, dict):
            continue

        hidden_groups, defined_groups = provider_contexts.setdefault(
            provider,
            _provider_quota_group_context(provider),
        )
        provider_index = status_index.setdefault(
            provider,
            {"stable_ids": {}, "accessors": {}, "filenames": {}},
        )

        for stable_id, state in credentials.items():
            if not isinstance(state, dict):
                continue

            status = _resolve_usage_credential_state_status(
                state,
                now=now,
                hidden_groups=hidden_groups,
                defined_groups=defined_groups,
            )
            _remember_usage_status(provider_index["stable_ids"], stable_id, status)

            accessor = state.get("accessor")
            for key in _usage_accessor_index_keys(accessor):
                _remember_usage_status(provider_index["accessors"], key, status)
            filename = (
                Path(str(accessor)).name
                if accessor and str(accessor).lower().endswith(".json")
                else ""
            )
            if filename:
                _remember_usage_status(provider_index["filenames"], filename, status)

        accessor_index = usage_data.get("accessor_index", {})
        if isinstance(accessor_index, dict):
            for accessor, stable_id in accessor_index.items():
                status = provider_index["stable_ids"].get(_usage_index_key(stable_id))
                if not status:
                    continue
                for key in _usage_accessor_index_keys(accessor):
                    _remember_usage_status(provider_index["accessors"], key, status)
                filename = (
                    Path(str(accessor)).name
                    if accessor and str(accessor).lower().endswith(".json")
                    else ""
                )
                if filename:
                    _remember_usage_status(provider_index["filenames"], filename, status)

    return status_index


def _lookup_oauth_usage_status(
    cred_info: dict[str, Any],
    usage_status_index: dict[str, dict[str, dict[str, str]]] | None,
    stable_id: str = "",
) -> str:
    """Find a persisted usage status for an OAuth credential, if available."""
    if not usage_status_index:
        return ""

    provider = str(cred_info.get("provider") or "").lower()
    provider_index = usage_status_index.get(provider)
    if not provider_index:
        return ""

    if stable_id:
        status = provider_index["stable_ids"].get(_usage_index_key(stable_id))
        if status:
            return status

    file_path = cred_info.get("file_path")
    for key in _usage_accessor_index_keys(file_path):
        status = provider_index["accessors"].get(key)
        if status:
            return status

    filename = _oauth_credential_filename(cred_info)
    if filename:
        status = provider_index["filenames"].get(_usage_index_key(filename))
        if status:
            return status

    return ""


def _resolve_oauth_credential_status(
    cred_info: dict[str, Any],
    usage_status_index: dict[str, dict[str, dict[str, str]]] | None = None,
) -> str:
    """Resolve an OAuth credential status from usage, health, or file metadata."""
    existing_status = _normalize_oauth_status_value(cred_info.get("status"))
    if existing_status and existing_status not in {"unknown", "error"}:
        return existing_status

    file_path = cred_info.get("file_path")
    if not file_path:
        return "unknown"

    local_status = ""
    stable_id = ""
    file_read_failed = False
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        metadata = data.get("_proxy_metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        local_status = _normalize_oauth_status_value(metadata.get("status"))
        stable_id = _oauth_stable_id_from_payload(data)
    except Exception:
        file_read_failed = True

    if local_status == "needs_reauth":
        return "needs_reauth"

    usage_status = _lookup_oauth_usage_status(
        cred_info,
        usage_status_index,
        stable_id=stable_id,
    )
    if local_status == "active" and usage_status == "needs_reauth":
        return "active"
    if usage_status:
        return usage_status

    if local_status:
        return local_status
    if file_read_failed:
        return "error"
    return "active"


def _oauth_credential_filename(cred_info: dict) -> str:
    """Return a stable filename for an OAuth credential info dict."""
    filename = cred_info.get("filename")
    if filename:
        return Path(str(filename)).name
    file_path = cred_info.get("file_path")
    return Path(str(file_path)).name if file_path else ""


def _get_oauth_credentials_summary() -> dict:
    """
    Get a summary of all OAuth credentials for all providers.

    Returns:
        Dict mapping provider names to lists of credential info dicts.
        Example: {"gemini_cli": [{"email": "user@example.com", "tier": "free-tier", ...}, ...]}
    """
    provider_factory, _ = _ensure_providers_loaded()
    oauth_providers = provider_factory.get_available_providers()
    oauth_summary = {}
    usage_status_index = _get_oauth_usage_status_index()

    for provider_name in oauth_providers:
        try:
            auth_class = provider_factory.get_provider_auth_class(provider_name)
            auth_instance = auth_class()
            credentials = auth_instance.list_credentials(_get_oauth_base_dir())
            for cred in credentials:
                cred.setdefault("provider", provider_name)
                cred.setdefault("filename", _oauth_credential_filename(cred))
                cred["status"] = _resolve_oauth_credential_status(
                    cred,
                    usage_status_index=usage_status_index,
                )
            oauth_summary[provider_name] = credentials
        except Exception:
            oauth_summary[provider_name] = []

    return oauth_summary


def _get_all_credentials_summary() -> dict:
    """
    Get a complete summary of all credentials (API keys and OAuth).

    Returns:
        Dict with "api_keys" and "oauth" sections containing credential summaries.
    """
    return {
        "api_keys": _get_api_keys_from_env(),
        "oauth": _get_oauth_credentials_summary(),
    }


def _normalize_oauth_cleanup_statuses(
    statuses: list[str] | tuple[str, ...] | None,
) -> set[str]:
    """Normalize user-selected cleanup statuses for OAuth credential filtering."""
    selected = statuses or DEFAULT_OAUTH_CLEANUP_STATUSES
    normalized = {
        str(status).strip().lower()
        for status in selected
        if str(status).strip()
    }
    return normalized or set(DEFAULT_OAUTH_CLEANUP_STATUSES)


def _credential_file_path_for_filename(filename: str) -> Path | None:
    """Resolve a credential filename under the OAuth base directory without allowing traversal."""
    if Path(filename).name != filename or "\\" in filename:
        return None

    base_dir = _get_oauth_base_dir()
    target = base_dir / filename
    try:
        if not target.resolve().is_relative_to(base_dir.resolve()):
            return None
    except OSError:
        return None
    return target


def _api_key_stable_id_from_value(key_value: str) -> str:
    """Return the usage stable ID for a raw API key without exposing the key."""
    return hashlib.sha256(key_value.encode()).hexdigest()[:12]


def _oauth_number_from_filename(filename: str) -> str:
    """Extract the numeric OAuth credential suffix from a credential filename."""
    match = re.fullmatch(r".+?_oauth_(\d+)\.json", filename)
    return match.group(1) if match else ""


def _read_oauth_stable_id_from_file(file_path: str) -> str:
    """Read an OAuth credential stable ID before the credential file is deleted."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return _oauth_stable_id_from_payload(data)
    except Exception:
        return ""


def _candidate_usage_cleanup_identity(candidate: dict[str, Any]) -> dict[str, Any]:
    """Build non-secret identity keys used to remove persisted usage leftovers."""
    provider = str(candidate.get("provider") or "").lower()
    stable_ids = {
        str(candidate.get("stable_id") or ""),
        str(candidate.get("usage_stable_id") or ""),
    }
    accessors = set(candidate.get("usage_accessors") or [])
    filenames = set(candidate.get("usage_filenames") or [])

    if candidate.get("type") == "oauth":
        file_path = str(candidate.get("file_path") or "")
        filename = str(candidate.get("filename") or (Path(file_path).name if file_path else ""))
        if file_path:
            accessors.add(file_path)
        if filename:
            filenames.add(filename)
            number = _oauth_number_from_filename(filename)
            if provider and number:
                accessors.add(f"env://{provider}/{number}")
        if not any(stable_ids) and file_path:
            stable_ids.add(_read_oauth_stable_id_from_file(file_path))

    return {
        "provider": provider,
        "stable_ids": {value for value in stable_ids if value},
        "accessors": {value for value in accessors if value},
        "filenames": {value for value in filenames if value},
    }


def _usage_cleanup_accessor_keys(values: set[str]) -> set[str]:
    """Return normalized accessor lookup keys for usage cleanup."""
    keys: set[str] = set()
    for value in values:
        keys.update(_usage_accessor_index_keys(value))
        if value:
            keys.add(_usage_index_key(value))
    return {key for key in keys if key}


def _usage_cleanup_filename_key(value: Any) -> str:
    """Return a normalized filename key for usage cleanup."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    return _usage_index_key(Path(raw).name)


def _usage_cleanup_matches_state(
    stable_id: str,
    state: dict[str, Any],
    *,
    stable_ids: set[str],
    accessors: set[str],
    filenames: set[str],
) -> bool:
    """Return True when a usage credential state belongs to a deleted credential."""
    if _usage_index_key(stable_id) in stable_ids:
        return True
    if _usage_accessor_index_keys(stable_id) & accessors:
        return True
    stable_id_filename = _usage_cleanup_filename_key(stable_id)
    if stable_id_filename and stable_id_filename in filenames:
        return True

    accessor = state.get("accessor") if isinstance(state, dict) else None
    if _usage_accessor_index_keys(accessor) & accessors:
        return True

    filename = _usage_cleanup_filename_key(accessor)
    return bool(filename and filename in filenames)


def _usage_cleanup_matches_accessor_index(
    accessor: str,
    stable_id: str,
    *,
    stable_ids: set[str],
    accessors: set[str],
    filenames: set[str],
) -> bool:
    """Return True when an accessor_index entry belongs to a deleted credential."""
    if _usage_index_key(stable_id) in stable_ids:
        return True
    if _usage_accessor_index_keys(stable_id) & accessors:
        return True
    stable_id_filename = _usage_cleanup_filename_key(stable_id)
    if stable_id_filename and stable_id_filename in filenames:
        return True
    if _usage_accessor_index_keys(accessor) & accessors:
        return True
    filename = _usage_cleanup_filename_key(accessor)
    return bool(filename and filename in filenames)


def _write_usage_file(path: Path, usage_data: dict[str, Any]) -> None:
    """Write a usage JSON file after local credential cleanup."""
    usage_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(usage_data, f, indent=2)
        f.write("\n")


def _cleanup_deleted_credential_usage(candidate: dict[str, Any]) -> dict[str, Any]:
    """Remove usage entries and accessor indexes for a deleted credential."""
    identity = _candidate_usage_cleanup_identity(candidate)
    provider = identity["provider"]
    if not provider:
        return {
            "success": False,
            "files_scanned": 0,
            "files_updated": 0,
            "removed_credentials": 0,
            "removed_accessors": 0,
            "leftovers": [],
            "errors": ["provider is required for usage cleanup"],
        }

    usage_dir = get_data_file("usage")
    if not usage_dir.exists() or not usage_dir.is_dir():
        return {
            "success": True,
            "files_scanned": 0,
            "files_updated": 0,
            "removed_credentials": 0,
            "removed_accessors": 0,
            "leftovers": [],
            "errors": [],
        }

    selected_stable_ids = {_usage_index_key(value) for value in identity["stable_ids"]}
    selected_accessors = _usage_cleanup_accessor_keys(identity["accessors"])
    selected_filenames = {
        _usage_cleanup_filename_key(value) for value in identity["filenames"]
    }
    selected_filenames = {value for value in selected_filenames if value}

    files_scanned = 0
    files_updated = 0
    removed_credentials = 0
    removed_accessors = 0
    leftovers: list[dict[str, str]] = []
    errors: list[str] = []

    for usage_file in sorted(usage_dir.rglob(f"usage_{provider}.json")):
        files_scanned += 1
        try:
            with open(usage_file, "r", encoding="utf-8") as f:
                usage_data = json.load(f)
        except Exception as exc:
            errors.append(f"{usage_file}: failed to read usage file ({exc})")
            continue

        if not isinstance(usage_data, dict):
            errors.append(f"{usage_file}: usage file root is not an object")
            continue

        changed = False
        removed_stable_ids: set[str] = set()
        credentials = usage_data.get("credentials", {})
        if isinstance(credentials, dict):
            for stable_id, state in list(credentials.items()):
                if not isinstance(state, dict):
                    continue
                if _usage_cleanup_matches_state(
                    stable_id,
                    state,
                    stable_ids=selected_stable_ids,
                    accessors=selected_accessors,
                    filenames=selected_filenames,
                ):
                    removed_stable_ids.add(_usage_index_key(stable_id))
                    credentials.pop(stable_id, None)
                    removed_credentials += 1
                    changed = True

        cleanup_stable_ids = selected_stable_ids | removed_stable_ids
        accessor_index = usage_data.get("accessor_index", {})
        if isinstance(accessor_index, dict):
            for accessor, stable_id in list(accessor_index.items()):
                if _usage_cleanup_matches_accessor_index(
                    accessor,
                    stable_id,
                    stable_ids=cleanup_stable_ids,
                    accessors=selected_accessors,
                    filenames=selected_filenames,
                ):
                    accessor_index.pop(accessor, None)
                    removed_accessors += 1
                    changed = True

        if changed:
            try:
                _write_usage_file(usage_file, usage_data)
                files_updated += 1
            except Exception as exc:
                errors.append(f"{usage_file}: failed to write usage cleanup ({exc})")
                continue

        credentials = usage_data.get("credentials", {})
        if isinstance(credentials, dict):
            for stable_id, state in credentials.items():
                if isinstance(state, dict) and _usage_cleanup_matches_state(
                    stable_id,
                    state,
                    stable_ids=selected_stable_ids,
                    accessors=selected_accessors,
                    filenames=selected_filenames,
                ):
                    leftovers.append(
                        {
                            "file": str(usage_file),
                            "section": "credentials",
                            "identifier": str(stable_id),
                        }
                    )

        accessor_index = usage_data.get("accessor_index", {})
        if isinstance(accessor_index, dict):
            for accessor, stable_id in accessor_index.items():
                if _usage_cleanup_matches_accessor_index(
                    accessor,
                    stable_id,
                    stable_ids=selected_stable_ids,
                    accessors=selected_accessors,
                    filenames=selected_filenames,
                ):
                    leftovers.append(
                        {
                            "file": str(usage_file),
                            "section": "accessor_index",
                            "identifier": str(accessor),
                        }
                    )

    return {
        "success": not errors and not leftovers,
        "files_scanned": files_scanned,
        "files_updated": files_updated,
        "removed_credentials": removed_credentials,
        "removed_accessors": removed_accessors,
        "leftovers": leftovers,
        "errors": errors,
    }


def _preview_oauth_cleanup_candidates(
    statuses: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """
    Preview OAuth credentials matching cleanup statuses without deleting anything.

    By default this returns credentials needing attention: needs_reauth, cooldown,
    and exhausted. Active credentials are skipped unless the caller explicitly
    includes active in ``statuses``.
    """
    selected_statuses = _normalize_oauth_cleanup_statuses(statuses)
    candidates = []

    oauth_summary = _get_oauth_credentials_summary()
    for provider, credentials in sorted(oauth_summary.items()):
        for credential in credentials or []:
            status = _resolve_oauth_credential_status(credential)
            if status not in selected_statuses:
                continue

            file_path = credential.get("file_path", "")
            filename = credential.get("filename") or (
                Path(file_path).name if file_path else ""
            )
            provider_name = str(credential.get("provider") or provider).lower()
            candidates.append(
                {
                    "type": "oauth",
                    "provider": provider_name,
                    "identifier": filename,
                    "filename": filename,
                    "file_path": str(file_path),
                    "email": credential.get("email", "unknown"),
                    "status": status,
                }
            )

    return {
        "statuses": sorted(selected_statuses),
        "candidates": candidates,
        "total": len(candidates),
    }


def _validate_batch_delete_item(
    item: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Validate one selected credential for batch deletion."""
    item_type = str(item.get("type", "")).lower()
    provider = str(item.get("provider", "")).lower()
    if item_type not in {"api_key", "oauth"}:
        return None, {
            "type": item_type or "unknown",
            "provider": provider,
            "identifier": str(item.get("key_name") or item.get("filename") or ""),
            "detail": "type must be api_key or oauth",
        }

    if item_type == "api_key":
        key_name = str(item.get("key_name") or "")
        env_keys = _get_api_keys_from_env()
        key_value = None
        key_provider = _api_key_provider_from_name(key_name)
        if not key_name:
            detail = "key_name is required for API key deletion"
        elif key_provider != provider:
            detail = f"API key {key_name} does not belong to provider {provider}"
        else:
            for discovered_provider, provider_keys in env_keys.items():
                if discovered_provider.lower() != provider:
                    continue
                for discovered_name, discovered_value in provider_keys:
                    if discovered_name == key_name:
                        key_value = discovered_value
                        break
        if key_value is None:
            detail = locals().get("detail", f"Key {key_name} not found")
            return None, {
                "type": item_type,
                "provider": provider,
                "identifier": key_name,
                "detail": detail,
            }
        return {
            "type": item_type,
            "provider": provider,
            "identifier": key_name,
            "key_name": key_name,
            "stable_id": _api_key_stable_id_from_value(key_value),
        }, None

    filename = str(item.get("filename") or "")
    target = _credential_file_path_for_filename(filename)
    provided_path = Path(str(item["file_path"])) if item.get("file_path") else None
    file_provider = _oauth_provider_from_filename(filename)
    if not filename:
        detail = "filename is required for OAuth deletion"
    elif file_provider != provider:
        detail = f"OAuth credential {filename} does not belong to provider {provider}"
    elif target is None or not target.exists() or not target.is_file():
        detail = "OAuth credential not found"
    elif provided_path and provided_path.resolve() != target.resolve():
        detail = "file_path does not match the configured OAuth credential directory"
    else:
        stable_id = _read_oauth_stable_id_from_file(str(target))
        usage_accessors = [str(target)]
        credential_number = _oauth_number_from_filename(filename)
        if credential_number:
            usage_accessors.append(f"env://{provider}/{credential_number}")
        return {
            "type": item_type,
            "provider": provider,
            "identifier": filename,
            "filename": filename,
            "file_path": str(target),
            "stable_id": stable_id,
            "usage_accessors": usage_accessors,
            "usage_filenames": [filename],
        }, None

    return None, {
        "type": item_type,
        "provider": provider,
        "identifier": filename,
        "detail": detail,
    }


def _delete_oauth_credential_file(provider: str, file_path: str) -> bool:
    """Delete an OAuth credential via the provider auth class when available."""
    try:
        provider_factory, _ = _ensure_providers_loaded()
        auth_class = provider_factory.get_provider_auth_class(provider)
        auth_instance = auth_class()
        return bool(auth_instance.delete_credential(file_path))
    except Exception:
        try:
            path = Path(file_path)
            if not path.exists() or _oauth_provider_from_filename(path.name) != provider:
                return False
            path.unlink()
            return True
        except Exception:
            return False


def _batch_delete_selected_credentials(
    items: list[dict[str, Any]],
    *,
    dry_run: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Validate and optionally delete selected API key/OAuth credentials.

    Dry-run mode returns candidates and errors without mutating .env or OAuth files.
    Execution requires ``confirm=True`` to make irreversible local deletions explicit.
    """
    candidates = []
    errors = []
    seen: set[tuple[str, str, str]] = set()

    for item in items:
        candidate, error = _validate_batch_delete_item(item)
        if error:
            errors.append(error)
            continue
        if not candidate:
            continue

        duplicate_key = (candidate["type"], candidate["provider"], candidate["identifier"])
        if duplicate_key in seen:
            errors.append(
                {
                    **candidate,
                    "detail": "Duplicate credential in request",
                }
            )
            continue
        seen.add(duplicate_key)
        candidates.append(candidate)

    if dry_run:
        return {
            "dry_run": True,
            "candidates": candidates,
            "deleted": [],
            "errors": errors,
        }

    if not confirm:
        return {
            "dry_run": False,
            "candidates": candidates,
            "deleted": [],
            "errors": [
                *errors,
                {
                    "type": "batch",
                    "provider": "",
                    "identifier": "",
                    "detail": "confirm must be true to delete credentials",
                },
            ],
        }

    if errors:
        return {
            "dry_run": False,
            "candidates": candidates,
            "deleted": [],
            "errors": errors,
        }

    deleted = []
    execution_errors = []
    for candidate in candidates:
        if candidate["type"] == "api_key":
            if _delete_api_key_from_env(candidate["key_name"]):
                usage_cleanup = _cleanup_deleted_credential_usage(candidate)
                deleted.append({**candidate, "usage_cleanup": usage_cleanup})
                if not usage_cleanup["success"]:
                    execution_errors.append(
                        {
                            **candidate,
                            "detail": "Deleted API key, but usage cleanup left leftovers",
                            "usage_cleanup": usage_cleanup,
                        }
                    )
            else:
                execution_errors.append(
                    {
                        **candidate,
                        "detail": "Failed to delete API key",
                    }
                )
        else:
            if _delete_oauth_credential_file(
                candidate["provider"],
                candidate["file_path"],
            ):
                usage_cleanup = _cleanup_deleted_credential_usage(candidate)
                deleted.append({**candidate, "usage_cleanup": usage_cleanup})
                if not usage_cleanup["success"]:
                    execution_errors.append(
                        {
                            **candidate,
                            "detail": "Deleted OAuth credential, but usage cleanup left leftovers",
                            "usage_cleanup": usage_cleanup,
                        }
                    )
            else:
                execution_errors.append(
                    {
                        **candidate,
                        "detail": "Failed to delete OAuth credential",
                    }
                )

    return {
        "dry_run": False,
        "candidates": candidates,
        "deleted": deleted,
        "errors": execution_errors,
    }


def _get_existing_custom_providers() -> list:
    """
    Scan the .env file for existing custom OpenAI-compatible providers.

    Custom providers are identified by *_API_BASE entries where the provider
    name is NOT a known LiteLLM provider.

    Returns:
        List of dicts with provider info:
        [{"name": "myserver", "api_base": "http://...", "has_key": True}, ...]
    """
    from .provider_config import KNOWN_PROVIDERS

    custom_providers = []
    env_file = _get_env_file()

    if not env_file.is_file():
        return custom_providers

    try:
        # First pass: collect all _API_BASE entries
        api_bases = {}
        api_keys = set()

        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "=" not in line:
                    continue

                key_name, _, value = line.partition("=")
                key_name = key_name.strip()
                value = value.strip().strip('"').strip("'")

                if key_name.endswith("_API_BASE") and value:
                    provider_name = key_name[:-9].lower()  # Remove _API_BASE
                    # Only include if NOT a known provider
                    if provider_name not in KNOWN_PROVIDERS:
                        api_bases[provider_name] = value
                elif "_API_KEY" in key_name and value:
                    # Extract provider name from API key
                    provider_prefix = key_name.split("_API_KEY")[0].lower()
                    api_keys.add(provider_prefix)

        # Build result list
        for provider_name, api_base in sorted(api_bases.items()):
            custom_providers.append(
                {
                    "name": provider_name,
                    "api_base": api_base,
                    "has_key": provider_name in api_keys,
                }
            )

    except Exception as e:
        console.print(f"[bold red]Error reading .env file: {e}[/bold red]")

    return custom_providers


def _display_custom_providers_summary():
    """
    Display a summary of existing custom OpenAI-compatible providers.
    """
    custom_providers = _get_existing_custom_providers()

    if not custom_providers:
        console.print(
            "[dim]No custom OpenAI-compatible providers configured yet.[/dim]\n"
        )
        return

    table = Table(
        title="Existing Custom Providers",
        box=None,
        padding=(0, 2),
        title_style="bold cyan",
    )
    table.add_column("Provider", style="yellow", no_wrap=True)
    table.add_column("API Base", style="dim")
    table.add_column("API Key", style="green", justify="center")

    for provider in custom_providers:
        name = provider["name"].upper()
        api_base = provider["api_base"]
        # Truncate long URLs
        if len(api_base) > 40:
            api_base = api_base[:37] + "..."
        has_key = "✓" if provider["has_key"] else "✗"
        key_style = "green" if provider["has_key"] else "red"
        table.add_row(name, api_base, Text(has_key, style=key_style))

    console.print(table)
    console.print()


def _display_credentials_summary():
    """
    Display a compact 2-column summary of all configured credentials.
    API Keys on the left, OAuth credentials on the right.
    Handles cases where only one type exists or neither.
    """
    from rich.columns import Columns

    summary = _get_all_credentials_summary()
    api_keys = summary["api_keys"]
    oauth_creds = summary["oauth"]

    # Calculate totals
    total_api_keys = sum(len(keys) for keys in api_keys.values())
    total_oauth = sum(len(creds) for creds in oauth_creds.values() if creds)

    # Handle empty case
    if total_api_keys == 0 and total_oauth == 0:
        console.print("[dim]No credentials configured yet.[/dim]\n")
        return

    # Build API Keys table (left column)
    api_table = None
    if total_api_keys > 0:
        api_table = Table(
            title="API Keys", box=None, padding=(0, 1), title_style="bold cyan"
        )
        api_table.add_column("Provider", style="yellow", no_wrap=True)
        api_table.add_column("Count", style="green", justify="right")

        for provider, keys in sorted(api_keys.items()):
            api_table.add_row(provider, str(len(keys)))

        # Add total row
        api_table.add_row("─" * 12, "─" * 5, style="dim")
        api_table.add_row("Total", str(total_api_keys), style="bold")

    # Build OAuth table (right column)
    oauth_table = None
    if total_oauth > 0:
        oauth_table = Table(
            title="OAuth Credentials", box=None, padding=(0, 1), title_style="bold cyan"
        )
        oauth_table.add_column("Provider", style="yellow", no_wrap=True)
        oauth_table.add_column("Count", style="green", justify="right")
        oauth_table.add_column("Tiers", style="dim", no_wrap=True)

        for provider, creds in sorted(oauth_creds.items()):
            if not creds:
                continue
            display_name = OAUTH_FRIENDLY_NAMES.get(provider, provider.title())
            count = len(creds)

            # Count and format tiers for providers that have tier info
            tier_counts = _count_tiers(creds)
            tier_str = _format_tier_counts(tier_counts)

            oauth_table.add_row(display_name, str(count), tier_str)

        # Add total row
        oauth_table.add_row("─" * 12, "─" * 5, "", style="dim")
        oauth_table.add_row("Total", str(total_oauth), "", style="bold")

    # Display based on what's available
    if api_table and oauth_table:
        # Both columns - use Columns for side-by-side layout
        console.print(Columns([api_table, oauth_table], padding=(0, 4), expand=False))
    elif api_table:
        # Only API keys
        console.print(api_table)
    elif oauth_table:
        # Only OAuth
        console.print(oauth_table)

    console.print("")  # Blank line after summary


def _display_oauth_providers_summary():
    """
    Display a compact summary of OAuth providers only (used when adding OAuth credentials).
    """
    oauth_summary = _get_oauth_credentials_summary()

    total = sum(len(creds) for creds in oauth_summary.values())

    # Build compact table
    table = Table(
        title="Current OAuth Credentials",
        box=None,
        padding=(0, 1),
        title_style="bold cyan",
    )
    table.add_column("Provider", style="yellow", no_wrap=True)
    table.add_column("Count", style="green", justify="right")

    for provider, creds in sorted(oauth_summary.items()):
        display_name = OAUTH_FRIENDLY_NAMES.get(provider, provider.title())
        table.add_row(display_name, str(len(creds)))

    if total > 0:
        table.add_row("─" * 12, "─" * 5, style="dim")
        table.add_row("Total", str(total), style="bold")

    console.print(table)
    console.print("")


def _display_provider_credentials(provider_name: str):
    """
    Display all credentials for a specific OAuth provider.

    Args:
        provider_name: The provider key (e.g., "gemini_cli")
    """
    provider_factory, _ = _ensure_providers_loaded()

    try:
        auth_class = provider_factory.get_provider_auth_class(provider_name)
        auth_instance = auth_class()
        credentials = auth_instance.list_credentials(_get_oauth_base_dir())
    except Exception:
        credentials = []

    display_name = OAUTH_FRIENDLY_NAMES.get(provider_name, provider_name.title())

    if not credentials:
        console.print(f"\n[dim]No existing credentials for {display_name}[/dim]\n")
        return

    console.print(f"\n[bold cyan]Existing {display_name} Credentials:[/bold cyan]")

    table = Table(box=None, padding=(0, 2))
    table.add_column("#", style="dim", width=3)
    table.add_column("File", style="yellow")
    table.add_column("Email/Identifier", style="cyan")

    # Add tier/project columns for Google OAuth providers
    if provider_name == "gemini_cli":
        table.add_column("Tier", style="green")
        table.add_column("Project", style="dim")
    elif provider_name == "codex":
        table.add_column("Workspace", style="green")
        table.add_column("Plan", style="magenta")
        table.add_column("Account ID", style="dim")

    for i, cred in enumerate(credentials, 1):
        file_name = Path(cred["file_path"]).name
        email = cred.get("email", "unknown")

        if provider_name == "gemini_cli":
            tier = cred.get("tier", "-")
            project = cred.get("project_id", "-")
            if project and len(project) > 20:
                project = project[:17] + "..."
            table.add_row(str(i), file_name, email, tier or "-", project or "-")
        elif provider_name == "codex":
            workspace = cred.get("workspace_title", "-") or "-"
            plan = cred.get("plan_type", "-") or "-"
            account_id = cred.get("account_id", "-") or "-"
            if account_id and len(account_id) > 12 and account_id != "-":
                account_id = account_id[:8] + "..."
            table.add_row(str(i), file_name, email, workspace, plan, account_id)
        else:
            table.add_row(str(i), file_name, email)

    console.print(table)
    console.print("")


async def _edit_oauth_credential_email(provider_name: str):
    """
    Edit the email field of an OAuth credential.

    Args:
        provider_name: The provider key (e.g., "gemini_cli")
    """
    provider_factory, _ = _ensure_providers_loaded()

    try:
        auth_class = provider_factory.get_provider_auth_class(provider_name)
        auth_instance = auth_class()
        credentials = auth_instance.list_credentials(_get_oauth_base_dir())
    except Exception as e:
        console.print(f"[bold red]Error loading credentials: {e}[/bold red]")
        return

    display_name = OAUTH_FRIENDLY_NAMES.get(provider_name, provider_name.title())

    if not credentials:
        console.print(
            f"[bold yellow]No {display_name} credentials found.[/bold yellow]"
        )
        return

    # Display credentials for selection
    _display_provider_credentials(provider_name)

    choice = Prompt.ask(
        Text.from_markup(
            "[bold]Select credential to edit or type [red]'b'[/red] to go back[/bold]"
        ),
        choices=[str(i) for i in range(1, len(credentials) + 1)] + ["b"],
        show_choices=False,
    )

    if choice.lower() == "b":
        return

    try:
        idx = int(choice) - 1
        cred_info = credentials[idx]
        cred_path = cred_info["file_path"]
        current_email = cred_info.get("email", "unknown")

        console.print(f"\nCurrent email: [cyan]{current_email}[/cyan]")
        new_email = Prompt.ask("Enter new email/identifier")

        if not new_email.strip():
            console.print("[bold yellow]No changes made (empty input).[/bold yellow]")
            return

        # Load and update the credential file
        with open(cred_path, "r") as f:
            creds = json.load(f)

        if "_proxy_metadata" not in creds:
            creds["_proxy_metadata"] = {}

        old_email = creds["_proxy_metadata"].get("email")
        creds["_proxy_metadata"]["email"] = new_email.strip()

        # Save the updated credentials
        with open(cred_path, "w") as f:
            json.dump(creds, f, indent=2)

        console.print(
            Panel(
                f"Email updated from [yellow]'{old_email}'[/yellow] to [green]'{new_email.strip()}'[/green]",
                style="bold green",
                title="Success",
                expand=False,
            )
        )

    except Exception as e:
        console.print(f"[bold red]Error editing credential: {e}[/bold red]")


async def view_credentials_menu():
    """
    Menu for viewing credentials. Shows summary first, then allows drilling
    down to view detailed credentials for a specific provider.
    """
    while True:
        clear_screen("View Credentials")

        # Display summary
        _display_credentials_summary()

        # Build list of all providers with credentials
        api_keys = _get_api_keys_from_env()
        oauth_creds = _get_oauth_credentials_summary()

        all_providers = []

        # Add API key providers
        for provider in sorted(api_keys.keys()):
            count = len(api_keys[provider])
            all_providers.append(("api", provider, count))

        # Add OAuth providers with credentials
        for provider in sorted(oauth_creds.keys()):
            if oauth_creds[provider]:
                count = len(oauth_creds[provider])
                display_name = OAUTH_FRIENDLY_NAMES.get(provider, provider.title())
                all_providers.append(("oauth", provider, count, display_name))

        if not all_providers:
            console.print("[bold yellow]No credentials configured.[/bold yellow]")
            console.print("\n[dim]Press Enter to return to main menu...[/dim]")
            input()
            break

        # Display provider selection menu
        console.print(
            Panel(
                Text.from_markup("[bold]Select a provider to view details:[/bold]"),
                title="View Provider Credentials",
                style="bold blue",
            )
        )

        for i, provider_info in enumerate(all_providers, 1):
            if provider_info[0] == "api":
                _, provider, count = provider_info
                console.print(f"  {i}. [cyan]API:[/cyan] {provider} ({count} key(s))")
            else:
                _, provider, count, display_name = provider_info
                console.print(
                    f"  {i}. [cyan]OAuth:[/cyan] {display_name} ({count} credential(s))"
                )

        choice = Prompt.ask(
            Text.from_markup(
                "\n[bold]Select provider or type [red]'b'[/red] to go back[/bold]"
            ),
            choices=[str(i) for i in range(1, len(all_providers) + 1)] + ["b"],
            show_choices=False,
        )

        if choice.lower() == "b":
            break

        try:
            idx = int(choice) - 1
            provider_info = all_providers[idx]

            if provider_info[0] == "api":
                _, provider, _ = provider_info
                await _view_api_keys_detail(provider)
            else:
                _, provider, _, _ = provider_info
                await _view_oauth_credentials_detail(provider)

        except (ValueError, IndexError):
            console.print("[bold red]Invalid choice.[/bold red]")
            await asyncio.sleep(1)


async def _view_api_keys_detail(provider_name: str):
    """Display detailed view of API keys for a specific provider."""
    clear_screen(f"View {provider_name} API Keys")

    api_keys = _get_api_keys_from_env()
    keys = api_keys.get(provider_name, [])

    if not keys:
        console.print(
            f"[bold yellow]No API keys found for {provider_name}.[/bold yellow]"
        )
        console.print("\n[dim]Press Enter to go back...[/dim]")
        input()
        return

    # Display detailed table
    table = Table(title=f"{provider_name} API Keys", box=None, padding=(0, 2))
    table.add_column("#", style="dim", width=4)
    table.add_column("Key Name", style="yellow")
    table.add_column("Value (masked)", style="dim")

    for i, (key_name, key_value) in enumerate(keys, 1):
        masked = f"****{key_value[-4:]}" if len(key_value) > 4 else "****"
        table.add_row(str(i), key_name, masked)

    console.print(table)
    console.print(f"\n[dim]Total: {len(keys)} key(s)[/dim]")
    console.print("\n[dim]Press Enter to go back...[/dim]")
    input()


async def _view_oauth_credentials_detail(provider_name: str):
    """Display detailed view of OAuth credentials for a specific provider."""
    display_name = OAUTH_FRIENDLY_NAMES.get(provider_name, provider_name.title())
    clear_screen(f"View {display_name} Credentials")

    provider_factory, _ = _ensure_providers_loaded()

    try:
        auth_class = provider_factory.get_provider_auth_class(provider_name)
        auth_instance = auth_class()
        credentials = auth_instance.list_credentials(_get_oauth_base_dir())
    except Exception:
        credentials = []

    if not credentials:
        console.print(
            f"[bold yellow]No credentials found for {display_name}.[/bold yellow]"
        )
        console.print("\n[dim]Press Enter to go back...[/dim]")
        input()
        return

    # Display detailed table
    table = Table(title=f"{display_name} Credentials", box=None, padding=(0, 2))
    table.add_column("#", style="dim", width=4)
    table.add_column("File", style="yellow")
    table.add_column("Email/Identifier", style="cyan")

    # Add tier/project columns for Google OAuth providers
    if provider_name == "gemini_cli":
        table.add_column("Tier", style="green")
        table.add_column("Project", style="dim")
    elif provider_name == "codex":
        table.add_column("Workspace", style="green")
        table.add_column("Plan", style="magenta")
        table.add_column("Account ID", style="dim")

    for i, cred in enumerate(credentials, 1):
        file_name = Path(cred["file_path"]).name
        email = cred.get("email", "unknown")

        if provider_name == "gemini_cli":
            tier = (
                format_tier_for_display(cred.get("tier")) if cred.get("tier") else "-"
            )
            project = cred.get("project_id", "-")
            if project and len(project) > 25:
                project = project[:22] + "..."
            table.add_row(str(i), file_name, email, tier, project or "-")
        elif provider_name == "codex":
            workspace = cred.get("workspace_title", "-") or "-"
            plan = cred.get("plan_type", "-") or "-"
            account_id = cred.get("account_id", "-") or "-"
            if account_id and len(account_id) > 12 and account_id != "-":
                account_id = account_id[:8] + "..."
            table.add_row(str(i), file_name, email, workspace, plan, account_id)
        else:
            table.add_row(str(i), file_name, email)

    console.print(table)
    console.print(f"\n[dim]Total: {len(credentials)} credential(s)[/dim]")
    console.print("\n[dim]Press Enter to go back...[/dim]")
    input()


def _display_batch_delete_candidates(
    candidates: list[dict[str, Any]],
    *,
    title: str = "Credential Deletion Candidates",
) -> None:
    """Display batch deletion candidates without exposing raw credential secrets."""
    if not candidates:
        console.print(
            "[bold yellow]No credential deletion candidates found.[/bold yellow]"
        )
        return

    table = Table(title=title, box=None, padding=(0, 2))
    table.add_column("#", style="dim", width=4)
    table.add_column("Type", style="cyan")
    table.add_column("Provider", style="cyan")
    table.add_column("Identifier", style="yellow")
    table.add_column("Email/Status", style="green")

    for i, candidate in enumerate(candidates, 1):
        provider_name = str(candidate.get("provider", "unknown"))
        provider = OAUTH_FRIENDLY_NAMES.get(provider_name, provider_name.title())
        if candidate.get("type") == "api_key":
            extra = candidate.get("masked_value", "masked")
        else:
            status = candidate.get("status", "unknown")
            email = candidate.get("email", "unknown")
            extra = f"{email} / {status}"
        table.add_row(
            str(i),
            candidate.get("type", "unknown"),
            provider,
            candidate.get("identifier", ""),
            extra,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(candidates)} credential(s)[/dim]")


def _display_oauth_cleanup_candidates(
    candidates: list[dict[str, Any]],
    *,
    title: str = "OAuth Cleanup Candidates",
) -> None:
    """Display OAuth cleanup candidates without exposing raw credential secrets."""
    _display_batch_delete_candidates(candidates, title=title)


def _all_batch_delete_candidates() -> list[dict[str, Any]]:
    """Build a selectable list of all API-key and OAuth credentials."""
    candidates: list[dict[str, Any]] = []
    for provider, keys in sorted(_get_api_keys_from_env().items()):
        for key_name, key_value in keys:
            masked = f"****{key_value[-4:]}" if len(key_value) > 4 else "****"
            candidates.append(
                {
                    "type": "api_key",
                    "provider": provider.lower(),
                    "identifier": key_name,
                    "key_name": key_name,
                    "masked_value": masked,
                }
            )

    oauth_summary = _get_oauth_credentials_summary()
    for provider, credentials in sorted(oauth_summary.items()):
        for credential in credentials or []:
            file_path = credential.get("file_path", "")
            filename = credential.get("filename") or (
                Path(file_path).name if file_path else ""
            )
            candidates.append(
                {
                    "type": "oauth",
                    "provider": str(credential.get("provider") or provider).lower(),
                    "identifier": filename,
                    "filename": filename,
                    "file_path": str(file_path),
                    "email": credential.get("email", "unknown"),
                    "status": _resolve_oauth_credential_status(credential),
                }
            )
    return candidates


def _batch_delete_item_from_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    """Convert a display candidate to the helper input shape."""
    if candidate.get("type") == "api_key":
        return {
            "type": "api_key",
            "provider": candidate["provider"],
            "key_name": candidate["key_name"],
        }
    return {
        "type": "oauth",
        "provider": candidate["provider"],
        "filename": candidate["filename"],
        "file_path": candidate["file_path"],
    }



def _prompt_oauth_cleanup_statuses() -> list[str]:
    """Prompt for OAuth cleanup statuses, defaulting to non-active cleanup states."""
    console.print("\n[bold cyan]Cleanup statuses:[/bold cyan]")
    for i, status in enumerate(OAUTH_CLEANUP_STATUS_CHOICES, 1):
        default_marker = (
            " [dim](default)[/dim]"
            if status in DEFAULT_OAUTH_CLEANUP_STATUSES
            else ""
        )
        warning = " [yellow](active)[/yellow]" if status == "active" else ""
        console.print(f"  {i}. {status}{default_marker}{warning}")

    default_value = "1,2,3"
    raw = Prompt.ask(
        "Select status numbers or names, comma-separated",
        default=default_value,
        show_default=True,
    )
    selected = []
    status_by_number = {
        str(i): status for i, status in enumerate(OAUTH_CLEANUP_STATUS_CHOICES, 1)
    }
    valid_statuses = set(OAUTH_CLEANUP_STATUS_CHOICES)
    for part in raw.split(","):
        value = part.strip().lower()
        if not value:
            continue
        if value in status_by_number:
            selected.append(status_by_number[value])
        elif value in valid_statuses:
            selected.append(value)
        else:
            console.print(f"[yellow]Ignoring unknown status: {value}[/yellow]")

    return selected or list(DEFAULT_OAUTH_CLEANUP_STATUSES)


def _parse_oauth_cleanup_candidate_selection(
    selection: str,
    candidate_count: int,
) -> list[int] | None:
    """Parse comma-separated one-based candidate selections into zero-based indexes."""
    value = selection.strip().lower()
    if value == "b":
        return None
    if value == "all":
        return list(range(candidate_count))

    indexes = []
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        if not item.isdigit():
            return []
        index = int(item) - 1
        if index < 0 or index >= candidate_count:
            return []
        if index not in indexes:
            indexes.append(index)
    return indexes


async def _preview_oauth_cleanup_menu():
    """Interactive preview for OAuth cleanup candidates by selected status."""
    clear_screen("Preview OAuth Cleanup Candidates")
    statuses = _prompt_oauth_cleanup_statuses()
    result = _preview_oauth_cleanup_candidates(statuses=statuses)
    _display_oauth_cleanup_candidates(result["candidates"])
    console.print("\n[dim]Preview only: no files were deleted.[/dim]")


async def _batch_delete_credentials_menu():
    """Interactive dry-run plus confirmed execution for selected credentials."""
    clear_screen("Batch Delete Selected Credentials")

    console.print(
        Panel(
            Text.from_markup(
                "[bold]Batch options:[/bold]\n"
                "1. OAuth cleanup candidates by status\n"
                "2. All API keys and OAuth credentials"
            ),
            title="Batch Delete Source",
            style="bold blue",
        )
    )
    source = Prompt.ask(
        "Select source or type 'b' to go back",
        choices=["1", "2", "b"],
        show_choices=False,
    )
    if source.lower() == "b":
        return

    if source == "1":
        statuses = _prompt_oauth_cleanup_statuses()
        preview = _preview_oauth_cleanup_candidates(statuses=statuses)
        candidates = preview["candidates"]
    else:
        candidates = _all_batch_delete_candidates()

    _display_batch_delete_candidates(candidates)
    if not candidates:
        return

    selection = Prompt.ask(
        "Select candidate numbers to delete, 'all', or 'b' to go back",
        default="all",
        show_default=True,
    )
    indexes = _parse_oauth_cleanup_candidate_selection(selection, len(candidates))
    if indexes is None:
        console.print("[dim]Batch deletion cancelled.[/dim]")
        return
    if not indexes:
        console.print("[bold red]Invalid selection. No credentials deleted.[/bold red]")
        return

    selected_candidates = [candidates[index] for index in indexes]
    items = [
        _batch_delete_item_from_candidate(candidate)
        for candidate in selected_candidates
    ]
    dry_run_result = _batch_delete_selected_credentials(items, dry_run=True)

    console.print("\n[bold cyan]Dry-run result:[/bold cyan]")
    _display_batch_delete_candidates(
        dry_run_result["candidates"],
        title="Selected Credentials",
    )
    if dry_run_result["errors"]:
        console.print("[bold red]Errors found; nothing was deleted:[/bold red]")
        for error in dry_run_result["errors"]:
            console.print(
                f"  • {error.get('identifier', 'unknown')}: {error['detail']}"
            )
        return

    console.print(
        "\n[yellow]This deletes local credential entries/files only; "
        "it does not revoke tokens upstream.[/yellow]"
    )
    confirmed = Confirm.ask(
        f"Delete {len(selected_candidates)} selected credential(s)?",
        default=False,
    )
    if not confirmed:
        console.print("[dim]Batch deletion cancelled after dry-run.[/dim]")
        return

    result = _batch_delete_selected_credentials(items, dry_run=False, confirm=True)
    if result["deleted"] and not result["errors"]:
        console.print(
            Panel(
                f"Deleted {len(result['deleted'])} credential(s).",
                style="bold green",
                title="Success",
                expand=False,
            )
        )
    else:
        console.print("[bold red]Batch deletion completed with errors:[/bold red]")
        for error in result["errors"]:
            console.print(
                f"  • {error.get('identifier', 'unknown')}: {error['detail']}"
            )


async def manage_credentials_submenu():
    """
    Submenu for viewing and managing all credentials (API keys and OAuth).
    Allows deletion of any credential and editing email for OAuth credentials.
    """
    while True:
        clear_screen("Manage Credentials")

        # Display full summary
        _display_credentials_summary()

        console.print(
            Panel(
                Text.from_markup(
                    "[bold]Actions:[/bold]\n"
                    "1. Delete an API Key\n"
                    "2. Delete an OAuth Credential\n"
                    "3. Edit OAuth Credential Email\n"
                    "4. Preview OAuth Cleanup Candidates\n"
                    "5. Batch Delete Selected Credentials"
                ),
                title="Choose action",
                style="bold blue",
            )
        )

        action = Prompt.ask(
            Text.from_markup(
                "[bold]Select an option or type [red]'b'[/red] to go back[/bold]"
            ),
            choices=["1", "2", "3", "4", "5", "b"],
            show_choices=False,
        )

        if action.lower() == "b":
            break

        if action == "1":
            # Delete API Key
            await _delete_api_key_menu()
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()

        elif action == "2":
            # Delete OAuth Credential
            await _delete_oauth_credential_menu()
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()

        elif action == "3":
            # Edit OAuth Credential Email
            await _edit_oauth_credential_menu()
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()

        elif action == "4":
            await _preview_oauth_cleanup_menu()
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()

        elif action == "5":
            await _batch_delete_credentials_menu()
            console.print("\n[dim]Press Enter to continue...[/dim]")
            input()


async def _delete_api_key_menu():
    """Menu for deleting an API key from the .env file."""
    clear_screen("Delete API Key")
    api_keys = _get_api_keys_from_env()

    if not api_keys:
        console.print("[bold yellow]No API keys configured.[/bold yellow]")
        return

    # Build a flat list of all keys for selection
    all_keys = []
    console.print("\n[bold cyan]Configured API Keys:[/bold cyan]")

    table = Table(box=None, padding=(0, 2))
    table.add_column("#", style="dim", width=3)
    table.add_column("Key Name", style="yellow")
    table.add_column("Provider", style="cyan")
    table.add_column("Value", style="dim")

    idx = 1
    for provider, keys in sorted(api_keys.items()):
        for key_name, key_value in keys:
            masked = f"****{key_value[-4:]}" if len(key_value) > 4 else "****"
            table.add_row(str(idx), key_name, provider, masked)
            all_keys.append((key_name, key_value, provider))
            idx += 1

    console.print(table)

    choice = Prompt.ask(
        Text.from_markup(
            "\n[bold]Select API key to delete or type [red]'b'[/red] to go back[/bold]"
        ),
        choices=[str(i) for i in range(1, len(all_keys) + 1)] + ["b"],
        show_choices=False,
    )

    if choice.lower() == "b":
        return

    try:
        idx = int(choice) - 1
        key_name, key_value, provider = all_keys[idx]

        # Confirmation prompt
        masked = f"****{key_value[-4:]}" if len(key_value) > 4 else "****"
        confirmed = Confirm.ask(
            f"[bold red]Delete[/bold red] [yellow]{key_name}[/yellow] ({masked})?"
        )

        if not confirmed:
            console.print("[dim]Deletion cancelled.[/dim]")
            return

        result = _batch_delete_selected_credentials(
            [
                {
                    "type": "api_key",
                    "provider": str(provider).lower(),
                    "key_name": key_name,
                }
            ],
            dry_run=False,
            confirm=True,
        )
        if result["deleted"] and not result["errors"]:
            console.print(
                Panel(
                    f"Successfully deleted [yellow]{key_name}[/yellow] and cleaned usage data",
                    style="bold green",
                    title="Success",
                    expand=False,
                )
            )
        elif result["deleted"]:
            console.print(
                Panel(
                    f"Deleted [yellow]{key_name}[/yellow], but usage cleanup reported errors",
                    style="bold red",
                    title="Partial Cleanup",
                    expand=False,
                )
            )
            for error in result["errors"]:
                console.print(f"  • {error.get('detail', 'Unknown cleanup error')}")
        else:
            console.print(
                Panel(
                    f"Failed to delete [yellow]{key_name}[/yellow]",
                    style="bold red",
                    title="Error",
                    expand=False,
                )
            )
            for error in result["errors"]:
                console.print(f"  • {error.get('detail', 'Unknown deletion error')}")

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")


async def _delete_oauth_credential_menu():
    """Menu for deleting an OAuth credential file."""
    clear_screen("Delete OAuth Credential")
    oauth_summary = _get_oauth_credentials_summary()

    # Check if there are any credentials
    total = sum(len(creds) for creds in oauth_summary.values())
    if total == 0:
        console.print("[bold yellow]No OAuth credentials configured.[/bold yellow]")
        return

    # First, select provider
    console.print("\n[bold cyan]Select OAuth Provider:[/bold cyan]")

    providers_with_creds = [(p, c) for p, c in oauth_summary.items() if c]
    for i, (provider, creds) in enumerate(providers_with_creds, 1):
        display_name = OAUTH_FRIENDLY_NAMES.get(provider, provider.title())
        console.print(f"  {i}. {display_name} ({len(creds)} credential(s))")

    provider_choice = Prompt.ask(
        Text.from_markup(
            "\n[bold]Select provider or type [red]'b'[/red] to go back[/bold]"
        ),
        choices=[str(i) for i in range(1, len(providers_with_creds) + 1)] + ["b"],
        show_choices=False,
    )

    if provider_choice.lower() == "b":
        return

    try:
        provider_idx = int(provider_choice) - 1
        provider_name, credentials = providers_with_creds[provider_idx]
        display_name = OAUTH_FRIENDLY_NAMES.get(provider_name, provider_name.title())

        # Now select credential
        _display_provider_credentials(provider_name)

        cred_choice = Prompt.ask(
            Text.from_markup(
                "[bold]Select credential to delete or type [red]'b'[/red] to go back[/bold]"
            ),
            choices=[str(i) for i in range(1, len(credentials) + 1)] + ["b"],
            show_choices=False,
        )

        if cred_choice.lower() == "b":
            return

        cred_idx = int(cred_choice) - 1
        cred_info = credentials[cred_idx]
        cred_path = cred_info["file_path"]
        email = cred_info.get("email", "unknown")

        # Confirmation prompt
        confirmed = Confirm.ask(
            f"[bold red]Delete[/bold red] credential for [cyan]{email}[/cyan] from {display_name}?"
        )

        if not confirmed:
            console.print("[dim]Deletion cancelled.[/dim]")
            return

        result = _batch_delete_selected_credentials(
            [
                {
                    "type": "oauth",
                    "provider": provider_name,
                    "filename": cred_info.get("filename") or Path(cred_path).name,
                    "file_path": cred_path,
                }
            ],
            dry_run=False,
            confirm=True,
        )
        if result["deleted"] and not result["errors"]:
            console.print(
                Panel(
                    f"Successfully deleted credential for [cyan]{email}[/cyan] and cleaned usage data",
                    style="bold green",
                    title="Success",
                    expand=False,
                )
            )
        elif result["deleted"]:
            console.print(
                Panel(
                    f"Deleted credential for [cyan]{email}[/cyan], but usage cleanup reported errors",
                    style="bold red",
                    title="Partial Cleanup",
                    expand=False,
                )
            )
            for error in result["errors"]:
                console.print(f"  • {error.get('detail', 'Unknown cleanup error')}")
        else:
            console.print(
                Panel(
                    f"Failed to delete credential for [cyan]{email}[/cyan]",
                    style="bold red",
                    title="Error",
                    expand=False,
                )
            )
            for error in result["errors"]:
                console.print(f"  • {error.get('detail', 'Unknown deletion error')}")

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")


async def _edit_oauth_credential_menu():
    """Menu for editing an OAuth credential's email field."""
    clear_screen("Edit OAuth Credential")
    oauth_summary = _get_oauth_credentials_summary()

    # Check if there are any credentials
    total = sum(len(creds) for creds in oauth_summary.values())
    if total == 0:
        console.print("[bold yellow]No OAuth credentials configured.[/bold yellow]")
        return

    # Show warning about editing
    console.print(
        Panel(
            Text.from_markup(
                "[bold yellow]Warning:[/bold yellow] Editing OAuth credentials is generally not recommended.\n"
                "For Gemini CLI OAuth credentials, the email is automatically\n"
                "retrieved during authentication and changing it may cause confusion."
            ),
            style="yellow",
            title="Edit OAuth Credential",
            expand=False,
        )
    )

    # First, select provider
    console.print("\n[bold cyan]Select OAuth Provider:[/bold cyan]")

    providers_with_creds = [(p, c) for p, c in oauth_summary.items() if c]
    for i, (provider, creds) in enumerate(providers_with_creds, 1):
        display_name = OAUTH_FRIENDLY_NAMES.get(provider, provider.title())
        console.print(f"  {i}. {display_name} ({len(creds)} credential(s))")

    provider_choice = Prompt.ask(
        Text.from_markup(
            "\n[bold]Select provider or type [red]'b'[/red] to go back[/bold]"
        ),
        choices=[str(i) for i in range(1, len(providers_with_creds) + 1)] + ["b"],
        show_choices=False,
    )

    if provider_choice.lower() == "b":
        return

    try:
        provider_idx = int(provider_choice) - 1
        provider_name, _ = providers_with_creds[provider_idx]
        await _edit_oauth_credential_email(provider_name)

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")


def clear_screen(subtitle: str = "Interactive Credential Setup"):
    """
    Cross-platform terminal clear with header display.

    Clears the terminal and displays the application header with an optional subtitle.

    Args:
        subtitle: The subtitle text to display in the header panel.
                  Defaults to "Interactive Credential Setup".

    Uses native OS commands instead of ANSI escape sequences:
    - Windows (conhost & Windows Terminal): cls
    - Unix-like systems (Linux, Mac): clear
    """
    os.system("cls" if os.name == "nt" else "clear")
    console.print(
        Panel(
            f"[bold cyan]{subtitle}[/bold cyan]",
            title="--- API Key Proxy ---",
        )
    )


def ensure_env_defaults():
    """
    Ensures the .env file exists and contains essential default values like PROXY_API_KEY.
    """
    if not _get_env_file().is_file():
        _get_env_file().touch()
        console.print(
            f"Creating a new [bold yellow]{_get_env_file().name}[/bold yellow] file..."
        )

    # Check for PROXY_API_KEY, similar to setup_env.bat
    if get_key(str(_get_env_file()), "PROXY_API_KEY") is None:
        default_key = "VerysecretKey"
        console.print(
            f"Adding default [bold cyan]PROXY_API_KEY[/bold cyan] to [bold yellow]{_get_env_file().name}[/bold yellow]..."
        )
        set_key(str(_get_env_file()), "PROXY_API_KEY", default_key)


# =============================================================================
# LiteLLM Provider Configuration
# Auto-generated from LiteLLM documentation. For full provider docs, visit:
# https://docs.litellm.ai/docs/providers
#
# Structure: Each provider has:
#   - api_key: Environment variable for API key (None if not needed)
#   - category: Provider category for display grouping
#   - note: (optional) Configuration notes shown to user
#   - extra_vars: (optional) Additional env vars needed [(name, label, default), ...]
#
# Note: Adding multiple API base URLs per provider is not yet supported.
# =============================================================================


def _search_providers(query: str, providers: dict) -> list:
    """Search providers by substring match (case-insensitive).

    Searches both the provider key and display name.
    """
    query_lower = query.lower()
    matches = []
    for provider_key, config in providers.items():
        display_name = config.get("display_name", provider_key)
        if query_lower in provider_key.lower() or query_lower in display_name.lower():
            matches.append((provider_key, config))
    return matches


def _get_providers_by_category(providers: dict) -> dict:
    """Group providers by category."""
    by_category = {}
    for name, config in providers.items():
        category = config.get("category", "other")
        if category not in by_category:
            by_category[category] = []
        by_category[category].append((name, config))
    return by_category


async def setup_api_key():
    """
    Interactively sets up a new API key for a provider.
    Supports search, categorized display, and additional configuration variables.
    """
    clear_screen("Add API Key")

    # Show info panel
    console.print(
        Panel(
            Text.from_markup(
                "[bold]This list is powered by the LiteLLM library.[/bold]\n"
                "Some providers require additional configuration (API base URL, etc.)\n\n"
                "[dim]Full documentation: https://docs.litellm.ai/docs/providers[/dim]\n"
                "[dim]Note: Adding multiple API base URLs per provider is not yet supported.[/dim]"
            ),
            style="blue",
            title="Provider Information",
            expand=False,
        )
    )
    console.print()

    # -------------------------------------------------------------------------
    # Discover custom providers from project's provider registry
    # -------------------------------------------------------------------------
    _, PROVIDER_PLUGINS = _ensure_providers_loaded()
    from .providers import DynamicOpenAICompatibleProvider

    # Build a set of API key env vars already in SCRAPED_PROVIDERS
    litellm_api_keys = set()
    for info in SCRAPED_PROVIDERS.values():
        for api_key_var in info.get("api_key_env_vars", []):
            litellm_api_keys.add(api_key_var)

    # OAuth-only providers to exclude entirely from API key setup
    oauth_only_providers = {
        "gemini_cli",  # OAuth-only
    }

    # Base classes to exclude
    base_classes = {
        "openai_compatible",
    }

    # Create combined providers dict with scraped data + UI config
    # Key is the provider route key, value includes display_name, api_key, category, etc.
    all_providers = {}

    # Add all scraped providers with their UI config
    for provider_key in SCRAPED_PROVIDERS:
        # Skip blacklisted providers
        if provider_key in PROVIDER_BLACKLIST:
            continue

        scraped_info = SCRAPED_PROVIDERS[provider_key]
        ui_config = LITELLM_PROVIDERS.get(provider_key, {"category": "other"})

        # Skip providers without API keys (OAuth-only or no auth)
        api_key_vars = scraped_info.get("api_key_env_vars", [])
        if not api_key_vars:
            continue

        # Prefer *_API_KEY pattern, fall back to first
        api_key_var = None
        for var in api_key_vars:
            if var.endswith("_API_KEY"):
                api_key_var = var
                break
        if not api_key_var:
            api_key_var = api_key_vars[0]

        all_providers[provider_key] = {
            "display_name": scraped_info.get("display_name", provider_key),
            "api_key": api_key_var,
            "category": ui_config.get("category", "other"),
            "note": ui_config.get("note"),
            "extra_vars": ui_config.get("extra_vars", []),
        }

    # Add custom providers from PROVIDER_PLUGINS
    for provider_key, provider_class in PROVIDER_PLUGINS.items():
        # Skip OAuth-only providers
        if provider_key in oauth_only_providers:
            continue

        # Skip base classes
        if provider_key in base_classes:
            continue

        # Skip if already in scraped providers
        if provider_key in all_providers:
            continue

        # Check if this is a dynamic OpenAI-compatible provider
        try:
            is_dynamic = isinstance(provider_class, type) and issubclass(
                provider_class, DynamicOpenAICompatibleProvider
            )
        except TypeError:
            is_dynamic = False

        env_var = f"{provider_key.upper()}_API_KEY"

        # Skip if API key already covered
        if env_var in litellm_api_keys:
            continue

        display_name = provider_key.replace("_", " ").title()

        if is_dynamic:
            # Dynamic OpenAI-compatible provider uses _API_BASE pattern
            all_providers[provider_key] = {
                "display_name": display_name,
                "api_key": env_var,
                "category": "custom_openai",
                "note": "Custom OpenAI-compatible provider.",
                "extra_vars": [
                    (f"{provider_key.upper()}_API_BASE", "API Base URL", None),
                ],
            }
        else:
            # First-party file-based provider
            all_providers[provider_key] = {
                "display_name": display_name,
                "api_key": env_var,
                "category": "custom",
                "note": "First-party provider from the library.",
            }

    # Search prompt
    search_query = Prompt.ask(
        "[bold]Search providers[/bold] [dim](or press Enter to see all)[/dim]",
        default="",
    )

    # Build provider list based on search
    if search_query.strip():
        # Search mode
        matches = _search_providers(search_query, all_providers)
        if not matches:
            console.print(
                f"[bold yellow]No providers found matching '{search_query}'[/bold yellow]"
            )
            console.print("[dim]Press Enter to continue...[/dim]")
            input()
            return

        # Build numbered list from search results
        provider_list = []
        provider_text = Text()
        provider_text.append(
            f"\nMatching providers for '{search_query}':\n\n", style="bold cyan"
        )

        for i, (provider_key, config) in enumerate(matches, 1):
            provider_list.append((provider_key, config))
            display_name = config.get("display_name", provider_key)
            category = config.get("category", "other")
            category_label = next(
                (label for cat, label in PROVIDER_CATEGORIES if cat == category),
                "Other",
            )
            api_key_var = config.get("api_key")
            if api_key_var:
                key_prefix = (
                    api_key_var.replace("_API_KEY", "")
                    .replace("_TOKEN", "")
                    .replace("_", " ")
                )
                provider_text.append(
                    f"  {i}. {display_name} ({key_prefix}) ", style="white"
                )
            else:
                provider_text.append(f"  {i}. {display_name} ", style="white")
            provider_text.append(f"[{category_label}]\n", style="dim")

        console.print(provider_text)

    else:
        # Full categorized list mode
        by_category = _get_providers_by_category(all_providers)
        provider_list = []
        provider_text = Text()

        for category_key, category_label in PROVIDER_CATEGORIES:
            if category_key not in by_category:
                continue

            providers_in_cat = by_category[category_key]
            provider_text.append(f"\n--- {category_label} ---\n", style="bold cyan")

            for provider_key, config in providers_in_cat:
                idx = len(provider_list) + 1
                provider_list.append((provider_key, config))
                display_name = config.get("display_name", provider_key)
                api_key_var = config.get("api_key")
                if api_key_var:
                    key_prefix = (
                        api_key_var.replace("_API_KEY", "")
                        .replace("_TOKEN", "")
                        .replace("_", " ")
                    )
                    provider_text.append(f"  {idx}. {display_name} ({key_prefix})\n")
                else:
                    provider_text.append(
                        f"  {idx}. {display_name} [dim](no API key)[/dim]\n"
                    )

        console.print(provider_text)

    # Provider selection
    console.print()
    choice = Prompt.ask(
        Text.from_markup(
            "[bold]Select a provider number or type [red]'b'[/red] to go back[/bold]"
        ),
        default="b",
    )

    if choice.lower() == "b":
        return

    try:
        choice_index = int(choice) - 1
        if choice_index < 0 or choice_index >= len(provider_list):
            console.print("[bold red]Invalid choice.[/bold red]")
            return

        provider_key, provider_config = provider_list[choice_index]
        display_name = provider_config.get("display_name", provider_key)
        api_key_var = provider_config.get("api_key")
        note = provider_config.get("note")
        extra_vars = provider_config.get("extra_vars", [])

        # Get additional info from scraped data
        scraped_info = SCRAPED_PROVIDERS.get(provider_key, {})
        route = scraped_info.get("route", "").rstrip("/")
        api_base_url = scraped_info.get("api_base_url")

        console.print()

        # Build and show provider info panel
        info_lines = []
        if route:
            info_lines.append(f"Route: [cyan]{route}/[/cyan]")
            info_lines.append(f"Example: [dim]{route}/model-name[/dim]")
        if api_base_url:
            info_lines.append(f"API Base: [dim]{api_base_url}[/dim]")
        if api_key_var:
            info_lines.append(f"Env Variable: [green]{api_key_var}[/green]")

        if info_lines:
            console.print(
                Panel(
                    "\n".join(info_lines),
                    title=f"[bold]{display_name}[/bold]",
                    expand=False,
                    border_style="blue",
                )
            )
            console.print()

        # Show provider note if exists
        if note:
            console.print(
                Panel(
                    note,
                    style="yellow",
                    title="Configuration Note",
                    expand=False,
                )
            )
            console.print()

        saved_vars = []

        # Prompt for API key (if provider has one)
        if api_key_var:
            api_key = Prompt.ask(
                f"[bold]Enter {api_key_var}[/bold] [dim](or press Enter to skip)[/dim]",
                default="",
            )

            if api_key.strip():
                # Find next available key index
                key_index = 1
                while True:
                    key_name = f"{api_key_var}_{key_index}"
                    if _get_env_file().is_file():
                        with open(_get_env_file(), "r") as f:
                            if not any(line.startswith(f"{key_name}=") for line in f):
                                break
                    else:
                        break
                    key_index += 1

                key_name = f"{api_key_var}_{key_index}"
                set_key(str(_get_env_file()), key_name, api_key.strip())
                saved_vars.append((key_name, api_key.strip()))

        # Prompt for extra variables
        if extra_vars:
            console.print("\n[bold]Additional configuration:[/bold]")
            for env_var_name, label, default_value in extra_vars:
                if default_value:
                    # Pre-fill with default
                    value = Prompt.ask(
                        f"  {label}",
                        default=default_value,
                    )
                else:
                    value = Prompt.ask(
                        f"  {label} [dim](or press Enter to skip)[/dim]",
                        default="",
                    )

                if value.strip():
                    set_key(str(_get_env_file()), env_var_name, value.strip())
                    saved_vars.append((env_var_name, value.strip()))

        # Show success message
        if saved_vars:
            success_lines = [f"Successfully configured [bold]{display_name}[/bold]:\n"]
            for var_name, var_value in saved_vars:
                if len(var_value) > 8:
                    masked = f"{var_value[:4]}...{var_value[-4:]}"
                elif len(var_value) > 4:
                    masked = f"****{var_value[-4:]}"
                else:
                    masked = "****"
                success_lines.append(f"  [yellow]{var_name}[/yellow] = {masked}")

            console.print(
                Panel(
                    Text.from_markup("\n".join(success_lines)),
                    style="bold green",
                    title="Success",
                    expand=False,
                )
            )
        else:
            console.print("[dim]No values configured (all skipped).[/dim]")

        # Wait for user to read the result
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    except ValueError:
        console.print(
            "[bold red]Invalid input. Please enter a number or 'b'.[/bold red]"
        )
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()


async def setup_custom_openai_provider():
    """
    Interactively sets up a custom OpenAI-compatible provider.

    This adds a new provider that uses the standard OpenAI API format but points
    to a custom endpoint (LM Studio, Ollama, vLLM, custom server, etc.).
    """
    clear_screen("Add Custom OpenAI-Compatible Provider")

    # Show info panel
    console.print(
        Panel(
            Text.from_markup(
                "[bold]Custom OpenAI-Compatible Providers[/bold]\n\n"
                "Add a custom endpoint that uses the OpenAI API format.\n"
                "This works with: LM Studio, Ollama, vLLM, text-generation-webui, "
                "and other OpenAI-compatible servers.\n\n"
                "[dim]The library will automatically discover available models from your endpoint.[/dim]\n"
                "[dim]You can also override built-in providers (e.g., OPENAI) to route traffic elsewhere.[/dim]\n\n"
                "[yellow]Please consult the provider's documentation for the correct API base URL.[/yellow]"
            ),
            style="blue",
            title="Custom Provider Setup",
            expand=False,
        )
    )
    console.print()

    # Show existing custom providers
    _display_custom_providers_summary()

    # Prompt for provider name
    console.print("[dim]Provider name will be used for environment variables.[/dim]")
    console.print(
        "[dim]Use alphanumeric characters and underscores only (e.g., MY_LOCAL_LLM).[/dim]\n"
    )

    while True:
        provider_name = Prompt.ask(
            "[bold]Enter provider name[/bold] [dim](or 'b' to go back)[/dim]",
            default="",
        )

        if provider_name.lower() == "b" or not provider_name.strip():
            return

        provider_name = provider_name.strip().upper()

        # Validate name (alphanumeric + underscores only)
        import re

        if not re.match(r"^[A-Z][A-Z0-9_]*$", provider_name):
            console.print(
                "[bold red]Invalid name. Use letters, numbers, and underscores only. "
                "Must start with a letter.[/bold red]"
            )
            continue

        # Check for conflict with built-in LiteLLM providers
        conflict_provider = None
        for litellm_name, config in LITELLM_PROVIDERS.items():
            api_key_var = config.get("api_key", "")
            if api_key_var:
                # Extract prefix from API key var (e.g., OPENAI_API_KEY -> OPENAI)
                prefix = api_key_var.replace("_API_KEY", "").replace("_TOKEN", "")
                if prefix == provider_name:
                    conflict_provider = litellm_name
                    break

        if conflict_provider:
            console.print(
                f"\n[bold yellow]Warning:[/bold yellow] '{provider_name}' matches the built-in "
                f"'{conflict_provider}' provider."
            )
            console.print(
                "If you continue, requests to this provider will be routed to your custom endpoint "
                "instead of the official API.\n"
            )
            override_confirm = Prompt.ask(
                "[bold]Do you want to override the built-in provider?[/bold]",
                choices=["y", "n"],
                default="n",
            )
            if override_confirm.lower() != "y":
                continue

        break

    # Prompt for API Base URL (required)
    console.print()
    console.print("[dim]The API base URL is where requests will be sent.[/dim]")
    console.print(
        "[dim]Common examples: http://localhost:1234/v1, http://localhost:11434/v1[/dim]\n"
    )

    while True:
        api_base = Prompt.ask(
            "[bold]Enter API Base URL[/bold] [dim](required)[/dim]",
            default="",
        )

        if not api_base.strip():
            console.print("[bold red]API Base URL is required.[/bold red]")
            continue

        api_base = api_base.strip()

        # Validate URL format
        if not api_base.startswith(("http://", "https://")):
            console.print(
                "[bold red]Invalid URL. Must start with http:// or https://[/bold red]"
            )
            continue

        break

    # Prompt for API Key (required)
    console.print()
    console.print("[dim]Enter the API key for authentication.[/dim]")
    console.print(
        "[dim]If your server doesn't require authentication, enter any placeholder value.[/dim]\n"
    )

    while True:
        api_key = Prompt.ask(
            "[bold]Enter API Key[/bold] [dim](required)[/dim]",
            default="",
        )

        if not api_key.strip():
            console.print("[bold red]API Key is required.[/bold red]")
            continue

        api_key = api_key.strip()
        break

    # Save to .env file
    env_file = _get_env_file()

    # Save API Base URL
    api_base_var = f"{provider_name}_API_BASE"
    set_key(str(env_file), api_base_var, api_base)

    # Save API Key (find next available index)
    api_key_var_base = f"{provider_name}_API_KEY"
    key_index = 1
    if env_file.is_file():
        with open(env_file, "r") as f:
            content = f.read()
            while f"{api_key_var_base}_{key_index}=" in content:
                key_index += 1

    api_key_var = f"{api_key_var_base}_{key_index}"
    set_key(str(env_file), api_key_var, api_key)

    # Mask the API key for display
    if len(api_key) > 8:
        masked_key = f"{api_key[:4]}...{api_key[-4:]}"
    elif len(api_key) > 4:
        masked_key = f"****{api_key[-4:]}"
    else:
        masked_key = "****"

    # Show success message
    console.print(
        Panel(
            Text.from_markup(
                f"Successfully configured custom provider [bold]{provider_name}[/bold]:\n\n"
                f"  [yellow]{api_base_var}[/yellow] = {api_base}\n"
                f"  [yellow]{api_key_var}[/yellow] = {masked_key}\n\n"
                "[dim]The library will automatically fetch available models from your endpoint.[/dim]\n"
                "[dim]Use launcher menu option 4 'List Available Models' to verify the setup.[/dim]"
            ),
            style="bold green",
            title="Success",
            expand=False,
        )
    )

    console.print("\n[dim]Press Enter to continue...[/dim]")
    input()


async def setup_new_credential(provider_name: str):
    """
    Interactively sets up a new OAuth credential for a given provider.

    Delegates all credential management logic to the auth class's setup_credential() method.
    """
    try:
        provider_factory, _ = _ensure_providers_loaded()
        auth_class = provider_factory.get_provider_auth_class(provider_name)
        auth_instance = auth_class()

        # Build display name for better user experience
        display_name = OAUTH_FRIENDLY_NAMES.get(
            provider_name, provider_name.replace("_", " ").title()
        )

        result = await auth_instance.setup_credential(_get_oauth_base_dir())

        if not result.success:
            console.print(
                Panel(
                    f"Credential setup failed: {result.error}",
                    style="bold red",
                    title="Error",
                )
            )
            return

        # Display success message with details
        if result.is_update:
            success_text = Text.from_markup(
                f"Successfully updated credential at [bold yellow]'{Path(result.file_path).name}'[/bold yellow] "
                f"for user [bold cyan]'{result.email}'[/bold cyan]."
            )
        else:
            success_text = Text.from_markup(
                f"Successfully created new credential at [bold yellow]'{Path(result.file_path).name}'[/bold yellow] "
                f"for user [bold cyan]'{result.email}'[/bold cyan]."
            )

        # Add workspace/account info if available (OpenAI Codex credentials)
        if result.credentials and isinstance(result.credentials, dict):
            metadata = result.credentials.get("_proxy_metadata", {})
            workspace_title = metadata.get("workspace_title")
            plan_type = metadata.get("plan_type")
            if workspace_title or plan_type:
                workspace_parts = []
                if workspace_title:
                    workspace_parts.append(workspace_title)
                if plan_type:
                    workspace_parts.append(f"({plan_type})")
                success_text.append(
                    f"\nWorkspace: {' '.join(workspace_parts)}"
                )
            if hasattr(result, "account_id") and result.account_id:
                success_text.append(
                    f"\nAccount ID: {result.account_id}"
                )

        # Add tier/project info if available (Google OAuth providers)
        if hasattr(result, "tier") and result.tier:
            # Try to get the full tier name for better display (e.g., "Google One AI PRO")
            tier_display = result.tier
            if result.credentials and isinstance(result.credentials, dict):
                tier_full = result.credentials.get("_proxy_metadata", {}).get(
                    "tier_full"
                )
                if tier_full:
                    tier_display = tier_full
            success_text.append(f"\nTier: {tier_display}")
        if hasattr(result, "project_id") and result.project_id:
            success_text.append(f"\nProject: {result.project_id}")

        console.print(Panel(success_text, style="bold green", title="Success"))

    except Exception as e:
        console.print(
            Panel(
                f"An error occurred during setup for {provider_name}: {e}",
                style="bold red",
                title="Error",
            )
        )


async def export_gemini_cli_to_env():
    """
    Export a Gemini CLI credential JSON file to .env format.
    Uses the auth class's build_env_lines() and list_credentials() methods.
    """
    clear_screen("Export Gemini CLI Credential")

    # Get auth instance for this provider
    provider_factory, _ = _ensure_providers_loaded()
    auth_class = provider_factory.get_provider_auth_class("gemini_cli")
    auth_instance = auth_class()

    # List available credentials using auth class
    credentials = auth_instance.list_credentials(_get_oauth_base_dir())

    if not credentials:
        console.print(
            Panel(
                "No Gemini CLI credentials found. Please add one first using 'Add OAuth Credential'.",
                style="bold red",
                title="No Credentials",
            )
        )
        return

    # Display available credentials
    cred_text = Text()
    for i, cred_info in enumerate(credentials):
        cred_text.append(
            f"  {i + 1}. {Path(cred_info['file_path']).name} ({cred_info['email']})\n"
        )

    console.print(
        Panel(
            cred_text,
            title="Available Gemini CLI Credentials",
            style="bold blue",
        )
    )

    choice = Prompt.ask(
        Text.from_markup(
            "[bold]Please select a credential to export or type [red]'b'[/red] to go back[/bold]"
        ),
        choices=[str(i + 1) for i in range(len(credentials))] + ["b"],
        show_choices=False,
    )

    if choice.lower() == "b":
        return

    try:
        choice_index = int(choice) - 1
        if 0 <= choice_index < len(credentials):
            cred_info = credentials[choice_index]

            # Use auth class to export
            env_path = auth_instance.export_credential_to_env(
                cred_info["file_path"], _get_oauth_base_dir()
            )

            if env_path:
                numbered_prefix = f"GEMINI_CLI_{cred_info['number']}"
                success_text = Text.from_markup(
                    f"Successfully exported credential to [bold yellow]'{Path(env_path).name}'[/bold yellow]\n\n"
                    f"[bold]Environment variable prefix:[/bold] [cyan]{numbered_prefix}_*[/cyan]\n\n"
                    f"[bold]To use this credential:[/bold]\n"
                    f"1. Copy the contents to your main .env file, OR\n"
                    f"2. Source it: [bold cyan]source {Path(env_path).name}[/bold cyan] (Linux/Mac)\n"
                    f"3. Or on Windows: [bold cyan]Get-Content {Path(env_path).name} | ForEach-Object {{ $_ -replace '^([^#].*)$', 'set $1' }} | cmd[/bold cyan]\n\n"
                    f"[bold]To combine multiple credentials:[/bold]\n"
                    f"Copy lines from multiple .env files into one file.\n"
                    f"Each credential uses a unique number ({numbered_prefix}_*)."
                )
                console.print(Panel(success_text, style="bold green", title="Success"))
            else:
                console.print(
                    Panel(
                        "Failed to export credential", style="bold red", title="Error"
                    )
                )
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
    except ValueError:
        console.print(
            "[bold red]Invalid input. Please enter a number or 'b'.[/bold red]"
        )
    except Exception as e:
        console.print(
            Panel(
                f"An error occurred during export: {e}", style="bold red", title="Error"
            )
        )


async def export_codex_to_env():
    """
    Export a Codex credential JSON file to .env format.
    Uses the auth class's build_env_lines() and list_credentials() methods.
    """
    clear_screen("Export Codex Credential")

    # Get auth instance for this provider
    provider_factory, _ = _ensure_providers_loaded()
    auth_class = provider_factory.get_provider_auth_class("codex")
    auth_instance = auth_class()

    # List available credentials using auth class
    credentials = auth_instance.list_credentials(_get_oauth_base_dir())

    if not credentials:
        console.print(
            Panel(
                "No Codex credentials found. Please add one first using 'Add OAuth Credential'.",
                style="bold red",
                title="No Credentials",
            )
        )
        return

    # Display available credentials
    cred_text = Text()
    for i, cred_info in enumerate(credentials):
        cred_text.append(
            f"  {i + 1}. {Path(cred_info['file_path']).name} ({cred_info['email']})\n"
        )

    console.print(
        Panel(
            cred_text,
            title="Available Codex Credentials",
            style="bold blue",
        )
    )

    choice = Prompt.ask(
        Text.from_markup(
            "[bold]Please select a credential to export or type [red]'b'[/red] to go back[/bold]"
        ),
        choices=[str(i + 1) for i in range(len(credentials))] + ["b"],
        show_choices=False,
    )

    if choice.lower() == "b":
        return

    try:
        choice_index = int(choice) - 1
        if 0 <= choice_index < len(credentials):
            cred_info = credentials[choice_index]

            # Use auth class to export
            env_path = auth_instance.export_credential_to_env(
                cred_info["file_path"], _get_oauth_base_dir()
            )

            if env_path:
                numbered_prefix = f"CODEX_{cred_info['number']}"
                success_text = Text.from_markup(
                    f"Successfully exported credential to [bold yellow]'{Path(env_path).name}'[/bold yellow]\n\n"
                    f"[bold]Environment variable prefix:[/bold] [cyan]{numbered_prefix}_*[/cyan]\n\n"
                    f"[bold]To use this credential:[/bold]\n"
                    f"1. Copy the contents to your main .env file, OR\n"
                    f"2. Source it: [bold cyan]source {Path(env_path).name}[/bold cyan] (Linux/Mac)\n\n"
                    f"[bold]To combine multiple credentials:[/bold]\n"
                    f"Copy lines from multiple .env files into one file.\n"
                    f"Each credential uses a unique number ({numbered_prefix}_*)."
                )
                console.print(Panel(success_text, style="bold green", title="Success"))
            else:
                console.print(
                    Panel(
                        "Failed to export credential", style="bold red", title="Error"
                    )
                )
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
    except ValueError:
        console.print(
            "[bold red]Invalid input. Please enter a number or 'b'.[/bold red]"
        )
    except Exception as e:
        console.print(
            Panel(
                f"An error occurred during export: {e}", style="bold red", title="Error"
            )
        )


async def export_anthropic_to_env():
    """
    Export an Anthropic credential JSON file to .env format.
    Uses the auth class's build_env_lines() and list_credentials() methods.
    """
    clear_screen("Export Anthropic Credential")

    # Get auth instance for this provider
    provider_factory, _ = _ensure_providers_loaded()
    auth_class = provider_factory.get_provider_auth_class("anthropic")
    auth_instance = auth_class()

    # List available credentials using auth class
    credentials = auth_instance.list_credentials(_get_oauth_base_dir())

    if not credentials:
        console.print(
            Panel(
                "No Anthropic credentials found. Please add one first using 'Add OAuth Credential'.",
                style="bold red",
                title="No Credentials",
            )
        )
        return

    # Display available credentials
    cred_text = Text()
    for i, cred_info in enumerate(credentials):
        cred_text.append(
            f"  {i + 1}. {Path(cred_info['file_path']).name} ({cred_info['email']})\n"
        )

    console.print(
        Panel(
            cred_text,
            title="Available Anthropic Credentials",
            style="bold blue",
        )
    )

    choice = Prompt.ask(
        Text.from_markup(
            "[bold]Please select a credential to export or type [red]'b'[/red] to go back[/bold]"
        ),
        choices=[str(i + 1) for i in range(len(credentials))] + ["b"],
        show_choices=False,
    )

    if choice.lower() == "b":
        return

    try:
        choice_index = int(choice) - 1
        if 0 <= choice_index < len(credentials):
            cred_info = credentials[choice_index]

            # Use auth class to export
            env_path = auth_instance.export_credential_to_env(
                cred_info["file_path"], _get_oauth_base_dir()
            )

            if env_path:
                numbered_prefix = f"ANTHROPIC_OAUTH_{cred_info['number']}"
                success_text = Text.from_markup(
                    f"Successfully exported credential to [bold yellow]'{Path(env_path).name}'[/bold yellow]\n\n"
                    f"[bold]Environment variable prefix:[/bold] [cyan]{numbered_prefix}_*[/cyan]\n\n"
                    f"[bold]To use this credential:[/bold]\n"
                    f"1. Copy the contents to your main .env file, OR\n"
                    f"2. Source it: [bold cyan]source {Path(env_path).name}[/bold cyan] (Linux/Mac)\n\n"
                    f"[bold]To combine multiple credentials:[/bold]\n"
                    f"Copy lines from multiple .env files into one file.\n"
                    f"Each credential uses a unique number ({numbered_prefix}_*)."
                )
                console.print(Panel(success_text, style="bold green", title="Success"))
            else:
                console.print(
                    Panel(
                        "Failed to export credential", style="bold red", title="Error"
                    )
                )
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
    except ValueError:
        console.print(
            "[bold red]Invalid input. Please enter a number or 'b'.[/bold red]"
        )
    except Exception as e:
        console.print(
            Panel(
                f"An error occurred during export: {e}", style="bold red", title="Error"
            )
        )

async def export_copilot_to_env():
    """ Export a Copilot credential JSON file to .env format. Uses the auth class's build_env_lines() and list_credentials() methods.
    """
    clear_screen("Export Copilot Credential")
    # Get auth instance for this provider
    provider_factory, _ = _ensure_providers_loaded()
    try:
        auth_class = provider_factory.get_provider_auth_class("copilot")
        auth_instance = auth_class()
    except Exception:
        console.print("[bold red]Unknown provider: copilot[/bold red]")
        return

    # List available credentials using auth class
    credentials = auth_instance.list_credentials(_get_oauth_base_dir())

    if not credentials:
        console.print(
            Panel(
                "No Copilot credentials found. Please add one first using 'Add OAuth Credential'.",
                style="bold red",
                title="No Credentials",
            )
        )
        return

    # Display available credentials
    cred_text = Text()
    for i, cred_info in enumerate(credentials):
        login = cred_info.get("login", cred_info.get("email", "unknown"))
        cred_text.append(
            f" {i + 1}. {Path(cred_info['file_path']).name} ({login})\n"
        )

    console.print(
        Panel(
            cred_text,
            title="Available Copilot Credentials",
            style="bold blue",
        )
    )

    choice = Prompt.ask(
        Text.from_markup(
            "[bold]Please select a credential to export or type [red]'b'[/red] to go back[/bold]"
        ),
        choices=[str(i + 1) for i in range(len(credentials))] + ["b"],
        show_choices=False,
    )

    if choice.lower() == "b":
        return

    try:
        choice_index = int(choice) - 1
        if 0 <= choice_index < len(credentials):
            cred_info = credentials[choice_index]

            # Use auth class to export
            env_path = auth_instance.export_credential_to_env(
                cred_info["file_path"], _get_oauth_base_dir()
            )

            if env_path:
                numbered_prefix = f"COPILOT_{cred_info['number']}"
                success_text = Text.from_markup(
                    f"Successfully exported credential to [bold yellow]'{Path(env_path).name}'[/bold yellow]\n\n"
                    f"[bold]Environment variable prefix:[/bold] [cyan]{numbered_prefix}_*[/cyan]\n\n"
                    f"[bold]To use this credential:[/bold]\n"
                    f"1. Copy the contents to your main .env file, OR\n"
                    f"2. Source it: [bold cyan]source {Path(env_path).name}[/bold cyan] (Linux/Mac)\n\n"
                    f"[bold]To combine multiple credentials:[/bold]\n"
                    f"Copy lines from multiple .env files into one file.\n"
                    f"Each credential uses a unique number ({numbered_prefix}_*)."
                )
                console.print(Panel(success_text, style="bold green", title="Success"))
            else:
                console.print(
                    Panel(
                        "Failed to export credential",
                        style="bold red",
                        title="Error",
                    )
                )
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")
    except ValueError:
        console.print(
            "[bold red]Invalid input. Please enter a number or 'b'.[/bold red]"
        )
    except Exception as e:
        console.print(
            Panel(
                f"An error occurred during export: {e}",
                style="bold red",
                title="Error",
            )
        )

async def export_all_provider_credentials(provider_name: str):
    """
    Export all credentials for a specific provider to individual .env files.
    Uses the auth class's list_credentials() and export_credential_to_env() methods.
    """
    display_name = provider_name.replace("_", " ").title()
    clear_screen(f"Export All {display_name} Credentials")
    # Get auth instance for this provider
    provider_factory, _ = _ensure_providers_loaded()
    try:
        auth_class = provider_factory.get_provider_auth_class(provider_name)
        auth_instance = auth_class()
    except Exception:
        console.print(f"[bold red]Unknown provider: {provider_name}[/bold red]")
        return

    display_name = provider_name.replace("_", " ").title()

    console.print(
        Panel(
            f"[bold cyan]Export All {display_name} Credentials[/bold cyan]",
            expand=False,
        )
    )

    # List all credentials using auth class
    credentials = auth_instance.list_credentials(_get_oauth_base_dir())

    if not credentials:
        console.print(
            Panel(
                f"No {display_name} credentials found.",
                style="bold red",
                title="No Credentials",
            )
        )
        return

    exported_count = 0
    for cred_info in credentials:
        try:
            # Use auth class to export
            env_path = auth_instance.export_credential_to_env(
                cred_info["file_path"], _get_oauth_base_dir()
            )

            if env_path:
                console.print(
                    f"  ✓ Exported [cyan]{Path(cred_info['file_path']).name}[/cyan] → [yellow]{Path(env_path).name}[/yellow]"
                )
                exported_count += 1
            else:
                console.print(
                    f"  ✗ Failed to export {Path(cred_info['file_path']).name}"
                )

        except Exception as e:
            console.print(
                f"  ✗ Failed to export {Path(cred_info['file_path']).name}: {e}"
            )

    console.print(
        Panel(
            f"Successfully exported {exported_count}/{len(credentials)} {display_name} credentials to individual .env files.",
            style="bold green",
            title="Export Complete",
        )
    )


async def combine_provider_credentials(provider_name: str):
    """
    Combine all credentials for a specific provider into a single .env file.
    Uses the auth class's list_credentials() and build_env_lines() methods.
    """
    display_name = provider_name.replace("_", " ").title()
    clear_screen(f"Combine {display_name} Credentials")
    # Get auth instance for this provider
    provider_factory, _ = _ensure_providers_loaded()
    try:
        auth_class = provider_factory.get_provider_auth_class(provider_name)
        auth_instance = auth_class()
    except Exception:
        console.print(f"[bold red]Unknown provider: {provider_name}[/bold red]")
        return

    display_name = provider_name.replace("_", " ").title()

    console.print(
        Panel(
            f"[bold cyan]Combine All {display_name} Credentials[/bold cyan]",
            expand=False,
        )
    )

    # List all credentials using auth class
    credentials = auth_instance.list_credentials(_get_oauth_base_dir())

    if not credentials:
        console.print(
            Panel(
                f"No {display_name} credentials found.",
                style="bold red",
                title="No Credentials",
            )
        )
        return

    combined_lines = [
        f"# Combined {display_name} Credentials",
        f"# Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Total credentials: {len(credentials)}",
        "#",
        "# Copy all lines below into your main .env file",
        "",
    ]

    combined_count = 0
    for cred_info in credentials:
        try:
            # Load credential file
            with open(cred_info["file_path"], "r") as f:
                creds = json.load(f)

            # Use auth class to build env lines
            env_lines = auth_instance.build_env_lines(creds, cred_info["number"])

            combined_lines.extend(env_lines)
            combined_lines.append("")  # Blank line between credentials
            combined_count += 1

        except Exception as e:
            console.print(
                f"  ✗ Failed to process {Path(cred_info['file_path']).name}: {e}"
            )

    # Write combined file
    combined_filename = f"{provider_name}_all_combined.env"
    combined_filepath = _get_oauth_base_dir() / combined_filename

    with open(combined_filepath, "w") as f:
        f.write("\n".join(combined_lines))

    console.print(
        Panel(
            Text.from_markup(
                f"Successfully combined {combined_count} {display_name} credentials into:\n"
                f"[bold yellow]{combined_filepath}[/bold yellow]\n\n"
                f"[bold]To use:[/bold] Copy the contents into your main .env file."
            ),
            style="bold green",
            title="Combine Complete",
        )
    )


async def combine_all_credentials():
    """
    Combine ALL credentials from ALL providers into a single .env file.
    Uses auth class list_credentials() and build_env_lines() methods.
    """
    clear_screen("Combine All Credentials")

    # List of providers that support OAuth credentials
    oauth_providers = ["gemini_cli", "codex", "anthropic", "copilot"]

    provider_factory, _ = _ensure_providers_loaded()

    combined_lines = [
        "# Combined All Provider Credentials",
        f"# Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "#",
        "# Copy all lines below into your main .env file",
        "",
    ]

    total_count = 0
    provider_counts = {}

    for provider_name in oauth_providers:
        try:
            auth_class = provider_factory.get_provider_auth_class(provider_name)
            auth_instance = auth_class()
        except Exception:
            continue  # Skip providers that don't have auth classes

        credentials = auth_instance.list_credentials(_get_oauth_base_dir())

        if not credentials:
            continue

        display_name = provider_name.replace("_", " ").title()
        combined_lines.append(f"# ===== {display_name} Credentials =====")
        combined_lines.append("")

        provider_count = 0
        for cred_info in credentials:
            try:
                # Load credential file
                with open(cred_info["file_path"], "r") as f:
                    creds = json.load(f)

                # Use auth class to build env lines
                env_lines = auth_instance.build_env_lines(creds, cred_info["number"])

                combined_lines.extend(env_lines)
                combined_lines.append("")
                provider_count += 1
                total_count += 1

            except Exception as e:
                console.print(
                    f"  ✗ Failed to process {Path(cred_info['file_path']).name}: {e}"
                )

        provider_counts[display_name] = provider_count

    if total_count == 0:
        console.print(
            Panel(
                "No credentials found to combine.",
                style="bold red",
                title="No Credentials",
            )
        )
        return

    # Write combined file
    combined_filename = "all_providers_combined.env"
    combined_filepath = _get_oauth_base_dir() / combined_filename

    with open(combined_filepath, "w") as f:
        f.write("\n".join(combined_lines))

    # Build summary
    summary_lines = [
        f"  • {name}: {count} credential(s)" for name, count in provider_counts.items()
    ]
    summary = "\n".join(summary_lines)

    console.print(
        Panel(
            Text.from_markup(
                f"Successfully combined {total_count} credentials from {len(provider_counts)} providers:\n"
                f"{summary}\n\n"
                f"[bold]Output file:[/bold] [yellow]{combined_filepath}[/yellow]\n\n"
                f"[bold]To use:[/bold] Copy the contents into your main .env file."
            ),
            style="bold green",
            title="Combine Complete",
        )
    )


def _clean_prompt_path(value: str) -> str:
    """Normalize a path pasted into the interactive credential tool."""
    return value.strip().strip('"').strip("'")


def _parse_prompt_paths(value: str) -> list[str]:
    """Parse newline/comma/semicolon-separated paths, respecting quotes."""
    paths: list[str] = []
    seen: set[str] = set()
    current: list[str] = []
    quote: str | None = None

    def append_current() -> None:
        raw_path = "".join(current)
        current.clear()
        path = _clean_prompt_path(raw_path)
        if path and path not in seen:
            seen.add(path)
            paths.append(path)

    for char in value:
        if char in {'"', "'"}:
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            current.append(char)
            continue

        if quote is None and char in {"\n", "\r", ",", ";"}:
            append_current()
            continue

        current.append(char)

    append_current()
    return paths


def _read_codex_import_paths() -> list[str]:
    """Read one or more Codex import paths from the terminal."""
    console.print(
        Text.from_markup(
            "[bold]Paste import file/folder path(s).[/bold]\n"
            "Use one path per line, or separate paths with commas/semicolons.\n"
            "Quoted paths are supported. Submit a blank line to start import; type [red]b[/red] to go back."
        )
    )

    lines: list[str] = []
    while True:
        line = input("> " if not lines else "  ")
        if not lines and line.strip().lower() == "b":
            return []
        if not line.strip():
            break
        lines.append(line)

    return _parse_prompt_paths("\n".join(lines))


def _merge_codex_import_result(target: CodexImportResult, partial: CodexImportResult) -> None:
    target.imported += partial.imported
    target.updated += partial.updated
    target.skipped += partial.skipped
    target.errors.extend(partial.errors)
    target.written_paths.extend(partial.written_paths)


async def import_codex_json_credentials():
    """Import Codex credentials from GPTSession2CPA/sub2api/Codex-Manager JSON."""
    clear_screen("Import Codex Credentials")
    console.print(
        Panel(
            Text.from_markup(
                "Paste a JSON/JSONL file or folder exported by GPTSession2CPAandSub2API,\n"
                "CodexAccountStatusQuotaChecker, Sub2API, CPA, Cockpit, 9router,\n"
                "Codex auth.json, AxonHub, or Codex-Manager.\n\n"
                "The proxy will write one [yellow]codex_oauth_*.json[/yellow] file per account."
            ),
            title="Supported Codex Import Formats",
            style="bold blue",
        )
    )

    import_paths = _read_codex_import_paths()
    if not import_paths:
        console.print("[bold yellow]No import paths provided.[/bold yellow]")
        return

    update_existing = Confirm.ask(
        "Update matching existing Codex credentials if found?",
        default=True,
    )

    result = CodexImportResult()
    for import_path in import_paths:
        partial = import_codex_credentials_from_path(
            import_path,
            _get_oauth_base_dir(),
            update_existing=update_existing,
        )
        _merge_codex_import_result(result, partial)

    summary = (
        f"Imported: {result.imported}\n"
        f"Updated: {result.updated}\n"
        f"Skipped/errors: {result.skipped}\n"
        f"Output directory: {_get_oauth_base_dir()}"
    )
    console.print(
        Panel(
            summary,
            style="bold green" if result.total_written else "bold yellow",
            title="Codex Import Complete",
        )
    )

    if result.written_paths:
        table = Table(title="Written Credentials", box=None, padding=(0, 2))
        table.add_column("#", style="dim", width=4)
        table.add_column("Path", style="yellow")
        for index, path in enumerate(result.written_paths[:20], start=1):
            table.add_row(str(index), path)
        console.print(table)
        if len(result.written_paths) > 20:
            console.print(f"[dim]...and {len(result.written_paths) - 20} more[/dim]")

    if result.errors:
        error_text = "\n".join(result.errors[:10])
        if len(result.errors) > 10:
            error_text += f"\n...and {len(result.errors) - 10} more"
        console.print(Panel(error_text, style="bold red", title="Import Warnings"))


async def export_codex_json_credentials():
    """Export Codex credentials to GPTSession2CPA/sub2api-compatible JSON."""
    clear_screen("Export Codex JSON Formats")
    credentials = load_codex_credentials_from_directory(_get_oauth_base_dir())
    if not credentials:
        console.print(
            Panel(
                "No Codex credentials found. Add or import Codex credentials first.",
                style="bold red",
                title="No Credentials",
            )
        )
        return

    table = Table(title="Supported Codex Export Formats", box=None, padding=(0, 2))
    table.add_column("#", style="dim", width=4)
    table.add_column("Format", style="cyan")
    table.add_column("Description", style="white")
    for index, format_info in enumerate(CODEX_EXPORT_FORMATS, start=1):
        table.add_row(str(index), format_info.label, format_info.description)
    console.print(table)

    choice = Prompt.ask(
        Text.from_markup("[bold]Select export format or type [red]'b'[/red] to go back[/bold]"),
        choices=[str(i) for i in range(1, len(CODEX_EXPORT_FORMATS) + 1)] + ["b"],
        show_choices=False,
    )
    if choice.lower() == "b":
        return

    format_info = CODEX_EXPORT_FORMATS[int(choice) - 1]
    timestamp = time.strftime("%Y%m%d%H%M%S")
    default_path = _get_oauth_base_dir() / f"codex-{format_info.id}-{timestamp}{format_info.extension}"
    raw_output = Prompt.ask(
        Text.from_markup("[bold]Output file path[/bold]"),
        default=str(default_path),
    )
    output_path = Path(_clean_prompt_path(raw_output))
    if not output_path.suffix:
        output_path = output_path.with_suffix(format_info.extension)

    try:
        written = write_codex_export_file(output_path, credentials, format_info.id)
    except Exception as exc:
        console.print(Panel(str(exc), style="bold red", title="Export Failed"))
        return

    console.print(
        Panel(
            Text.from_markup(
                f"Exported [bold cyan]{len(credentials)}[/bold cyan] Codex credential(s)\n"
                f"Format: [bold]{format_info.label}[/bold]\n"
                f"Output: [yellow]{written}[/yellow]"
            ),
            style="bold green",
            title="Codex Export Complete",
        )
    )


async def export_credentials_submenu():
    """
    Submenu for credential export options.
    """
    while True:
        clear_screen("Export Credentials")

        console.print(
            Panel(
                Text.from_markup(
                    "[bold]Individual Exports:[/bold]\n"
                    "1. Export Gemini CLI credential\n"
                    "2. Export Codex credential\n"
                    "3. Export Anthropic credential\n"
                    "4. Export Copilot credential\n"
                    "\n"
                    "[bold]Bulk Exports (per provider):[/bold]\n"
                    "5. Export ALL Gemini CLI credentials\n"
                    "6. Export ALL Codex credentials\n"
                    "7. Export ALL Anthropic credentials\n"
                    "8. Export ALL Copilot credentials\n"
                    "\n"
                    "[bold]Combine Credentials:[/bold]\n"
                    "9. Combine all Gemini CLI into one file\n"
                    "10. Combine all Codex into one file\n"
                    "11. Combine all Anthropic into one file\n"
                    "12. Combine all Copilot into one file\n"
                    "13. Combine ALL providers into one file\n"
                    "\n"
                    "[bold]Codex JSON Formats:[/bold]\n"
                    "14. Export ALL Codex to CPA/sub2api/Codex-Manager JSON"
                ),
                title="Choose export option",
                style="bold blue",
            )
        )

        export_choice = Prompt.ask(
            Text.from_markup(
                "[bold]Please select an option or type [red]'b'[/red] to go back[/bold]"
            ),
            choices=[
                "1", "2", "3", "4", "5", "6",
                "7", "8", "9", "10", "11", "12", "13", "14",
                "b",
            ],
            show_choices=False,
        )

        if export_choice.lower() == "b":
            break

        # Individual exports
        if export_choice == "1":
            await export_gemini_cli_to_env()
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "2":
            await export_codex_to_env()
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "3":
            await export_anthropic_to_env()
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "4":
            await export_copilot_to_env()
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        # Bulk exports (all credentials for a provider)
        elif export_choice == "5":
            await export_all_provider_credentials("gemini_cli")
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "6":
            await export_all_provider_credentials("codex")
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "7":
            await export_all_provider_credentials("anthropic")
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "8":
            await export_all_provider_credentials("copilot")
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        # Combine per provider
        elif export_choice == "9":
            await combine_provider_credentials("gemini_cli")
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "10":
            await combine_provider_credentials("codex")
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "11":
            await combine_provider_credentials("anthropic")
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "12":
            await combine_provider_credentials("copilot")
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        # Combine all providers
        elif export_choice == "13":
            await combine_all_credentials()
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()
        elif export_choice == "14":
            await export_codex_json_credentials()
            console.print("\n[dim]Press Enter to return to export menu...[/dim]")
            input()


async def main(clear_on_start=True):
    """
    An interactive CLI tool to add new credentials.

    Args:
        clear_on_start: If False, skip initial screen clear (used when called from launcher
                       to preserve the loading screen)
    """
    ensure_env_defaults()

    # Only show header if we're clearing (standalone mode)
    if clear_on_start:
        clear_screen()

    while True:
        # Clear screen between menu selections for cleaner UX
        clear_screen()

        # Display credentials summary at the top
        _display_credentials_summary()

        console.print(
            Panel(
                Text.from_markup(
                    "1. Add OAuth Credential\n"
                    "2. Add API Key\n"
                    "3. Add Custom OpenAI-Compatible Provider\n"
                    "4. Export Credentials\n"
                    "5. View Credentials\n"
                    "6. Manage Credentials\n"
                    "7. Import Codex JSON/JSONL Credentials"
                ),
                title="Choose action",
                style="bold blue",
            )
        )

        setup_type = Prompt.ask(
            Text.from_markup(
                "[bold]Please select an option or type [red]'q'[/red] to quit[/bold]"
            ),
            choices=["1", "2", "3", "4", "5", "6", "7", "q"],
            show_choices=False,
        )

        if setup_type.lower() == "q":
            break

        if setup_type == "1":
            # Clear and show OAuth providers summary before listing providers
            clear_screen("Add OAuth Credential")
            _display_oauth_providers_summary()

            provider_factory, _ = _ensure_providers_loaded()
            available_providers = provider_factory.get_available_providers()

            provider_text = Text()
            for i, provider in enumerate(available_providers):
                display_name = OAUTH_FRIENDLY_NAMES.get(
                    provider, provider.replace("_", " ").title()
                )
                provider_text.append(f"  {i + 1}. {display_name}\n")

            console.print(
                Panel(
                    provider_text,
                    title="Available Providers for OAuth",
                    style="bold blue",
                )
            )

            choice = Prompt.ask(
                Text.from_markup(
                    "[bold]Please select a provider or type [red]'b'[/red] to go back[/bold]"
                ),
                choices=[str(i + 1) for i in range(len(available_providers))] + ["b"],
                show_choices=False,
            )

            if choice.lower() == "b":
                continue

            try:
                choice_index = int(choice) - 1
                if 0 <= choice_index < len(available_providers):
                    provider_name = available_providers[choice_index]
                    display_name = OAUTH_FRIENDLY_NAMES.get(
                        provider_name, provider_name.replace("_", " ").title()
                    )

                    # Show existing credentials for this provider before proceeding
                    _display_provider_credentials(provider_name)

                    console.print(
                        f"Starting OAuth setup for [bold cyan]{display_name}[/bold cyan]..."
                    )
                    await setup_new_credential(provider_name)
                    # Don't clear after OAuth - user needs to see full flow
                    console.print("\n[dim]Press Enter to return to main menu...[/dim]")
                    input()
                else:
                    console.print(
                        "[bold red]Invalid choice. Please try again.[/bold red]"
                    )
                    await asyncio.sleep(1.5)
            except ValueError:
                console.print(
                    "[bold red]Invalid input. Please enter a number or 'b'.[/bold red]"
                )
                await asyncio.sleep(1.5)

        elif setup_type == "2":
            await setup_api_key()
            # console.print("\n[dim]Press Enter to return to main menu...[/dim]")
            # input()

        elif setup_type == "3":
            await setup_custom_openai_provider()

        elif setup_type == "4":
            await export_credentials_submenu()

        elif setup_type == "5":
            await view_credentials_menu()

        elif setup_type == "6":
            await manage_credentials_submenu()

        elif setup_type == "7":
            await import_codex_json_credentials()
            console.print("\n[dim]Press Enter to return to main menu...[/dim]")
            input()


def run_credential_tool(from_launcher=False):
    """
    Entry point for credential tool.

    Args:
        from_launcher: If True, skip loading screen (launcher already showed it)
    """
    # Check if we need to show loading screen
    if not from_launcher:
        # Standalone mode - show full loading UI
        os.system("cls" if os.name == "nt" else "clear")

        _start_time = time.time()

        # Phase 1: Show initial message
        print("━" * 70)
        print("Interactive Credential Setup Tool")
        print("GitHub: https://github.com/Mirrowel/LLM-API-Key-Proxy")
        print("━" * 70)
        print("Loading credential management components...")

        # Phase 2: Load dependencies with spinner
        with console.status("Loading authentication providers...", spinner="dots"):
            _ensure_providers_loaded()
        console.print("✓ Authentication providers loaded")

        with console.status("Initializing credential tool...", spinner="dots"):
            time.sleep(0.2)  # Brief pause for UI consistency
        console.print("✓ Credential tool initialized")

        _elapsed = time.time() - _start_time
        _, PROVIDER_PLUGINS = _ensure_providers_loaded()
        print(
            f"✓ Tool ready in {_elapsed:.2f}s ({len(PROVIDER_PLUGINS)} providers available)"
        )

        # Small delay to let user see the ready message
        time.sleep(0.5)

    # Run the main async event loop
    # If from launcher, don't clear screen at start to preserve loading messages
    try:
        asyncio.run(main(clear_on_start=not from_launcher))
        clear_screen()  # Clear terminal when credential tool exits
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Exiting setup.[/bold yellow]")
        clear_screen()  # Clear terminal on keyboard interrupt too
