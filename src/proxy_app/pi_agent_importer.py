# SPDX-License-Identifier: MIT
# Copyright (c) 2026 b3nw

"""Import Pi agent auth/model registry into proxy environment variables.

This module intentionally has no rotator_library imports. It must run before
provider plugin discovery so dynamic OpenAI-compatible providers can be
registered from the imported *_API_BASE variables.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
from typing import Any
from urllib.parse import urlparse


SUPPORTED_PROVIDER_APIS = {
    "anthropic-messages",
    "google-generative-ai",
    "openai-completions",
    "openai-responses",
}
# Windows rejects individual environment variable values above 32,767 chars.
# Leave headroom for implementation-specific accounting and fall back to a file.
MAX_ENV_VALUE_LENGTH = 30_000
_PI_MONO_MODELS_GLOB = "*.models.ts"
DEFAULT_AUTH_ALIASES = {
    # Pi names AI Studio credentials as "google" in auth.json, while models.json
    # exposes the OpenAI-compatible local gateway as "aistudio".
    "aistudio": ["google", "google-ai-studio", "ai-studio"],
    "anthropic": ["anthropic-oauth", "anthropic_oauth", "claude", "claude-code"],
    "anthropic_oauth": ["anthropic", "anthropic-oauth", "claude", "claude-code"],
    "antigravity": ["google-antigravity", "google_antigravity"],
    "codex": ["openai-codex", "openai_codex", "openai"],
    "copilot": ["github-copilot", "github_copilot", "github"],
    "gemini_cli": ["gemini-cli", "google-gemini-cli", "google_gemini_cli"],
    "github-copilot": ["copilot", "github_copilot", "github"],
    "iflow": ["iflowcn", "iflow-cn"],
    "openai-codex": ["codex", "openai_codex", "openai"],
    "qwen_code": ["qwen-code", "qwen", "qwen-ai"],
}

# Keep these prefixes aligned with rotator_library.credential_manager.  This
# module intentionally avoids importing rotator_library because it runs before
# provider plugin discovery.
NATIVE_OAUTH_IMPORTS: dict[str, dict[str, Any]] = {
    "gemini_cli": {"env_prefix": "GEMINI_CLI", "cache_provider": "gemini_cli"},
    "qwen_code": {"env_prefix": "QWEN_CODE", "cache_provider": "qwen_code"},
    "iflow": {"env_prefix": "IFLOW", "cache_provider": "iflow", "requires_api_key": True},
    "antigravity": {"env_prefix": "ANTIGRAVITY", "cache_provider": "antigravity"},
    "codex": {"env_prefix": "CODEX", "cache_provider": "codex"},
    "anthropic_oauth": {"env_prefix": "ANTHROPIC_OAUTH", "cache_provider": "anthropic"},
    "copilot": {"env_prefix": "COPILOT", "cache_provider": "copilot", "github_token_from_refresh": True},
}


@dataclass
class PiImportedCredential:
    """Credential imported from Pi auth.json without exposing the secret in cache."""

    secret: str
    source_type: str
    request: dict[str, Any] | None = None


@dataclass
class PiAgentImportSummary:
    """Result details for startup logging and diagnostics."""

    enabled: bool = False
    providers_loaded: int = 0
    api_keys_loaded: int = 0
    oauth_api_keys_loaded: int = 0
    oauth_credentials_loaded: int = 0
    credential_overrides_loaded: int = 0
    models_loaded: int = 0
    cache_path: str | None = None
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def compact_message(self) -> str:
        """Return a concise human-readable startup message."""
        if not self.enabled:
            return "Pi agent import disabled (no Pi auth/models metadata found)."

        message = (
            "Pi agent import loaded "
            f"{self.providers_loaded} provider(s), "
            f"{self.models_loaded} model(s), "
            f"{self.api_keys_loaded} API key slot(s)"
        )
        if self.oauth_api_keys_loaded:
            message += f", {self.oauth_api_keys_loaded} OAuth-as-key slot(s)"
        if self.oauth_credentials_loaded:
            message += f", {self.oauth_credentials_loaded} native OAuth credential(s)"
        if self.credential_overrides_loaded:
            message += f", {self.credential_overrides_loaded} request override(s)"
        if self.skipped:
            message += f"; skipped {len(self.skipped)} provider(s)"
        if self.cache_path:
            message += f"; cache: {self.cache_path}"
        return message


def import_pi_agent_config(
    *,
    root_dir: Path,
    current_port: int | None = None,
) -> PiAgentImportSummary:
    """Load Pi auth/models JSON files and expose them as proxy env vars.

    Optional env vars:
        PI_AGENT_IMPORT_ENABLED=false: disable importer
        PI_AGENT_AUTH_PATH: override path to Pi auth.json
        PI_AGENT_MODELS_PATH: override path to Pi models.json
        PI_AGENT_CACHE_PATH: override cache output path
        PI_AGENT_CREDENTIAL_OVERRIDES_DIR: override directory for large request overrides
        PI_AGENT_AUTH_ALIASES: comma list like "aistudio:google,foo:bar|baz"
        PI_AGENT_SKIP_PROVIDERS: comma list of Pi provider IDs to skip
    """
    summary = PiAgentImportSummary()

    if os.getenv("PI_AGENT_IMPORT_ENABLED", "true").lower() in {"0", "false", "no"}:
        return summary

    auth_path, models_path = _resolve_pi_metadata_paths(
        os.getenv("PI_AGENT_AUTH_PATH"),
        os.getenv("PI_AGENT_MODELS_PATH"),
    )
    if auth_path is None and models_path is None:
        return summary

    summary.enabled = True
    if auth_path is None or models_path is None:
        summary.warnings.append(
            "Both PI_AGENT_AUTH_PATH and PI_AGENT_MODELS_PATH are required, "
            "or ~/.pi/agent/auth.json and models.json must both exist."
        )
        return summary

    auth_data = _load_json_object(auth_path, "PI_AGENT_AUTH_PATH", summary)
    models_data = _load_json_object(models_path, "PI_AGENT_MODELS_PATH", summary)
    if auth_data is None or models_data is None:
        return summary

    providers_raw = models_data.get("providers")
    providers = dict(providers_raw) if isinstance(providers_raw, dict) else {}
    providers.update(
        {
            provider_id: provider_config
            for provider_id, provider_config in _discover_active_extension_providers(
                auth_path,
                models_path,
            ).items()
            if provider_id not in providers
        }
    )

    aliases = _load_auth_aliases()

    # --- Dynamically discover built-in pi-mono providers and merge ---
    builtin_defaults = _discover_builtin_provider_defaults(
        os.getenv("PI_MONO_PATH"),
        root_dir,
    )
    for _bpid, _bpinfo in builtin_defaults.items():
        if _bpid not in providers:
            _bmodels = _bpinfo.get("model_ids")
            if _bmodels and _has_matching_auth_entries(auth_data, _bpid, aliases):
                providers[_bpid] = {
                    "api": _bpinfo.get("api", ""),
                    "baseUrl": _bpinfo.get("baseUrl", ""),
                    "models": [{"id": mid} for mid in _bmodels],
                }

    if not isinstance(providers_raw, dict) and not providers:
        summary.warnings.append("PI_AGENT_MODELS_PATH does not contain a providers object.")
        return summary
    skip_providers = _load_csv_env("PI_AGENT_SKIP_PROVIDERS")
    cache_payload: dict[str, Any] = {
        "source": {
            "auth_path": str(auth_path),
            "models_path": str(models_path),
        },
        "providers": {},
        "oauth_providers": {},
    }
    imported_model_catalog: dict[str, dict[str, dict[str, Any]]] = {}

    for pi_provider_id, provider_config in providers.items():
        if not isinstance(provider_config, dict):
            summary.skipped.append(f"{pi_provider_id}: invalid provider config")
            continue

        if pi_provider_id.lower() in skip_providers:
            summary.skipped.append(f"{pi_provider_id}: skipped by PI_AGENT_SKIP_PROVIDERS")
            continue

        api_type = str(provider_config.get("api") or "").strip()
        if not api_type:
            _bp = builtin_defaults.get(pi_provider_id, {})
            api_type = str(_bp.get("api") or "openai-completions").strip()
        if api_type not in SUPPORTED_PROVIDER_APIS:
            summary.skipped.append(f"{pi_provider_id}: unsupported api '{api_type}'")
            continue

        base_url = str(provider_config.get("baseUrl") or "").strip()
        if not base_url:
            _bp = builtin_defaults.get(pi_provider_id, {})
            _candidate = str(_bp.get("baseUrl") or "").strip()
            if _candidate and "{" not in _candidate:
                base_url = _candidate
            else:
                base_url = _find_auth_base_url(
                    auth_data, pi_provider_id, aliases,
                )
        if not base_url:
            summary.skipped.append(f"{pi_provider_id}: missing baseUrl")
            continue

        if _is_self_referential_base_url(base_url, current_port):
            summary.skipped.append(f"{pi_provider_id}: self-referential baseUrl")
            continue

        env_prefix = _provider_env_prefix(pi_provider_id, provider_config)
        provider_name = env_prefix.lower()
        model_definitions = _build_model_definitions(
            provider_id=pi_provider_id,
            models=provider_config.get("models"),
        )
        if not model_definitions:
            summary.skipped.append(f"{pi_provider_id}: no usable models")
            continue

        os.environ.setdefault(f"{env_prefix}_API_BASE", base_url.rstrip("/"))
        os.environ.setdefault(f"{env_prefix}_MODELS", json.dumps(model_definitions))

        credentials, auth_entries_found = _find_provider_credentials(
            auth_data,
            provider_id=pi_provider_id,
            env_prefix=env_prefix,
            aliases=aliases,
        )
        using_model_api_key = False
        if not auth_entries_found:
            model_api_key_credential = _credential_from_provider_api_key(provider_config)
            if model_api_key_credential is not None:
                credentials = [model_api_key_credential]
                using_model_api_key = True
        loaded_keys, loaded_overrides, oauth_as_keys = _inject_numbered_api_keys(
            env_prefix,
            credentials,
            root_dir=root_dir,
            summary=summary,
            include_legacy_duplicate_check=not using_model_api_key,
        )

        summary.providers_loaded += 1
        summary.models_loaded += len(model_definitions)
        summary.api_keys_loaded += loaded_keys
        summary.oauth_api_keys_loaded += oauth_as_keys
        summary.credential_overrides_loaded += loaded_overrides
        if not loaded_keys:
            if auth_entries_found:
                summary.warnings.append(
                    f"{pi_provider_id}: matching auth entries did not produce usable API keys"
                )
            else:
                summary.warnings.append(f"{pi_provider_id}: no matching auth entries")
        if oauth_as_keys:
            summary.warnings.append(
                f"{pi_provider_id}: imported {oauth_as_keys} Pi OAuth credential(s) "
                "as API-key slots; refresh remains Pi-managed. Restart proxy after Pi refresh."
            )

        cache_payload["providers"][provider_name] = {
            "pi_provider_id": pi_provider_id,
            "api": api_type,
            "api_base": base_url.rstrip("/"),
            "models": list(model_definitions.keys()),
            "api_key_count": loaded_keys,
            "oauth_as_api_key_count": oauth_as_keys,
            "credential_override_count": loaded_overrides,
        }
        imported_model_catalog[provider_name] = model_definitions

    generated_model_env = _inject_auto_model_env_vars(imported_model_catalog)
    if generated_model_env:
        cache_payload["model_env"] = generated_model_env

    _import_supported_oauth_env_credentials(auth_data, aliases, summary, cache_payload)

    cache_path = _write_cache(root_dir, cache_payload, summary)
    if cache_path:
        summary.cache_path = str(cache_path)

    return summary


def _resolve_path(path_value: str) -> Path:
    expanded = os.path.expandvars(path_value.strip().strip('"'))
    return Path(expanded).expanduser()


def _load_json_object(
    path: Path,
    label: str,
    summary: PiAgentImportSummary,
) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        summary.warnings.append(f"{label} not found: {path}")
        return None
    except json.JSONDecodeError as exc:
        summary.warnings.append(f"{label} contains invalid JSON: {exc}")
        return None
    except OSError as exc:
        summary.warnings.append(f"{label} could not be read: {exc}")
        return None

    if not isinstance(data, dict):
        summary.warnings.append(f"{label} must contain a JSON object.")
        return None
    return data


def _resolve_pi_metadata_paths(
    auth_path_raw: str | None,
    models_path_raw: str | None,
) -> tuple[Path | None, Path | None]:
    if auth_path_raw or models_path_raw:
        auth_path = _resolve_path(auth_path_raw) if auth_path_raw else None
        models_path = _resolve_path(models_path_raw) if models_path_raw else None
        return auth_path, models_path

    for agent_dir in _candidate_pi_agent_dirs():
        candidate_auth_path = agent_dir / "auth.json"
        candidate_models_path = agent_dir / "models.json"
        if candidate_auth_path.is_file() and candidate_models_path.is_file():
            return candidate_auth_path, candidate_models_path

    return None, None


def _candidate_pi_agent_dirs() -> list[Path]:
    return [home_dir / ".pi" / "agent" for home_dir in _candidate_home_dirs()]


def _candidate_home_dirs() -> list[Path]:
    candidates: list[Path] = []
    for env_name in ("HOME", "USERPROFILE"):
        env_value = os.getenv(env_name)
        if env_value:
            candidates.append(_resolve_path(env_value))

    home_drive = os.getenv("HOMEDRIVE")
    home_path = os.getenv("HOMEPATH")
    if home_drive and home_path:
        candidates.append(_resolve_path(f"{home_drive}{home_path}"))

    try:
        candidates.append(Path.home())
    except RuntimeError:
        pass

    return _dedupe_paths(candidates)


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            key = os.path.normcase(str(path.resolve(strict=False)))
        except OSError:
            key = os.path.normcase(str(path.absolute()))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def _discover_active_extension_providers(
    auth_path: Path,
    models_path: Path,
) -> dict[str, dict[str, Any]]:
    providers: dict[str, dict[str, Any]] = {}
    for extensions_root in _active_extension_roots(auth_path, models_path):
        for extension_dir in _iter_extension_package_dirs(extensions_root):
            package_data = _load_json_file_object(extension_dir / "package.json")
            if package_data is None:
                continue
            for provider_config in _load_extension_provider_configs(extension_dir, package_data):
                normalized_provider = _normalize_extension_provider_config(provider_config)
                if normalized_provider is None:
                    continue
                provider_id = str(normalized_provider.pop("providerId"))
                providers.setdefault(provider_id, normalized_provider)
    return providers


def _active_extension_roots(auth_path: Path, models_path: Path) -> list[Path]:
    candidates = [auth_path.parent / "extensions", models_path.parent / "extensions"]
    return [path for path in _dedupe_paths(candidates) if path.is_dir()]


def _iter_extension_package_dirs(extensions_root: Path):
    if (extensions_root / "package.json").is_file():
        yield extensions_root

    try:
        children = sorted(extensions_root.iterdir(), key=lambda path: path.name.lower())
    except OSError:
        return

    for child in children:
        if child.is_dir() and (child / "package.json").is_file():
            yield child


def _load_json_file_object(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _load_extension_provider_configs(
    extension_dir: Path,
    package_data: dict[str, Any],
) -> list[dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    config_paths: list[Path] = []

    pi_metadata = package_data.get("pi")
    if isinstance(pi_metadata, dict):
        extension_entries = pi_metadata.get("extensions")
        if isinstance(extension_entries, list):
            for entry in extension_entries:
                if not isinstance(entry, dict):
                    continue
                kind = str(entry.get("kind") or entry.get("type") or "").strip().lower()
                if kind and kind != "provider":
                    continue
                config_value = entry.get("config") or entry.get("configPath") or entry.get("path")
                if isinstance(config_value, dict):
                    configs.append(config_value)
                elif isinstance(config_value, str):
                    config_path = _safe_extension_config_path(extension_dir, config_value)
                    if config_path is not None:
                        config_paths.append(config_path)

        provider_metadata = pi_metadata.get("provider")
        if isinstance(provider_metadata, dict):
            configs.append(provider_metadata)

    if not config_paths:
        fallback_path = extension_dir / "config.json"
        if fallback_path.is_file():
            config_paths.append(fallback_path)

    for config_path in _dedupe_paths(config_paths):
        config_data = _load_json_file_object(config_path)
        if config_data is not None:
            configs.append(config_data)

    return configs


def _safe_extension_config_path(extension_dir: Path, config_value: str) -> Path | None:
    config_name = config_value.strip()
    if not config_name:
        return None

    try:
        extension_root = extension_dir.resolve(strict=False)
        config_path = (extension_dir / config_name).resolve(strict=False)
    except OSError:
        return None

    if not config_path.is_relative_to(extension_root):
        return None
    return config_path


def _normalize_extension_provider_config(
    config_data: dict[str, Any],
) -> dict[str, Any] | None:
    provider_id = _first_string(config_data, "providerId", "provider_id", "id")
    if not provider_id:
        return None

    models = _normalize_extension_models(config_data.get("models"))
    if not models:
        return None

    api_type = _first_string(config_data, "api", "apiType", "api_type") or ""
    base_url = _first_string(
        config_data,
        "baseUrl",
        "base_url",
        "upstreamUrl",
        "upstream_url",
    )

    provider_config: dict[str, Any] = {
        "providerId": provider_id,
        "api": api_type,
        "baseUrl": base_url or "",
        "models": models,
    }
    api_key = _first_string(config_data, "apiKey", "api_key")
    if api_key:
        provider_config["apiKey"] = api_key
    return provider_config


def _normalize_extension_models(models: Any) -> list[dict[str, Any]]:
    if isinstance(models, list):
        return [model for item in models if (model := _normalize_extension_model(item))]

    if isinstance(models, dict):
        normalized_models: list[dict[str, Any]] = []
        for model_id, model_config in models.items():
            model = _normalize_extension_model(model_config)
            if model is None and isinstance(model_id, str):
                model = {"id": model_id}
            elif model is not None and not model.get("id") and isinstance(model_id, str):
                model["id"] = model_id
            if model is not None:
                normalized_models.append(model)
        return normalized_models

    return []


def _normalize_extension_model(model: Any) -> dict[str, Any] | None:
    if isinstance(model, str) and model.strip():
        return {"id": model.strip()}

    if not isinstance(model, dict):
        return None

    normalized_model = dict(model)
    model_id = _first_string(normalized_model, "id", "modelId", "model_id", "name")
    if not model_id:
        return None
    normalized_model["id"] = model_id
    return normalized_model


def _first_string(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _load_csv_env(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _load_auth_aliases() -> dict[str, list[str]]:
    aliases = {key: list(value) for key, value in DEFAULT_AUTH_ALIASES.items()}
    raw = os.getenv("PI_AGENT_AUTH_ALIASES", "")
    for pair in raw.split(","):
        if ":" not in pair:
            continue
        provider_id, alias_raw = pair.split(":", 1)
        provider_id = provider_id.strip().lower()
        provider_aliases = [
            alias.strip().lower()
            for alias in re.split(r"[|;]", alias_raw)
            if alias.strip()
        ]
        if provider_id and provider_aliases:
            aliases.setdefault(provider_id, []).extend(provider_aliases)
    return aliases


def _provider_env_prefix(provider_id: str, provider_config: dict[str, Any]) -> str:
    api_key_name = str(provider_config.get("apiKey") or "").strip()
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*_API_KEY", api_key_name):
        return api_key_name[:-8].upper()
    return _sanitize_env_prefix(provider_id)


def _sanitize_env_prefix(value: str) -> str:
    prefix = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    return prefix or "PI_AGENT_PROVIDER"


def _build_model_definitions(
    *,
    provider_id: str,
    models: Any,
) -> dict[str, dict[str, Any]]:
    if not isinstance(models, list):
        return {}

    definitions: dict[str, dict[str, Any]] = {}
    provider_headers = _provider_default_headers(provider_id)
    for model in models:
        if not isinstance(model, dict):
            continue
        model_id = str(model.get("id") or "").strip()
        if not model_id:
            continue

        display_id = model_id.rsplit("/", 1)[-1]
        if display_id in definitions:
            display_id = model_id

        options: dict[str, Any] = {}
        extra_headers = dict(provider_headers)
        headers = model.get("headers")
        if isinstance(headers, dict):
            extra_headers.update(
                {
                    str(key).strip(): value
                    for key, value in headers.items()
                    if str(key).strip() and isinstance(value, str)
                }
            )
        if extra_headers:
            options["extra_headers"] = extra_headers

        definition: dict[str, Any] = {"id": model_id}
        if options:
            definition["options"] = options
        definitions[display_id] = definition

    return definitions


def _provider_default_headers(provider_id: str) -> dict[str, str]:
    normalized = provider_id.strip().lower()
    if normalized == "kilo":
        return {"X-KILOCODE-EDITORNAME": "Pi"}
    if normalized == "cline":
        return {
            "Accept": "application/json",
            "User-Agent": "Cline/3.80.0",
            "X-PLATFORM": "Visual Studio Code",
            "X-PLATFORM-VERSION": "1.109.3",
            "X-CLIENT-TYPE": "VSCode Extension",
            "X-CLIENT-VERSION": "3.80.0",
            "X-CORE-VERSION": "3.80.0",
            "HTTP-Referer": "https://cline.bot",
            "X-Title": "Cline",
            "X-IS-MULTIROOT": "false",
        }
    return {}


def _find_provider_credentials(
    auth_data: dict[str, Any],
    *,
    provider_id: str,
    env_prefix: str,
    aliases: dict[str, list[str]],
) -> tuple[list[PiImportedCredential], bool]:
    candidate_names = [provider_id, env_prefix]
    candidate_names.extend(aliases.get(provider_id.lower(), []))
    normalized_candidates = {_normalize_auth_name(name) for name in candidate_names}

    matched: list[tuple[tuple[int, str], PiImportedCredential]] = []
    auth_entries_found = False
    for auth_name, auth_config in auth_data.items():
        if not isinstance(auth_config, dict):
            continue
        sort_key = _auth_match_sort_key(auth_name, normalized_candidates)
        if sort_key is None:
            continue

        auth_entries_found = True
        credential = _credential_from_auth_config(provider_id, auth_config)
        if credential is not None:
            matched.append((sort_key, credential))

    matched.sort(key=lambda item: item[0])
    credentials: list[PiImportedCredential] = []
    seen: set[tuple[str, str]] = set()
    for _, credential in matched:
        dedupe_key = (
            credential.secret,
            json.dumps(credential.request or {}, sort_keys=True),
        )
        if dedupe_key in seen:
            continue
        credentials.append(credential)
        seen.add(dedupe_key)
    return credentials, auth_entries_found


def _credential_from_auth_config(
    provider_id: str,
    auth_config: dict[str, Any],
) -> PiImportedCredential | None:
    request = _normalize_request_overrides(auth_config.get("request"))
    credential_type = auth_config.get("type")
    if credential_type == "api_key":
        api_key = _resolve_pi_config_value(auth_config.get("key"))
        if api_key:
            return PiImportedCredential(
                secret=api_key,
                source_type="api_key",
                request=request,
            )
        return None

    if credential_type == "oauth":
        oauth_secret = _oauth_as_api_key_secret(provider_id, auth_config)
        if oauth_secret:
            return PiImportedCredential(
                secret=oauth_secret,
                source_type="oauth_as_api_key",
                request=request,
            )
    return None


def _credential_from_provider_api_key(
    provider_config: dict[str, Any],
) -> PiImportedCredential | None:
    api_key = _resolve_pi_config_value(provider_config.get("apiKey"))
    if not api_key:
        return None
    return PiImportedCredential(secret=api_key, source_type="api_key")


def _resolve_pi_config_value(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    lookup_value = value.strip()
    if not lookup_value:
        return None

    if lookup_value.startswith("!"):
        command = lookup_value[1:].strip()
        if not command:
            return None
        try:
            args = shlex.split(command, posix=os.name != "nt")
            if not args:
                return None
            completed = subprocess.run(
                args,
                capture_output=True,
                check=True,
                shell=False,
                text=True,
            )
        except (OSError, ValueError, subprocess.CalledProcessError):
            return None
        resolved = completed.stdout.strip()
        return resolved or None

    env_value = os.environ.get(lookup_value)
    if env_value is not None:
        return env_value
    return value


def _oauth_as_api_key_secret(provider_id: str, auth_config: dict[str, Any]) -> str | None:
    access_token = auth_config.get("access")
    if not isinstance(access_token, str) or not access_token:
        return None

    normalized = provider_id.strip().lower()
    if normalized == "kilo":
        return access_token
    if normalized == "cline":
        return f"workos:{access_token}"
    return None


def _normalize_request_overrides(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None

    request: dict[str, Any] = {}
    base_url = value.get("baseUrl")
    if isinstance(base_url, str) and base_url.strip():
        request["base_url"] = base_url.strip().rstrip("/")

    headers = value.get("headers")
    if isinstance(headers, dict):
        normalized_headers = {
            str(key).strip(): header_value
            for key, header_value in headers.items()
            if str(key).strip() and isinstance(header_value, str)
        }
        if normalized_headers:
            request["headers"] = normalized_headers

    return request or None


def _normalize_auth_name(value: str) -> str:
    return re.sub(r"[-_]+", "-", value.strip().lower())


def _auth_match_sort_key(
    auth_name: str,
    normalized_candidates: set[str],
) -> tuple[int, str] | None:
    normalized_name = _normalize_auth_name(auth_name)
    for candidate in normalized_candidates:
        if normalized_name == candidate:
            return (0, normalized_name)
        prefix = f"{candidate}-"
        if normalized_name.startswith(prefix):
            suffix = normalized_name[len(prefix) :]
            if suffix.isdigit():
                return (int(suffix) + 1, normalized_name)
    return None


def _inject_numbered_api_keys(
    env_prefix: str,
    credentials: list[PiImportedCredential],
    *,
    root_dir: Path,
    summary: PiAgentImportSummary,
    include_legacy_duplicate_check: bool = True,
) -> tuple[int, int, int]:
    loaded = 0
    overrides_loaded = 0
    oauth_as_keys_loaded = 0
    index = 1
    existing_values = {
        value
        for key, value in os.environ.items()
        if key.startswith(f"{env_prefix}_API_KEY_")
    }
    legacy_api_key = os.environ.get(f"{env_prefix}_API_KEY")
    if include_legacy_duplicate_check and legacy_api_key:
        existing_values.add(legacy_api_key)
    credential_overrides = _load_json_env_dict(f"{env_prefix}_CREDENTIAL_OVERRIDES")

    for credential in credentials:
        if credential.secret in existing_values:
            continue
        while os.environ.get(f"{env_prefix}_API_KEY_{index}"):
            index += 1
        os.environ[f"{env_prefix}_API_KEY_{index}"] = credential.secret
        existing_values.add(credential.secret)
        loaded += 1
        if credential.source_type == "oauth_as_api_key":
            oauth_as_keys_loaded += 1
        if credential.request:
            credential_overrides[_credential_hash(credential.secret)] = credential.request
            overrides_loaded += 1
        index += 1

    if credential_overrides:
        _store_credential_overrides(
            env_prefix,
            credential_overrides,
            root_dir=root_dir,
            summary=summary,
        )

    return loaded, overrides_loaded, oauth_as_keys_loaded


def _store_credential_overrides(
    env_prefix: str,
    credential_overrides: dict[str, Any],
    *,
    root_dir: Path,
    summary: PiAgentImportSummary,
) -> None:
    env_name = f"{env_prefix}_CREDENTIAL_OVERRIDES"
    path_env_name = f"{env_prefix}_CREDENTIAL_OVERRIDES_PATH"
    serialized = json.dumps(
        credential_overrides,
        sort_keys=True,
        separators=(",", ":"),
    )

    if len(serialized) <= MAX_ENV_VALUE_LENGTH:
        os.environ[env_name] = serialized
        return

    path = _credential_overrides_path(env_prefix, root_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            handle.write(serialized)
    except OSError as exc:
        summary.warnings.append(
            f"{env_prefix}: credential overrides too large for environment "
            f"and could not be written to {path}: {exc}"
        )
        return

    os.environ[path_env_name] = str(path)
    os.environ.pop(env_name, None)


def _credential_overrides_path(env_prefix: str, root_dir: Path) -> Path:
    explicit_path = os.getenv(f"{env_prefix}_CREDENTIAL_OVERRIDES_PATH")
    if explicit_path:
        return _resolve_path(explicit_path)

    overrides_dir_raw = os.getenv("PI_AGENT_CREDENTIAL_OVERRIDES_DIR")
    overrides_dir = (
        _resolve_path(overrides_dir_raw)
        if overrides_dir_raw
        else root_dir / "cache" / "pi_agent_credential_overrides"
    )
    return overrides_dir / f"{env_prefix.lower()}.json"


def _load_json_env_dict(name: str) -> dict[str, Any]:
    raw = os.getenv(name)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _credential_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _inject_auto_model_env_vars(
    provider_models: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, str]:
    generated: dict[str, str] = {}
    generated.update(_inject_cross_provider_aliases(provider_models))
    generated.update(_inject_latest_model_aliases(provider_models))
    return generated


def _inject_cross_provider_aliases(
    provider_models: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, str]:
    grouped: dict[str, list[tuple[str, str]]] = {}
    for provider, models in provider_models.items():
        for display_name, definition in models.items():
            canonical = _canonical_model_alias_name(display_name, definition)
            if not canonical:
                continue
            grouped.setdefault(canonical, []).append((provider, display_name))

    generated: dict[str, str] = {}
    for canonical, targets in sorted(grouped.items()):
        providers = {provider for provider, _ in targets}
        if len(providers) < 2:
            continue
        env_name = f"MODEL_ALIAS_{_model_env_suffix(canonical)}"
        if os.getenv(env_name):
            continue
        value = ",".join(
            f"{provider}:{model_name}"
            for provider, model_name in sorted(targets, key=lambda item: item[0])
        )
        os.environ[env_name] = value
        generated[env_name] = value
    return generated


def _inject_latest_model_aliases(
    provider_models: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, str]:
    generated: dict[str, str] = {}
    for provider, models in sorted(provider_models.items()):
        series: dict[str, str] = {}
        series_counts: dict[str, int] = {}
        for display_name, definition in models.items():
            model_name = _bare_model_name(definition.get("id") or display_name)
            series_name, glob_pattern = _version_series_name_and_glob(model_name)
            if not series_name or not glob_pattern:
                continue
            series[series_name] = glob_pattern
            series_counts[series_name] = series_counts.get(series_name, 0) + 1

        for series_name, count in sorted(series_counts.items()):
            if count < 2:
                continue
            alias_name = f"{provider}-{series_name}-latest"
            env_name = f"MODEL_LATEST_{_model_env_suffix(alias_name)}"
            if os.getenv(env_name):
                continue
            value = f"{provider}:{series[series_name]}"
            os.environ[env_name] = value
            generated[env_name] = value
    return generated


def _canonical_model_alias_name(display_name: str, definition: dict[str, Any]) -> str:
    model_id = definition.get("id")
    candidate = _bare_model_name(model_id) if isinstance(model_id, str) else display_name
    return candidate.strip().lower().replace(".", "-")


def _bare_model_name(model_name: Any) -> str:
    value = str(model_name or "").strip()
    return value.rsplit("/", 1)[-1]


def _version_series_name_and_glob(model_name: str) -> tuple[str | None, str | None]:
    bare_name = _bare_model_name(model_name).strip().lower()
    if not bare_name:
        return None, None

    first_digit = re.search(r"\d", bare_name)
    if first_digit is None:
        return None, None

    glob_prefix = bare_name[: first_digit.start()]
    series_name = glob_prefix.rstrip("-_.")
    if len(series_name) < 2:
        return None, None
    return series_name.replace(".", "-"), f"{glob_prefix}*"


def _model_env_suffix(value: str) -> str:
    suffix = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    return suffix or "MODEL"


def _import_supported_oauth_env_credentials(
    auth_data: dict[str, Any],
    aliases: dict[str, list[str]],
    summary: PiAgentImportSummary,
    cache_payload: dict[str, Any],
) -> None:
    for provider_id, spec in NATIVE_OAUTH_IMPORTS.items():
        count = _import_native_oauth_credentials(auth_data, provider_id, spec, aliases)
        if not count:
            continue

        summary.oauth_credentials_loaded += count
        cache_payload["oauth_providers"][spec["cache_provider"]] = {
            "pi_provider_id": provider_id,
            "credential_count": count,
        }


def _import_native_oauth_credentials(
    auth_data: dict[str, Any],
    provider_id: str,
    spec: dict[str, Any],
    aliases: dict[str, list[str]],
) -> int:
    env_prefix = str(spec["env_prefix"])
    entries = _find_oauth_auth_configs(auth_data, provider_id, aliases)
    token_suffix = "GITHUB_TOKEN" if spec.get("github_token_from_refresh") else "ACCESS_TOKEN"
    existing_tokens = _existing_env_values(env_prefix, token_suffix)
    loaded = 0

    for _, auth_config in entries:
        if spec.get("github_token_from_refresh"):
            primary_token = _auth_string(auth_config, "refresh")
            if not primary_token:
                continue
        else:
            primary_token = _auth_string(auth_config, "access")
            refresh_token = _auth_string(auth_config, "refresh")
            if not primary_token or not refresh_token:
                continue

        if primary_token in existing_tokens:
            continue

        api_key = _oauth_api_key(auth_config)
        if spec.get("requires_api_key") and not api_key:
            continue

        index = _next_numbered_env_index(env_prefix)
        prefix = f"{env_prefix}_{index}"
        if spec.get("github_token_from_refresh"):
            os.environ[f"{prefix}_GITHUB_TOKEN"] = primary_token
        else:
            os.environ[f"{prefix}_ACCESS_TOKEN"] = primary_token
            os.environ[f"{prefix}_REFRESH_TOKEN"] = refresh_token
            _set_optional_env(prefix, "API_KEY", api_key)
            _set_optional_env(prefix, "ID_TOKEN", _auth_string(auth_config, "id"))

        _set_optional_env(prefix, "ACCOUNT_ID", _auth_string(auth_config, "accountId"))
        _set_optional_env(prefix, "EMAIL", _auth_string(auth_config, "email"))
        _set_optional_env(prefix, "PROJECT_ID", _auth_string(auth_config, "projectId"))
        _set_optional_env(prefix, "RESOURCE_URL", _auth_string(auth_config, "resourceUrl"))
        _set_optional_env(prefix, "TIER", _auth_string(auth_config, "tier"))
        _set_oauth_expiry_env(prefix, auth_config.get("expires"))
        existing_tokens.add(primary_token)
        loaded += 1
    return loaded


def _auth_string(auth_config: dict[str, Any], key: str) -> str | None:
    value = auth_config.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _oauth_api_key(auth_config: dict[str, Any]) -> str | None:
    for key in ("apiKey", "api_key", "key"):
        value = _auth_string(auth_config, key)
        if value:
            return value
    return None


def _set_oauth_expiry_env(prefix: str, value: Any) -> None:
    if value is None:
        return
    value_str = str(value).strip()
    if not value_str:
        return
    os.environ[f"{prefix}_EXPIRES"] = value_str
    os.environ[f"{prefix}_EXPIRY_DATE"] = value_str


def _find_oauth_auth_configs(
    auth_data: dict[str, Any],
    provider_id: str,
    aliases: dict[str, list[str]],
) -> list[tuple[tuple[int, str], dict[str, Any]]]:
    candidate_names = [provider_id]
    candidate_names.extend(aliases.get(provider_id.lower(), []))
    normalized_candidates = {_normalize_auth_name(name) for name in candidate_names}
    entries: list[tuple[tuple[int, str], dict[str, Any]]] = []
    for auth_name, auth_config in auth_data.items():
        if not isinstance(auth_config, dict) or auth_config.get("type") != "oauth":
            continue
        sort_key = _auth_match_sort_key(auth_name, normalized_candidates)
        if sort_key is not None:
            entries.append((sort_key, auth_config))
    entries.sort(key=lambda item: item[0])
    return entries


def _existing_env_values(env_prefix: str, suffix: str) -> set[str]:
    values: set[str] = set()
    legacy_name = f"{env_prefix}_{suffix}"
    if os.getenv(legacy_name):
        values.add(os.environ[legacy_name])

    pattern = re.compile(rf"^{re.escape(env_prefix)}_(\d+)_{re.escape(suffix)}$")
    for key, value in os.environ.items():
        if pattern.match(key) and value:
            values.add(value)
    return values


def _next_numbered_env_index(env_prefix: str) -> int:
    index = 1
    while any(key.startswith(f"{env_prefix}_{index}_") for key in os.environ):
        index += 1
    return index


def _set_optional_env(prefix: str, suffix: str, value: Any) -> None:
    if value is None:
        return
    value_str = str(value).strip()
    if value_str:
        os.environ[f"{prefix}_{suffix}"] = value_str


def _is_self_referential_base_url(base_url: str, current_port: int | None) -> bool:
    if current_port is None:
        return False
    parsed = urlparse(base_url)
    hostname = (parsed.hostname or "").lower()
    return hostname in {"127.0.0.1", "localhost", "::1"} and parsed.port == current_port


def _write_cache(
    root_dir: Path,
    payload: dict[str, Any],
    summary: PiAgentImportSummary,
) -> Path | None:
    cache_path_raw = os.getenv("PI_AGENT_CACHE_PATH")
    cache_path = (
        _resolve_path(cache_path_raw)
        if cache_path_raw
        else root_dir / "cache" / "pi_agent_import_cache.json"
    )
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return cache_path
    except OSError as exc:
        summary.warnings.append(f"PI agent cache could not be written: {exc}")
        return None


# ---------------------------------------------------------------------------
# Built-in pi-mono provider discovery
# ---------------------------------------------------------------------------

def _discover_builtin_provider_defaults(
    pi_mono_path_env: str | None,
    root_dir: Path,
) -> dict[str, dict[str, Any]]:
    """Dynamically discover built-in provider configs from pi-mono source.

    Scans ``*.models.ts`` files in the pi-mono providers directory to extract
    each provider's API type, base URL, and model IDs.  Results are cached so
    the filesystem is only scanned once per process.
    """
    mono_root = _find_pi_mono_root(pi_mono_path_env, root_dir)
    if mono_root is None:
        return {}

    providers_dir = mono_root / "packages" / "ai" / "src" / "providers"
    if not providers_dir.is_dir():
        return {}

    defaults: dict[str, dict[str, Any]] = {}
    for models_file in sorted(providers_dir.glob(_PI_MONO_MODELS_GLOB)):
        try:
            content = models_file.read_text(encoding="utf-8")
        except OSError:
            continue

        provider_ids = re.findall(r'provider:\s+"([^"]+)"', content)
        if not provider_ids:
            continue
        provider_id = provider_ids[0]

        apis = re.findall(r'\bapi:\s+"([^"]+)"', content)
        # Prefer openai-completions if multiple APIs are available (most common)
        api_type = "openai-completions" if "openai-completions" in apis else (apis[0] if apis else "")

        base_urls = re.findall(r'baseUrl:\s+"([^"]+)"', content)
        # Prefer URLs without template variables and with /v1 suffix
        base_url = ""
        for url in base_urls:
            if "{" not in url:
                base_url = url
                break
        if not base_url and base_urls:
            base_url = base_urls[0]

        model_ids = re.findall(r'^\t"([^"]+)":\s+\{', content, re.MULTILINE)

        defaults[provider_id] = {
            "api": api_type,
            "baseUrl": base_url,
            "model_ids": model_ids,
        }

    return defaults


def _find_pi_mono_root(
    pi_mono_path_env: str | None,
    root_dir: Path,
) -> Path | None:
    """Locate the pi-mono repository root directory.

    Search order:
      1. ``PI_MONO_PATH`` environment variable
      2. Sibling directory of the proxy root (``root_dir/.. / pi-mono``)
      3. Common development paths relative to the proxy root
    """
    resolved_root = root_dir.resolve()
    candidates: list[Path] = []

    if pi_mono_path_env:
        candidates.append(_resolve_path(pi_mono_path_env))

    # Sibling of the proxy project root
    parent = resolved_root.parent
    candidates.append(parent / "pi-mono")

    # Also check two levels up (e.g. ~/repos/pi-mono)
    grandparent = parent.parent if parent else resolved_root
    candidates.append(grandparent / "pi-mono")

    for candidate in _dedupe_paths(candidates):
        providers_dir = candidate / "packages" / "ai" / "src" / "providers"
        if providers_dir.is_dir():
            return candidate

    return None


def _find_auth_base_url(
    auth_data: dict[str, Any],
    provider_id: str,
    aliases: dict[str, list[str]],
) -> str:
    """Return the first matching auth entry's ``request.baseUrl``.

    Used as a fallback when a provider has no global base URL (e.g. per-account
    Cloudflare Workers AI endpoints).
    """
    candidate_names = [provider_id]
    candidate_names.extend(aliases.get(provider_id.lower(), []))
    normalized_candidates = {_normalize_auth_name(name) for name in candidate_names}

    for auth_name, auth_config in auth_data.items():
        if not isinstance(auth_config, dict):
            continue
        if _auth_match_sort_key(auth_name, normalized_candidates) is None:
            continue
        request = auth_config.get("request")
        if isinstance(request, dict):
            url = request.get("baseUrl")
            if isinstance(url, str) and url.strip():
                return url.strip().rstrip("/")
    return ""


def _has_matching_auth_entries(
    auth_data: dict[str, Any],
    provider_id: str,
    aliases: dict[str, list[str]],
) -> bool:
    """Return True if *any* auth entry matches the given provider ID.

    Lightweight check used before synthesising built-in provider entries to
    avoid adding providers that have no credentials in the local auth store.
    """
    candidate_names = [provider_id]
    candidate_names.extend(aliases.get(provider_id.lower(), []))
    normalized_candidates = {_normalize_auth_name(name) for name in candidate_names}

    for auth_name, auth_config in auth_data.items():
        if not isinstance(auth_config, dict):
            continue
        if _auth_match_sort_key(auth_name, normalized_candidates) is not None:
            return True
    return False
