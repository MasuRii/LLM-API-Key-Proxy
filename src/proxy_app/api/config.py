"""Admin API for proxy configuration and credential management."""

import asyncio
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from dotenv import load_dotenv
from rotator_library.utils.paths import get_data_file

_credential_lock = asyncio.Lock()

router = APIRouter(prefix="/v1/admin", tags=["admin-config"])


def _read_json(path: Path) -> dict:
    with open(path) as fh:
        return json.load(fh)

logger = logging.getLogger(__name__)

# Matches a .env KEY (exported or not), capturing the key name.
# Handles: KEY=..., export KEY=...,  KEY =...
_ENV_KEY_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def _env_path() -> Path:
    return get_data_file(".env")


def _inplace_set_key(dotenv_path: str, key: str, value: str) -> None:
    """Write-in-place replacement for dotenv.set_key.

    python-dotenv's set_key uses os.replace() under the hood, which fails
    with EBUSY when the .env file is a Docker bind-mount. This helper
    reads, modifies, and writes back in-place (truncate mode) instead.
    """
    path = Path(dotenv_path)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = existing.splitlines(keepends=True)
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    new_line = f'{key}="{escaped}"\n'

    found = False
    for i, line in enumerate(lines):
        m = _ENV_KEY_RE.match(line)
        if m and m.group(1) == key:
            lines[i] = new_line
            found = True
            break

    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(new_line)

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _inplace_unset_key(dotenv_path: str, key: str) -> None:
    """Write-in-place replacement for dotenv.unset_key.

    Same motivation as _inplace_set_key — avoids os.replace().
    """
    path = Path(dotenv_path)
    if not path.exists():
        return
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    new_lines = []
    for line in lines:
        m = _ENV_KEY_RE.match(line)
        if m and m.group(1) == key:
            continue
        new_lines.append(line)

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


def _oauth_dir() -> Path:
    import sys
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).parent
    else:
        base = Path.cwd()
    d = base / "oauth_creds"
    d.mkdir(exist_ok=True)
    return d


def _get_env_vars() -> dict[str, str]:
    """Read all env vars from the .env file."""
    from dotenv import dotenv_values
    vals = dotenv_values(_env_path())
    return {k: v for k, v in vals.items() if v is not None}


def _mask_key(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]


@dataclass(frozen=True)
class CredentialDeletionCandidate:
    type: str
    provider: str
    identifier: str
    key_name: Optional[str] = None
    filename: Optional[str] = None
    key_value: Optional[str] = None
    target: Optional[Path] = None
    stable_id: Optional[str] = None
    usage_accessors: tuple[str, ...] = ()
    usage_filenames: tuple[str, ...] = ()


def _api_key_provider_from_name(key_name: str) -> Optional[str]:
    if key_name.startswith("PROXY_"):
        return None
    match = re.fullmatch(r"(.+?)_API_KEY(?:_\d+)?", key_name)
    if not match:
        return None
    return match.group(1).lower()


def _oauth_provider_from_filename(filename: str) -> Optional[str]:
    match = re.fullmatch(r"(.+?)_oauth_\d+\.json", filename)
    if not match:
        return None
    return match.group(1).lower()


def _normalize_status_filter(statuses: Optional[list[str]]) -> set[str]:
    selected: set[str] = set()
    for value in statuses or []:
        selected.update(part.strip().lower() for part in value.split(",") if part.strip())
    return selected


def _api_key_stable_id_from_value(key_value: str) -> str:
    return hashlib.sha256(key_value.encode()).hexdigest()[:12]


def _oauth_stable_id_from_payload(data: dict) -> str:
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


def _oauth_stable_id_from_file(path: Path) -> str:
    try:
        return _oauth_stable_id_from_payload(_read_json(path))
    except Exception:
        return ""


def _oauth_number_from_filename(filename: str) -> str:
    match = re.fullmatch(r".+?_oauth_(\d+)\.json", filename)
    return match.group(1) if match else ""


def _cleanup_usage_for_deleted_candidate(candidate: CredentialDeletionCandidate) -> dict:
    payload = {
        "type": candidate.type,
        "provider": candidate.provider,
        "identifier": candidate.identifier,
        "stable_id": candidate.stable_id or "",
        "usage_accessors": list(candidate.usage_accessors),
        "usage_filenames": list(candidate.usage_filenames),
    }
    if candidate.key_name:
        payload["key_name"] = candidate.key_name
    if candidate.filename:
        payload["filename"] = candidate.filename
    if candidate.target:
        payload["file_path"] = str(candidate.target)

    try:
        from rotator_library.credential_tool import _cleanup_deleted_credential_usage

        return _cleanup_deleted_credential_usage(payload)
    except Exception as exc:
        return {
            "success": False,
            "files_scanned": 0,
            "files_updated": 0,
            "removed_credentials": 0,
            "removed_accessors": 0,
            "leftovers": [],
            "errors": [f"usage cleanup failed: {exc}"],
        }


def _validate_api_key_candidate(
    provider: str,
    key_name: Optional[str],
    env_vars: dict[str, str],
) -> CredentialDeletionCandidate:
    provider_lower = provider.lower()
    if not key_name:
        raise HTTPException(status_code=400, detail="key_name is required for API key deletion")
    if key_name not in env_vars:
        raise HTTPException(status_code=404, detail=f"Key {key_name} not found")

    key_provider = _api_key_provider_from_name(key_name)
    if key_provider != provider_lower:
        raise HTTPException(
            status_code=400,
            detail=f"API key {key_name} does not belong to provider {provider_lower}",
        )

    key_value = env_vars[key_name]
    return CredentialDeletionCandidate(
        type="api_key",
        provider=provider_lower,
        identifier=key_name,
        key_name=key_name,
        key_value=key_value,
        stable_id=_api_key_stable_id_from_value(key_value),
    )


def _validate_oauth_candidate(
    provider: str,
    filename: Optional[str],
    oauth_dir: Path,
) -> CredentialDeletionCandidate:
    provider_lower = provider.lower()
    if not filename:
        raise HTTPException(status_code=400, detail="filename is required for OAuth deletion")
    if Path(filename).name != filename or "\\" in filename:
        raise HTTPException(status_code=403, detail="Access denied")

    target = oauth_dir / filename
    try:
        if not target.resolve().is_relative_to(oauth_dir.resolve()):
            raise HTTPException(status_code=403, detail="Access denied")
    except OSError as exc:
        raise HTTPException(status_code=403, detail="Access denied") from exc

    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="OAuth credential not found")

    file_provider = _oauth_provider_from_filename(filename)
    if file_provider != provider_lower:
        raise HTTPException(
            status_code=400,
            detail=f"OAuth credential {filename} does not belong to provider {provider_lower}",
        )

    credential_number = _oauth_number_from_filename(filename)
    usage_accessors = [str(target)]
    if credential_number:
        usage_accessors.append(f"env://{provider_lower}/{credential_number}")

    return CredentialDeletionCandidate(
        type="oauth",
        provider=provider_lower,
        identifier=filename,
        filename=filename,
        target=target,
        stable_id=_oauth_stable_id_from_file(target),
        usage_accessors=tuple(usage_accessors),
        usage_filenames=(filename,),
    )


def _candidate_response(candidate: CredentialDeletionCandidate, **extra: object) -> dict:
    item = {
        "type": candidate.type,
        "provider": candidate.provider,
        "identifier": candidate.identifier,
    }
    if candidate.key_name:
        item["key_name"] = candidate.key_name
    if candidate.filename:
        item["filename"] = candidate.filename
    item.update(extra)
    return item


def _item_identifier(item: "CredentialBatchDeleteItem") -> str:
    if item.type == "api_key":
        return item.key_name or ""
    if item.type == "oauth":
        return item.filename or ""
    return item.key_name or item.filename or ""


def _remove_api_key_from_runtime(
    request: Request,
    provider_lower: str,
    key_value: Optional[str],
) -> bool:
    if key_value is None:
        return False

    removed_from_proxy = False
    try:
        client = request.app.state.rotating_client
        if provider_lower in client.all_credentials:
            before = len(client.all_credentials[provider_lower])
            client.all_credentials[provider_lower] = [
                c for c in client.all_credentials[provider_lower]
                if c != key_value
            ]
            removed_from_proxy = len(client.all_credentials[provider_lower]) < before
        if provider_lower in client.api_keys:
            before = len(client.api_keys[provider_lower])
            client.api_keys[provider_lower] = [
                c for c in client.api_keys[provider_lower]
                if c != key_value
            ]
            removed_from_proxy = removed_from_proxy or len(client.api_keys[provider_lower]) < before
    except Exception as e:
        logger.warning(f"Could not remove API key from running proxy: {e}")
    return removed_from_proxy


def _remove_oauth_from_runtime(request: Request, provider_lower: str, filename: str) -> bool:
    removed_from_proxy = False
    try:
        client = request.app.state.rotating_client
        if provider_lower in client.all_credentials:
            before = len(client.all_credentials[provider_lower])
            client.all_credentials[provider_lower] = [
                c for c in client.all_credentials[provider_lower]
                if not str(c).endswith(filename)
            ]
            removed_from_proxy = len(client.all_credentials[provider_lower]) < before
        if provider_lower in client.oauth_credentials:
            before = len(client.oauth_credentials[provider_lower])
            client.oauth_credentials[provider_lower] = [
                c for c in client.oauth_credentials[provider_lower]
                if not str(c).endswith(filename)
            ]
            removed_from_proxy = removed_from_proxy or len(
                client.oauth_credentials[provider_lower]
            ) < before
    except Exception as e:
        logger.warning(f"Could not remove credential from running proxy: {e}")
    return removed_from_proxy


def _delete_api_key_candidate(
    candidate: CredentialDeletionCandidate,
    request: Request,
) -> bool:
    if not candidate.key_name:
        raise HTTPException(status_code=400, detail="key_name is required for API key deletion")

    env_file = str(_env_path())
    _inplace_unset_key(env_file, candidate.key_name)
    os.environ.pop(candidate.key_name, None)
    load_dotenv(env_file, override=True)
    return _remove_api_key_from_runtime(request, candidate.provider, candidate.key_value)


def _delete_oauth_candidate(candidate: CredentialDeletionCandidate, request: Request) -> bool:
    if not candidate.filename or not candidate.target:
        raise HTTPException(status_code=400, detail="filename is required for OAuth deletion")

    candidate.target.unlink()
    return _remove_oauth_from_runtime(request, candidate.provider, candidate.filename)


@router.get("/config")
async def get_config():
    env_vars = _get_env_vars()
    oauth_dir = _oauth_dir()

    try:
        from proxy_app.provider_urls import PROVIDER_URL_MAP
    except ImportError:
        PROVIDER_URL_MAP = {}

    providers: dict = {}
    custom_providers: dict = {}
    concurrency: dict = {}
    rotation_modes: dict = {}
    model_filters: dict = {}
    latest_aliases: dict = {}
    strip_suffixes: list = []

    for key, value in env_vars.items():
        if key == "PROXY_API_KEY":
            continue

        api_key_match = re.match(r"^(.+?)_API_KEY(?:_\d+)?$", key)
        if api_key_match and not key.startswith("PROXY_"):
            provider_name = api_key_match.group(1).lower()
            if provider_name not in providers:
                providers[provider_name] = {"api_key_count": 0, "oauth_count": 0, "has_custom_base": False}
            providers[provider_name]["api_key_count"] += 1

        elif key.endswith("_API_BASE"):
            provider_name = key.replace("_API_BASE", "").lower()
            if provider_name not in PROVIDER_URL_MAP:
                custom_providers[provider_name] = value
            if provider_name not in providers:
                providers[provider_name] = {"api_key_count": 0, "oauth_count": 0, "has_custom_base": True}
            else:
                providers[provider_name]["has_custom_base"] = True

        elif key.startswith("MAX_CONCURRENT_REQUESTS_PER_KEY_"):
            provider_name = key.replace("MAX_CONCURRENT_REQUESTS_PER_KEY_", "").lower()
            if provider_name not in concurrency:
                concurrency[provider_name] = {"max": -1, "optimal": -1}
            try:
                concurrency[provider_name]["max"] = int(value)
            except ValueError:
                pass

        elif key.startswith("OPTIMAL_CONCURRENT_REQUESTS_PER_KEY_"):
            provider_name = key.replace("OPTIMAL_CONCURRENT_REQUESTS_PER_KEY_", "").lower()
            if provider_name not in concurrency:
                concurrency[provider_name] = {"max": -1, "optimal": -1}
            try:
                concurrency[provider_name]["optimal"] = int(value)
            except ValueError:
                pass

        elif key.startswith("ROTATION_MODE_"):
            provider_name = key.replace("ROTATION_MODE_", "").lower()
            rotation_modes[provider_name] = value

        elif key.startswith("IGNORE_MODELS_"):
            provider_name = key.replace("IGNORE_MODELS_", "").lower()
            if provider_name not in model_filters:
                model_filters[provider_name] = {"ignore": [], "whitelist": []}
            model_filters[provider_name]["ignore"] = [p.strip() for p in value.split(",") if p.strip()]

        elif key.startswith("WHITELIST_MODELS_"):
            provider_name = key.replace("WHITELIST_MODELS_", "").lower()
            if provider_name not in model_filters:
                model_filters[provider_name] = {"ignore": [], "whitelist": []}
            model_filters[provider_name]["whitelist"] = [p.strip() for p in value.split(",") if p.strip()]

        elif key.startswith("MODEL_LATEST_") and key != "MODEL_LATEST_STRIP_SUFFIXES":
            alias_name = key.replace("MODEL_LATEST_", "").lower()
            latest_aliases[alias_name] = value

        elif key == "MODEL_LATEST_STRIP_SUFFIXES":
            strip_suffixes = [s.strip() for s in value.split(",") if s.strip()]

    # Collect PROXY_URL_* settings
    proxy_urls: dict = {}
    for key, value in env_vars.items():
        if key == "PROXY_URL_DEFAULT":
            proxy_urls["default"] = value
        elif key.startswith("PROXY_URL_CREDENTIAL_"):
            slug = key[len("PROXY_URL_CREDENTIAL_"):].lower()
            proxy_urls.setdefault("credentials", {})[slug] = value
        elif key.startswith("PROXY_URL_") and not key.startswith("PROXY_URL_CREDENTIAL_"):
            provider = key[len("PROXY_URL_"):].lower()
            proxy_urls.setdefault("providers", {})[provider] = value

    # Count OAuth credentials from files
    if oauth_dir.exists():
        for f in oauth_dir.iterdir():
            if f.is_file() and f.suffix == ".json" and "_oauth_" in f.name:
                provider_name = f.name.split("_oauth_")[0].lower()
                if provider_name not in providers:
                    providers[provider_name] = {"api_key_count": 0, "oauth_count": 0, "has_custom_base": False}
                providers[provider_name]["oauth_count"] += 1

    result: dict = {
        "proxy_api_key_set": bool(env_vars.get("PROXY_API_KEY")),
        "providers": providers,
        "custom_providers": custom_providers,
        "concurrency": concurrency,
        "rotation_modes": rotation_modes,
        "model_filters": model_filters,
        "latest_aliases": latest_aliases,
        "strip_suffixes": strip_suffixes,
    }
    if proxy_urls:
        result["proxy_urls"] = proxy_urls
    return result


class ConfigUpdate(BaseModel):
    changes: dict[str, Optional[str]]


class CredentialHealthClearRequest(BaseModel):
    confirm: bool = False
    reason: str = Field(
        default="manual_reauth_completed",
        pattern=r"^[a-zA-Z0-9_\-]+$",
        max_length=80,
    )


_CONFIG_BLOCKED_KEYS = {"PROXY_API_KEY", "PATH", "HOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"}
_CONFIG_ALLOWED_PREFIXES = (
    "ROTATION_MODE_", "MAX_CONCURRENT_REQUESTS_PER_KEY_", "OPTIMAL_CONCURRENT_REQUESTS_PER_KEY_",
    "IGNORE_MODELS_", "WHITELIST_MODELS_", "MODEL_LATEST_",
)


@router.patch("/config")
async def update_config(update: ConfigUpdate):
    env_file = str(_env_path())
    updated = []
    rejected = []
    for key, value in update.changes.items():
        if key in _CONFIG_BLOCKED_KEYS:
            rejected.append(key)
            continue
        if not any(key.startswith(p) for p in _CONFIG_ALLOWED_PREFIXES) and not key.endswith(("_API_BASE",)):
            rejected.append(key)
            continue
        if value is None:
            _inplace_unset_key(env_file, key)
            os.environ.pop(key, None)
        else:
            _inplace_set_key(env_file, key, value)
            os.environ[key] = value
        updated.append(key)

    load_dotenv(env_file, override=True)
    result: dict = {"updated": updated}
    if rejected:
        result["rejected"] = rejected
    return result


@router.get("/credentials")
async def get_credentials(
    request: Request,
    status: Optional[list[str]] = Query(default=None),
):
    status_filter = _normalize_status_filter(status)
    env_vars = _get_env_vars()
    oauth_dir = _oauth_dir()

    # Build a lookup of runtime credential status from the proxy's quota stats
    runtime_status: dict[str, str] = {}
    loaded_providers: set[str] = set()
    try:
        client = request.app.state.rotating_client
        loaded_providers = {p.lower() for p in client.all_credentials}
        quota_stats = await client.get_quota_stats()
        for pstats in quota_stats.get("providers", {}).values():
            for cred_data in pstats.get("credentials", {}).values():
                full_path = cred_data.get("full_path", "")
                if full_path:
                    runtime_status[Path(full_path).name] = cred_data.get("status", "unknown")
    except Exception:
        pass

    # Cross-reference ErrorTracker for credentials with token refresh errors
    errored_creds: set[str] = set()
    try:
        from rotator_library.error_tracker import get_error_tracker
        tracker = get_error_tracker()
        records, _ = tracker.get_recent_errors(limit=50)
        for rec in records:
            if rec.error_type in ("CredentialNeedsReauth", "TokenRefreshFailed"):
                cred_id = rec.credential_masked
                errored_creds.add(cred_id)
    except Exception:
        pass

    api_keys: dict[str, list] = {}
    if not status_filter:
        for key, value in env_vars.items():
            api_key_match = re.match(r"^(.+?)_API_KEY(?:_\d+)?$", key)
            if api_key_match and not key.startswith("PROXY_"):
                provider_name = api_key_match.group(1).lower()
                if provider_name not in api_keys:
                    api_keys[provider_name] = []
                api_keys[provider_name].append({
                    "key_name": key,
                    "masked_value": _mask_key(value),
                    "provider": provider_name,
                })

    oauth: dict[str, list] = {}
    if oauth_dir.exists():
        for f in sorted(oauth_dir.iterdir()):
            if f.is_file() and f.suffix == ".json" and "_oauth_" in f.name:
                provider_name = f.name.split("_oauth_")[0].lower()
                # Extract number from filename (e.g. codex_oauth_2.json -> 2)
                num_match = re.search(r"_oauth_(\d+)\.json$", f.name)
                cred_number = int(num_match.group(1)) if num_match else None
                info: dict = {
                    "filename": f.name,
                    "provider": provider_name,
                    "number": cred_number,
                }
                try:
                    data = await asyncio.to_thread(_read_json, f)
                    meta = data.get("_proxy_metadata", {})
                    info["email"] = meta.get("email") or meta.get("login") or data.get("email")
                    info["tier"] = meta.get("tier") or meta.get("plan_type") or meta.get("sku")
                    file_status = meta.get("status", "unknown")
                    # Durable file/usage health is authoritative for manual
                    # reauth; runtime quota status cannot make it active.
                    resolved = "needs_reauth" if file_status == "needs_reauth" else None
                    if not resolved:
                        resolved = runtime_status.get(f.name)
                    if not resolved:
                        if file_status and file_status != "unknown":
                            resolved = file_status
                        elif provider_name in loaded_providers:
                            resolved = "active"
                        else:
                            resolved = "unknown"
                    # Override to needs_reauth if ErrorTracker has recent refresh errors
                    if resolved == "active" and f.name in errored_creds:
                        resolved = "needs_reauth"
                    info["status"] = resolved
                except Exception:
                    info["status"] = runtime_status.get(f.name, "error")
                if not status_filter or str(info["status"]).lower() in status_filter:
                    oauth.setdefault(provider_name, []).append(info)

    return {"api_keys": api_keys, "oauth": oauth}


class AddApiKeyRequest(BaseModel):
    provider: str = Field(pattern=r"^[a-zA-Z0-9_]+$", min_length=1, max_length=50)
    key: str = Field(min_length=1, max_length=500)


class CredentialBatchDeleteItem(BaseModel):
    type: str = Field(pattern=r"^(api_key|oauth)$")
    provider: str = Field(pattern=r"^[a-zA-Z0-9_]+$", min_length=1, max_length=50)
    key_name: Optional[str] = None
    filename: Optional[str] = None


class CredentialBatchDeleteRequest(BaseModel):
    items: list[CredentialBatchDeleteItem] = Field(default_factory=list)
    dry_run: bool = True
    confirm: bool = False


async def _ensure_usage_manager(client, provider: str, credentials: list) -> None:
    """Create a usage manager if missing, then (re-)initialize with current credentials."""
    from rotator_library.usage.config import load_provider_usage_config
    from rotator_library.usage import UsageManager as NewUsageManager

    usage_manager = client.get_usage_manager(provider)
    if usage_manager is None:
        reg = client._usage_registry
        config = load_provider_usage_config(provider, client._provider_plugins)
        config.rotation_tolerance = reg._rotation_tolerance
        reg.apply_usage_reset_config(provider, credentials, config)
        mode = config.rotation_mode.value
        max_c, opt_c = reg.get_concurrency_settings(provider, mode)
        usage_manager = NewUsageManager(
            provider=provider,
            file_path=client._usage_base_path / f"usage_{provider}.json",
            provider_plugins=client._provider_plugins,
            config=config,
            max_concurrent_per_key=max_c,
            optimal_concurrent_per_key=opt_c,
        )
        reg.managers[provider] = usage_manager

    priorities, tiers = client._usage_registry.get_credential_metadata(
        provider, credentials
    )
    await usage_manager.initialize(
        credentials, priorities=priorities, tiers=tiers
    )

    plugin = client._get_provider_instance(provider)
    if plugin and hasattr(plugin, "set_usage_manager"):
        plugin.set_usage_manager(usage_manager)


async def _hot_load_api_key(client, provider: str, api_key: str) -> bool:
    """Hot-load a new API key into the running client's credential maps.

    Returns True if the credential was newly added, False if it was already present.
    """
    provider = provider.lower()
    added = False

    client.api_keys.setdefault(provider, [])
    if api_key not in client.api_keys[provider]:
        client.api_keys[provider].append(api_key)
        added = True

    client.all_credentials.setdefault(provider, [])
    if api_key not in client.all_credentials[provider]:
        client.all_credentials[provider].append(api_key)
        added = True

    if added:
        await _ensure_usage_manager(client, provider, client.all_credentials[provider])

    return added


async def _hot_load_custom_provider(client, provider_name: str, api_key: str) -> dict:
    """Register a new custom OpenAI-compatible provider at runtime."""
    from rotator_library.providers import PROVIDER_PLUGINS, DynamicOpenAICompatibleProvider
    from rotator_library.provider_config import KNOWN_PROVIDERS

    provider = provider_name.lower()
    result = {"plugin_registered": False, "models_discovered": 0}

    if provider not in KNOWN_PROVIDERS and provider not in PROVIDER_PLUGINS:
        def _make_plugin(name):
            class _Plug(DynamicOpenAICompatibleProvider):
                def __init__(self):
                    super().__init__(name)
            return _Plug

        PROVIDER_PLUGINS[provider] = _make_plugin(provider)
        result["plugin_registered"] = True

    client.provider_config._load_api_bases()

    client.api_keys.setdefault(provider, [])
    if api_key not in client.api_keys[provider]:
        client.api_keys[provider].append(api_key)

    client.all_credentials.setdefault(provider, [])
    if api_key not in client.all_credentials[provider]:
        client.all_credentials[provider].append(api_key)

    await _ensure_usage_manager(client, provider, client.all_credentials[provider])

    try:
        models = await client.get_available_models(provider, force_refresh=True)
        result["models_discovered"] = len(models)
    except Exception as exc:
        logger.warning(f"Model discovery failed for {provider}: {exc}")
        result["model_discovery_error"] = str(exc)

    return result


@router.post("/credentials/api-key")
async def add_api_key(req: AddApiKeyRequest, request: Request):
    async with _credential_lock:
        env_file = str(_env_path())
        env_vars = _get_env_vars()

        provider_upper = req.provider.upper()
        existing = [k for k in env_vars if k.startswith(f"{provider_upper}_API_KEY")]
        if existing:
            nums = []
            for k in existing:
                suffix = k.replace(f"{provider_upper}_API_KEY", "")
                if suffix.startswith("_") and suffix[1:].isdigit():
                    nums.append(int(suffix[1:]))
                elif not suffix:
                    nums.append(0)
            next_num = max(nums) + 1 if nums else 1
            key_name = f"{provider_upper}_API_KEY_{next_num}"
        else:
            key_name = f"{provider_upper}_API_KEY"

        _inplace_set_key(env_file, key_name, req.key)
        os.environ[key_name] = req.key
        load_dotenv(env_file, override=True)

        hot_loaded = False
        try:
            client = request.app.state.rotating_client
            hot_loaded = await _hot_load_api_key(client, req.provider.lower(), req.key)
            logger.info(
                f"Hot-loaded API key for {req.provider}: "
                f"{'new' if hot_loaded else 'existing'} credential"
            )
        except Exception:
            logger.warning(f"Hot-load failed for {req.provider}", exc_info=True)

    return {"key_name": key_name, "hot_loaded": hot_loaded}


@router.post("/credentials/batch-delete")
async def batch_delete_credentials(req: CredentialBatchDeleteRequest, request: Request):
    if not req.items:
        raise HTTPException(status_code=400, detail="At least one credential is required")
    if not req.dry_run and not req.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true to delete credentials")

    async with _credential_lock:
        env_vars = _get_env_vars()
        oauth_dir = _oauth_dir()
        candidates = []
        errors = []
        seen: set[tuple[str, str, str]] = set()

        for item in req.items:
            try:
                if item.type == "api_key":
                    candidate = _validate_api_key_candidate(item.provider, item.key_name, env_vars)
                else:
                    candidate = _validate_oauth_candidate(item.provider, item.filename, oauth_dir)

                duplicate_key = (candidate.type, candidate.provider, candidate.identifier)
                if duplicate_key in seen:
                    raise HTTPException(status_code=400, detail="Duplicate credential in request")
                seen.add(duplicate_key)
                candidates.append(candidate)
            except HTTPException as exc:
                errors.append({
                    "type": item.type,
                    "provider": item.provider.lower(),
                    "identifier": _item_identifier(item),
                    "status_code": exc.status_code,
                    "detail": exc.detail,
                })

        if errors:
            return {
                "dry_run": req.dry_run,
                "candidates": [_candidate_response(candidate) for candidate in candidates],
                "deleted": [],
                "errors": errors,
            }

        candidate_results = [_candidate_response(candidate) for candidate in candidates]
        if req.dry_run:
            return {
                "dry_run": True,
                "candidates": candidate_results,
                "deleted": [],
                "errors": [],
            }

        deleted = []
        deletion_errors = []
        for candidate in candidates:
            if candidate.type == "api_key":
                removed_from_proxy = _delete_api_key_candidate(candidate, request)
            else:
                removed_from_proxy = _delete_oauth_candidate(candidate, request)
            usage_cleanup = _cleanup_usage_for_deleted_candidate(candidate)
            deleted.append(
                _candidate_response(
                    candidate,
                    removed_from_proxy=removed_from_proxy,
                    usage_cleanup=usage_cleanup,
                )
            )
            if not usage_cleanup.get("success"):
                deletion_errors.append(
                    {
                        "type": candidate.type,
                        "provider": candidate.provider,
                        "identifier": candidate.identifier,
                        "detail": "Deleted credential, but usage cleanup reported errors",
                        "usage_cleanup": usage_cleanup,
                    }
                )

    return {
        "dry_run": False,
        "candidates": candidate_results,
        "deleted": deleted,
        "errors": deletion_errors,
    }


@router.delete("/credentials/api-key/{provider}/{key_name}")
async def delete_api_key(provider: str, key_name: str, request: Request):
    async with _credential_lock:
        candidate = _validate_api_key_candidate(provider, key_name, _get_env_vars())
        removed_from_proxy = _delete_api_key_candidate(candidate, request)
        usage_cleanup = _cleanup_usage_for_deleted_candidate(candidate)

    return {
        "deleted": key_name,
        "removed_from_proxy": removed_from_proxy,
        "usage_cleanup": usage_cleanup,
        "errors": [] if usage_cleanup.get("success") else [
            {
                "detail": "Deleted API key, but usage cleanup reported errors",
                "usage_cleanup": usage_cleanup,
            }
        ],
    }


@router.delete("/credentials/oauth/{provider}/{filename}")
async def delete_oauth_credential(provider: str, filename: str, request: Request):
    async with _credential_lock:
        candidate = _validate_oauth_candidate(provider, filename, _oauth_dir())
        removed_from_proxy = _delete_oauth_candidate(candidate, request)
        usage_cleanup = _cleanup_usage_for_deleted_candidate(candidate)

    return {
        "deleted": filename,
        "removed_from_proxy": removed_from_proxy,
        "usage_cleanup": usage_cleanup,
        "errors": [] if usage_cleanup.get("success") else [
            {
                "detail": "Deleted OAuth credential, but usage cleanup reported errors",
                "usage_cleanup": usage_cleanup,
            }
        ],
    }


@router.post("/credentials/oauth/{provider}/{filename}/clear-health")
async def clear_oauth_credential_health(
    provider: str,
    filename: str,
    req: CredentialHealthClearRequest,
    request: Request,
):
    if not req.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true to clear health")

    async with _credential_lock:
        candidate = _validate_oauth_candidate(provider, filename, _oauth_dir())
        assert candidate.target is not None

        data = await asyncio.to_thread(_read_json, candidate.target)
        metadata = data.setdefault("_proxy_metadata", {})
        metadata["status"] = "active"
        metadata["health_cleared_reason"] = req.reason

        def _write_json() -> None:
            with open(candidate.target, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)

        await asyncio.to_thread(_write_json)

        runtime_cleared = False
        try:
            client = request.app.state.rotating_client
            if hasattr(client, "clear_credential_health_block"):
                runtime_cleared = await client.clear_credential_health_block(
                    candidate.provider,
                    candidate.filename,
                )
            elif hasattr(client, "get_usage_manager"):
                manager = client.get_usage_manager(candidate.provider)
                if manager and hasattr(manager, "clear_credential_health_block"):
                    runtime_cleared = await manager.clear_credential_health_block(
                        str(candidate.target),
                        reason=req.reason,
                    )
        except Exception as exc:
            logger.warning("Could not clear runtime credential health: %s", exc)

    return {
        "provider": candidate.provider,
        "filename": candidate.filename,
        "status": "active",
        "cleared_runtime": runtime_cleared,
    }


class AddCustomProviderRequest(BaseModel):
    name: str
    base_url: str
    api_key: str


@router.post("/credentials/custom-provider")
async def add_custom_provider(req: AddCustomProviderRequest, request: Request):
    async with _credential_lock:
        env_file = str(_env_path())
        provider_upper = req.name.upper()

        _inplace_set_key(env_file, f"{provider_upper}_API_BASE", req.base_url)
        _inplace_set_key(env_file, f"{provider_upper}_API_KEY", req.api_key)
        os.environ[f"{provider_upper}_API_BASE"] = req.base_url
        os.environ[f"{provider_upper}_API_KEY"] = req.api_key
        load_dotenv(env_file, override=True)

        hot_load_info = {}
        try:
            client = request.app.state.rotating_client
            hot_load_info = await _hot_load_custom_provider(
                client, req.name, req.api_key
            )
            logger.info(
                f"Hot-loaded custom provider {req.name}: "
                f"plugin={'new' if hot_load_info.get('plugin_registered') else 'existing'}, "
                f"models={hot_load_info.get('models_discovered', 0)}"
            )
        except Exception:
            logger.warning(f"Hot-load failed for {req.name}", exc_info=True)
            hot_load_info["error"] = "hot_load_failed"

    return {"provider": req.name, **hot_load_info}


@router.get("/config/model-filters/{provider}")
async def get_model_filters(provider: str):
    env_vars = _get_env_vars()
    provider_upper = provider.upper()

    ignore_key = f"IGNORE_MODELS_{provider_upper}"
    whitelist_key = f"WHITELIST_MODELS_{provider_upper}"

    ignore = [p.strip() for p in env_vars.get(ignore_key, "").split(",") if p.strip()]
    whitelist = [p.strip() for p in env_vars.get(whitelist_key, "").split(",") if p.strip()]

    return {"ignore": ignore, "whitelist": whitelist}


class ModelFilterUpdate(BaseModel):
    ignore: list[str]
    whitelist: list[str]


@router.put("/config/model-filters/{provider}")
async def update_model_filters(provider: str, filters: ModelFilterUpdate):
    env_file = str(_env_path())
    provider_upper = provider.upper()

    ignore_key = f"IGNORE_MODELS_{provider_upper}"
    whitelist_key = f"WHITELIST_MODELS_{provider_upper}"

    if filters.ignore:
        _inplace_set_key(env_file, ignore_key, ",".join(filters.ignore))
    else:
        _inplace_unset_key(env_file, ignore_key)

    if filters.whitelist:
        _inplace_set_key(env_file, whitelist_key, ",".join(filters.whitelist))
    else:
        _inplace_unset_key(env_file, whitelist_key)

    load_dotenv(env_file, override=True)
    return {"provider": provider, "updated": True}


@router.post("/reload")
async def reload_proxy():
    try:
        env_file = _env_path()
        load_dotenv(str(env_file), override=True)
        logger.info("Proxy configuration reloaded via admin API")
        return {"status": "ok", "message": "Configuration reloaded from .env"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
