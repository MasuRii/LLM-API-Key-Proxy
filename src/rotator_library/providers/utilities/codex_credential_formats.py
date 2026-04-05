"""Codex credential import/export helpers.

Supports the JSON shapes produced by GPTSession2CPAandSub2API and the local
CodexAccountStatusQuotaChecker utility, then normalizes them into the proxy's
``codex_oauth_*.json`` credential shape.
"""

from __future__ import annotations

import base64
import copy
import datetime as _dt
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

AXONHUB_PLACEHOLDER_REFRESH_TOKEN = "__missing_refresh_token__"
SUPPORTED_IMPORT_EXTENSIONS = {".json", ".jsonl", ".txt"}


@dataclass(frozen=True)
class CodexFormatInfo:
    """Display metadata for a supported Codex import/export format."""

    id: str
    label: str
    description: str
    extension: str = ".json"


CODEX_EXPORT_FORMATS: tuple[CodexFormatInfo, ...] = (
    CodexFormatInfo(
        "sub2api_admin_data",
        "Sub2API Admin Data Import JSON",
        "exported_at/proxies/accounts import JSON used by Sub2API admin.",
    ),
    CodexFormatInfo(
        "cpa",
        "CPA / Codex Session JSON",
        "Codex CPA flat credential object or array.",
    ),
    CodexFormatInfo(
        "codex_session_array",
        "Codex Session JSON Array",
        "Array of CPA-compatible Codex session objects.",
    ),
    CodexFormatInfo(
        "codex_session_jsonl",
        "Codex Session JSON Lines",
        "One CPA-compatible Codex session object per line.",
        ".jsonl",
    ),
    CodexFormatInfo(
        "cockpit_codex_array",
        "Cockpit Tools Codex Account Array",
        "Flat Cockpit Tools Codex token objects.",
    ),
    CodexFormatInfo(
        "9router",
        "9router Codex OAuth JSON",
        "9router provider/authType OAuth credential object or array.",
    ),
    CodexFormatInfo(
        "codex",
        "Native Codex auth.json",
        "Codex auth.json shape with auth_mode and tokens.",
    ),
    CodexFormatInfo(
        "axonhub",
        "AxonHub Codex auth.json",
        "AxonHub auth.json shape with tokens and last_refresh.",
    ),
    CodexFormatInfo(
        "codexmanager",
        "Codex-Manager Batch Import JSON",
        "Codex-Manager tokens/meta import object or array.",
    ),
    CodexFormatInfo(
        "plain_token_array",
        "Plain Token JSON Array",
        "Simple top-level token records for generic importers.",
    ),
)

CODEX_EXPORT_FORMAT_BY_ID = {item.id: item for item in CODEX_EXPORT_FORMATS}
CODEX_EXPORT_ALIASES = {
    "sub2api": "sub2api_admin_data",
    "sub2api_admin": "sub2api_admin_data",
    "sub2api_admin_data": "sub2api_admin_data",
    "cpa": "cpa",
    "codex_session": "codex_session_array",
    "codex_session_array": "codex_session_array",
    "jsonl": "codex_session_jsonl",
    "codex_session_jsonl": "codex_session_jsonl",
    "cockpit": "cockpit_codex_array",
    "cockpit_codex_array": "cockpit_codex_array",
    "9router": "9router",
    "nine_router": "9router",
    "codex": "codex",
    "auth_json": "codex",
    "axonhub": "axonhub",
    "codexmanager": "codexmanager",
    "codex_manager": "codexmanager",
    "plain": "plain_token_array",
    "plain_token_array": "plain_token_array",
}


@dataclass
class CodexImportRecord:
    """A source payload found while scanning an import document."""

    payload: dict[str, Any]
    source_name: str
    path: str


@dataclass
class CodexImportResult:
    """Summary returned after importing one or more Codex credential files."""

    imported: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    written_paths: list[str] = field(default_factory=list)

    @property
    def total_written(self) -> int:
        return self.imported + self.updated


class CodexCredentialFormatError(ValueError):
    """Raised when a Codex credential import/export payload is invalid."""


def _is_plain_object(value: Any) -> bool:
    return isinstance(value, dict)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value).strip()
    return ""


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = _normalize_text(value)
        if text:
            return text
    return ""


def _get_nested(record: dict[str, Any], *path: str) -> Any:
    node: Any = record
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _decode_base64_url(value: str) -> bytes:
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value.encode("ascii"))


def decode_jwt_payload(token: Any) -> dict[str, Any]:
    token = _normalize_text(token)
    if not token or token.count(".") < 2:
        return {}
    try:
        payload = token.split(".")[1]
        decoded = _decode_base64_url(payload).decode("utf-8", "replace")
        parsed = json.loads(decoded)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _openai_auth_section(payload: dict[str, Any]) -> dict[str, Any]:
    auth = payload.get("https://api.openai.com/auth") if isinstance(payload, dict) else None
    return auth if isinstance(auth, dict) else {}


def _openai_profile_section(payload: dict[str, Any]) -> dict[str, Any]:
    profile = payload.get("https://api.openai.com/profile") if isinstance(payload, dict) else None
    return profile if isinstance(profile, dict) else {}


def parse_timestamp_seconds(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        raw = int(value)
        if raw > 1_000_000_000_000:
            raw //= 1000
        return raw if raw > 0 else None

    text = _normalize_text(value)
    if not text:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        raw = int(float(text))
        if raw > 1_000_000_000_000:
            raw //= 1000
        return raw if raw > 0 else None

    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return int(parsed.timestamp())
    except ValueError:
        return None


def _timestamp_from_expires_in(value: Any, now: Optional[float] = None) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return int((now or time.time()) + seconds)


def _iso_from_seconds(value: Any, milliseconds: bool = True) -> str:
    ts = parse_timestamp_seconds(value)
    if not ts:
        return ""
    try:
        dt = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
        if milliseconds:
            return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        return ""


def _iso_now(milliseconds: bool = True) -> str:
    now = _dt.datetime.now(_dt.timezone.utc)
    if milliseconds:
        return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return now.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _strip_unavailable(value: Any) -> Any:
    if isinstance(value, list):
        return [item for item in (_strip_unavailable(item) for item in value) if item is not None]
    if isinstance(value, dict):
        entries = []
        for key, item in value.items():
            stripped = _strip_unavailable(item)
            if stripped is not None:
                entries.append((key, stripped))
        return dict(entries) if entries else None
    if value is None or value == "":
        return None
    return value


def _to_email_key(email: str) -> str:
    email = _normalize_text(email).lower()
    if not email:
        return ""
    return re.sub(r"[^a-z0-9]+", "_", email).strip("_")


def _token_expiry(access_token: str) -> Optional[int]:
    payload = decode_jwt_payload(access_token)
    return parse_timestamp_seconds(payload.get("exp"))


def _extract_access_token(record: dict[str, Any]) -> str:
    return _first_non_empty(
        record.get("accessToken"),
        record.get("access_token"),
        _get_nested(record, "tokens", "accessToken"),
        _get_nested(record, "tokens", "access_token"),
        _get_nested(record, "token", "accessToken"),
        _get_nested(record, "token", "access_token"),
        _get_nested(record, "credentials", "accessToken"),
        _get_nested(record, "credentials", "access_token"),
    )


def _extract_refresh_token(record: dict[str, Any]) -> str:
    value = _first_non_empty(
        record.get("refreshToken"),
        record.get("refresh_token"),
        record.get("rt"),
        _get_nested(record, "tokens", "refreshToken"),
        _get_nested(record, "tokens", "refresh_token"),
        _get_nested(record, "token", "refreshToken"),
        _get_nested(record, "token", "refresh_token"),
        _get_nested(record, "credentials", "refreshToken"),
        _get_nested(record, "credentials", "refresh_token"),
    )
    return "" if value == AXONHUB_PLACEHOLDER_REFRESH_TOKEN else value


def _extract_id_token(record: dict[str, Any]) -> str:
    return _first_non_empty(
        record.get("idToken"),
        record.get("id_token"),
        _get_nested(record, "tokens", "idToken"),
        _get_nested(record, "tokens", "id_token"),
        _get_nested(record, "token", "idToken"),
        _get_nested(record, "token", "id_token"),
        _get_nested(record, "credentials", "idToken"),
        _get_nested(record, "credentials", "id_token"),
    )


def _extract_api_key(record: dict[str, Any]) -> str:
    return _first_non_empty(
        record.get("api_key"),
        record.get("OPENAI_API_KEY"),
        _get_nested(record, "tokens", "api_key"),
        _get_nested(record, "credentials", "api_key"),
    )


def _extract_session_token(record: dict[str, Any]) -> str:
    return _first_non_empty(
        record.get("sessionToken"),
        record.get("session_token"),
        _get_nested(record, "tokens", "sessionToken"),
        _get_nested(record, "tokens", "session_token"),
        _get_nested(record, "token", "sessionToken"),
        _get_nested(record, "token", "session_token"),
        _get_nested(record, "credentials", "sessionToken"),
        _get_nested(record, "credentials", "session_token"),
    )


def _looks_like_credential_record(record: dict[str, Any]) -> bool:
    return bool(
        _extract_access_token(record)
        or _extract_refresh_token(record)
        or _extract_api_key(record)
    )


def collect_codex_credential_records(
    payload: Any,
    source_name: str = "pasted-json",
) -> list[CodexImportRecord]:
    """Find all credential-like objects in a GPTSession2CPA/Codex JSON payload."""
    found: list[CodexImportRecord] = []
    visited: set[int] = set()

    def visit(item: Any, path: str) -> None:
        if isinstance(item, dict):
            item_id = id(item)
            if item_id in visited:
                return
            visited.add(item_id)

            if _looks_like_credential_record(item):
                found.append(CodexImportRecord(item, source_name, path))
                return

            for key, child in item.items():
                if key in {"accessToken", "access_token", "refreshToken", "refresh_token"}:
                    continue
                visit(child, f"{path}.{key}")
            return

        if isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, f"{path}[{index}]")

    visit(payload, "$")
    return found


def _detect_source_format(record: dict[str, Any]) -> str:
    if isinstance(record.get("accounts"), list):
        return "sub2api_admin_data"
    if record.get("auth_mode") == "chatgpt" and isinstance(record.get("tokens"), dict):
        return "codex_auth_json"
    if record.get("provider") == "codex" and record.get("authType") == "oauth":
        return "9router"
    if isinstance(record.get("meta"), dict) and isinstance(record.get("tokens"), dict):
        return "codexmanager"
    if isinstance(record.get("credentials"), dict):
        return "sub2api_account"
    if record.get("type") == "codex":
        return "cpa_or_cockpit"
    return "plain_token_json"


def normalize_codex_credential_record(
    record: dict[str, Any],
    *,
    now: Optional[float] = None,
    source_format: str = "",
) -> dict[str, Any]:
    """Normalize a single external Codex credential object to proxy credential JSON."""
    if not isinstance(record, dict):
        raise CodexCredentialFormatError("credential record is not a JSON object")

    now = now or time.time()
    access_token = _extract_access_token(record)
    refresh_token = _extract_refresh_token(record)
    id_token = _extract_id_token(record)
    api_key = _extract_api_key(record)
    session_token = _extract_session_token(record)

    if not (access_token or refresh_token or api_key):
        raise CodexCredentialFormatError("credential record is missing access/refresh/API token")

    access_payload = decode_jwt_payload(access_token)
    id_payload = decode_jwt_payload(id_token)
    access_auth = _openai_auth_section(access_payload)
    id_auth = _openai_auth_section(id_payload)
    access_profile = _openai_profile_section(access_payload)

    account_id = _first_non_empty(
        _get_nested(record, "account", "id"),
        record.get("account_id"),
        record.get("chatgptAccountId"),
        record.get("chatgpt_account_id"),
        _get_nested(record, "tokens", "accountId"),
        _get_nested(record, "tokens", "account_id"),
        _get_nested(record, "tokens", "chatgptAccountId"),
        _get_nested(record, "tokens", "chatgpt_account_id"),
        _get_nested(record, "meta", "chatgptAccountId"),
        _get_nested(record, "meta", "chatgpt_account_id"),
        _get_nested(record, "providerSpecificData", "chatgptAccountId"),
        _get_nested(record, "providerSpecificData", "chatgpt_account_id"),
        _get_nested(record, "credentials", "chatgpt_account_id"),
        _get_nested(record, "credentials", "account_id"),
        access_auth.get("chatgpt_account_id"),
        id_auth.get("chatgpt_account_id"),
        record.get("id") if record.get("provider") == "codex" else None,
    )
    chatgpt_user_id = _first_non_empty(
        _get_nested(record, "user", "id"),
        record.get("user_id"),
        record.get("chatgptUserId"),
        record.get("chatgpt_user_id"),
        _get_nested(record, "credentials", "chatgpt_user_id"),
        _get_nested(record, "credentials", "user_id"),
        _get_nested(record, "providerSpecificData", "chatgptUserId"),
        _get_nested(record, "providerSpecificData", "chatgpt_user_id"),
        access_auth.get("chatgpt_user_id"),
        access_auth.get("user_id"),
        id_auth.get("chatgpt_user_id"),
        id_auth.get("user_id"),
        access_payload.get("sub"),
        id_payload.get("sub"),
    )
    organization_id = _first_non_empty(
        record.get("organization_id"),
        record.get("org_id"),
        _get_nested(record, "credentials", "organization_id"),
        _get_nested(record, "credentials", "poid"),
        access_auth.get("poid"),
        access_auth.get("organization_id"),
        id_auth.get("poid"),
        id_auth.get("organization_id"),
        access_payload.get("organization_id"),
        id_payload.get("organization_id"),
    )
    email = _first_non_empty(
        _get_nested(record, "user", "email"),
        record.get("email"),
        _get_nested(record, "meta", "label"),
        record.get("label"),
        _get_nested(record, "credentials", "email"),
        _get_nested(record, "extra", "email"),
        _get_nested(record, "providerSpecificData", "email"),
        access_profile.get("email"),
        id_payload.get("email"),
        access_payload.get("email"),
    )
    plan_type = _first_non_empty(
        _get_nested(record, "account", "planType"),
        _get_nested(record, "account", "plan_type"),
        record.get("planType"),
        record.get("plan_type"),
        record.get("chatgpt_plan_type"),
        _get_nested(record, "credentials", "plan_type"),
        _get_nested(record, "extra", "plan_type"),
        _get_nested(record, "providerSpecificData", "chatgptPlanType"),
        _get_nested(record, "providerSpecificData", "chatgpt_plan_type"),
        access_auth.get("chatgpt_plan_type"),
        id_auth.get("chatgpt_plan_type"),
    )
    workspace_id = _first_non_empty(
        _get_nested(record, "account", "workspaceId"),
        _get_nested(record, "account", "workspace_id"),
        record.get("workspaceId"),
        record.get("workspace_id"),
        _get_nested(record, "meta", "workspaceId"),
        _get_nested(record, "meta", "workspace_id"),
        _get_nested(record, "providerSpecificData", "workspaceId"),
        _get_nested(record, "providerSpecificData", "workspace_id"),
        _get_nested(record, "credentials", "workspace_id"),
        access_payload.get("workspace_id"),
        id_payload.get("workspace_id"),
    )
    workspace_title = _first_non_empty(
        record.get("workspace_title"),
        record.get("workspaceTitle"),
        _get_nested(record, "meta", "workspace_title"),
        _get_nested(record, "providerSpecificData", "workspaceTitle"),
    )
    name = _first_non_empty(
        record.get("name"),
        _get_nested(record, "extra", "name"),
        _get_nested(record, "meta", "label"),
        email,
        account_id,
        "Codex Account",
    )

    expiry_date = (
        parse_timestamp_seconds(record.get("expiry_date"))
        or parse_timestamp_seconds(_get_nested(record, "tokens", "expiry_date"))
        or _token_expiry(access_token)
        or parse_timestamp_seconds(record.get("expires"))
        or parse_timestamp_seconds(record.get("expiresAt"))
        or parse_timestamp_seconds(record.get("expired"))
        or parse_timestamp_seconds(record.get("expires_at"))
        or parse_timestamp_seconds(_get_nested(record, "credentials", "expires_at"))
        or parse_timestamp_seconds(_get_nested(record, "account", "expires_at"))
        or _timestamp_from_expires_in(record.get("expires_in"), now)
        or _timestamp_from_expires_in(_get_nested(record, "credentials", "expires_in"), now)
        or 0
    )

    metadata = copy.deepcopy(record.get("_proxy_metadata")) if isinstance(record.get("_proxy_metadata"), dict) else {}
    for key, value in {
        "email": email,
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": chatgpt_user_id,
        "organization_id": organization_id,
        "plan_type": plan_type,
        "workspace_id": workspace_id,
        "workspace_title": workspace_title,
        "display_name": name,
        "last_check_timestamp": now,
        "imported_from_format": source_format or _detect_source_format(record),
        "imported_at": _iso_now(milliseconds=True),
    }.items():
        if value not in (None, ""):
            metadata[key] = value

    normalized: dict[str, Any] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expiry_date": expiry_date,
        "_proxy_metadata": metadata,
    }
    if id_token:
        normalized["id_token"] = id_token
    if api_key:
        normalized["api_key"] = api_key
    if account_id:
        normalized["account_id"] = account_id
    if session_token:
        normalized["session_token"] = session_token
    if chatgpt_user_id:
        normalized["chatgpt_user_id"] = chatgpt_user_id
    if organization_id:
        normalized["organization_id"] = organization_id

    return normalized


def normalize_codex_credential_payload(payload: Any, source_name: str = "credential") -> dict[str, Any]:
    """Normalize a payload expected to contain exactly one Codex credential."""
    if not isinstance(payload, dict):
        raise CodexCredentialFormatError(f"{source_name} is not a JSON object")

    if _looks_like_credential_record(payload):
        existing_format = _get_nested(payload, "_proxy_metadata", "imported_from_format")
        return normalize_codex_credential_record(
            payload,
            source_format=_first_non_empty(existing_format, _detect_source_format(payload)),
        )

    records = collect_codex_credential_records(payload, source_name)
    if not records:
        raise CodexCredentialFormatError(f"{source_name} does not contain a Codex credential")
    if len(records) > 1:
        raise CodexCredentialFormatError(
            f"{source_name} contains {len(records)} Codex credentials; import it first "
            "so each account is written to its own codex_oauth_*.json file"
        )
    record = records[0]
    return normalize_codex_credential_record(
        record.payload,
        source_format=_detect_source_format(record.payload),
    )


def _parse_json_or_jsonl(text: str, source_name: str) -> list[Any]:
    stripped = text.strip()
    if not stripped:
        return []

    try:
        return [json.loads(stripped)]
    except json.JSONDecodeError as json_error:
        documents: list[Any] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                documents.append(json.loads(line))
            except json.JSONDecodeError as line_error:
                raise CodexCredentialFormatError(
                    f"{source_name} is not valid JSON or JSONL: "
                    f"line {line_number}: {line_error}"
                ) from json_error
        return documents


def parse_codex_credentials_from_text(
    text: str,
    source_name: str = "pasted-json",
) -> list[dict[str, Any]]:
    """Parse JSON/JSONL text into normalized proxy Codex credential dictionaries."""
    credentials: list[dict[str, Any]] = []
    documents = _parse_json_or_jsonl(text, source_name)
    now = time.time()

    for document_index, document in enumerate(documents):
        records = collect_codex_credential_records(document, source_name)
        if not records:
            continue
        for record in records:
            credential = normalize_codex_credential_record(
                record.payload,
                now=now,
                source_format=_detect_source_format(record.payload),
            )
            credential.setdefault("_proxy_metadata", {})["source_path"] = record.path
            if len(documents) > 1:
                credential["_proxy_metadata"]["source_document_index"] = document_index
            credentials.append(credential)

    return credentials


def parse_codex_credentials_from_file(path: str | Path) -> list[dict[str, Any]]:
    """Read a JSON/JSONL import file and return normalized Codex credentials."""
    input_path = Path(path).expanduser()
    text = input_path.read_text(encoding="utf-8-sig")
    credentials = parse_codex_credentials_from_text(text, str(input_path))
    if not credentials:
        raise CodexCredentialFormatError(f"No Codex credentials found in {input_path}")
    return credentials


def _credential_number(path: Path) -> int:
    match = re.search(r"_oauth_(\d+)\.json$", path.name)
    return int(match.group(1)) if match else 0


def next_codex_credential_number(base_dir: str | Path) -> int:
    base = Path(base_dir)
    existing = [_credential_number(path) for path in base.glob("codex_oauth_*.json")]
    existing = [number for number in existing if number > 0]
    return (max(existing) + 1) if existing else 1


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    tmp_path.replace(path)


def _hash_value(value: Any) -> str:
    text = _normalize_text(value)
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def _dedupe_keys(credential: dict[str, Any]) -> list[str]:
    metadata = credential.get("_proxy_metadata") if isinstance(credential.get("_proxy_metadata"), dict) else {}
    keys: list[str] = []
    for field_name in ("refresh_token", "access_token", "api_key"):
        digest = _hash_value(credential.get(field_name))
        if digest:
            keys.append(f"{field_name}:{digest}")
    account_id = _first_non_empty(credential.get("account_id"), metadata.get("account_id"))
    email = _normalize_text(metadata.get("email")).lower()
    if account_id and email:
        keys.append(f"identity:{email}:{account_id}")
    return keys


def _load_existing_codex_credentials(base_dir: Path) -> dict[str, Path]:
    key_to_path: dict[str, Path] = {}
    for cred_path in sorted(base_dir.glob("codex_oauth_*.json")):
        try:
            with open(cred_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            credential = normalize_codex_credential_payload(payload, str(cred_path))
        except Exception:
            continue
        for key in _dedupe_keys(credential):
            key_to_path.setdefault(key, cred_path)
    return key_to_path


def _merge_existing_codex_credential(
    existing: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    """Merge duplicate imports without discarding older usable secrets.

    New non-empty values win. Empty imported refresh/id/API/session tokens do not
    erase existing values, which matters when a later ChatGPT session export lacks
    a refresh token but the proxy already has one for the same identity.
    """
    merged = copy.deepcopy(existing)

    for key, value in incoming.items():
        if key == "_proxy_metadata":
            continue
        if key == "expiry_date":
            if parse_timestamp_seconds(value):
                merged[key] = value
            continue
        if value not in (None, ""):
            merged[key] = value

    existing_metadata = merged.get("_proxy_metadata") if isinstance(merged.get("_proxy_metadata"), dict) else {}
    incoming_metadata = incoming.get("_proxy_metadata") if isinstance(incoming.get("_proxy_metadata"), dict) else {}
    merged_metadata = dict(existing_metadata)
    for key, value in incoming_metadata.items():
        if value not in (None, ""):
            merged_metadata[key] = value
    if merged_metadata:
        merged["_proxy_metadata"] = merged_metadata

    return merged


def write_codex_credentials_to_directory(
    credentials: Iterable[dict[str, Any]],
    base_dir: str | Path,
    *,
    update_existing: bool = True,
) -> CodexImportResult:
    """Write normalized Codex credentials into ``codex_oauth_*.json`` files."""
    base = Path(base_dir).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    result = CodexImportResult()
    key_to_path = _load_existing_codex_credentials(base)
    next_number = next_codex_credential_number(base)

    for index, credential in enumerate(credentials, start=1):
        try:
            normalized = normalize_codex_credential_payload(credential, f"credential #{index}")
            keys = _dedupe_keys(normalized)
            existing_path = next((key_to_path[key] for key in keys if key in key_to_path), None)

            if existing_path and not update_existing:
                result.skipped += 1
                continue

            if existing_path:
                target_path = existing_path
                with open(existing_path, "r", encoding="utf-8") as fh:
                    existing_payload = json.load(fh)
                existing_normalized = normalize_codex_credential_payload(
                    existing_payload,
                    str(existing_path),
                )
                normalized = _merge_existing_codex_credential(
                    existing_normalized,
                    normalized,
                )
                result.updated += 1
            else:
                target_path = base / f"codex_oauth_{next_number}.json"
                next_number += 1
                result.imported += 1

            _write_json(target_path, normalized)
            result.written_paths.append(str(target_path.resolve()))
            for key in set(keys) | set(_dedupe_keys(normalized)):
                key_to_path[key] = target_path
        except Exception as exc:
            result.skipped += 1
            result.errors.append(f"credential #{index}: {exc}")

    return result


def _iter_import_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise CodexCredentialFormatError(f"Import path does not exist: {path}")
    return sorted(
        file_path
        for file_path in path.rglob("*")
        if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_IMPORT_EXTENSIONS
    )


def import_codex_credentials_from_path(
    import_path: str | Path,
    base_dir: str | Path,
    *,
    update_existing: bool = True,
) -> CodexImportResult:
    """Import one JSON/JSONL file or a directory of files into the Codex pool."""
    files = _iter_import_files(Path(import_path).expanduser())
    result = CodexImportResult()
    if not files:
        result.errors.append(f"No JSON/JSONL import files found in {import_path}")
        return result

    for file_path in files:
        try:
            credentials = parse_codex_credentials_from_file(file_path)
            partial = write_codex_credentials_to_directory(
                credentials,
                base_dir,
                update_existing=update_existing,
            )
            result.imported += partial.imported
            result.updated += partial.updated
            result.skipped += partial.skipped
            result.errors.extend(f"{file_path}: {error}" for error in partial.errors)
            result.written_paths.extend(partial.written_paths)
        except Exception as exc:
            result.skipped += 1
            result.errors.append(f"{file_path}: {exc}")

    return result


def _credential_display_name(credential: dict[str, Any], index: int) -> str:
    metadata = credential.get("_proxy_metadata") if isinstance(credential.get("_proxy_metadata"), dict) else {}
    return _first_non_empty(
        metadata.get("display_name"),
        metadata.get("email"),
        credential.get("account_id"),
        f"codex-account-{index:04d}",
    )


def _credential_email(credential: dict[str, Any]) -> str:
    metadata = credential.get("_proxy_metadata") if isinstance(credential.get("_proxy_metadata"), dict) else {}
    return _first_non_empty(metadata.get("email"), credential.get("email"))


def _credential_plan_type(credential: dict[str, Any]) -> str:
    metadata = credential.get("_proxy_metadata") if isinstance(credential.get("_proxy_metadata"), dict) else {}
    return _first_non_empty(
        metadata.get("plan_type"),
        credential.get("plan_type"),
        credential.get("chatgpt_plan_type"),
    )


def _credential_account_id(credential: dict[str, Any]) -> str:
    metadata = credential.get("_proxy_metadata") if isinstance(credential.get("_proxy_metadata"), dict) else {}
    return _first_non_empty(
        credential.get("account_id"),
        metadata.get("account_id"),
        metadata.get("chatgpt_account_id"),
    )


def _credential_user_id(credential: dict[str, Any]) -> str:
    metadata = credential.get("_proxy_metadata") if isinstance(credential.get("_proxy_metadata"), dict) else {}
    return _first_non_empty(
        credential.get("chatgpt_user_id"),
        metadata.get("chatgpt_user_id"),
        metadata.get("user_id"),
    )


def _credential_workspace_id(credential: dict[str, Any]) -> str:
    metadata = credential.get("_proxy_metadata") if isinstance(credential.get("_proxy_metadata"), dict) else {}
    return _first_non_empty(
        credential.get("workspace_id"),
        metadata.get("workspace_id"),
    )


def _credential_expiry(credential: dict[str, Any]) -> Optional[int]:
    return parse_timestamp_seconds(credential.get("expiry_date")) or _token_expiry(
        _normalize_text(credential.get("access_token"))
    )


def _expires_in(expiry: Optional[int], now: Optional[float] = None) -> Optional[int]:
    if not expiry:
        return None
    return max(0, int(expiry - (now or time.time())))


def _cpa_record(credential: dict[str, Any], index: int, now_iso: str) -> dict[str, Any]:
    account_id = _credential_account_id(credential)
    email = _credential_email(credential)
    plan_type = _credential_plan_type(credential)
    expiry = _credential_expiry(credential)
    record = {
        "type": "codex",
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "email": email,
        "name": _credential_display_name(credential, index),
        "plan_type": plan_type,
        "chatgpt_plan_type": plan_type,
        "id_token": _normalize_text(credential.get("id_token")),
        "access_token": _normalize_text(credential.get("access_token")),
        "refresh_token": _normalize_text(credential.get("refresh_token")),
        "session_token": _normalize_text(credential.get("session_token")),
        "last_refresh": now_iso,
        "expired": _iso_from_seconds(expiry, milliseconds=True),
    }
    return _strip_unavailable(record) or {}


def _sub2api_account(credential: dict[str, Any], index: int, now_iso: str) -> dict[str, Any]:
    account_id = _credential_account_id(credential)
    email = _credential_email(credential)
    plan_type = _credential_plan_type(credential)
    user_id = _credential_user_id(credential)
    expiry = _credential_expiry(credential)
    name = _credential_display_name(credential, index)
    account = {
        "name": name,
        "platform": "openai",
        "type": "oauth",
        "expires_at": expiry,
        "auto_pause_on_expired": True,
        "concurrency": 10,
        "priority": 1,
        "credentials": {
            "access_token": _normalize_text(credential.get("access_token")),
            "refresh_token": _normalize_text(credential.get("refresh_token")),
            "id_token": _normalize_text(credential.get("id_token")),
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": user_id,
            "email": email,
            "expires_at": _iso_from_seconds(expiry, milliseconds=True),
            "expires_in": _expires_in(expiry),
            "plan_type": plan_type,
        },
        "extra": {
            "email": email,
            "email_key": _to_email_key(email),
            "name": name,
            "auth_provider": "openai",
            "source": "llm-api-key-proxy",
            "last_refresh": now_iso,
        },
    }
    return _strip_unavailable(account) or {}


def _cockpit_record(credential: dict[str, Any], index: int, now_iso: str) -> dict[str, Any]:
    expiry = _credential_expiry(credential)
    record = {
        "type": "codex",
        "id_token": _normalize_text(credential.get("id_token")),
        "access_token": _normalize_text(credential.get("access_token")),
        "refresh_token": _normalize_text(credential.get("refresh_token")),
        "account_id": _credential_account_id(credential),
        "last_refresh": now_iso,
        "email": _credential_email(credential),
        "expired": _iso_from_seconds(expiry, milliseconds=True),
        "account_note": f"Exported from LLM API Key Proxy #{index}",
    }
    return _strip_unavailable(record) or {}


def _nine_router_record(credential: dict[str, Any], index: int, now_iso: str) -> dict[str, Any]:
    account_id = _credential_account_id(credential)
    plan_type = _credential_plan_type(credential)
    expiry = _credential_expiry(credential)
    record = {
        "accessToken": _normalize_text(credential.get("access_token")),
        "refreshToken": _normalize_text(credential.get("refresh_token")),
        "expiresAt": _iso_from_seconds(expiry, milliseconds=True),
        "testStatus": "active",
        "expiresIn": _expires_in(expiry),
        "providerSpecificData": {
            "chatgptAccountId": account_id,
            "chatgptPlanType": plan_type,
        },
        "id": account_id,
        "provider": "codex",
        "authType": "oauth",
        "name": _credential_display_name(credential, index),
        "email": _credential_email(credential),
        "priority": 9,
        "isActive": True,
        "createdAt": now_iso,
        "updatedAt": now_iso,
    }
    return _strip_unavailable(record) or {}


def _codex_auth_json(credential: dict[str, Any]) -> dict[str, Any]:
    return {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": credential.get("api_key") or None,
        "tokens": {
            "id_token": _normalize_text(credential.get("id_token")),
            "access_token": _normalize_text(credential.get("access_token")),
            "refresh_token": _normalize_text(credential.get("refresh_token")),
            "account_id": _credential_account_id(credential),
        },
        "last_refresh": _iso_now(milliseconds=True),
    }


def _axonhub_auth_json(credential: dict[str, Any]) -> dict[str, Any]:
    refresh_token = _normalize_text(credential.get("refresh_token"))
    record = {
        "auth_mode": "chatgpt",
        "last_refresh": _iso_now(milliseconds=True),
        "tokens": {
            "access_token": _normalize_text(credential.get("access_token")),
            "refresh_token": refresh_token or AXONHUB_PLACEHOLDER_REFRESH_TOKEN,
            "id_token": _normalize_text(credential.get("id_token")),
        },
        "axonhub_refresh_token_placeholder": True if not refresh_token else None,
        "axonhub_note": (
            "refresh_token is a placeholder; access_token works only until it expires."
            if not refresh_token
            else None
        ),
    }
    return _strip_unavailable(record) or {}


def _codex_manager_record(credential: dict[str, Any], index: int) -> dict[str, Any]:
    account_id = _credential_account_id(credential)
    workspace_id = _credential_workspace_id(credential)
    record = {
        "tokens": {
            "access_token": _normalize_text(credential.get("access_token")),
            "refresh_token": _normalize_text(credential.get("refresh_token")),
            "id_token": _normalize_text(credential.get("id_token")),
            "account_id": account_id,
            "chatgpt_account_id": account_id,
        },
        "meta": {
            "label": _credential_display_name(credential, index),
            "workspace_id": workspace_id,
            "chatgpt_account_id": account_id,
            "note": "Imported from LLM API Key Proxy",
        },
    }
    return _strip_unavailable(record) or {}


def _plain_record(credential: dict[str, Any], index: int) -> dict[str, Any]:
    metadata = credential.get("_proxy_metadata") if isinstance(credential.get("_proxy_metadata"), dict) else {}
    record = {
        "access_token": _normalize_text(credential.get("access_token")),
        "refresh_token": _normalize_text(credential.get("refresh_token")),
        "id_token": _normalize_text(credential.get("id_token")),
        "api_key": _normalize_text(credential.get("api_key")),
        "account_id": _credential_account_id(credential),
        "email": _credential_email(credential),
        "name": _credential_display_name(credential, index),
        "plan_type": _credential_plan_type(credential),
        "expired": _iso_from_seconds(_credential_expiry(credential), milliseconds=True),
        "metadata": metadata,
    }
    return _strip_unavailable(record) or {}


def normalize_export_format_id(format_id: str) -> str:
    normalized = _normalize_text(format_id).lower().replace("-", "_")
    if normalized in CODEX_EXPORT_ALIASES:
        return CODEX_EXPORT_ALIASES[normalized]
    raise CodexCredentialFormatError(f"Unsupported Codex export format: {format_id}")


def build_codex_export_payload(
    credentials: Iterable[dict[str, Any]],
    format_id: str,
) -> Any:
    """Build an export payload in a GPTSession2CPA/local checker compatible format."""
    requested_format = _normalize_text(format_id).lower().replace("-", "_")
    normalized_format = normalize_export_format_id(format_id)
    normalized_credentials = [
        normalize_codex_credential_payload(credential, f"credential #{index}")
        for index, credential in enumerate(credentials, start=1)
    ]
    now_iso = _iso_now(milliseconds=True)

    if normalized_format == "sub2api_admin_data":
        return {
            "exported_at": now_iso,
            "proxies": [],
            "accounts": [
                _sub2api_account(credential, index, now_iso)
                for index, credential in enumerate(normalized_credentials, start=1)
            ],
        }

    if normalized_format in {"cpa", "codex_session_array"}:
        records = [
            _cpa_record(credential, index, now_iso)
            for index, credential in enumerate(normalized_credentials, start=1)
        ]
        return records if normalized_format == "codex_session_array" or len(records) != 1 else records[0]

    if normalized_format == "codex_session_jsonl":
        return "".join(
            json.dumps(_cpa_record(credential, index, now_iso), ensure_ascii=False, separators=(",", ":"))
            + "\n"
            for index, credential in enumerate(normalized_credentials, start=1)
        )

    if normalized_format == "cockpit_codex_array":
        records = [
            _cockpit_record(credential, index, now_iso)
            for index, credential in enumerate(normalized_credentials, start=1)
        ]
        return records if requested_format == "cockpit_codex_array" or len(records) != 1 else records[0]

    if normalized_format == "9router":
        records = [
            _nine_router_record(credential, index, now_iso)
            for index, credential in enumerate(normalized_credentials, start=1)
        ]
        return records if len(records) != 1 else records[0]

    if normalized_format == "codex":
        records = [_codex_auth_json(credential) for credential in normalized_credentials]
        return records if len(records) != 1 else records[0]

    if normalized_format == "axonhub":
        records = [_axonhub_auth_json(credential) for credential in normalized_credentials]
        return records if len(records) != 1 else records[0]

    if normalized_format == "codexmanager":
        records = [
            _codex_manager_record(credential, index)
            for index, credential in enumerate(normalized_credentials, start=1)
        ]
        return records if len(records) != 1 else records[0]

    if normalized_format == "plain_token_array":
        return [
            _plain_record(credential, index)
            for index, credential in enumerate(normalized_credentials, start=1)
        ]

    raise CodexCredentialFormatError(f"Unsupported Codex export format: {format_id}")


def load_codex_credentials_from_directory(base_dir: str | Path) -> list[dict[str, Any]]:
    """Load and normalize all ``codex_oauth_*.json`` credentials from a directory."""
    credentials: list[dict[str, Any]] = []
    for path in sorted(Path(base_dir).expanduser().glob("codex_oauth_*.json")):
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        credential = normalize_codex_credential_payload(payload, str(path))
        credential.setdefault("_proxy_metadata", {})["file_path"] = str(path.resolve())
        credentials.append(credential)
    return credentials


def write_codex_export_file(
    output_path: str | Path,
    credentials: Iterable[dict[str, Any]],
    format_id: str,
) -> Path:
    """Write Codex credentials to an export file in the selected format."""
    payload = build_codex_export_payload(credentials, format_id)
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    return path
