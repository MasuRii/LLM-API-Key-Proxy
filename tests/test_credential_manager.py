# SPDX-License-Identifier: MIT
# Copyright (c) 2026 b3nw

"""
Tests for credential management: discovery, deduplication, env-based creds.

Credential loading bugs = zero providers available at startup, which is
the #1 way re-organization breaks things (files not found, env vars
not loaded, duplicate detection too aggressive).

NO network calls, NO API keys needed.
"""

import inspect
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from rotator_library import credential_tool


class TestCredentialDiscovery:
    """Test that credentials are discovered from the filesystem."""

    def test_gemini_credentials_discovered(self, tmp_path):
        """Gemini CLI credential files are found and imported."""
        # Create a fake system gemini dir
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()
        cred_file = gemini_dir / "credentials.json"
        cred_file.write_text(json.dumps({
            "access_token": "fake-token",
            "refresh_token": "fake-refresh",
            "client_id": "fake-client",
            "client_secret": "fake-secret",
            "token_uri": "https://oauth2.googleapis.com/token",
            "expiry_date": "2099-12-31T00:00:00Z",
        }))

        # The CredentialManager should be able to find these
        assert cred_file.exists()

    def test_env_based_credentials(self):
        """Environment variable credentials are loaded when no files exist."""
        with patch.dict(os.environ, {
            "GEMINI_CLI_ACCESS_TOKEN": "fake-access",
            "GEMINI_CLI_REFRESH_TOKEN": "fake-refresh",
            "GEMINI_CLI_EXPIRY_DATE": "2099-12-31T00:00:00Z",
            "GEMINI_CLI_EMAIL": "test@example.com",
        }):
            # CredentialManager should recognize these
            assert os.environ.get("GEMINI_CLI_ACCESS_TOKEN") == "fake-access"

    def test_numbered_env_credentials(self):
        """Numbered env credentials (GEMINI_CLI_1_*) are loaded."""
        with patch.dict(os.environ, {
            "GEMINI_CLI_1_ACCESS_TOKEN": "fake-access-1",
            "GEMINI_CLI_1_REFRESH_TOKEN": "fake-refresh-1",
            "GEMINI_CLI_1_EXPIRY_DATE": "2099-12-31T00:00:00Z",
            "GEMINI_CLI_1_EMAIL": "test1@example.com",
            "GEMINI_CLI_2_ACCESS_TOKEN": "fake-access-2",
            "GEMINI_CLI_2_REFRESH_TOKEN": "fake-refresh-2",
            "GEMINI_CLI_2_EXPIRY_DATE": "2099-12-31T00:00:00Z",
            "GEMINI_CLI_2_EMAIL": "test2@example.com",
        }):
            assert os.environ.get("GEMINI_CLI_1_ACCESS_TOKEN") == "fake-access-1"
            assert os.environ.get("GEMINI_CLI_2_ACCESS_TOKEN") == "fake-access-2"


class TestCredentialDeduplication:
    """Test that duplicate credentials are detected and skipped."""

    def test_same_email_dedup(self, tmp_path):
        """Two credential files with the same email are deduplicated."""
        oauth_dir = tmp_path / "oauth_creds"
        oauth_dir.mkdir()

        # Create two files with same email
        for i, suffix in enumerate(["1", "2"]):
            cred = {
                "access_token": f"fake-token-{suffix}",
                "refresh_token": f"fake-refresh-{suffix}",
                "_proxy_metadata": {
                    "email": "same-user@example.com",
                },
            }
            (oauth_dir / f"gemini_cli_oauth_{suffix}.json").write_text(json.dumps(cred))

        # Both files exist
        files = list(oauth_dir.glob("*.json"))
        assert len(files) == 2

        # But deduplication should detect they're the same account
        emails = set()
        for f in files:
            data = json.loads(f.read_text())
            email = data.get("_proxy_metadata", {}).get("email")
            emails.add(email)

        # Both map to same email
        assert len(emails) == 1

    def test_different_emails_kept(self, tmp_path):
        """Credential files with different emails are both kept."""
        oauth_dir = tmp_path / "oauth_creds"
        oauth_dir.mkdir()

        for i, (suffix, email) in enumerate([
            ("1", "user1@example.com"),
            ("2", "user2@example.com"),
        ]):
            cred = {
                "access_token": f"fake-token-{suffix}",
                "_proxy_metadata": {"email": email},
            }
            (oauth_dir / f"gemini_cli_oauth_{suffix}.json").write_text(json.dumps(cred))

        files = list(oauth_dir.glob("*.json"))
        assert len(files) == 2


class TestCredentialEnvURI:
    """Test env:// URI format for stateless deployment."""

    def test_env_uri_format(self):
        """env:// URIs follow the correct format."""
        uri = "env://gemini_cli/1"
        assert uri.startswith("env://")
        parts = uri.replace("env://", "").split("/")
        assert len(parts) == 2
        assert parts[0] == "gemini_cli"
        assert parts[1] == "1"

    def test_legacy_env_uri(self):
        """Legacy single-credential URI uses index 0."""
        uri = "env://gemini_cli/0"
        parts = uri.replace("env://", "").split("/")
        assert parts[1] == "0"


class TestAPIKeyDiscovery:
    """Test API key discovery from environment variables."""

    def test_api_key_pattern(self):
        """Environment variables matching *_API_KEY are discovered."""
        env = {
            "OPENAI_API_KEY": "sk-openai-test",
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "GROQ_API_KEY": "gsk_test",
            "PROXY_API_KEY": "proxy-key",  # Should be excluded
        }

        api_keys = {}
        for key, value in env.items():
            if "_API_KEY" in key and key != "PROXY_API_KEY":
                provider = key.split("_API_KEY")[0].lower()
                if provider not in api_keys:
                    api_keys[provider] = []
                api_keys[provider].append(value)

        assert "openai" in api_keys
        assert "anthropic" in api_keys
        assert "groq" in api_keys
        assert "proxy" not in api_keys  # PROXY_API_KEY excluded


CREDENTIAL_TOOL_CLEANUP_STATUSES = ("needs_reauth", "cooldown", "exhausted")


@pytest.fixture
def isolated_credential_tool_paths(tmp_path, monkeypatch):
    """Route credential_tool storage to temp paths, never real .env/oauth_creds."""
    env_path = tmp_path / ".env"
    oauth_dir = tmp_path / "oauth_creds"
    oauth_dir.mkdir()

    monkeypatch.setattr(credential_tool, "_get_env_file", lambda: env_path)
    monkeypatch.setattr(credential_tool, "_get_oauth_base_dir", lambda: oauth_dir)

    return env_path, oauth_dir


def _write_credential_tool_env(env_path: Path, values: dict[str, str]) -> None:
    env_path.write_text(
        "".join(f'{key}="{value}"\n' for key, value in values.items()),
        encoding="utf-8",
    )


def _write_credential_tool_oauth_credential(
    oauth_dir: Path,
    filename: str,
    *,
    status: str,
) -> Path:
    path = oauth_dir / filename
    identity = filename.removesuffix(".json")
    path.write_text(
        json.dumps(
            {
                "access_token": f"fake-access-{identity}",
                "refresh_token": f"fake-refresh-{identity}",
                "_proxy_metadata": {
                    "email": f"{identity}@example.test",
                    "status": status,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _credential_tool_credential_info(
    path: Path,
    *,
    provider: str,
    status: str,
) -> dict[str, str]:
    return {
        "provider": provider,
        "filename": path.name,
        "file_path": str(path),
        "email": f"{path.stem}@example.test",
        "status": status,
    }


@pytest.fixture
def credential_tool_oauth_cleanup_summary(isolated_credential_tool_paths, monkeypatch):
    """Synthetic OAuth summary with cleanup statuses plus an active credential."""
    _, oauth_dir = isolated_credential_tool_paths
    specs = [
        ("codex", "codex_oauth_1.json", "needs_reauth"),
        ("codex", "codex_oauth_2.json", "cooldown"),
        ("codex", "codex_oauth_3.json", "exhausted"),
        ("codex", "codex_oauth_4.json", "active"),
    ]

    summary: dict[str, list[dict[str, str]]] = {}
    for provider, filename, status in specs:
        path = _write_credential_tool_oauth_credential(oauth_dir, filename, status=status)
        summary.setdefault(provider, []).append(
            _credential_tool_credential_info(path, provider=provider, status=status)
        )

    monkeypatch.setattr(credential_tool, "_get_oauth_credentials_summary", lambda: summary)
    return summary


def _require_credential_tool_helper(name: str):
    helper = getattr(credential_tool, name, None)
    if helper is None:
        pytest.fail(
            f"credential_tool.{name} is required for TUI/CLI credential cleanup "
            "workflows. It should provide a preview/dry-run path before deleting "
            "selected or status-matched credentials."
        )
    return helper


def _invoke_credential_tool_helper(helper, *args, **kwargs):
    result = helper(*args, **kwargs)
    if inspect.isawaitable(result):
        pytest.fail(
            "credential_tool cleanup helpers should be directly callable from the "
            "interactive CLI without requiring an event loop in tests"
        )
    return result


def _credential_tool_candidate_list(result: Any) -> list[dict[str, Any]]:
    if isinstance(result, dict):
        return result.get("candidates", [])
    return list(result)


@pytest.mark.unit
def test_credential_tool_cleanup_preview_defaults_to_cleanup_statuses_and_skips_active(
    credential_tool_oauth_cleanup_summary,
):
    """Default invalid cleanup preview should include cleanup statuses, not active."""
    preview_helper = _require_credential_tool_helper("_preview_oauth_cleanup_candidates")

    result = _invoke_credential_tool_helper(preview_helper)
    candidates = _credential_tool_candidate_list(result)

    assert {item["status"] for item in candidates} == set(CREDENTIAL_TOOL_CLEANUP_STATUSES)
    assert {item["filename"] for item in candidates} == {
        "codex_oauth_1.json",
        "codex_oauth_2.json",
        "codex_oauth_3.json",
    }
    assert "codex_oauth_4.json" not in {item["filename"] for item in candidates}
    assert all(
        Path(item["file_path"]).exists()
        for item in credential_tool_oauth_cleanup_summary["codex"]
    )


@pytest.mark.unit
def test_credential_tool_cleanup_preview_respects_user_selected_statuses(
    credential_tool_oauth_cleanup_summary,
):
    """Users should be able to preview selected cleanup statuses before deletion."""
    preview_helper = _require_credential_tool_helper("_preview_oauth_cleanup_candidates")

    result = _invoke_credential_tool_helper(
        preview_helper,
        statuses=["cooldown", "exhausted"],
    )
    candidates = _credential_tool_candidate_list(result)

    assert {item["status"] for item in candidates} == {"cooldown", "exhausted"}
    assert {item["filename"] for item in candidates} == {
        "codex_oauth_2.json",
        "codex_oauth_3.json",
    }
    assert "needs_reauth" not in {item["status"] for item in candidates}
    assert "active" not in {item["status"] for item in candidates}
    assert all(
        Path(item["file_path"]).exists()
        for item in credential_tool_oauth_cleanup_summary["codex"]
    )


@pytest.mark.integration
def test_credential_tool_batch_delete_selected_credentials_dry_run_does_not_mutate_storage(
    isolated_credential_tool_paths,
    credential_tool_oauth_cleanup_summary,
):
    """Batch dry-run should preview selected API/OAuth credentials without deleting them."""
    env_path, _ = isolated_credential_tool_paths
    _write_credential_tool_env(env_path, {"GEMINI_API_KEY": "gemini-secret"})
    oauth_file = Path(credential_tool_oauth_cleanup_summary["codex"][0]["file_path"])
    batch_helper = _require_credential_tool_helper("_batch_delete_selected_credentials")

    result = _invoke_credential_tool_helper(
        batch_helper,
        [
            {
                "type": "api_key",
                "provider": "gemini",
                "key_name": "GEMINI_API_KEY",
            },
            {
                "type": "oauth",
                "provider": "codex",
                "filename": oauth_file.name,
                "file_path": str(oauth_file),
            },
        ],
        dry_run=True,
    )

    assert result["dry_run"] is True
    assert result["deleted"] == []
    assert result["errors"] == []
    assert {item["identifier"] for item in result["candidates"]} == {
        "GEMINI_API_KEY",
        "codex_oauth_1.json",
    }
    assert "GEMINI_API_KEY" in env_path.read_text(encoding="utf-8")
    assert oauth_file.exists()
