# SPDX-License-Identifier: MIT
# Copyright (c) 2026 b3nw

"""Verification tests for pi_agent_importer key resolution logic.

Tests cover:
- SUPPORTED_PROVIDER_APIS includes "openai-responses"
- _resolve_pi_config_value handles all three modes (literal, env-var, !command)
- _credential_from_provider_api_key resolves models.json apiKey
- Full import_pi_agent_config flow with literal / env-var / command keys
- Fallback injection when auth.json lacks matching entries
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# 1.  Import the module (must run after setting up any env vars it reads)
# ---------------------------------------------------------------------------

os.environ.pop("PI_AGENT_AUTH_PATH", None)
os.environ.pop("PI_AGENT_MODELS_PATH", None)
os.environ.pop("PI_AGENT_IMPORT_ENABLED", None)
os.environ.pop("PI_AGENT_CACHE_PATH", None)
os.environ.pop("PI_AGENT_CREDENTIAL_OVERRIDES_DIR", None)
os.environ.pop("PI_AGENT_AUTH_ALIASES", None)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "proxy_app"))
import pi_agent_importer as pai


# ---------------------------------------------------------------------------
# 2.  Test SUPPORTED_PROVIDER_APIS
# ---------------------------------------------------------------------------

def test_supported_provider_apis_contains_openai_responses():
    assert "openai-responses" in pai.SUPPORTED_PROVIDER_APIS, (
        "SUPPORTED_PROVIDER_APIS must include openai-responses"
    )
    print("  PASS: SUPPORTED_PROVIDER_APIS includes 'openai-responses'")


# ---------------------------------------------------------------------------
# 3.  Test _resolve_pi_config_value - three modes
# ---------------------------------------------------------------------------

def test_resolve_literal_value():
    """A plain string that is NOT an env-var should be returned as-is."""
    result = pai._resolve_pi_config_value("pai_abc123_literal")
    assert result == "pai_abc123_literal", f"Expected literal, got {result!r}"
    print("  PASS: literal value returned as-is")


def test_resolve_env_var_value():
    """A string matching a set env-var should resolve to its value."""
    os.environ["__TEST_PI_SECRET_KEY"] = "pai_env_resolved_999"
    result = pai._resolve_pi_config_value("__TEST_PI_SECRET_KEY")
    assert result == "pai_env_resolved_999", f"Expected resolved env value, got {result!r}"
    print("  PASS: env-var name resolves to its value")


def test_resolve_env_var_precedence_over_literal():
    """If the value matches an env-var, the env-var wins (not literal)."""
    os.environ["__TEST_PI_SECRET_KEY"] = "pai_env_wins"
    result = pai._resolve_pi_config_value("__TEST_PI_SECRET_KEY")
    assert result == "pai_env_wins", f"Expected env value, got {result!r}"
    print("  PASS: env-var takes precedence over treating value as literal")


def test_resolve_command_value():
    """A string starting with '!' should execute via subprocess."""
    result = pai._resolve_pi_config_value("!echo pai_cmd_resolved")
    assert result == "pai_cmd_resolved", f"Expected 'pai_cmd_resolved', got {result!r}"
    print("  PASS: !command returns stdout")


def test_resolve_command_trailing_newline_stripped():
    """subprocess stdout should be stripped of trailing whitespace."""
    result = pai._resolve_pi_config_value("!echo pai_cmd_stripped")
    assert result == "pai_cmd_stripped", f"Expected 'pai_cmd_stripped', got {result!r}"
    print("  PASS: !command stdout is stripped")


def test_resolve_empty_after_strip_returns_none():
    """A value that is all whitespace should return None."""
    result = pai._resolve_pi_config_value("   ")
    assert result is None, f"Expected None, got {result!r}"
    print("  PASS: all-whitespace value returns None")


def test_resolve_none_or_non_string():
    """Non-string types and None should return None."""
    assert pai._resolve_pi_config_value(None) is None
    assert pai._resolve_pi_config_value(42) is None
    assert pai._resolve_pi_config_value(["pai_abc"]) is None
    print("  PASS: None and non-string return None")


def test_resolve_failed_command_returns_none():
    """A command that fails should return None gracefully."""
    result = pai._resolve_pi_config_value("!nonexistent_command_xyz_12345")
    assert result is None, f"Expected None for failed command, got {result!r}"
    print("  PASS: failed !command returns None")


# ---------------------------------------------------------------------------
# 4.  Test _credential_from_provider_api_key
# ---------------------------------------------------------------------------

def test_credential_from_provider_api_key_literal():
    """models.json apiKey literal should produce a credential."""
    cred = pai._credential_from_provider_api_key({"apiKey": "pai_from_models_json"})
    assert cred is not None, "Expected a credential from apiKey"
    assert cred.secret == "pai_from_models_json"
    assert cred.source_type == "api_key"
    print("  PASS: _credential_from_provider_api_key returns credential from literal apiKey")


def test_credential_from_provider_api_key_env_var():
    """models.json apiKey as env-var name should resolve."""
    os.environ["__TEST_PI_MODELS_KEY"] = "pai_resolved_from_models"
    cred = pai._credential_from_provider_api_key({"apiKey": "__TEST_PI_MODELS_KEY"})
    assert cred is not None, "Expected a credential from apiKey env-var"
    assert cred.secret == "pai_resolved_from_models"
    print("  PASS: _credential_from_provider_api_key resolves env-var apiKey")


def test_credential_from_provider_api_key_command():
    """models.json apiKey as !command should resolve."""
    cred = pai._credential_from_provider_api_key({"apiKey": "!echo pai_cmd_from_models"})
    assert cred is not None, "Expected a credential from command apiKey"
    assert cred.secret == "pai_cmd_from_models"
    print("  PASS: _credential_from_provider_api_key resolves !command apiKey")


def test_credential_from_provider_api_key_missing():
    """No apiKey field returns None."""
    cred = pai._credential_from_provider_api_key({})
    assert cred is None, "Expected None when no apiKey"
    print("  PASS: _credential_from_provider_api_key returns None when apiKey missing")


def test_credential_from_provider_api_key_empty():
    """Empty apiKey returns None."""
    cred = pai._credential_from_provider_api_key({"apiKey": ""})
    assert cred is None, "Expected None when apiKey empty"
    print("  PASS: _credential_from_provider_api_key returns None when apiKey empty")


# ---------------------------------------------------------------------------
# 5.  Full integration test with temp auth.json / models.json
# ---------------------------------------------------------------------------

def integration_test_with_temp_files():
    """Simulate the full import flow with auth.json and models.json."""
    from pathlib import Path
    import tempfile

    tmpdir = Path(tempfile.mkdtemp(prefix="pi_verify_"))
    auth_file = tmpdir / "auth.json"
    models_file = tmpdir / "models.json"
    cache_file = tmpdir / "cache.json"

    # --- Write auth.json with mixed key types ---
    # Pi uses numbered suffixes for multiple credentials
    auth_data = {
        "myprovider": {
            "type": "api_key",
            "key": "pai_auth_literal_111",
        },
        "myprovider-1": {
            "type": "api_key",
            "key": "__TEST_PI_AUTH_ENV_KEY",
        },
        "myprovider-2": {
            "type": "api_key",
            "key": "!echo pai_auth_cmd_222",
        },
        "other-provider": {
            "type": "api_key",
            "key": "pai_other_provider",
        },
    }
    auth_file.write_text(json.dumps(auth_data), encoding="utf-8")

    # --- Write models.json ---
    models_data = {
        "providers": {
            "myprovider": {
                "api": "openai-responses",
                "baseUrl": "https://api.myprovider.com/v1",
                "models": [{"id": "myprovider/model-alpha"}],
            },
        }
    }
    models_file.write_text(json.dumps(models_data), encoding="utf-8")

    # --- Set env-var for auth.json env-key ---
    os.environ["__TEST_PI_AUTH_ENV_KEY"] = "pai_auth_env_resolved"

    # --- Preserve and clear then restore env vars that could interfere ---
    old_auth = os.environ.get("PI_AGENT_AUTH_PATH")
    old_models = os.environ.get("PI_AGENT_MODELS_PATH")
    old_cache = os.environ.get("PI_AGENT_CACHE_PATH")
    old_prefix_auth = os.environ.get("MYPROVIDER_API_KEY_1")
    old_prefix_base = os.environ.get("MYPROVIDER_API_BASE")

    try:
        os.environ["PI_AGENT_AUTH_PATH"] = str(auth_file)
        os.environ["PI_AGENT_MODELS_PATH"] = str(models_file)
        os.environ["PI_AGENT_CACHE_PATH"] = str(cache_file)
        os.environ.pop("MYPROVIDER_API_KEY_1", None)
        os.environ.pop("MYPROVIDER_API_BASE", None)

        summary = pai.import_pi_agent_config(root_dir=tmpdir)

        print(f"  Summary: {summary.compact_message()}")
        assert summary.enabled, "Expected import to be enabled"
        assert summary.providers_loaded == 1, f"Expected 1 provider, got {summary.providers_loaded}"
        assert summary.api_keys_loaded == 3, (
            f"Expected 3 API keys (literal+env+cmd), got {summary.api_keys_loaded}"
        )
        assert summary.models_loaded == 1, f"Expected 1 model, got {summary.models_loaded}"

        # --- Verify injected env vars ---
        # _auth_match_sort_key ranks exact match (0, name) over numbered suffixed (N+1, name)
        api_key_1 = os.environ.get("MYPROVIDER_API_KEY_1")
        api_key_2 = os.environ.get("MYPROVIDER_API_KEY_2")
        api_key_3 = os.environ.get("MYPROVIDER_API_KEY_3")
        # myprovider (exact match) comes first, then myprovider-1 (sort key 2), then myprovider-2 (sort key 3)
        assert api_key_1 == "pai_auth_literal_111", f"Expected MYPROVIDER_API_KEY_1='pai_auth_literal_111', got {api_key_1!r}"
        assert api_key_2 == "pai_auth_env_resolved", f"Expected MYPROVIDER_API_KEY_2='pai_auth_env_resolved', got {api_key_2!r}"
        assert api_key_3 == "pai_auth_cmd_222", f"Expected MYPROVIDER_API_KEY_3='pai_auth_cmd_222', got {api_key_3!r}"

        api_base = os.environ.get("MYPROVIDER_API_BASE")
        assert api_base == "https://api.myprovider.com/v1", f"Expected MYPROVIDER_API_BASE, got {api_base!r}"

        print("  PASS: Full integration - literal, env, and command keys all resolved correctly")

    finally:
        # Cleanup
        for key in ["PI_AGENT_AUTH_PATH", "PI_AGENT_MODELS_PATH", "PI_AGENT_CACHE_PATH",
                     "MYPROVIDER_API_KEY_1", "MYPROVIDER_API_KEY_2", "MYPROVIDER_API_KEY_3",
                     "MYPROVIDER_API_BASE", "__TEST_PI_AUTH_ENV_KEY"]:
            os.environ.pop(key, None)
        if old_auth is not None:
            os.environ["PI_AGENT_AUTH_PATH"] = old_auth
        if old_models is not None:
            os.environ["PI_AGENT_MODELS_PATH"] = old_models
        if old_cache is not None:
            os.environ["PI_AGENT_CACHE_PATH"] = old_cache
        if old_prefix_auth is not None:
            os.environ["MYPROVIDER_API_KEY_1"] = old_prefix_auth
        if old_prefix_base is not None:
            os.environ["MYPROVIDER_API_BASE"] = old_prefix_base
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("  PASS: Integration test cleaned up successfully")


# ---------------------------------------------------------------------------
# 6.  Fallback to models.json apiKey when auth.json lacks entries
# ---------------------------------------------------------------------------

def integration_test_fallback_to_models_api_key():
    """When auth.json has NO matching entries, models.json apiKey should be injected."""
    tmpdir = Path(tempfile.mkdtemp(prefix="pi_fallback_"))
    auth_file = tmpdir / "auth.json"
    models_file = tmpdir / "models.json"

    # auth.json has no "fallback-provider" entries
    auth_data = {"unrelated": {"type": "api_key", "key": "pai_unrelated"}}
    auth_file.write_text(json.dumps(auth_data), encoding="utf-8")

    # models.json has an apiKey on the provider config
    models_data = {
        "providers": {
            "fallback-provider": {
                "api": "openai-completions",
                "baseUrl": "https://api.fallback.com/v1",
                "apiKey": "__TEST_PI_FALLBACK_KEY",
                "models": [{"id": "fallback/model-one"}],
            },
        }
    }
    models_file.write_text(json.dumps(models_data), encoding="utf-8")

    os.environ["__TEST_PI_FALLBACK_KEY"] = "pai_fallback_resolved"

    old_auth = os.environ.get("PI_AGENT_AUTH_PATH")
    old_models = os.environ.get("PI_AGENT_MODELS_PATH")

    try:
        os.environ["PI_AGENT_AUTH_PATH"] = str(auth_file)
        os.environ["PI_AGENT_MODELS_PATH"] = str(models_file)

        summary = pai.import_pi_agent_config(root_dir=tmpdir)

        print(f"  Summary: {summary.compact_message()}")
        assert summary.enabled, "Expected import to be enabled"
        assert summary.providers_loaded == 1, f"Expected 1 provider, got {summary.providers_loaded}"
        assert summary.api_keys_loaded == 1, (
            f"Expected 1 API key from models.json fallback, got {summary.api_keys_loaded}"
        )

        api_key_1 = os.environ.get("FALLBACK_PROVIDER_API_KEY_1")
        assert api_key_1 == "pai_fallback_resolved", (
            f"Expected FALLBACK_PROVIDER_API_KEY_1='pai_fallback_resolved', got {api_key_1!r}"
        )

        api_base = os.environ.get("FALLBACK_PROVIDER_API_BASE")
        assert api_base == "https://api.fallback.com/v1", (
            f"Expected FALLBACK_PROVIDER_API_BASE, got {api_base!r}"
        )

        print("  PASS: Fallback to models.json apiKey works correctly")
        print("  PASS: Env-var resolution in fallback apiKey works")

    finally:
        for key in ["PI_AGENT_AUTH_PATH", "PI_AGENT_MODELS_PATH",
                     "FALLBACK_PROVIDER_API_KEY_1", "FALLBACK_PROVIDER_API_BASE",
                     "__TEST_PI_FALLBACK_KEY"]:
            os.environ.pop(key, None)
        if old_auth is not None:
            os.environ["PI_AGENT_AUTH_PATH"] = old_auth
        if old_models is not None:
            os.environ["PI_AGENT_MODELS_PATH"] = old_models
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 7.  Test self-referential base URL skip
# ---------------------------------------------------------------------------

def test_self_referential_base_url():
    assert pai._is_self_referential_base_url("http://127.0.0.1:8080", 8080) is True
    assert pai._is_self_referential_base_url("http://127.0.0.1:8081", 8080) is False
    assert pai._is_self_referential_base_url("http://localhost:8080", 8080) is True
    assert pai._is_self_referential_base_url("http://example.com:8080", 8080) is False
    assert pai._is_self_referential_base_url("http://127.0.0.1:8080", None) is False
    print("  PASS: self-referential base URL detection")


# ---------------------------------------------------------------------------
# 8.  Run all tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Pi Agent Importer Verification Tests")
    print("=" * 70)
    print()

    passed = 0
    failed = 0

    tests = [
        ("SUPPORTED_PROVIDER_APIS", test_supported_provider_apis_contains_openai_responses),
        ("Literal value", test_resolve_literal_value),
        ("Env-var value", test_resolve_env_var_value),
        ("Env-var precedence", test_resolve_env_var_precedence_over_literal),
        ("Command value", test_resolve_command_value),
        ("Command trailing newline", test_resolve_command_trailing_newline_stripped),
        ("Empty after strip", test_resolve_empty_after_strip_returns_none),
        ("None/non-string", test_resolve_none_or_non_string),
        ("Failed command", test_resolve_failed_command_returns_none),
        ("Credential from apiKey literal", test_credential_from_provider_api_key_literal),
        ("Credential from apiKey env-var", test_credential_from_provider_api_key_env_var),
        ("Credential from apiKey cmd", test_credential_from_provider_api_key_command),
        ("Credential from apiKey missing", test_credential_from_provider_api_key_missing),
        ("Credential from apiKey empty", test_credential_from_provider_api_key_empty),
        ("Self-referential URL", test_self_referential_base_url),
    ]

    for name, func in tests:
        try:
            func()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
        print()

    print("=" * 70)
    print("Integration tests (create temp files)")
    print("=" * 70)
    print()

    try:
        integration_test_with_temp_files()
        passed += 1
    except Exception as e:
        print(f"  FAIL: full integration: {e}")
        import traceback
        traceback.print_exc()
        failed += 1
    print()

    try:
        integration_test_fallback_to_models_api_key()
        passed += 1
    except Exception as e:
        print(f"  FAIL: fallback integration: {e}")
        import traceback
        traceback.print_exc()
        failed += 1
    print()

    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 70)

    sys.exit(1 if failed else 0)
