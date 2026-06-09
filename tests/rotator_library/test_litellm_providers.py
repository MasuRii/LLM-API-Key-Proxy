import urllib.request
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rotator_library.litellm_providers import get_provider_route

with patch.object(urllib.request, "urlopen", side_effect=OSError("network disabled in tests")):
    from rotator_library.providers.codex_provider import CodexProvider
from rotator_library.providers.provider_interface import SingletonABCMeta

MOCK_PROVIDERS = {
    "provider_with_slash": {
        "route": "myroute/",
    },
    "provider_without_slash": {
        "route": "myroute",
    },
    "provider_empty_route": {
        "route": "",
    },
    "provider_no_route": {
        "other_key": "value",
    },
    "provider_none_route": {
        "route": None,
    },
    "provider_int_route": {
        "route": 123,
    },
}

@pytest.mark.parametrize("provider_key, expected", [
    ("provider_with_slash", "myroute"),
    ("provider_without_slash", "myroute"),
    ("provider_empty_route", None),
    ("provider_no_route", None),
    ("unknown_provider", None),
    ("provider_none_route", None),
    ("provider_int_route", None),
])
@patch("rotator_library.litellm_providers.SCRAPED_PROVIDERS", MOCK_PROVIDERS)
def test_get_provider_route(provider_key, expected):
    assert get_provider_route(provider_key) == expected


@pytest.fixture
def codex_provider():
    SingletonABCMeta._instances.pop(CodexProvider, None)
    provider = CodexProvider()
    yield provider
    SingletonABCMeta._instances.pop(CodexProvider, None)


def _mock_codex_auth(codex_provider):
    codex_provider.get_auth_header = AsyncMock(
        return_value={"Authorization": "Bearer fake-codex-token"}
    )
    codex_provider.get_account_id = AsyncMock(return_value=None)


async def _acompletion_with_service_tier(codex_provider, service_tier, *, stream=False):
    kwargs = {}
    if service_tier is not _SERVICE_TIER_OMITTED:
        kwargs["service_tier"] = service_tier

    return await codex_provider.acompletion(
        MagicMock(),
        credential_identifier="test-codex-credential.json",
        model="codex/gpt-5.3-codex",
        messages=[{"role": "user", "content": "write a tiny function"}],
        stream=stream,
        **kwargs,
    )


_SERVICE_TIER_OMITTED = object()


class TestCodexServiceTierForwarding:
    @pytest.mark.asyncio
    async def test_priority_service_tier_is_forwarded_to_upstream_responses_payload(
        self, codex_provider
    ):
        _mock_codex_auth(codex_provider)
        codex_provider._non_stream_with_retry = AsyncMock(return_value="ok")

        await _acompletion_with_service_tier(codex_provider, "priority")

        payload = codex_provider._non_stream_with_retry.await_args.args[2]
        assert payload["service_tier"] == "priority"

    @pytest.mark.parametrize("service_tier", ["auto", "default", "flex", "scale", "priority"])
    @pytest.mark.asyncio
    async def test_supported_service_tiers_are_forwarded_unchanged(
        self, codex_provider, service_tier
    ):
        _mock_codex_auth(codex_provider)
        codex_provider._non_stream_with_retry = AsyncMock(return_value="ok")

        await _acompletion_with_service_tier(codex_provider, service_tier)

        payload = codex_provider._non_stream_with_retry.await_args.args[2]
        assert payload["service_tier"] == service_tier

    @pytest.mark.asyncio
    async def test_fast_service_tier_alias_is_forwarded_as_priority(self, codex_provider):
        _mock_codex_auth(codex_provider)
        codex_provider._non_stream_with_retry = AsyncMock(return_value="ok")

        await _acompletion_with_service_tier(codex_provider, "fast")

        payload = codex_provider._non_stream_with_retry.await_args.args[2]
        assert payload["service_tier"] == "priority"

    @pytest.mark.parametrize("service_tier", [_SERVICE_TIER_OMITTED, ""])
    @pytest.mark.asyncio
    async def test_missing_or_empty_service_tier_is_omitted(self, codex_provider, service_tier):
        _mock_codex_auth(codex_provider)
        codex_provider._non_stream_with_retry = AsyncMock(return_value="ok")

        await _acompletion_with_service_tier(codex_provider, service_tier)

        payload = codex_provider._non_stream_with_retry.await_args.args[2]
        assert "service_tier" not in payload

    @pytest.mark.parametrize("service_tier", ["premium", 123])
    @pytest.mark.asyncio
    async def test_unsupported_service_tier_raises_before_upstream_dispatch(
        self, codex_provider, service_tier
    ):
        _mock_codex_auth(codex_provider)
        codex_provider._non_stream_with_retry = AsyncMock(return_value="ok")

        with pytest.raises(ValueError, match="service_tier"):
            await _acompletion_with_service_tier(codex_provider, service_tier)

        codex_provider._non_stream_with_retry.assert_not_called()
        codex_provider.get_auth_header.assert_not_called()
        codex_provider.get_account_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_service_tier_is_forwarded_to_streaming_payload(self, codex_provider):
        _mock_codex_auth(codex_provider)
        stream_result = MagicMock()
        codex_provider._stream_with_retry = MagicMock(return_value=stream_result)

        result = await _acompletion_with_service_tier(codex_provider, "priority", stream=True)

        payload = codex_provider._stream_with_retry.call_args.args[2]
        assert payload["service_tier"] == "priority"
        assert result is stream_result
