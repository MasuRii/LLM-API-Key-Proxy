# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Mirrowel

import hashlib
import json
import os
from pathlib import Path
import uuid
import httpx
import logging
from typing import List, Dict, Any
from .provider_interface import ProviderInterface
from ..model_definitions import ModelDefinitions

lib_logger = logging.getLogger("rotator_library")
lib_logger.propagate = False
if not lib_logger.handlers:
    lib_logger.addHandler(logging.NullHandler())


class OpenAICompatibleProvider(ProviderInterface):
    """
    Generic provider implementation for any OpenAI-compatible API.
    This provider can be configured via environment variables to support
    custom OpenAI-compatible endpoints without requiring code changes.
    Supports both dynamic model discovery and static model definitions.

    Environment variable pattern:
        <NAME>_API_BASE - The API base URL (required)
        <NAME>_API_KEY  - The API key (optional for some providers)

    Example:
        MYSERVER_API_BASE=http://localhost:8000/v1
        MYSERVER_API_KEY=sk-xxx

    Note: This is only used for providers NOT in the known LiteLLM providers list.
    For known providers, setting _API_BASE will override their default endpoint.
    """

    skip_cost_calculation: bool = True  # Skip cost calculation for custom providers

    def __init__(self, provider_name: str):
        self.provider_name = provider_name
        # Get API base URL from environment (using _API_BASE pattern)
        self.api_base = os.getenv(f"{provider_name.upper()}_API_BASE")
        if not self.api_base:
            raise ValueError(
                f"Environment variable {provider_name.upper()}_API_BASE is required for custom OpenAI-compatible provider"
            )

        # Initialize model definitions loader
        self.model_definitions = ModelDefinitions()
        self._credential_overrides = self._load_credential_overrides()

    async def get_models(self, api_key: str, client: httpx.AsyncClient) -> List[str]:
        """
        Fetches the list of available models from the OpenAI-compatible API.
        Combines dynamic discovery with static model definitions.
        """
        models = []

        # First, try to get static model definitions
        static_models = self.model_definitions.get_all_provider_models(
            self.provider_name
        )
        if static_models:
            models.extend(static_models)
            lib_logger.info(
                f"Loaded {len(static_models)} static models for {self.provider_name}"
            )

        # Then, try dynamic discovery to get additional models
        try:
            models_url = f"{self.api_base.rstrip('/')}/models"
            response = await client.get(
                models_url, headers={"Authorization": f"Bearer {api_key}"}
            )
            response.raise_for_status()

            dynamic_models = [
                f"{self.provider_name}/{model['id']}"
                for model in response.json().get("data", [])
                if model["id"] not in [m.split("/")[-1] for m in static_models]
            ]

            if dynamic_models:
                models.extend(dynamic_models)
                lib_logger.debug(
                    f"Discovered {len(dynamic_models)} additional models for {self.provider_name}"
                )

        except httpx.RequestError:
            # Silently ignore dynamic discovery errors
            pass
        except Exception:
            # Silently ignore dynamic discovery errors
            pass

        return models

    def get_model_options(self, model_name: str) -> Dict[str, Any]:
        """
        Get options for a specific model from static definitions or environment variables.

        Args:
            model_name: Model name (without provider prefix)

        Returns:
            Dictionary of model options
        """
        # Extract model name without provider prefix if present
        if "/" in model_name:
            model_name = model_name.split("/")[-1]

        return self.model_definitions.get_model_options(self.provider_name, model_name)

    def _load_credential_overrides(self) -> Dict[str, Dict[str, Any]]:
        """Load credential-scoped request overrides from environment JSON or file."""
        env_prefix = self.provider_name.upper()
        overrides: Dict[str, Dict[str, Any]] = {}

        env_name = f"{env_prefix}_CREDENTIAL_OVERRIDES"
        raw = os.getenv(env_name)
        if raw:
            parsed = self._load_credential_override_json(raw, env_name)
            if parsed:
                overrides.update(parsed)

        path_env_name = f"{env_prefix}_CREDENTIAL_OVERRIDES_PATH"
        path_raw = os.getenv(path_env_name)
        if path_raw:
            try:
                raw = Path(path_raw).expanduser().read_text(encoding="utf-8")
            except OSError as exc:
                lib_logger.warning(
                    f"Could not read credential overrides from {path_env_name}: {exc}"
                )
            else:
                parsed = self._load_credential_override_json(raw, path_env_name)
                if parsed:
                    overrides.update(parsed)

        return overrides

    @staticmethod
    def _load_credential_override_json(
        raw: str,
        source: str,
    ) -> Dict[str, Dict[str, Any]]:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            lib_logger.warning(f"Invalid JSON in {source}; ignoring credential overrides")
            return {}
        if not isinstance(parsed, dict):
            lib_logger.warning(f"{source} must be a JSON object; ignoring")
            return {}

        overrides: Dict[str, Dict[str, Any]] = {}
        for credential_hash, value in parsed.items():
            if isinstance(credential_hash, str) and isinstance(value, dict):
                overrides[credential_hash] = value
        return overrides

    @staticmethod
    def _credential_hash(credential: str) -> str:
        return hashlib.sha256(credential.encode("utf-8")).hexdigest()

    @staticmethod
    def _merge_headers(
        existing_headers: Any,
        new_headers: Dict[str, str],
    ) -> Dict[str, str]:
        merged = dict(existing_headers) if isinstance(existing_headers, dict) else {}
        merged.update(new_headers)
        return merged

    def _default_request_headers(self) -> Dict[str, str]:
        """Provider-specific headers needed by some Pi OpenAI-compatible providers."""
        provider = self.provider_name.lower()
        if provider == "kilo":
            return {"X-KILOCODE-EDITORNAME": "Pi"}
        if provider == "cline":
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
                "X-TASK-ID": uuid.uuid4().hex,
                "X-IS-MULTIROOT": "false",
            }
        return {}

    async def transform_request(
        self,
        kwargs: Dict[str, Any],
        model_name: str,
        credential: str,
    ) -> List[str]:
        """Apply Pi-imported credential base URL/header overrides."""
        modifications: List[str] = []

        default_headers = self._default_request_headers()
        if default_headers:
            kwargs["extra_headers"] = self._merge_headers(
                kwargs.get("extra_headers"),
                default_headers,
            )
            modifications.append("applied provider request headers")

        override = self._credential_overrides.get(self._credential_hash(credential), {})
        base_url = override.get("base_url")
        if isinstance(base_url, str) and base_url.strip():
            kwargs["api_base"] = base_url.rstrip("/")
            modifications.append("applied credential api_base override")

        headers = override.get("headers")
        if isinstance(headers, dict):
            normalized_headers = {
                str(key): value
                for key, value in headers.items()
                if isinstance(value, str)
            }
            if normalized_headers:
                kwargs["extra_headers"] = self._merge_headers(
                    kwargs.get("extra_headers"),
                    normalized_headers,
                )
                modifications.append("applied credential header overrides")

        return modifications

    def has_custom_logic(self) -> bool:
        """
        Returns False since we want to use the standard litellm flow
        with just custom API base configuration.
        """
        return False

    async def get_auth_header(self, credential_identifier: str) -> Dict[str, str]:
        """
        Returns the standard Bearer token header for API key authentication.
        """
        return {"Authorization": f"Bearer {credential_identifier}"}
