# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Mirrowel

"""
Credential health checker.

Blocks credentials with durable manual re-auth health records before ordinary
cooldowns, quota windows, or fair-cycle checks are evaluated.
"""

from typing import Optional

from ..types import CredentialState, LimitCheckResult, LimitResult
from .base import LimitChecker


class CredentialHealthChecker(LimitChecker):
    """Checks durable credential health state."""

    @property
    def name(self) -> str:
        return "credential_health"

    def check(
        self,
        state: CredentialState,
        model: str,
        quota_group: Optional[str] = None,
    ) -> LimitCheckResult:
        """Block credentials that require manual re-authentication."""
        health = getattr(state, "credential_health", None)
        if health and health.is_blocking:
            return LimitCheckResult.blocked(
                result=LimitResult.BLOCKED_CREDENTIAL_HEALTH,
                reason=f"Credential health status: {health.status} ({health.reason or 'unknown'})",
            )

        return LimitCheckResult.ok()

    def reset(
        self,
        state: CredentialState,
        model: Optional[str] = None,
        quota_group: Optional[str] = None,
    ) -> None:
        """Clear the durable health block for this credential."""
        if hasattr(state, "credential_health"):
            delattr(state, "credential_health")
