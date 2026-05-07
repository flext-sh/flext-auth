"""FLEXT Auth JWT Token Validator - Dedicated token validation service.

This module provides a dedicated service for JWT token validation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import c, p, r, t, u


class FlextAuthJwtTokenValidator:
    """Dedicated JWT token validator service.

    Single responsibility: Validate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: p.Auth.FlextAuthBaseProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def validate_token(self, token: str) -> p.Result[t.Auth.TokensClaimMap]:
        """Validate JWT token with railway-oriented programming.

        Args:
        token: JWT token string to validate

        Returns:
        r containing token payload or error

        """
        try:
            settings = self._provider.settings
            if not settings:
                return r[t.Auth.TokensClaimMap].fail(
                    "JWT configuration not provided",
                )
            return r[t.Auth.TokensClaimMap].from_result(
                u.Auth.decode_token(
                    token,
                    settings,
                ),
            )
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[t.Auth.TokensClaimMap].fail_op("Token validation", exc)


__all__: t.MutableSequenceOf[str] = ["FlextAuthJwtTokenValidator"]
