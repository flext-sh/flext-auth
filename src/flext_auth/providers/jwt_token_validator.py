"""FLEXT Auth JWT Token Validator - Dedicated token validation service.

This module provides a dedicated service for JWT token validation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import FlextAuthProviderMixin, p, r, t, u


class FlextAuthJwtTokenValidator:
    """Dedicated JWT token validator service.

    Single responsibility: Validate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: FlextAuthProviderMixin) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def validate_token(self, token: str) -> p.Result[t.JsonMapping]:
        """Validate JWT token with railway-oriented programming.

        Args:
        token: JWT token string to validate

        Returns:
        r containing token payload or error

        """
        try:
            settings = self._provider.settings
            if not settings:
                return r[t.JsonMapping].fail(
                    "JWT configuration not provided",
                )
            secret_key_value = settings.get("secret_key")
            match secret_key_value:
                case str() as secret if secret:
                    secret_key = secret
                case _:
                    return r[t.JsonMapping].fail(
                        "JWT secret key not configured",
                    )
            algorithm_value = settings.get("algorithm")
            match algorithm_value:
                case str() as algorithm_str:
                    algorithm = algorithm_str
                case _:
                    return r[t.JsonMapping].fail(
                        "JWT algorithm not configured",
                    )
            audience_value = settings.get("audience")
            if audience_value is not None:
                match audience_value:
                    case str() as audience_str:
                        audience = audience_str
                    case _:
                        return r[t.JsonMapping].fail(
                            "JWT audience must be a string if provided",
                        )
            else:
                audience = None
            decode_result = u.Auth.decode_token(
                token,
                t.SecretStr(secret_key),
                algorithms=(algorithm,),
                audience=audience,
            )
            if decode_result.failure:
                return r[t.JsonMapping].fail(
                    decode_result.error or "Invalid token",
                )
            return r[t.JsonMapping].ok(decode_result.value)
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as exc:
            return r[t.JsonMapping].fail(
                f"Token validation failed: {exc}",
            )


__all__: t.MutableSequenceOf[str] = ["FlextAuthJwtTokenValidator"]
