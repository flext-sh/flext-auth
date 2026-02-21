"""FLEXT Auth JWT Token Validator - Dedicated token validation service.

This module provides a dedicated service for JWT token validation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import jwt
from flext_auth.providers.jwt import FlextAuthJwtProvider
from flext_auth.typings import t
from flext_core import r


class FlextAuthJwtTokenValidator:
    """Dedicated JWT token validator service.

    Single responsibility: Validate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def validate_token(self, token: str) -> r[dict[str, t.GeneralValueType]]:
        """Validate JWT token with railway-oriented programming.

        Args:
        token: JWT token string to validate

        Returns:
        FlextResult containing token payload or error

        """
        try:
            # Get configuration from provider
            config = self._provider.config
            if not config:
                return r[dict[str, t.GeneralValueType]].fail(
                    "JWT configuration not provided"
                )

            secret_key_value = config.get("secret_key")
            if not isinstance(secret_key_value, str) or not secret_key_value:
                return r[dict[str, t.GeneralValueType]].fail(
                    "JWT secret key not configured"
                )
            secret_key = secret_key_value

            algorithm_value = config.get("algorithm")
            if not isinstance(algorithm_value, str):
                return r[dict[str, t.GeneralValueType]].fail(
                    "JWT algorithm not configured"
                )
            algorithm = algorithm_value

            audience_value = config.get("audience")
            if audience_value is not None:
                if not isinstance(audience_value, str):
                    return r[dict[str, t.GeneralValueType]].fail(
                        "JWT audience must be a string if provided",
                    )
                audience = audience_value
            else:
                audience = None

            # Decode and validate token
            decode_options = {"verify_exp": True, "verify_iat": True}
            if audience is not None:
                payload = jwt.decode(
                    token,
                    secret_key,
                    algorithms=[algorithm],
                    audience=audience,
                    options=decode_options,
                )
            else:
                payload = jwt.decode(
                    token,
                    secret_key,
                    algorithms=[algorithm],
                    options=decode_options,
                )

            return r[dict[str, t.GeneralValueType]].ok(payload)

        except jwt.ExpiredSignatureError:
            return r[dict[str, t.GeneralValueType]].fail("Token has expired")
        except jwt.InvalidTokenError as e:
            return r[dict[str, t.GeneralValueType]].fail(f"Invalid token: {e}")
        except Exception as e:
            return r[dict[str, t.GeneralValueType]].fail(
                f"Token validation failed: {e}"
            )


__all__ = ["FlextAuthJwtTokenValidator"]
