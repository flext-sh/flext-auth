"""FLEXT Auth JWT Token Validator - Dedicated token validation service.

This module provides a dedicated service for JWT token validation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import jwt
from flext_core import FlextResult

if TYPE_CHECKING:
    from flext_auth.providers.jwt import FlextAuthJwtProvider


class FlextAuthJwtTokenValidator:
    """Dedicated JWT token validator service.

    Single responsibility: Validate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def validate_token(self, token: str) -> FlextResult[dict[str, Any]]:
        """Validate JWT token with railway-oriented programming.

        Args:
            token: JWT token string to validate

        Returns:
            FlextResult containing token payload or error

        """
        try:
            # Get configuration from provider
            config = self._provider.config
            secret_key = config.get("secret_key")
            algorithm = config.get("algorithm", "HS256")
            audience = config.get("audience")

            if not secret_key:
                return FlextResult.fail("JWT secret key not configured")

            # Decode and validate token
            payload = jwt.decode(
                token,
                secret_key,
                algorithms=[algorithm],
                audience=audience,
                options={"verify_exp": True, "verify_iat": True},
            )

            return FlextResult.ok(payload)

        except jwt.ExpiredSignatureError:
            return FlextResult.fail("Token has expired")
        except jwt.InvalidTokenError as e:
            return FlextResult.fail(f"Invalid token: {e}")
        except Exception as e:
            return FlextResult.fail(f"Token validation failed: {e}")


__all__ = ["FlextAuthJwtTokenValidator"]
