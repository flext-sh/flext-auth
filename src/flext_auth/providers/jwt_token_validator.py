"""FLEXT Auth JWT Token Validator - Dedicated token validation service.

This module provides a dedicated service for JWT token validation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping

import jwt
from flext_core import r

from flext_auth.providers.jwt import FlextAuthJwtProvider


class FlextAuthJwtTokenValidator:
    """Dedicated JWT token validator service.

    Single responsibility: Validate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def validate_token(self, token: str) -> r[Mapping[str, object]]:
        """Validate JWT token with railway-oriented programming.

        Args:
        token: JWT token string to validate

        Returns:
        r containing token payload or error

        """
        try:
            config = self._provider.config
            if not config:
                return r[object].fail("JWT configuration not provided")
            secret_key_value = config.get("secret_key")
            match secret_key_value:
                case str() as secret if secret:
                    secret_key = secret
                case _:
                    return r[object].fail("JWT secret key not configured")
            algorithm_value = config.get("algorithm")
            match algorithm_value:
                case str() as algorithm_str:
                    algorithm = algorithm_str
                case _:
                    return r[object].fail("JWT algorithm not configured")
            audience_value = config.get("audience")
            if audience_value is not None:
                match audience_value:
                    case str() as audience_str:
                        audience = audience_str
                    case _:
                        return r[object].fail(
                            "JWT audience must be a string if provided"
                        )
            else:
                audience = None
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
                    token, secret_key, algorithms=[algorithm], options=decode_options
                )
            return r[object].ok(payload)
        except jwt.ExpiredSignatureError:
            return r[object].fail("Token has expired")
        except jwt.InvalidTokenError as e:
            return r[object].fail(f"Invalid token: {e}")
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as e:
            return r[object].fail(f"Token validation failed: {e}")


__all__ = ["FlextAuthJwtTokenValidator"]
