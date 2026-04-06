"""FLEXT Auth JWT Token Validator - Dedicated token validation service.

This module provides a dedicated service for JWT token validation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import jwt
from jwt.types import Options

from flext_auth import FlextAuthJwtProvider, t
from flext_core import r


class FlextAuthJwtTokenValidator:
    """Dedicated JWT token validator service.

    Single responsibility: Validate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def validate_token(self, token: str) -> r[t.ContainerValueMapping]:
        """Validate JWT token with railway-oriented programming.

        Args:
        token: JWT token string to validate

        Returns:
        r containing token payload or error

        """
        try:
            config = self._provider.config
            if not config:
                return r[t.ContainerValueMapping].fail(
                    "JWT configuration not provided",
                )
            secret_key_value = config.get("secret_key")
            match secret_key_value:
                case str() as secret if secret:
                    secret_key = secret
                case _:
                    return r[t.ContainerValueMapping].fail(
                        "JWT secret key not configured",
                    )
            algorithm_value = config.get("algorithm")
            match algorithm_value:
                case str() as algorithm_str:
                    algorithm = algorithm_str
                case _:
                    return r[t.ContainerValueMapping].fail(
                        "JWT algorithm not configured",
                    )
            audience_value = config.get("audience")
            if audience_value is not None:
                match audience_value:
                    case str() as audience_str:
                        audience = audience_str
                    case _:
                        return r[t.ContainerValueMapping].fail(
                            "JWT audience must be a string if provided",
                        )
            else:
                audience = None
            decode_options = Options(verify_exp=True, verify_iat=True)
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
            return r[t.ContainerValueMapping].ok(payload)
        except jwt.ExpiredSignatureError:
            return r[t.ContainerValueMapping].fail("Token has expired")
        except jwt.InvalidTokenError as exc:
            return r[t.ContainerValueMapping].fail(f"Invalid token: {exc}")
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as exc:
            return r[t.ContainerValueMapping].fail(
                f"Token validation failed: {exc}",
            )


__all__ = ["FlextAuthJwtTokenValidator"]
