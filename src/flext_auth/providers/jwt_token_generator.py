"""FLEXT Auth JWT Token Generator - Dedicated token generation service.

This module provides a dedicated service for JWT token generation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import jwt
from flext_core import FlextResult

if TYPE_CHECKING:
    from flext_auth.providers.jwt import FlextAuthJwtProvider


class FlextAuthJwtTokenGenerator:
    """Dedicated JWT token generator service.

    Single responsibility: Generate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def _get_config_str(self, key: str, error_msg: str) -> FlextResult[str]:
        """Get and validate string configuration value."""
        config = self._provider.config
        value = config.get(key)
        if not isinstance(value, str) or not value:
            return FlextResult[str].fail(error_msg)
        return FlextResult[str].ok(value)

    def _get_config_int(self, key: str, error_msg: str) -> FlextResult[int]:
        """Get and validate integer configuration value."""
        config = self._provider.config
        value = config.get(key)
        if not isinstance(value, int):
            return FlextResult[int].fail(error_msg)
        return FlextResult[int].ok(value)

    def _get_optional_config_str(self, key: str) -> FlextResult[str]:
        """Get optional string configuration value.

        Returns empty string if not provided (no None in FlextResult).
        """
        config = self._provider.config
        value = config.get(key)
        if value is None:
            # Return empty string instead of None - no None in FlextResult
            return FlextResult[str].ok("")
        if not isinstance(value, str):
            return FlextResult[str].fail(f"{key} must be a string if provided")
        return FlextResult[str].ok(value)

    def _validate_expiry(
        self, expiry_minutes: int | None, default: int
    ) -> FlextResult[int]:
        """Validate and determine expiry time."""
        if expiry_minutes is None:
            return FlextResult[int].ok(default)
        if not isinstance(expiry_minutes, int) or expiry_minutes <= 0:
            return FlextResult[int].fail("expiry_minutes must be a positive integer")
        return FlextResult[int].ok(expiry_minutes)

    def _build_payload(
        self,
        identity_id: str,
        expiry_minutes: int,
        issuer: str,
        audience: str | None,
        extra_claims: dict[str, object] | None,
    ) -> dict[str, object]:
        """Build JWT token payload."""
        now = datetime.now(UTC)
        payload: dict[str, object] = {
            "sub": identity_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=expiry_minutes)).timestamp()),
            "iss": issuer,
        }
        if audience is not None:
            payload["aud"] = audience
        if extra_claims:
            payload.update(extra_claims)
        return payload

    def generate_token(
        self,
        identity_id: str,
        expiry_minutes: int | None = None,
        extra_claims: dict[str, object] | None = None,
    ) -> FlextResult[str]:
        """Generate JWT token with railway-oriented programming.

        Args:
        identity_id: Identity identifier for token subject
        expiry_minutes: Custom expiry time (uses config default if None)
        extra_claims: Additional claims to include in token

        Returns:
        FlextResult containing token string or error

        """
        try:
            # Get required configuration values
            secret_result = self._get_config_str(
                "secret_key", "JWT secret key not configured"
            )
            if secret_result.is_failure:
                return FlextResult[str].fail(secret_result.error or "Secret key error")

            algorithm_result = self._get_config_str(
                "algorithm", "JWT algorithm not configured"
            )
            if algorithm_result.is_failure:
                return FlextResult[str].fail(
                    algorithm_result.error or "Algorithm error"
                )

            expiry_config_result = self._get_config_int(
                "expiry_minutes", "JWT expiry_minutes not configured"
            )
            if expiry_config_result.is_failure:
                return FlextResult[str].fail(
                    expiry_config_result.error or "Expiry error"
                )

            issuer_result = self._get_config_str("issuer", "JWT issuer not configured")
            if issuer_result.is_failure:
                return FlextResult[str].fail(issuer_result.error or "Issuer error")

            # Validate expiry
            expiry_result = self._validate_expiry(
                expiry_minutes, expiry_config_result.unwrap()
            )
            if expiry_result.is_failure:
                return FlextResult[str].fail(
                    expiry_result.error or "Expiry validation error"
                )

            # Get optional audience
            audience_result = self._get_optional_config_str("audience")
            if audience_result.is_failure:
                return FlextResult[str].fail(audience_result.error or "Audience error")

            # Build payload and generate token
            audience_value = audience_result.unwrap()
            # Use None only for payload construction, not in FlextResult
            audience: str | None = audience_value or None

            payload = self._build_payload(
                identity_id,
                expiry_result.unwrap(),
                issuer_result.unwrap(),
                audience,
                extra_claims,
            )
            token_bytes = jwt.encode(
                payload, secret_result.unwrap(), algorithm=algorithm_result.unwrap()
            )
            token = token_bytes.decode("utf-8")
            return FlextResult[str].ok(token)

        except Exception as e:
            return FlextResult[str].fail(f"Token generation failed: {e}")


__all__ = ["FlextAuthJwtTokenGenerator"]
