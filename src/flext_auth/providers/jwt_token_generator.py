"""FLEXT Auth JWT Token Generator - Dedicated token generation service.

This module provides a dedicated service for JWT token generation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt

from flext import r
from flext_auth.providers.jwt import FlextAuthJwtProvider


class FlextAuthJwtTokenGenerator:
    """Dedicated JWT token generator service.

    Single responsibility: Generate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def _get_config_str(self, key: str, error_msg: str) -> r[str]:
        """Get and validate string configuration value."""
        config = self._provider.config
        value = config.get(key)
        if not isinstance(value, str) or not value:
            return r[str].fail(error_msg)
        return r[str].ok(value)

    def _get_config_int(self, key: str, error_msg: str) -> r[int]:
        """Get and validate integer configuration value."""
        config = self._provider.config
        value = config.get(key)
        if not isinstance(value, int):
            return r[int].fail(error_msg)
        return r[int].ok(value)

    def _get_optional_config_str(self, key: str) -> r[str]:
        """Get optional string configuration value.

        Returns empty string if not provided (no None in r).
        """
        config = self._provider.config
        value = config.get(key)
        if value is None:
            # Return empty string instead of None - no None in r
            return r[str].ok("")
        if not isinstance(value, str):
            return r[str].fail(f"{key} must be a string if provided")
        return r[str].ok(value)

    def _validate_expiry(self, expiry_minutes: int | None, default: int) -> r[int]:
        """Validate and determine expiry time."""
        if expiry_minutes is None:
            return r[int].ok(default)
        if not isinstance(expiry_minutes, int) or expiry_minutes <= 0:
            return r[int].fail("expiry_minutes must be a positive integer")
        return r[int].ok(expiry_minutes)

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
    ) -> r[str]:
        """Generate JWT token with railway-oriented programming.

        Args:
        identity_id: Identity identifier for token subject
        expiry_minutes: Custom expiry time (uses config default if None)
        extra_claims: Additional claims to include in token

        Returns:
        r containing token string or error

        """
        try:
            # Get required configuration values
            secret_result = self._get_config_str(
                "secret_key",
                "JWT secret key not configured",
            )
            if secret_result.is_failure:
                return r[str].fail(secret_result.error or "Secret key error")

            algorithm_result = self._get_config_str(
                "algorithm",
                "JWT algorithm not configured",
            )
            if algorithm_result.is_failure:
                return r[str].fail(algorithm_result.error or "Algorithm error")

            expiry_config_result = self._get_config_int(
                "expiry_minutes",
                "JWT expiry_minutes not configured",
            )
            if expiry_config_result.is_failure:
                return r[str].fail(expiry_config_result.error or "Expiry error")

            issuer_result = self._get_config_str("issuer", "JWT issuer not configured")
            if issuer_result.is_failure:
                return r[str].fail(issuer_result.error or "Issuer error")

            # Validate expiry
            expiry_result = self._validate_expiry(
                expiry_minutes,
                expiry_config_result.value,
            )
            if expiry_result.is_failure:
                return r[str].fail(expiry_result.error or "Expiry validation error")

            # Get optional audience
            audience_result = self._get_optional_config_str("audience")
            if audience_result.is_failure:
                return r[str].fail(audience_result.error or "Audience error")

            # Build payload and generate token
            audience_value = audience_result.value
            # Use None only for payload construction, not in r
            audience: str | None = audience_value or None

            payload = self._build_payload(
                identity_id,
                expiry_result.value,
                issuer_result.value,
                audience,
                extra_claims,
            )
            token_result = jwt.encode(
                payload,
                secret_result.value,
                algorithm=algorithm_result.value,
            )
            # Handle both string and bytes return types from jwt.encode
            if isinstance(token_result, bytes):
                token = token_result.decode("utf-8")
            else:
                token = str(token_result)
            return r[str].ok(token)

        except Exception as e:
            return r[str].fail(f"Token generation failed: {e}")


__all__ = ["FlextAuthJwtTokenGenerator"]
