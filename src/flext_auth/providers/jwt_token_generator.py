"""FLEXT Auth JWT Token Generator - Dedicated token generation service.

This module provides a dedicated service for JWT token generation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flext_api import r

from flext_auth import FlextAuthJwtProvider, c, p, t, u


class FlextAuthJwtTokenGenerator:
    """Dedicated JWT token generator service.

    Single responsibility: Generate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def generate_token(
        self,
        identity_id: str,
        expiry_minutes: int | None = None,
        extra_claims: t.JsonMapping | None = None,
    ) -> p.Result[str]:
        """Generate JWT token with railway-oriented programming.

        Args:
        identity_id: Identity identifier for token subject
        expiry_minutes: Custom expiry time (uses settings default if None)
        extra_claims: Additional claims to include in token

        Returns:
        r containing token string or error

        """
        try:
            secret_result = self._get_config_str(
                "secret_key",
                "JWT secret key not configured",
            )
            algorithm_result = self._get_config_str(
                "algorithm",
                "JWT algorithm not configured",
            )
            expiry_config_result = self._get_config_int(
                "expiry_minutes",
                "JWT expiry_minutes not configured",
            )
            issuer_result = self._get_config_str("issuer", "JWT issuer not configured")
            audience_result = self._get_optional_config_str("audience")

            config_errors = [
                res.error or label
                for res, label in (
                    (secret_result, "Secret key error"),
                    (algorithm_result, "Algorithm error"),
                    (expiry_config_result, "Expiry error"),
                    (issuer_result, "Issuer error"),
                    (audience_result, "Audience error"),
                )
                if res.failure
            ]
            if config_errors:
                return r[str].fail(config_errors[0])

            expiry_result = self._validate_expiry(
                expiry_minutes,
                expiry_config_result.value,
            )
            if expiry_result.failure:
                return r[str].fail(expiry_result.error or "Expiry validation error")

            audience = audience_result.value or None
            payload = self._build_payload(
                identity_id,
                expiry_result.value,
                issuer_result.value,
                audience,
                extra_claims,
            )
            token_result = u.Auth.encode_token(
                dict(payload),
                secret_result.value,
                algorithm_result.value,
            )
            return (
                r[str].fail(token_result.error or "Token encoding failed")
                if token_result.failure
                else r[str].ok(token_result.value)
            )
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[str].fail_op("Token generation", exc)

    def _build_payload(
        self,
        identity_id: str,
        expiry_minutes: int,
        issuer: str,
        audience: str | None,
        extra_claims: t.JsonMapping | None,
    ) -> t.JsonMapping:
        """Build JWT token payload."""
        now = datetime.now(UTC)
        payload: t.MutableJsonMapping = {
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

    def _get_config_int(self, key: str, error_msg: str) -> p.Result[int]:
        """Get and validate integer configuration value."""
        settings = self._provider.settings
        if not settings:
            return r[int].fail(error_msg)
        value = settings.get(key)
        match value:
            case int() as number:
                return r[int].ok(number)
            case _:
                return r[int].fail(error_msg)

    def _get_config_str(self, key: str, error_msg: str) -> p.Result[str]:
        """Get and validate string configuration value."""
        settings = self._provider.settings
        if not settings:
            return r[str].fail(error_msg)
        value = settings.get(key)
        match value:
            case str() as text if text:
                return r[str].ok(text)
            case _:
                return r[str].fail(error_msg)

    def _get_optional_config_str(self, key: str) -> p.Result[str]:
        """Get optional string configuration value.

        Returns empty string if not provided (no None in r).
        """
        settings = self._provider.settings
        if not settings:
            return r[str].ok("")
        value = settings.get(key)
        if value is None:
            return r[str].ok("")
        match value:
            case str() as text:
                return r[str].ok(text)
            case _:
                return r[str].fail(f"{key} must be a string if provided")

    def _validate_expiry(
        self, expiry_minutes: int | None, default: int
    ) -> p.Result[int]:
        """Validate and determine expiry time."""
        if expiry_minutes is None:
            return r[int].ok(default)
        match expiry_minutes:
            case int() as minutes if minutes > 0:
                return r[int].ok(minutes)
            case _:
                return r[int].fail("expiry_minutes must be a positive integer")


__all__: t.MutableSequenceOf[str] = ["FlextAuthJwtTokenGenerator"]
