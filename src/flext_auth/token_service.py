"""Token Service - JWT token management and validation service.

Provides centralized JWT token operations including creation, validation,
refresh, and revocation. Implements Railway-Oriented Programming for
robust token lifecycle management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextLogger, r

from flext_auth import (
    FlextAuthJwtProvider,
    FlextAuthManagers,
    FlextAuthProviderService,
    FlextAuthSettings,
    ServiceManagers,
    c,
    m,
    p,
    s,
)


class FlextAuthTokenService(s[bool]):
    """Flexible token service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Flexible composition with dependency injection and error handling.
    """

    def __init__(
        self,
        *,
        config: FlextAuthSettings,
        provider_service: FlextAuthProviderService,
        dispatcher: p.Dispatcher,
    ) -> None:
        """Flexible initialization with dependency injection."""
        super().__init__()
        self._managers = ServiceManagers(config, dispatcher)
        self._provider_service = provider_service
        self._jwt_provider_cache: FlextAuthJwtProvider | None = None

    @property
    def user_manager(self) -> FlextAuthManagers.FlextAuthUserManager:
        """Direct access to user manager for token operations."""
        return self._managers.user_manager

    @staticmethod
    def _short_token(token: str | None, length: int = 10) -> str:
        if token is None:
            return "None"
        if len(token) <= length:
            return token
        return f"{token[:length]}..."

    @override
    def execute(self) -> r[bool]:
        """Railway-oriented execute with focused service pattern."""
        return r[bool].fail(
            "Use specific token methods: validate_token, generate_jwt_token, etc.",
        )

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
        token_kind: str = c.Auth.TokenTypes.ACCESS.value,
    ) -> r[str]:
        """Railway-oriented JWT token generation with audit logging."""
        user_result = self.user_manager.get_user(user_id)
        if user_result.is_failure:
            error = user_result.error
            FlextLogger(__name__).info(
                "Token creation",
                user_id=user_id,
                token_type=token_kind,
                success=False,
                reason=error or "",
            )
            return r[str].fail(error or "User lookup failed")
        user = user_result.value
        user_dict = user.model_dump(exclude={"credential_hash"})
        token_result = self._get_jwt_provider_cached().flat_map(
            lambda provider: provider.generate_token_for_user(
                user_dict,
                token_kind=token_kind,
                expiry_minutes=expires_in_minutes,
            ),
        )
        if token_result.is_failure:
            error = token_result.error
            FlextLogger(__name__).info(
                "Token creation",
                user_id=user_id,
                token_type=token_kind,
                success=False,
                reason=error or "",
            )
            return r[str].fail(error or "Token generation failed")
        token_value = token_result.value
        FlextLogger(__name__).debug(
            "Token creation successful",
            user_id=user_id,
            token_type=token_kind,
        )
        return r[str].ok(token_value)

    def refresh_token(self, token: str) -> r[m.Auth.AuthToken]:
        """Railway-oriented token refresh with audit logging."""
        result = self._get_jwt_provider_cached().flat_map(
            lambda provider: provider.refresh(token),
        )
        if result.is_failure:
            error = result.error
            FlextLogger(__name__).info(
                "Token refresh",
                success=False,
                old_token_id=self._short_token(token),
                reason=error or "",
            )
            return r[m.Auth.AuthToken].fail(error or "Token refresh failed")
        refreshed = result.value
        auth_token = m.Auth.AuthToken(
            identity_id=refreshed.user_id,
            token=refreshed.token,
            expires_at=refreshed.expires_at,
            is_revoked=refreshed.is_revoked,
        )
        FlextLogger(__name__).debug(
            "Token refresh successful",
            old_token_id=self._short_token(token),
            new_token_id=self._short_token(auth_token.token),
        )
        return r[m.Auth.AuthToken].ok(auth_token)

    def validate_token(self, token: str) -> r[bool]:
        """Railway-oriented token validation with audit logging."""

        def _log_token_validation_error(error: str) -> None:
            FlextLogger(__name__).debug(
                "Token validation",
                success=False,
                token_id=self._short_token(token),
                reason=error or "Unknown error",
            )

        return (
            self
            ._get_jwt_provider_cached()
            .flat_map(lambda provider: provider.validate_token(token))
            .tap_error(_log_token_validation_error)
        )

    def _get_jwt_provider_cached(self) -> r[FlextAuthJwtProvider]:
        """Get JWT provider with lazy caching to eliminate repeated lookups."""
        if self._jwt_provider_cache is not None:
            return r[FlextAuthJwtProvider].ok(self._jwt_provider_cache)
        result = self._provider_service.get_jwt_provider()
        if result.is_failure:
            return result
        self._jwt_provider_cache = result.value
        return r[FlextAuthJwtProvider].ok(self._jwt_provider_cache)


__all__ = ["FlextAuthTokenService"]
