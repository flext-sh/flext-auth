"""Token Service - JWT token management and validation service.

Provides centralized JWT token operations including creation, validation,
refresh, and revocation. Implements Railway-Oriented Programming for
robust token lifecycle management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# FLEXT Standard imports
from flext import FlextResult as r,
    FlextService as s
from flext_core.dispatcher import FlextDispatcher

from flext_auth.constants import FlextAuthConstants as c
from flext_auth.managers import (
    FlextAuthManagers,
    ServiceManagerMixin,
)
from flext_auth.models import FlextAuthModels

# Forward reference to avoid circular import
# Import FlextAuthModels locally in methods where needed
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers.jwt import FlextAuthJwtProvider
from flext_auth.settings import FlextAuthSettings


class FlextAuthTokenService(ServiceManagerMixin, s[object]):
    """Flexible token service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Flexible composition with dependency injection and error handling.
    """

    def __init__(
        self,
        *,
        config: FlextAuthSettings,
        provider_service: FlextAuthProviderService,
        dispatcher: FlextDispatcher,
    ) -> None:
        """Flexible initialization with dependency injection."""
        super().__init__()
        self.init_managers(config, dispatcher)
        self._provider_service = provider_service
        # Lazy cache for JWT provider (initialized on first access)
        self._jwt_provider_cache: FlextAuthJwtProvider | None = None

    @property
    def user_manager(self) -> FlextAuthManagers.FlextAuthUserManager:
        """Direct access to user manager for token operations."""
        return self._user_manager

    def execute(self) -> r[object]:
        """Railway-oriented execute with focused service pattern."""
        return r[object].fail(
            "Use specific token methods: validate_token, generate_jwt_token, etc.",
        )

    # =========================================================================
    # ADVANCED TOKEN OPERATIONS WITH RAILWAY PATTERNS
    # =========================================================================

    def validate_token(self, token: str) -> r[FlextAuthModels.AuthIdentity]:
        """Railway-oriented token validation with audit logging."""
        result = self._get_jwt_provider_cached().flat_map(
            lambda provider: provider.validate_token(token),
        )
        if result.is_failure:
            error_msg = result.error if result.error is not None else "Unknown error"
            self.logger.debug(
                "Token validation",
                success=False,
                token_id=self._short_token(token),
                reason=error_msg,
            )
            return result
        identity = result.value
        self.logger.log_token_validation(
            success=True,
            username=identity.username,
            token_id=self._short_token(token),
        )
        return r[FlextAuthModels.AuthIdentity].ok(identity)

    def refresh_token(self, token: str) -> r[FlextAuthModels.AuthToken]:
        """Railway-oriented token refresh with audit logging."""
        result = self._get_jwt_provider_cached().flat_map(
            lambda provider: provider.refresh(token),
        )
        if result.is_failure:
            error = result.error
            self.logger.info(
                "Token refresh",
                success=False,
                old_token_id=self._short_token(token),
                reason=error,
            )

            return r[FlextAuthModels.AuthToken].fail(error or "Token refresh failed")

        refreshed = result.value
        self.logger.log_token_refresh(
            success=True,
            old_token_id=self._short_token(token),
            new_token_id=self._short_token(refreshed.token),
            username=refreshed.identity_id,
        )
        return r[FlextAuthModels.AuthToken].ok(refreshed)

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
        token_type: str = c.Auth.TokenTypes.ACCESS.value,
    ) -> r[str]:
        """Railway-oriented JWT token generation with audit logging."""
        user_result = self.user_manager.get_user(user_id)
        if user_result.is_failure:
            error = user_result.error
            self.logger.info(
                "Token creation",
                user_id=user_id,
                token_type=token_type,
                success=False,
                reason=error,
            )
            return r[str].fail(error or "User lookup failed")

        user = user_result.value
        token_result = self._get_jwt_provider_cached().flat_map(
            lambda provider: provider.generate_token_for_user(
                user,
                token_type=token_type,
                expiry_minutes=expires_in_minutes,
            ),
        )

        if token_result.is_failure:
            error = token_result.error
            self.logger.info(
                "Token creation",
                user_id=user_id,
                token_type=token_type,
                success=False,
                reason=error,
            )
            return r[str].fail(error or "Token generation failed")

        token_value = token_result.value
        self.logger.log_token_creation(
            user_id=user_id,
            token_type=token_type,
            success=True,
        )
        return r[str].ok(token_value)

    # =========================================================================
    # PRIVATE HELPER METHODS
    # =========================================================================

    def _get_jwt_provider_cached(self) -> r[FlextAuthJwtProvider]:
        """Get JWT provider with lazy caching to eliminate repeated lookups."""
        if self._jwt_provider_cache is not None:
            return r.ok(self._jwt_provider_cache)

        result = self._provider_service.get_provider("jwt").flat_map(
            lambda p: r.ok(p)
            if isinstance(p, FlextAuthJwtProvider)
            else r.fail("Invalid JWT provider type"),
        )
        if result.is_failure:
            return result
        self._jwt_provider_cache = result.value
        return r.ok(self._jwt_provider_cache)

    @staticmethod
    def _short_token(token: str | None, length: int = 10) -> str:
        if token is None:
            return "None"
        if len(token) <= length:
            return token
        return f"{token[:length]}..."


__all__ = ["FlextAuthTokenService"]
