"""FLEXT Auth Token Service - Flexible flext-core patterns with minimal line count.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated patterns
for maximum maintainability. Single FlextAuthTokenService class with composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDispatcher, FlextResult, FlextService

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.managers import (
    ServiceManagerMixin,
)
from flext_auth.models import FlextAuthModels
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers.jwt import FlextAuthJwtProvider


class FlextAuthTokenService(ServiceManagerMixin, FlextService):
    """Flexible token service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Flexible composition with dependency injection and error handling.
    """

    def __init__(
        self,
        config: FlextAuthConfig,
        provider_service: FlextAuthProviderService,
        dispatcher: FlextDispatcher,
    ) -> None:
        """Flexible initialization with dependency injection."""
        super().__init__()
        self._init_managers(config, dispatcher)
        self._provider_service = provider_service
        # Lazy cache for JWT provider (initialized on first access)
        self._jwt_provider_cache: FlextAuthJwtProvider | None = None

    def execute(self) -> FlextResult[object]:
        """Railway-oriented execute with focused service pattern."""
        return FlextResult.fail(
            "Use specific token methods: validate_token, generate_jwt_token, etc."
        )

    # =========================================================================
    # ADVANCED TOKEN OPERATIONS WITH RAILWAY PATTERNS
    # =========================================================================

    def validate_token(self, token: str) -> FlextResult[FlextAuthModels.Identity]:
        """Railway-oriented token validation with audit logging."""
        provider_result = self._get_jwt_provider_cached().flat_map(
            lambda provider: provider.validate_token(token)
        )
        if provider_result.is_failure:
            error = provider_result.error
            self._audit_logger.log_token_validation(
                success=False,
                token_id=self._short_token(token),
                reason=error,
            )
            return FlextResult[FlextAuthModels.Identity].fail(error)

        identity_result = self._ensure_identity_present(provider_result.unwrap())
        if identity_result.is_failure:
            error = identity_result.error
            self._audit_logger.log_token_validation(
                success=False,
                token_id=self._short_token(token),
                reason=error,
            )
            return FlextResult[FlextAuthModels.Identity].fail(error)

        identity = identity_result.unwrap()
        self._audit_logger.log_token_validation(
            success=True,
            username=identity.username,
            token_id=self._short_token(token),
        )
        return FlextResult[FlextAuthModels.Identity].ok(identity)

    def refresh_token(self, token: str) -> FlextResult[FlextAuthModels.AuthToken]:
        """Railway-oriented token refresh with audit logging."""
        result = self._get_jwt_provider_cached().flat_map(
            lambda provider: provider.refresh(token)
        )
        if result.is_failure:
            error = result.error
            self._audit_logger.log_token_refresh(
                success=False,
                old_token_id=self._short_token(token),
                reason=error,
            )
            return FlextResult[FlextAuthModels.AuthToken].fail(error)

        refreshed = result.unwrap()
        self._audit_logger.log_token_refresh(
            success=True,
            old_token_id=self._short_token(token),
            new_token_id=self._short_token(refreshed.token),
            username=refreshed.identity_id,
        )
        return FlextResult[FlextAuthModels.AuthToken].ok(refreshed)

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
        token_type: str = FlextAuthConstants.TOKEN_TYPE_ACCESS,
    ) -> FlextResult[str]:
        """Railway-oriented JWT token generation with audit logging."""
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            error = user_result.error
            self._audit_logger.log_token_creation(
                user_id=user_id,
                token_type=token_type,
                success=False,
                reason=error,
            )
            return FlextResult[str].fail(error)

        user = user_result.unwrap()
        token_result = self._get_jwt_provider_cached().flat_map(
            lambda provider: provider.generate_token_for_user(
                user, token_type=token_type, expiry_minutes=expires_in_minutes
            )
        )

        if token_result.is_failure:
            error = token_result.error
            self._audit_logger.log_token_creation(
                user_id=user_id,
                token_type=token_type,
                success=False,
                reason=error,
            )
            return FlextResult[str].fail(error)

        token_value = token_result.unwrap()
        self._audit_logger.log_token_creation(
            user_id=user_id,
            token_type=token_type,
            success=True,
        )
        return FlextResult[str].ok(token_value)

    # =========================================================================
    # PRIVATE HELPER METHODS
    # =========================================================================

    def _get_jwt_provider_cached(self) -> FlextResult[FlextAuthJwtProvider]:
        """Get JWT provider with lazy caching to eliminate repeated lookups."""
        if self._jwt_provider_cache is None:
            result = self._provider_service.get_provider("jwt").flat_map(
                lambda p: FlextResult.ok(p)
                if isinstance(p, FlextAuthJwtProvider)
                else FlextResult.fail("Invalid JWT provider type")
            )
            if result.is_failure:
                return result
            self._jwt_provider_cache = result.unwrap()
        return FlextResult.ok(self._jwt_provider_cache)

    def _ensure_identity_present(
        self, identity: FlextAuthModels.Identity | None
    ) -> FlextResult[FlextAuthModels.Identity]:
        if identity is None:
            return FlextResult[FlextAuthModels.Identity].fail(
                "Token validation returned no identity"
            )
        return FlextResult[FlextAuthModels.Identity].ok(identity)

    @staticmethod
    def _short_token(token: str, length: int = 10) -> str:
        if len(token) <= length:
            return token
        return f"{token[:length]}..."


__all__ = ["FlextAuthTokenService"]
