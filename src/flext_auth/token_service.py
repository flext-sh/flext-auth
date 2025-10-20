"""FLEXT Auth Token Service - Advanced flext-core patterns with minimal line count.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated patterns
for maximum maintainability. Single FlextAuthTokenService class with advanced composition.

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
from flext_auth.utilities import FlextAuthUtilities


class FlextAuthTokenService(ServiceManagerMixin, FlextService):
    """Advanced token service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Advanced composition with dependency injection and error handling.
    """

    def __init__(
        self,
        config: FlextAuthConfig,
        provider_service: FlextAuthProviderService,
        dispatcher: FlextDispatcher,
    ) -> None:
        """Advanced initialization with dependency injection."""
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
        return (
            self._get_jwt_provider_cached()
            .flat_map(lambda p: p.validate(token))
            .flat_map(lambda _: self._decode_token_payload(token))
            .flat_map(lambda payload: self._get_user_from_payload(payload, token))
            .tap(
                lambda _: self._audit_logger.log_token_validation(
                    success=True, token_id=token[:10] + "..."
                )
            )
            .recover(FlextResult.fail)
        )

    def refresh_token(self, token: str) -> FlextResult[FlextAuthModels.AuthToken]:
        """Railway-oriented token refresh with audit logging."""
        return (
            self._get_jwt_provider_cached()
            .flat_map(lambda p: p.refresh(token))
            .tap(
                lambda t: self._audit_logger.log_token_refresh(
                    success=True,
                    old_token_id=token[:10] + "...",
                    new_token_id=t.token[:10] + "...",
                )
            )
            .recover(FlextResult.fail)
        )

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
        token_type: str = FlextAuthConstants.TOKEN_TYPE_ACCESS,
    ) -> FlextResult[str]:
        """Railway-oriented JWT token generation with audit logging."""
        # Get user
        user_result = self._user_manager.get_user(user_id)
        if not user_result.is_success:
            return FlextResult.fail(user_result.error)

        # Create token
        token_result = FlextAuthModels.AuthToken.create_token(
            identity_id=user_id,
            expiry_minutes=expires_in_minutes or 1440,
            token_type=token_type,
        )
        if not token_result.is_success:
            return FlextResult.fail(token_result.error)

        # Audit logging
        self._audit_logger.log_token_creation(
            success=True, user_id=user_id, token_type=token_type
        )

        return FlextResult.ok(token_result.unwrap().token)

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

    def _decode_token_payload(self, token: str) -> FlextResult[dict[str, object]]:
        """Decode token payload with railway pattern."""
        return (
            self._get_jwt_provider_cached()
            .flat_map(lambda p: p.get_decoding_params())
            .flat_map(
                lambda params: FlextAuthUtilities.JWTProcessing.decode_token(
                    token, str(params["secret_key"]), str(params["algorithm"])
                )
            )
        )

    def _get_user_from_payload(
        self,
        payload: dict[str, object],
        token: str,  # noqa: ARG002
    ) -> FlextResult[FlextAuthModels.Identity]:
        """Extract identity from token payload with validation."""
        user_id = payload.get("sub")
        if not user_id or not isinstance(user_id, str):
            return FlextResult.fail("Invalid token: missing or invalid user ID")

        return self._user_manager.get_user(user_id).recover(
            lambda e: FlextResult.fail(f"User not found: {e}")
        )


__all__ = ["FlextAuthTokenService"]
