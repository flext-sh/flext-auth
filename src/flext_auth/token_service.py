"""FLEXT Auth Token Service - Focused token operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextDispatcher, FlextLogger, FlextResult, FlextService

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.managers import FlextAuthManagers
from flext_auth.models import FlextAuthModels
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers import FlextAuthJwtProvider
from flext_auth.utilities import FlextAuthUtilities


class FlextAuthTokenService(FlextService):
    """Focused service for token operations with complete flext-core integration."""

    def __init__(
        self,
        config: FlextAuthConfig,
        provider_service: FlextAuthProviderService,
        dispatcher: FlextDispatcher,
    ) -> None:
        """Initialize token service with flext-core integration."""
        super().__init__(logger=FlextLogger(__name__))
        self._config = config
        self._dispatcher = dispatcher
        self._user_manager = FlextAuthManagers.FlextAuthUserManager(config)
        self._audit_logger = FlextAuthManagers.FlextAuthAuditLogger(config, dispatcher)
        self._utils = FlextAuthUtilities()
        self._provider_service = provider_service

    def execute(self) -> FlextResult[object]:
        """Execute method for FlextService interface.

        Token service doesn't use generic execute pattern.
        Use specific token methods instead.
        """
        return FlextResult[object].fail(
            "FlextAuthTokenService is focused - use specific token methods like validate_token()"
        )

    def validate_token(self, token: str) -> FlextResult[FlextAuthModels.User]:
        """Validate an authentication token and return user."""
        # Use JWT provider for validation
        jwt_provider_result = self._get_jwt_provider()
        if jwt_provider_result.is_failure:
            return FlextResult[FlextAuthModels.User].fail(jwt_provider_result.error)

        jwt_provider = jwt_provider_result.value
        validation_result = jwt_provider.validate(token)

        if validation_result.is_failure:
            self._audit_logger.log_token_validation(
                success=False,
                token_id=token[:10] + "..." if token else "unknown",
                reason=str(validation_result.error),
            )
            return FlextResult[FlextAuthModels.User].fail(validation_result.error)

        # Token is valid, decode to get user information
        if not isinstance(jwt_provider, FlextAuthJwtProvider):
            return FlextResult[FlextAuthModels.User].fail("Invalid JWT provider type")

        # Get decoding parameters from provider
        params_result = jwt_provider.get_decoding_params()
        if params_result.is_failure:
            return FlextResult[FlextAuthModels.User].fail(
                f"Failed to get JWT decoding parameters: {params_result.error}"
            )

        params = params_result.value
        decode_result = FlextAuthUtilities.JWTProcessing.decode_token(
            token, str(params["secret_key"]), str(params["algorithm"])
        )

        if decode_result.is_failure:
            self._audit_logger.log_token_validation(
                success=False,
                token_id=token[:10] + "...",
                reason=str(decode_result.error),
            )
            return FlextResult[FlextAuthModels.User].fail(decode_result.error)

        payload = decode_result.value
        user_id = payload.get("sub")
        if not user_id or not isinstance(user_id, str):
            return FlextResult[FlextAuthModels.User].fail(
                "Invalid token: missing or invalid user ID"
            )

        # Get user from user manager
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            self._audit_logger.log_token_validation(
                success=False,
                token_id=token[:10] + "...",
                reason="user_not_found",
            )
            return FlextResult[FlextAuthModels.User].fail("User not found")

        self._audit_logger.log_token_validation(
            success=True,
            token_id=token[:10] + "...",
        )

        return user_result

    def refresh_token(self, token: str) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh an authentication token."""
        jwt_provider_result = self._get_jwt_provider()
        if jwt_provider_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                jwt_provider_result.error
            )

        jwt_provider = jwt_provider_result.value
        refresh_result = jwt_provider.refresh(token)

        if refresh_result.is_success:
            self._audit_logger.log_token_refresh(
                success=True,
                old_token_id=token[:10] + "...",
                new_token_id=refresh_result.value.token[:10] + "...",
            )
        else:
            self._audit_logger.log_token_refresh(
                success=False,
                old_token_id=token[:10] + "..." if token else "unknown",
                new_token_id=None,
                reason=str(refresh_result.error),
            )

        return refresh_result

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
        token_type: str = FlextAuthConstants.Jwt.DEFAULT_ACCESS_TOKEN_TYPE,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Generate a JWT token for a user."""
        # Get user first to ensure they exist
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(user_result.error)

        # Create JWT token
        token_result = FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            expiry_minutes=expires_in_minutes
            or FlextAuthConstants.Jwt.DEFAULT_EXPIRY_MINUTES,
            token_type=token_type,
        )

        if token_result.is_success:
            self._audit_logger.log_token_creation(
                success=True,
                user_id=user_id,
                token_type=token_type,
            )
        else:
            self._audit_logger.log_token_creation(
                success=False,
                user_id=user_id,
                token_type=token_type,
                reason=str(token_result.error),
            )

        return token_result

    def _get_jwt_provider(self) -> FlextResult[FlextAuthJwtProvider]:
        """Get the JWT provider from the provider service."""
        result = self._provider_service.get_provider("jwt")
        if result.is_failure:
            return FlextResult[FlextAuthJwtProvider].fail(result.error)

        provider = result.value
        if not isinstance(provider, FlextAuthJwtProvider):
            return FlextResult[FlextAuthJwtProvider].fail(
                "Provider is not a JWT provider"
            )

        return FlextResult[FlextAuthJwtProvider].ok(provider)


__all__ = ["FlextAuthTokenService"]
