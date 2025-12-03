"""FLEXT Auth JWT Provider - JWT-based authentication provider.

This module implements JWT (JSON Web Token) authentication following the
base provider protocol with SOLID principles. Uses dedicated services for
token generation, validation, and password hashing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flext_core import r

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers.jwt_password_hasher import FlextAuthPasswordHasher
from flext_auth.providers.jwt_token_generator import FlextAuthJwtTokenGenerator
from flext_auth.providers.jwt_token_validator import FlextAuthJwtTokenValidator
from flext_auth.providers.rfc import FlextAuthRfcProvider


class FlextAuthJwtProvider(FlextAuthRfcProvider):
    """SOLID-compliant JWT authentication provider.

    Uses dedicated services for token generation, validation, and password hashing.
    Railway-oriented programming with flext-core patterns for maximum maintainability.
    """

    def __init__(self, config: FlextAuthModels.ProviderConfiguration) -> None:
        """Initialize JWT provider with SOLID delegation.

        Uses dedicated services for token generation, validation, and password hashing.
        Railway-oriented initialization with proper error handling.
        """
        super().__init__()
        self.logger = FlextLogger(__name__)
        self._config = config

        # Initialize dedicated services using composition
        self._token_generator = FlextAuthJwtTokenGenerator(self)
        self._token_validator = FlextAuthJwtTokenValidator(self)
        self._password_hasher = FlextAuthPasswordHasher(self)

        # Initialize flext-core components
        self._context = FlextContext()

    @property
    def config(self) -> FlextAuthModels.ProviderConfiguration:
        """Get provider configuration."""
        return self._config

    def get_expiry_minutes(self) -> int:
        """Get token expiry time in minutes from configuration."""
        expiry_value = self._config.get("expiry_minutes")
        if not isinstance(expiry_value, int) or expiry_value <= 0:
            return FlextAuthConstants.Jwt.EXPIRY_DEFAULT_MINUTES
        return expiry_value

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (e.g., "RFC 7617", "RFC 6749")

        """
        return "RFC 7519"

    def _validate_configuration(self) -> r[bool]:
        """Railway-oriented configuration validation."""
        # Validate required JWT configuration fields
        secret_key_value = self._config.get("secret_key")
        if not isinstance(secret_key_value, str) or not secret_key_value:
            return r[bool].fail(
                "JWT secret_key is required and must be a non-empty string"
            )

        algorithm_value = self._config.get("algorithm")
        if algorithm_value is not None:
            if not isinstance(algorithm_value, str) or not algorithm_value:
                return r[bool].fail(
                    "JWT algorithm must be a non-empty string if provided"
                )
            if algorithm_value not in FlextAuthConstants.JwtExtended.ALGORITHMS:
                return r[bool].fail(
                    f"JWT algorithm must be one of {FlextAuthConstants.JwtExtended.ALGORITHMS}, "
                    f"got {algorithm_value}"
                )
        # If algorithm is None, use default from constants

        return r[bool].ok(True)

    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> r[FlextAuthModels.AuthToken]:
        """Authenticate user with username/password using SOLID delegation.

        Delegates password verification and token generation to dedicated services.
        Railway-oriented authentication with proper error handling.
        """
        # Validate credentials
        validation_result = self._validate_credentials_dict(
            credentials, ["username", "password"]
        )
        if validation_result.is_failure:
            return r[FlextAuthModels.AuthToken].fail(
                validation_result.error or "Credential validation failed"
            )

        username_value = credentials.get("username")
        if not isinstance(username_value, str) or not username_value:
            return r[FlextAuthModels.AuthToken].fail(
                "Username must be a non-empty string"
            )
        username = username_value

        password_value = credentials.get("password")
        if not isinstance(password_value, str) or not password_value:
            return r[FlextAuthModels.AuthToken].fail(
                "Password must be a non-empty string"
            )
        password = password_value

        # Get user password hash using railway pattern
        hash_result = self._get_user_password_hash(username)
        if hash_result.is_failure:
            return r[FlextAuthModels.AuthToken].fail(
                hash_result.error or "Password hashing failed"
            )

        password_hash = hash_result.unwrap()

        # Use dedicated password hasher service for authentication
        return self._password_hasher.verify_password(password, password_hash).bind(
            lambda is_valid: self._process_authentication(username, is_valid=is_valid)
        )

    def _process_authentication(
        self,
        username: str,
        *,
        is_valid: bool,
    ) -> r[FlextAuthModels.AuthToken]:
        """Process authentication result."""
        if not is_valid:
            return r[FlextAuthModels.AuthToken].fail("Invalid credentials")

        # Generate token using dedicated token generator service
        return self._token_generator.generate_token(username).map(
            lambda token: FlextAuthModels.AuthToken(
                identity_id=username,
                token=token,
                token_type=FlextAuthConstants.TOKEN_TYPE_ACCESS,
                expires_at=datetime.now(UTC)
                + timedelta(minutes=self.get_expiry_minutes()),
                is_revoked=False,
            )
        )

    def _get_user_password_hash(self, username: str) -> r[str]:
        """Get user password hash from identity manager.

        Uses FlextContainer to access the global FlextAuth instance
        and retrieve the user's password hash through the identity service.
        """
        # Import here to avoid circular dependency - runtime import required
        from flext_auth.api import FlextAuth

        # Get FlextAuth instance from container
        container = FlextContainer.get_global()
        auth_result = container.get("flext_auth")
        if auth_result.is_failure:
            return r[str].fail("FlextAuth instance not found in container")

        auth = auth_result.unwrap()
        if not isinstance(auth, FlextAuth):
            return r[str].fail("Invalid FlextAuth instance in container")

        # Get user by username using public API
        user_result = auth.get_user_by_username(username)
        if user_result.is_failure:
            return r[str].fail(user_result.error or "User retrieval failed")

        user = user_result.unwrap()
        if not user.credential_hash:
            return r[str].fail("User has no credential hash")

        return r[str].ok(user.credential_hash)

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[bool]:
        """Validate JWT token using dedicated token validator service."""
        token_str = self._extract_token_string(token)
        return self._token_validator.validate_token(token_str).map(lambda _: True)

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[FlextAuthModels.AuthToken]:
        """Refresh JWT token using dedicated services."""
        token_str = self._extract_token_string(token)

        # Get the payload first, then generate token, then create auth token
        payload_result = self._token_validator.validate_token(token_str)
        if payload_result.is_failure:
            return r[FlextAuthModels.AuthToken].fail(
                payload_result.error or "Token payload validation failed"
            )

        payload = payload_result.unwrap()
        token_result = self._token_generator.generate_token(str(payload["sub"]))
        if token_result.is_failure:
            return r[FlextAuthModels.AuthToken].fail(
                token_result.error or "Token generation failed"
            )

        new_token = token_result.unwrap()
        return FlextResult.ok(
            FlextAuthModels.AuthToken(
                identity_id=str(payload["sub"]),
                token=new_token,
                token_type=FlextAuthConstants.TOKEN_TYPE_ACCESS,
                expires_at=datetime.now(UTC)
                + timedelta(minutes=self.get_expiry_minutes()),
                is_revoked=False,
            )
        )

    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[bool]:
        """Revoke JWT token.

        For JWT tokens, revocation is typically handled by token expiration
        or by maintaining a revocation list. This implementation validates the token
        and returns success if the token is valid (revocation would be handled
        by external token storage/blacklist).

        Args:
            token: Token to revoke

        Returns:
            r[bool]: True if token was valid and can be revoked,
                            False if token is invalid, error on failure

        """
        token_str = self._extract_token_string(token)
        validation_result = self._token_validator.validate_token(token_str)
        if validation_result.is_failure:
            return r[bool].fail(
                validation_result.error or "Token validation failed"
            )

        # Token is valid - in a production system, this would add the token
        # to a revocation list/blacklist. For now, we just validate it exists.
        return r[bool].ok(True)

    def supports(self) -> set[str]:
        """Return JWT provider capabilities using composition."""
        return {"jwt", "token", "validate", "refresh", "revoke", "password"}

    def get_metadata(self) -> dict[str, object]:
        """Get JWT provider metadata using composition."""
        algorithm_value = self._config.get("algorithm")
        if not isinstance(algorithm_value, str):
            config = FlextAuthModels.ProviderConfiguration(
                name="jwt",
                type="jwt",
                enabled=True,
                capabilities=list(self.supports()),
            )
        else:
            config = FlextAuthModels.ProviderConfiguration(
                name="jwt",
                type="jwt",
                enabled=True,
                algorithm=algorithm_value,
                capabilities=list(self.supports()),
            )
        return dict(config)

    def validate_token(self, token: str) -> r[FlextAuthModels.Identity]:
        """Validate JWT token and return identity using dedicated token validator service."""
        return self._token_validator.validate_token(token).flat_map(
            self._extract_identity_from_payload
        )

    def _extract_identity_from_payload(
        self, payload: dict[str, object]
    ) -> r[FlextAuthModels.Identity]:
        """Extract identity from JWT payload with proper validation."""
        sub_value = payload.get("sub")
        if not isinstance(sub_value, str) or not sub_value:
            return r[FlextAuthModels.Identity].fail(
                "Token payload missing subject"
            )

        email_value = payload.get("email")
        if not isinstance(email_value, str):
            return r[FlextAuthModels.Identity].fail(
                "Token payload missing email"
            )
        contact = email_value

        roles_value = payload.get("roles")
        if not isinstance(roles_value, list):
            return r[FlextAuthModels.Identity].fail(
                "Token payload roles must be a list"
            )
        roles = roles_value

        permissions_value = payload.get("permissions")
        if not isinstance(permissions_value, list):
            return r[FlextAuthModels.Identity].fail(
                "Token payload permissions must be a list"
            )
        permissions = permissions_value

        identity = FlextAuthModels.Identity(
            unique_id=sub_value,
            name=sub_value,
            contact=contact,
            roles=roles,
            permissions=permissions,
        )
        return r[FlextAuthModels.Identity].ok(identity)

    def generate_token_for_user(
        self,
        user: FlextAuthModels.Identity,
        token_type: str = FlextAuthConstants.TOKEN_TYPE_ACCESS,
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Generate JWT token for user using dedicated token generator service."""
        return self._token_generator.generate_token(
            user.user_id,
            expiry_minutes=expiry_minutes,
            extra_claims={
                "username": user.username,
                "email": user.email,
                "token_type": token_type,
                "roles": user.roles,
                "permissions": user.permissions,
            },
        )


__all__ = ["FlextAuthJwtProvider"]
