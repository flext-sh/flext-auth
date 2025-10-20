"""FLEXT Auth JWT Provider - JWT-based authentication provider.

This module implements JWT (JSON Web Token) authentication following the
base provider protocol with SOLID principles. Uses dedicated services for
token generation, validation, and password hashing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flext_core import FlextBus, FlextContext, FlextLogger, FlextResult

from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.jwt_password_hasher import FlextAuthPasswordHasher
from flext_auth.providers.jwt_token_generator import FlextAuthJwtTokenGenerator
from flext_auth.providers.jwt_token_validator import FlextAuthJwtTokenValidator
from flext_auth.providers.mixin import FlextAuthProviderMixin


class FlextAuthJwtProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
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

        # Use railway-oriented validation
        validation_result = self._validate_configuration()
        if validation_result.is_failure:
            msg = f"JWT configuration validation failed: {validation_result.error}"
            raise ValueError(msg)

        # Initialize dedicated services using composition
        self._token_generator = FlextAuthJwtTokenGenerator(self)
        self._token_validator = FlextAuthJwtTokenValidator(self)
        self._password_hasher = FlextAuthPasswordHasher(self)

        # Initialize flext-core components
        self._context = FlextContext()
        self._bus = FlextBus()

    @property
    def config(self) -> FlextAuthModels.ProviderConfiguration:
        """Get provider configuration."""
        return self._config

    def authenticate(
        self,
        credentials: FlextAuthModels.CredentialValidation,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate user with username/password using SOLID delegation.

        Delegates password verification and token generation to dedicated services.
        Railway-oriented authentication with proper error handling.
        """
        # Validate credentials
        validation_result = self._validate_credentials_dict(
            credentials, ["username", "password"]
        )
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(validation_result.error)

        username = credentials["username"]
        password = credentials["password"]

        if not isinstance(username, str) or not isinstance(password, str):
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Username and password must be strings"
            )

        # Use dedicated password hasher service for authentication
        return self._password_hasher.verify_password(
            password, self._get_user_password_hash(username)
        ).bind(
            lambda is_valid: self._process_authentication(username, is_valid=is_valid)
        )

    def _process_authentication(
        self,
        username: str,
        *,
        is_valid: bool,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Process authentication result."""
        if not is_valid:
            return FlextResult[FlextAuthModels.AuthToken].fail("Invalid credentials")

        # Generate token using dedicated token generator service
        return self._token_generator.generate_token(username).map(
            lambda token: FlextAuthModels.AuthToken(
                identity_id=username,
                token=token,
                token_type="jwt_access",  # noqa: S106
                expires_at=datetime.now(UTC)
                + timedelta(minutes=self.get_expiry_minutes()),
                is_revoked=False,
            )
        )

    def _get_user_password_hash(self, _username: str) -> str:
        """Get user password hash (simplified for demo)."""
        # In production, this would query a user database
        # For now, return a demo hash
        return "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPjLZVx0kVj."  # "demo" hashed

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[bool]:
        """Validate JWT token using dedicated token validator service."""
        token_str = self._extract_token_string(token)
        return self._token_validator.validate_token(token_str).map(lambda _: True)

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh JWT token using dedicated services."""
        token_str = self._extract_token_string(token)

        # Get the payload first, then generate token, then create auth token
        payload_result = self._token_validator.validate_token(token_str)
        if payload_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(payload_result.error)

        payload = payload_result.unwrap()
        token_result = self._token_generator.generate_token(str(payload["sub"]))
        if token_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(token_result.error)

        new_token = token_result.unwrap()
        return FlextResult.ok(
            FlextAuthModels.AuthToken(
                identity_id=str(payload["sub"]),
                token=new_token,
                token_type="jwt_access",  # noqa: S106
                expires_at=datetime.now(UTC)
                + timedelta(minutes=self.get_expiry_minutes()),
                is_revoked=False,
            )
        )

    def supports(self) -> set[str]:
        """Return JWT provider capabilities using composition."""
        return {"jwt", "token", "validate", "refresh", "password"}

    def get_metadata(self) -> FlextAuthModels.ProviderConfiguration:
        """Get JWT provider metadata using composition."""
        return FlextAuthModels.ProviderConfiguration(
            name="jwt",
            type="jwt",
            enabled=True,
            algorithm=self._config.get("algorithm", "HS256"),
            capabilities=list(self.supports()),
        )

    def validate_token(
        self, token: str
    ) -> FlextResult[FlextAuthModels.Identity | None]:
        """Validate JWT token and return identity using dedicated token validator service."""
        return self._token_validator.validate_token(token).map(
            lambda payload: FlextAuthModels.Identity(
                id=str(payload.get("sub", "")),
                name=str(payload.get("sub", "")),
                contact=str(payload.get("email", "")),
                roles=payload.get("roles", [])
                if isinstance(payload.get("roles"), list)
                else [],
                permissions=payload.get("permissions", [])
                if isinstance(payload.get("permissions"), list)
                else [],
            )
        )

    def generate_token_for_user(
        self,
        user: FlextAuthModels.Identity,
        _token_type: str = "jwt_access",  # noqa: S107
        expiry_minutes: int | None = None,
    ) -> FlextResult[str]:
        """Generate JWT token for user using dedicated token generator service."""
        return self._token_generator.generate_token(
            user.user_id,
            expiry_minutes=expiry_minutes,
            extra_claims={"username": user.username, "email": user.email},
        )


__all__ = ["FlextAuthJwtProvider"]
