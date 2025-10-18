"""FLEXT Auth API - Generic authentication with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuth class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import ClassVar, Self

from flext_core import FlextContainer, FlextDispatcher, FlextResult, FlextService
from pydantic import SecretStr

from flext_auth.config import FlextAuthConfig
from flext_auth.models import FlextAuthModels
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers import FlextAuthBaseProvider
from flext_auth.registry import FlextAuthRegistry
from flext_auth.token_service import FlextAuthTokenService
from flext_auth.typings import FlextAuthTypes
from flext_auth.user_service import FlextAuthIdentityService


class FlextAuth(FlextService[FlextAuthTypes.AuthenticationResponseDict]):
    """Advanced authentication service using flext-core patterns.

    Thread-safe singleton service with:
    - Railway-oriented programming via FlextResult[T]
    - Advanced DI with FlextContainer
    - Event-driven architecture with FlextDispatcher
    - Comprehensive provider ecosystem with registry
    - Advanced token lifecycle management
    - Python 3.13+ type safety throughout
    """

    _instance: ClassVar[FlextAuth | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, config: FlextAuthConfig | None = None, service_name: str | None = None) -> None:
        """Initialize with dependency injection and event bus."""
        super().__init__()
        self._config = config or FlextAuthConfig()
        self._registry = FlextAuthRegistry()
        self._dispatcher = FlextDispatcher()
        self._service_name = service_name or "flext_auth"

        container = FlextContainer.get_global()
        container_result = container.register(self._service_name, self)
        if not container_result.is_success:
            msg = f"Failed to register FlextAuth: {container_result.error}"
            raise RuntimeError(msg)

        # Initialize provider service for dependency injection
        self._provider_service = FlextAuthProviderService(self._config)

        # Initialize token service with dependencies
        self._token_service = FlextAuthTokenService(
            self._config, self._provider_service, self._dispatcher
        )

    @classmethod
    def get_global(cls) -> FlextAuth:
        """Thread-safe singleton pattern with advanced configuration."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(service_name="flext_auth")
        return cls._instance

    @classmethod
    def with_config(
        cls,
        secret_key: str,
        algorithm: str = "HS256",
        expiration_hours: int = 24,
    ) -> Self:
        """Factory method with generic configuration."""
        config = FlextAuthConfig(
            auth_secret=SecretStr(secret_key),
            algorithm=algorithm,
            expiry_minutes=expiration_hours * 60,
        )
        return cls(config)

    @property
    def config(self) -> FlextAuthConfig:
        """Configuration access."""
        return self._config

    @property
    def registry(self) -> FlextAuthRegistry:
        """Registry access."""
        return self._registry

    def authenticate(
        self,
        credentials: dict[str, object],
        provider: str | None = None,  # noqa: ARG002 - Reserved for future provider selection
    ) -> FlextResult[FlextAuthModels.Identity]:
        """Railway-oriented authentication with advanced chaining."""
        # Extract username and password from credentials
        username = credentials.get("username")
        password = credentials.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            return FlextResult[FlextAuthModels.Identity].fail(
                "Invalid credentials: username and password must be strings"
            )

        # Create identity service with existing provider service
        identity_service = FlextAuthIdentityService(self._config, self._dispatcher)
        return identity_service.authenticate_identity(username, password)

    def validate_token(self, token: str) -> FlextResult[bool]:
        """Advanced token validation with railway pattern."""
        return self._token_service.validate_token(token).map(lambda _result: True)

    def list_providers(self) -> list[str]:
        """Provider listing."""
        return self._registry.list_providers()

    def register_provider(
        self,
        name: str,
        provider: type[FlextAuthBaseProvider],
    ) -> FlextResult[None]:
        """Railway-oriented provider registration."""
        return self._registry.register(name, provider)

    def get_provider(
        self,
        name: str,
    ) -> FlextResult[FlextAuthBaseProvider]:
        """Railway-oriented provider retrieval."""
        return self._registry.get(name)

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
    ) -> FlextResult[FlextAuthModels.Identity]:
        """Railway-oriented user registration."""
        # Create identity service for user management
        identity_service = FlextAuthIdentityService(self._config, self._dispatcher)
        return identity_service.create_identity(name=username, contact=email, credential=password)

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
    ) -> FlextResult[str]:
        """Generate JWT token for user (alias for create_token)."""
        return self.create_token(identity_id=user_id, extra_claims=None)

    def create_token(
        self,
        identity_id: str,
        extra_claims: dict[str, object] | None = None,
    ) -> FlextResult[str]:
        """Railway-oriented token creation."""
        claims: dict[str, str | int | float | bool | datetime | None] = {
            "sub": identity_id
        }
        if extra_claims:
            # Convert extra_claims to the expected type for claims
            for key, value in extra_claims.items():
                if (
                    isinstance(value, (str, int, float, bool))
                    or value is None
                    or isinstance(value, datetime)
                ):
                    claims[key] = value
                else:
                    # Convert other objects to string representation
                    claims[key] = str(value)
        identity_id = str(claims.get("sub", ""))
        return self._token_service.generate_jwt_token(
            user_id=identity_id,
            expires_in_minutes=self._config.expiry_minutes,
        ).map(lambda token: str(token.token))

    def verify_token(
        self, token: str
    ) -> FlextResult[dict[str, str | int | float | bool | None]]:
        """Railway-oriented token verification with payload extraction."""

        def extract_identity_data(
            identity: FlextAuthModels.Identity,
        ) -> dict[str, str | int | float | bool | None]:
            return {
                "sub": identity.id,
                "name": identity.name,
                "contact": identity.contact,
                "roles": identity.roles,
                "permissions": identity.permissions,
            }

        return self._token_service.validate_token(token).map(extract_identity_data)

    def execute(self) -> FlextResult[FlextAuthTypes.AuthenticationResponseDict]:
        """Advanced execute implementation with railway orchestration."""
        return FlextResult[FlextAuthTypes.AuthenticationResponseDict].fail(
            "FlextAuth is a focused service - use specific methods like authenticate() instead"
        )
