"""FLEXT Auth API - Main authentication service class.

Enterprise-grade authentication service consolidating all auth operations
into a single FlextAuth class following FLEXT single-class-per-project pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import threading
from typing import ClassVar

from flext_core import FlextResult, FlextService, FlextTypes

from flext_auth.config import FlextAuthConfig
from flext_auth.managers import FlextAuthManagers
from flext_auth.models import FlextAuthModels
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers import (
    FlextAuthBaseProvider,
)
from flext_auth.providers.mixin import FlextAuthProviderMixin

# Lazy import to avoid circular dependency
# from flext_auth.quickstart import FlextAuthQuickstart
from flext_auth.registry import FlextAuthRegistry
from flext_auth.session_service import FlextAuthSessionService
from flext_auth.token_service import FlextAuthTokenService
from flext_auth.typings import FlextAuthTypes
from flext_auth.user_service import FlextAuthUserService


class FlextAuth(FlextService[FlextAuthTypes.AuthenticationResponseDict]):
    """Main authentication service class consolidating all auth operations.

    Enterprise-grade authentication service following FLEXT single-class-per-project
    pattern. All authentication functionality unified into one main class with
    nested classes for complex subsystems.

    **SINGLE-CLASS ARCHITECTURE**: Everything consolidated into one main class
    - No separate module files - all functionality integrated
    - Nested classes for complex subsystems (Config, Providers, Sessions)
    - Clean facade API with rich internal organization

    **COMPREHENSIVE AUTHENTICATION OPERATIONS**:
    - Multi-provider authentication (JWT, OAuth2, LDAP, Basic, etc.)
    - User management and registration
    - Session management and lifecycle
    - Token validation and refresh
    - Role-based access control
    - Security monitoring and audit logging

    **FLEXT INTEGRATION**:
    - FlextResult[T] for railway-oriented error handling
    - FlextService for dependency injection and lifecycle
    - FlextLogger for structured logging
    - FlextContainer for service management
    """

    # Singleton pattern
    _instance: FlextAuth | None = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, config: FlextAuthConfig | None = None) -> None:
        """Initialize consolidated authentication operations.

        Args:
            config: Optional auth configuration. If not provided, uses default instance.

        """
        super().__init__()

        # Core state
        self._config: FlextAuthConfig = (
            config if config is not None else FlextAuthConfig()
        )

        # Lazy-loaded services
        self._provider_service: FlextAuthProviderService | None = None
        self._user_service: FlextAuthUserService | None = None
        self._token_service: FlextAuthTokenService | None = None
        self._session_service: FlextAuthSessionService | None = None
        self._registry: FlextAuthRegistry | None = None
        self._managers: FlextAuthManagers | None = None

    @classmethod
    def get_instance(cls) -> FlextAuth:
        """Get singleton FlextAuth instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def quick_start(cls, create_REDACTED_LDAP_BIND_PASSWORD: bool = False) -> FlextAuth:
        """Factory method to create FlextAuth with quick start configuration.

        Args:
            create_REDACTED_LDAP_BIND_PASSWORD: Whether to create an REDACTED_LDAP_BIND_PASSWORD user during initialization.

        Returns:
            FlextAuth: Configured authentication service instance.

        """
        from flext_auth.quickstart import FlextAuthQuickstart

        quickstart = FlextAuthQuickstart()
        config = quickstart.create_config()
        instance = cls(config)

        if create_REDACTED_LDAP_BIND_PASSWORD:
            quickstart.create_REDACTED_LDAP_BIND_PASSWORD_user(instance)

        return instance

    @classmethod
    def with_jwt(
        cls,
        secret_key: str,
        algorithm: str = "HS256",
        expiration_hours: int = 24,
    ) -> FlextAuth:
        """Factory method to create FlextAuth with JWT provider.

        Args:
            secret_key: JWT secret key for token signing.
            algorithm: JWT algorithm (default: HS256).
            expiration_hours: Token expiration time in hours.

        Returns:
            FlextAuth: Configured authentication service instance.

        """
        config = FlextAuthConfig(
            jwt_secret_key=secret_key,
            jwt_algorithm=algorithm,
            jwt_expiration_hours=expiration_hours,
        )
        return cls(config)

    @classmethod
    def with_oauth2(
        cls,
        client_id: str,
        client_secret: str,
        provider_url: str,
        **kwargs,
    ) -> FlextAuth:
        """Factory method to create FlextAuth with OAuth2 provider.

        Args:
            client_id: OAuth2 client ID.
            client_secret: OAuth2 client secret.
            provider_url: OAuth2 provider base URL.
            **kwargs: Additional configuration options.

        Returns:
            FlextAuth: Configured authentication service instance.

        """
        config = FlextAuthConfig(
            oauth2_client_id=client_id,
            oauth2_client_secret=client_secret,
            oauth2_provider_url=provider_url,
            **kwargs,
        )
        return cls(config)

    @classmethod
    def with_provider(
        cls,
        provider: FlextAuthBaseProvider,
        **kwargs,
    ) -> FlextAuth:
        """Factory method to create FlextAuth with custom provider.

        Args:
            provider: Custom authentication provider instance.
            **kwargs: Additional configuration options.

        Returns:
            FlextAuth: Configured authentication service instance.

        """
        config = FlextAuthConfig(**kwargs)
        instance = cls(config)
        instance.registry.register("custom", provider)
        return instance

    @property
    def config(self) -> FlextAuthConfig:
        """Get authentication configuration."""
        return self._config

    @property
    def provider_service(self) -> FlextAuthProviderService:
        """Get provider service instance."""
        if self._provider_service is None:
            self._provider_service = FlextAuthProviderService(self._config)
        return self._provider_service

    @property
    def user_service(self) -> FlextAuthUserService:
        """Get user service instance."""
        if self._user_service is None:
            self._user_service = FlextAuthUserService(
                self._config, self.provider_service
            )
        return self._user_service

    @property
    def token_service(self) -> FlextAuthTokenService:
        """Get token service instance."""
        if self._token_service is None:
            from flext_core import FlextDispatcher

            dispatcher = FlextDispatcher()
            self._token_service = FlextAuthTokenService(
                self._config, self.provider_service, dispatcher
            )
        return self._token_service

    @property
    def session_service(self) -> FlextAuthSessionService:
        """Get session service instance."""
        if self._session_service is None:
            self._session_service = FlextAuthSessionService(
                self._config, self.user_service
            )
        return self._session_service

    @property
    def registry(self) -> FlextAuthRegistry:
        """Get provider registry instance."""
        if self._registry is None:
            self._registry = FlextAuthRegistry()
        return self._registry

    @property
    def managers(self) -> FlextAuthManagers:
        """Get managers instance."""
        if self._managers is None:
            self._managers = FlextAuthManagers(self._config)
        return self._managers

    def execute(self) -> FlextResult[FlextAuthTypes.AuthenticationResponseDict]:
        """Execute method for FlextService interface.

        Returns authentication service status.
        """
        return FlextResult[FlextAuthTypes.AuthenticationResponseDict].ok({
            "user": {
                "id": "system",
                "username": "system",
                "email": "system@internal.invalid",
                "full_name": "Flext Auth System",
                "is_active": True,
                "roles": ["system"],
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-01-01T00:00:00Z",
                "last_login": None,
            },
            "session": {
                "id": "system-session",
                "user_id": "system",
                "session_token": "system-token",
                "expires_at": "2025-12-31T23:59:59Z",
                "created_at": "2025-01-01T00:00:00Z",
                "last_accessed_at": "2025-01-01T00:00:00Z",
                "is_active": True,
                "ip_address": "127.0.0.1",
                "user_agent": "FlextAuth/1.0",
            },
            "jwt_token": "system-jwt-token",
            "authenticated": True,
            "success": True,
        })

    def authenticate(
        self,
        credentials: dict,
        provider: str | None = None,
    ) -> FlextResult[FlextAuthModels.TokenPayload]:
        """Authenticate user with credentials.

        Args:
            credentials: User credentials dictionary.
            provider: Optional provider name to use.

        Returns:
            FlextResult[TokenPayload]: Authentication result with token payload.

        """
        return self.user_service.authenticate_user(credentials, provider)

    def validate_token(
        self,
        token: str,
        provider: str | None = None,
    ) -> FlextResult[bool]:
        """Validate an authentication token.

        Args:
            token: JWT token to validate.
            provider: Optional provider name.

        Returns:
            FlextResult[bool]: True if token is valid.

        """
        result = self.token_service.validate_token(token)
        return result.map(lambda _: True)

    def list_providers(self) -> FlextTypes.StringList:
        """List all registered authentication providers.

        Returns:
            StringList: List of provider names.

        """
        return self.registry.list_providers()

    def get_provider(self, name: str) -> FlextResult[FlextAuthBaseProvider]:
        """Get a specific authentication provider.

        Args:
            name: Provider name.

        Returns:
            FlextResult[BaseProvider]: Provider instance.

        """
        return self.registry.get(name)

    def get_provider_capabilities(self, name: str) -> FlextResult[set[str]]:
        """Get capabilities of a specific provider.

        Args:
            name: Provider name.

        Returns:
            FlextResult[set[str]]: Provider capabilities.

        """
        result = self.get_provider(name)
        if result.is_failure:
            return FlextResult[set[str]].fail(result.error)

        provider = result.unwrap()
        capabilities = set()
        if isinstance(provider, FlextAuthProviderMixin):
            capabilities.update(provider.get_capabilities())

        return FlextResult[set[str]].ok(capabilities)

    def get_token_manager(self) -> FlextAuthTokenService:
        """Get token manager instance.

        Returns:
            FlextAuthTokenService: Token management service.

        """
        return self.token_service

    def get_session_manager(self) -> FlextAuthSessionService:
        """Get session manager instance.

        Returns:
            FlextAuthSessionService: Session management service.

        """
        return self.session_service

    def get_credential_manager(self) -> FlextAuthUserService:
        """Get credential manager instance.

        Returns:
            FlextAuthUserService: User/credential management service.

        """
        return self.user_service
