"""FLEXT Auth API - Generic authentication with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuth class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
from typing import ClassVar, Self, cast

from flext_core import r, FlextService
from pydantic import SecretStr

from flext_auth.config import FlextAuthConfig
from flext_auth.managers import ServiceManagerMixin
from flext_auth.models import FlextAuthModels
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers import FlextAuthBaseProvider
from flext_auth.registry import FlextAuthRegistry
from flext_auth.session_service import FlextAuthSessionService
from flext_auth.token_service import FlextAuthTokenService
from flext_auth.typings import FlextAuthTypes
from flext_auth.user_service import FlextAuthIdentityService


class FlextAuth(FlextService[FlextAuthTypes.Responses.Authentication]):
    """Flexible authentication service using flext-core patterns.

    Thread-safe singleton service with:
    - Railway-oriented programming via r[T]
    - Flexible DI with FlextContainer
    - Event-driven architecture with FlextDispatcher
    - Complete provider ecosystem with registry
    - Flexible token lifecycle management
    - Python 3.13+ type safety throughout
    """

    _instance: ClassVar[FlextAuth | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(
        self, config: FlextAuthConfig | None = None, service_name: str | None = None
    ) -> None:
        """Initialize with dependency injection and event bus."""
        super().__init__()
        # Use provided config or create default (config is optional for convenience)
        self._config = config if config is not None else FlextAuthConfig()
        self._registry = FlextAuthRegistry()
        self._dispatcher = FlextDispatcher()
        # Use provided service_name or default (service_name is optional)
        self._service_name = service_name if service_name is not None else "flext_auth"

        # Note: FlextContainer registration removed - use service directly
        # Container integration can be added when FlextContainer.register is available

        # Create shared managers once to ensure data consistency across services
        shared_managers = ServiceManagerMixin()
        shared_managers.init_managers(self._config, self._dispatcher)

        # Initialize service dependencies once with shared managers
        self._provider_service = FlextAuthProviderService(config=self._config)
        # Register providers from provider_service into main registry
        for provider_name in self._provider_service.list_providers():
            provider_result = self._provider_service.get_provider(provider_name)
            if provider_result.is_success:
                self._registry.register(provider_name, provider_result.unwrap())
        self._identity_service = FlextAuthIdentityService(
            config=self._config, dispatcher=self._dispatcher
        )
        # Share managers between services to ensure data consistency
        self._identity_service.user_manager = shared_managers.user_manager
        self._identity_service.session_manager = shared_managers.session_manager
        self._identity_service.audit_logger = shared_managers.audit_logger
        self._identity_service.rate_limiter = shared_managers.rate_limiter

        self._token_service = FlextAuthTokenService(
            config=self._config,
            provider_service=self._provider_service,
            dispatcher=self._dispatcher,
        )
        # Share managers with token service
        self._token_service.user_manager = shared_managers.user_manager
        self._token_service.session_manager = shared_managers.session_manager
        self._token_service.audit_logger = shared_managers.audit_logger
        self._token_service.rate_limiter = shared_managers.rate_limiter

        self._session_service = FlextAuthSessionService(
            config=self._config, dispatcher=self._dispatcher
        )
        # Share managers with session service
        self._session_service.user_manager = shared_managers.user_manager
        self._session_service.session_manager = shared_managers.session_manager
        self._session_service.audit_logger = shared_managers.audit_logger
        self._session_service.rate_limiter = shared_managers.rate_limiter

    @classmethod
    def get_global(cls) -> FlextAuth:
        """Thread-safe singleton pattern with configuration."""
        if cls._instance is not None:
            return cls._instance
        with cls._lock:
            if cls._instance is not None:
                return cls._instance
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
        return cls(config=config)

    @classmethod
    def quick_start(
        cls,
        *,
        create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
    ) -> Self:
        """Quick start factory with default configuration.

        Args:
        create_REDACTED_LDAP_BIND_PASSWORD: Reserved for future REDACTED_LDAP_BIND_PASSWORD creation functionality

        Returns:
        Initialized FlextAuth instance

        """
        instance = cls()
        if create_REDACTED_LDAP_BIND_PASSWORD:
            # Admin creation logic would go here
            # For now, just create the instance
            pass
        return instance

    @classmethod
    def create_with_config_overrides(
        cls,
        config_overrides: dict[str, str | int | bool] | None = None,
        **_kwargs: str | int | bool,
    ) -> Self:
        """Create FlextAuth instance with configuration overrides.

        Args:
        config_overrides: Dictionary of configuration overrides
        **kwargs: Additional configuration parameters

        Returns:
        Initialized FlextAuth instance with overridden configuration

        """
        if config_overrides:
            # Apply configuration overrides
            config = FlextAuthConfig(**config_overrides)
        else:
            config = FlextAuthConfig()

        return cls(config=config)

    @property
    def config(self) -> FlextConfig:
        """Configuration access."""
        return cast("FlextConfig", self._config)

    @property
    def registry(self) -> FlextAuthRegistry:
        """Registry access."""
        return self._registry

    @property
    def token_service(self) -> FlextAuthTokenService:
        """Token service access for usage."""
        return self._token_service

    @property
    def identity_service(self) -> FlextAuthIdentityService:
        """Identity service access for usage."""
        return self._identity_service

    @property
    def session_service(self) -> FlextAuthSessionService:
        """Session service access for usage."""
        return self._session_service

    def authenticate(
        self,
        credentials: dict[str, str],
        _provider: str | None = None,
    ) -> r[FlextAuthModels.Identity]:
        """Railway-oriented authentication with chaining."""
        # Extract username and password from credentials - fast fail if missing
        username_value = credentials.get("username")
        if not isinstance(username_value, str) or not username_value:
            return r[FlextAuthModels.Identity].fail(
                "Invalid credentials: username is required and must be a non-empty string"
            )

        password_value = credentials.get("password")
        if not isinstance(password_value, str) or not password_value:
            return r[FlextAuthModels.Identity].fail(
                "Invalid credentials: password is required and must be a non-empty string"
            )

        return self._identity_service.authenticate_identity(
            username_value, password_value
        )

    def authenticate_user(
        self,
        username: str,
        password: str,
        _ip_address: str | None = None,
        _user_agent: str | None = None,
    ) -> r[FlextAuthModels.Identity]:
        """Authenticate user by username and password with optional metadata.

        Args:
        username: User username
        password: User password

        Returns:
        Authentication result with user identity

        Note:
        ip_address and user_agent are reserved for future audit trail implementation

        """
        # Authenticate identity
        auth_result = self._identity_service.authenticate_identity(username, password)

        # Create session automatically on successful authentication
        if auth_result.is_success:
            identity = auth_result.unwrap()
            # Generate token for the session
            token_result = self.create_token(identity_id=identity.unique_id)
            if token_result.is_success:
                token = token_result.unwrap()
                # Create session with the token
                session_result = self._session_service.session_manager.create_session(
                    user_id=identity.unique_id,
                    token=token,
                    expires_in_minutes=self._config.session_expiry_minutes,
                    ip_address=_ip_address or "",
                    user_agent=_user_agent or "",
                )
                # If session creation fails, log but don't fail authentication
                if session_result.is_failure:
                    self.logger.warning(
                        f"Failed to create session for user {identity.name}: {session_result.error}"
                    )

        return auth_result

    def validate_token(self, token: str) -> r[bool]:
        """Flexible token validation with railway pattern."""
        return self._token_service.validate_token(token).map(lambda _result: True)

    def list_providers(self) -> list[str]:
        """Provider listing."""
        return self._registry.list_providers()

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: list[str] | None = None,
        role: str | None = None,
        **kwargs: str | int | bool | list[str] | None,
    ) -> r[FlextAuthModels.Identity]:
        """Register a new user.

        Args:
        username: User username
        email: User email address
        password: User password
        roles: Optional list of user roles
        role: Optional user role (defaults to 'user') - for backward compatibility
        **kwargs: Additional user data

        Returns:
        Registration result with user identity

        """
        # Handle roles parameter - prefer roles list over single role
        if roles is not None:
            user_roles = roles
        elif role is not None:
            user_roles = [role]
        else:
            user_roles = ["user"]

        return self._identity_service.create_identity(
            name=username,
            contact=email,
            credential=password,
            roles=user_roles,
            **kwargs,
        )

    def register_provider(
        self,
        name: str,
        provider: FlextAuthBaseProvider,
    ) -> r[bool]:
        """Railway-oriented provider registration."""
        return self._registry.register(name, provider)

    def get_provider(
        self,
        name: str,
    ) -> r[FlextAuthBaseProvider]:
        """Railway-oriented provider retrieval."""
        return self._registry.get(name)

    def register_user_simple(
        self,
        username: str,
        email: str,
        password: str,
    ) -> r[FlextAuthModels.Identity]:
        """Railway-oriented user registration via identity service."""
        return self._identity_service.create_identity(
            name=username, contact=email, credential=password
        )

    def create_token(
        self,
        identity_id: str,
        extra_claims: dict[str, str | int | bool] | None = None,
    ) -> r[str]:
        """Railway-oriented token creation.

        Args:
            identity_id: Identity ID for token subject
            extra_claims: Reserved for future extra claims support

        """
        if not identity_id or not isinstance(identity_id, str):
            return r[str].fail("Identity ID must be a non-empty string")

        _ = extra_claims  # Reserved for future use
        return self._token_service.generate_jwt_token(
            user_id=identity_id,
            expires_in_minutes=self._config.expiry_minutes,
        )

    def verify_token(
        self, token: str
    ) -> r[dict[str, str | int | bool | list[str]]]:
        """Railway-oriented token verification with payload extraction."""

        def extract_identity_data(
            identity: FlextAuthModels.Identity,
        ) -> dict[str, bool | int | list[str] | str]:
            return {
                "sub": identity.id,
                "name": identity.name,
                "contact": identity.contact,
                "roles": identity.roles,
                "permissions": identity.permissions,
            }

        return self._token_service.validate_token(token).map(extract_identity_data)

    # =========================================================================
    # CONVENIENCE API METHODS (Delegations to services)
    # =========================================================================

    def get_user(self, user_id: str) -> r[FlextAuthModels.Identity]:
        """Get identity by ID - delegation to identity_service."""
        return self._identity_service.identity_manager.get_user(user_id)

    def get_user_by_username(
        self, username: str
    ) -> r[FlextAuthModels.Identity]:
        """Get identity by username - delegation to identity_service."""
        return self._identity_service.identity_manager.get_user_by_username(username)

    def update_user(
        self, user_id: str, **updates: str | int | bool | list[str] | None
    ) -> r[FlextAuthModels.Identity]:
        """Update identity - delegation to identity_service."""
        return self._identity_service.identity_manager.update_user(user_id, **updates)

    def delete_user(self, user_id: str) -> r[bool]:
        """Delete identity - delegation to identity_service."""
        return self._identity_service.identity_manager.delete_user(user_id)

    def cleanup_expired_sessions(self) -> r[int]:
        """Clean up expired sessions.

        Returns:
        Number of sessions cleaned up

        """
        return self._session_service.cleanup_expired_sessions()

    def logout_user(self, session_id: str) -> r[bool]:
        """Logout user by session ID."""
        return self._session_service.session_manager.end_session_by_id(session_id)

    def get_user_sessions(
        self, user_id: str
    ) -> r[list[FlextAuthModels.Session]]:
        """Get user sessions."""
        return self._session_service.session_manager.get_active_sessions(user_id)

    def revoke_session(self, session_id: str) -> r[bool]:
        """Revoke a session."""
        return self._session_service.session_manager.end_session_by_id(session_id)

    def execute(
        self, **_kwargs: object
    ) -> r[FlextAuthTypes.Responses.Authentication]:
        """Flexible execute implementation with railway orchestration."""
        return r[FlextAuthTypes.Responses.Authentication].fail(
            "FlextAuth is a focused service - use specific methods like authenticate() instead"
        )
