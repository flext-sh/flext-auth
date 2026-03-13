"""FLEXT Auth API - Generic authentication with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuth class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import ClassVar, Self

from flext_core import FlextContainer, FlextLogger, p, r

from flext_auth import (
    FlextAuthBaseProvider,
    FlextAuthIdentityService,
    FlextAuthProviderService,
    FlextAuthRegistry,
    FlextAuthSessionService,
    FlextAuthSettings,
    FlextAuthTokenService,
    c,
    m,
    t,
)


class FlextAuth:
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
    logger: FlextLogger
    _registry: FlextAuthRegistry
    _provider_service: FlextAuthProviderService
    _identity_service: FlextAuthIdentityService
    _token_service: FlextAuthTokenService
    _session_service: FlextAuthSessionService

    def __init__(
        self, config: FlextAuthSettings | None = None, service_name: str | None = None
    ) -> None:
        """Initialize with dependency injection and event bus."""
        super().__init__()
        if config is not None:
            self._config = config
        else:
            self._config = FlextAuthSettings()
        self._registry = FlextAuthRegistry()
        command_bus_result = FlextContainer.get_global().get("command_bus").unwrap()
        if not isinstance(command_bus_result, p.CommandBus):
            err_msg = "command_bus is not a CommandBus"
            raise TypeError(err_msg)
        self._dispatcher = command_bus_result
        self._service_name = service_name if service_name is not None else "flext_auth"
        self.logger = FlextLogger(__name__)
        self._provider_service = FlextAuthProviderService(config=self._config)
        for provider_name in self._provider_service.list_providers():
            provider_result = self._provider_service.get_provider(provider_name)
            if provider_result.is_success:
                self._registry.register_provider(provider_name, provider_result.value)
        self._identity_service = FlextAuthIdentityService(
            config=self._config, dispatcher=self._dispatcher
        )
        self._token_service = FlextAuthTokenService(
            config=self._config,
            provider_service=self._provider_service,
            dispatcher=self._dispatcher,
        )
        self._session_service = FlextAuthSessionService(
            config=self._config, dispatcher=self._dispatcher
        )

    @property
    def config(self) -> FlextAuthSettings:
        """Configuration access."""
        return self._config

    @property
    def identity_service(self) -> FlextAuthIdentityService:
        """Identity service access for usage."""
        return self._identity_service

    @property
    def registry(self) -> FlextAuthRegistry:
        """Registry access."""
        return self._registry

    @property
    def session_service(self) -> FlextAuthSessionService:
        """Session service access for usage."""
        return self._session_service

    @property
    def token_service(self) -> FlextAuthTokenService:
        """Token service access for usage."""
        return self._token_service

    @classmethod
    def create_with_config_overrides(cls, **config_overrides: t.Scalar) -> Self:
        """Factory method to create FlextAuth with configuration overrides.

        Args:
            **config_overrides: Configuration parameters to override defaults

        Returns:
            Initialized FlextAuth instance with custom configuration

        """
        custom_config = FlextAuthSettings.model_validate(config_overrides)
        return cls(config=custom_config)

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
    def quick_start(cls, *, create_admin_user: bool = True) -> Self:
        """Quick start factory with default configuration.

        Args:
        create_admin_user: Reserved for future admin creation functionality

        Returns:
        Initialized FlextAuth instance

        """
        instance = cls()
        if create_admin_user:
            pass
        return instance

    def authenticate(
        self, credentials: Mapping[str, str], _provider: str | None = None
    ) -> r[m.Auth.AuthIdentity]:
        """Railway-oriented authentication with chaining."""
        username_value = credentials.get("username")
        match username_value:
            case str() as username if username:
                username_value = username
            case _:
                return r[m.Auth.AuthIdentity].fail(
                    "Invalid credentials: username is required and must be a non-empty string"
                )
        password_value = credentials.get("password")
        match password_value:
            case str() as password if password:
                password_value = password
            case _:
                return r[m.Auth.AuthIdentity].fail(
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
    ) -> r[m.Auth.AuthIdentity]:
        """Authenticate user by username and password with optional metadata.

        Args:
        username: User username
        password: User password

        Returns:
        Authentication result with user identity

        Note:
        ip_address and user_agent are reserved for future audit trail implementation

        """
        auth_result = self._identity_service.authenticate_identity(username, password)
        if auth_result.is_success:
            identity = auth_result.value
            token_result = self.create_token(identity_id=identity.unique_id)
            if token_result.is_success:
                token = token_result.value
                session_result = self._session_service.session_manager.create_session(
                    user_id=identity.unique_id,
                    token=token,
                    expires_in_minutes=self._config.session_expiry_minutes,
                    ip_address=_ip_address or "",
                    user_agent=_user_agent or "",
                )

                def _log_session_error(err: str) -> None:
                    self.logger.warning(
                        f"Failed to create session for user {identity.name}: {err}"
                    )

                session_result.tap_error(_log_session_error)
        return auth_result

    def cleanup_expired_sessions(self) -> r[int]:
        """Clean up expired sessions.

        Returns:
        Number of sessions cleaned up

        """
        return self._session_service.cleanup_expired_sessions()

    def create_token(
        self,
        identity_id: str,
        extra_claims: Mapping[str, str | int | bool] | None = None,
    ) -> r[str]:
        """Railway-oriented token creation.

        Args:
            identity_id: Identity ID for token subject
            extra_claims: Reserved for future extra claims support

        """
        match identity_id:
            case str() as identity if identity:
                identity_id = identity
            case _:
                return r[str].fail("Identity ID must be a non-empty string")
        _ = extra_claims
        return self._token_service.generate_jwt_token(
            user_id=identity_id, expires_in_minutes=self._config.expiry_minutes
        )

    def delete_user(self, user_id: str) -> r[bool]:
        """Delete identity - delegation to identity_service."""
        return self._identity_service.identity_manager.delete_user(user_id)

    def execute(self) -> r[object]:
        """Flexible execute implementation with railway orchestration."""
        return r[object].fail(
            "FlextAuth is a focused service - use specific methods like authenticate() instead"
        )

    def get_provider(self, name: str) -> r[FlextAuthBaseProvider]:
        """Railway-oriented provider retrieval."""
        return self._registry.get(name)

    def get_user(self, user_id: str) -> r[m.Auth.AuthIdentity]:
        """Get identity by ID - delegation to identity_service."""
        return self._identity_service.identity_manager.get_user(user_id)

    def get_user_by_username(self, username: str) -> r[m.Auth.AuthIdentity]:
        """Get identity by username - delegation to identity_service."""
        return self._identity_service.identity_manager.get_user_by_username(username)

    def get_user_sessions(self, user_id: str) -> r[list[m.Auth.Session]]:
        """Get user sessions."""
        return self._session_service.session_manager.get_active_sessions(user_id)

    def list_providers(self) -> list[str]:
        """Provider listing."""
        return self._registry.list_providers()

    def logout_user(self, session_id: str) -> r[bool]:
        """Logout user by session ID."""
        return self._session_service.session_manager.end_session_by_id(session_id)

    def register_provider(self, name: str, provider: FlextAuthBaseProvider) -> r[bool]:
        """Railway-oriented provider registration."""
        return self._registry.register_provider(name, provider)

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: list[str] | None = None,
        role: str | None = None,
        **kwargs: str | int | bool | list[str] | None,
    ) -> r[m.Auth.AuthIdentity]:
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
        if roles is not None:
            user_roles = roles
        elif role is not None:
            user_roles = [role]
        else:
            user_roles = [c.Auth.RoleTypes.USER.value]
        return self._identity_service.create_identity(
            name=username,
            contact=email,
            credential=password,
            roles=user_roles,
            **kwargs,
        )

    def register_user_simple(
        self, username: str, email: str, password: str
    ) -> r[m.Auth.AuthIdentity]:
        """Railway-oriented user registration via identity service."""
        return self._identity_service.create_identity(
            name=username, contact=email, credential=password
        )

    def revoke_session(self, session_id: str) -> r[bool]:
        """Revoke a session."""
        return self._session_service.session_manager.end_session_by_id(session_id)

    def update_user(
        self, user_id: str, **updates: str | int | bool | list[str] | None
    ) -> r[m.Auth.AuthIdentity]:
        """Update identity - delegation to identity_service."""
        return self._identity_service.identity_manager.update_user(user_id, **updates)

    def validate_token(self, token: str) -> r[bool]:
        """Flexible token validation with railway pattern."""
        return self._token_service.validate_token(token).map(lambda _result: True)

    def verify_token(self, token: str) -> r[bool]:
        """Verify token validity - delegated to token service."""
        return self._token_service.validate_token(token)
