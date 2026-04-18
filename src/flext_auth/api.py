"""FLEXT Auth API - Generic authentication with flext-core integration.

Single FlextAuth class exposing underlying service instances directly.
Trivial CRUD/delegation methods were intentionally removed (YAGNI): use
``auth.identity_service``, ``auth.token_service``, ``auth.session_service``,
and ``auth.registry`` accessors for direct CRUD access. Orchestration
helpers (authenticate, authenticate_user, register_user, create_token)
live on the facade because they compose multiple services.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
from typing import ClassVar, Self

from flext_auth import (
    FlextAuthIdentityService,
    FlextAuthProviderService,
    FlextAuthRegistry,
    FlextAuthSessionService,
    FlextAuthSettings,
    FlextAuthTokenService,
    FlextAuthUtilitiesManagers,
    c,
    m,
    p,
    r,
    t,
    u,
)
from flext_core import FlextContainer


class FlextAuth:
    """Authentication facade composing identity, token, session, and provider services."""

    _instance: ClassVar[Self | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()
    logger: p.Logger
    _config: FlextAuthSettings
    _registry: FlextAuthRegistry
    _dispatcher: p.Dispatcher
    _provider_service: FlextAuthProviderService
    _identity_service: FlextAuthIdentityService
    _token_service: FlextAuthTokenService
    _session_service: FlextAuthSessionService

    def __init__(
        self,
        settings: FlextAuthSettings | None = None,
    ) -> None:
        """Initialize with dependency injection and event bus."""
        self._config = settings if settings is not None else FlextAuthSettings()
        self._registry = FlextAuthRegistry()
        self._dispatcher = FlextContainer.shared().dispatcher().unwrap()
        self.logger = u.fetch_logger(__name__)
        shared_managers = FlextAuthUtilitiesManagers.ServiceManagers(
            self._config,
            self._dispatcher,
        )
        self._provider_service = FlextAuthProviderService(
            settings=self._config,
            registry=self._registry,
        )
        self._identity_service = FlextAuthIdentityService(
            settings=self._config,
            dispatcher=self._dispatcher,
            managers=shared_managers,
        )
        self._token_service = FlextAuthTokenService(
            settings=self._config,
            provider_service=self._provider_service,
            dispatcher=self._dispatcher,
            managers=shared_managers,
        )
        self._session_service = FlextAuthSessionService(
            settings=self._config,
            dispatcher=self._dispatcher,
            managers=shared_managers,
        )

    @property
    def settings(self) -> FlextAuthSettings:
        """Configuration access."""
        return self._config

    @property
    def identity_service(self) -> FlextAuthIdentityService:
        """Identity service access."""
        return self._identity_service

    @property
    def registry(self) -> FlextAuthRegistry:
        """Registry access."""
        return self._registry

    @property
    def session_service(self) -> FlextAuthSessionService:
        """Session service access."""
        return self._session_service

    @property
    def token_service(self) -> FlextAuthTokenService:
        """Token service access."""
        return self._token_service

    @classmethod
    def get_global(cls) -> Self:
        """Thread-safe singleton accessor."""
        instance = cls._instance
        if isinstance(instance, cls):
            return instance
        with cls._lock:
            locked_instance = cls._instance
            if isinstance(locked_instance, cls):
                return locked_instance
            instance = cls()
            cls._instance = instance
            return instance

    @classmethod
    def quick_start(cls, *, create_admin_user: bool = True) -> Self:
        """Quick start factory with default configuration."""
        auth: Self = cls()
        if create_admin_user:
            result = auth.register_user(
                "REDACTED_LDAP_BIND_PASSWORD",
                "REDACTED_LDAP_BIND_PASSWORD@example.com",
                "AdminPass123!",
                roles=["ADMIN"],
            )
            if result.failure and result.error is not None:
                auth.logger.warning(
                    "Quick start admin user provisioning failed: %s",
                    result.error,
                )
        return auth

    def authenticate(
        self,
        credentials: t.StrMapping,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Validate credentials mapping and dispatch to the identity service."""
        username_value = credentials.get("username")
        match username_value:
            case str() as username if username:
                username_value = username
            case _:
                return r[m.Auth.AuthIdentity].fail(
                    "Invalid credentials: username required",
                )
        password_value = credentials.get("password")
        match password_value:
            case str() as password if password:
                password_value = password
            case _:
                return r[m.Auth.AuthIdentity].fail(
                    "Invalid credentials: password required",
                )
        return self._identity_service.authenticate_identity(
            username_value,
            password_value,
        )

    def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Authenticate and provision token + session for the user."""
        auth_result = self._identity_service.authenticate_identity(username, password)
        if auth_result.success:
            identity = auth_result.value
            token_result = self._token_service.generate_jwt_token(
                user_id=identity.unique_id,
                expires_in_minutes=self._config.expiry_minutes,
            )
            if token_result.success:
                session_result = self._session_service.session_manager.create_session(
                    user_id=identity.unique_id,
                    token=token_result.value,
                    expires_in_minutes=self._config.session_expiry_minutes,
                    ip_address=ip_address or "",
                    user_agent=user_agent or "",
                )

                def _log_session_error(err: str) -> None:
                    self.logger.warning(
                        f"Failed to create session for user {identity.name}: {err}",
                    )

                session_result.tap_error(_log_session_error)
        return auth_result

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: t.StrSequence | None = None,
        role: str | None = None,
        **kwargs: t.Scalar | t.StrSequence | None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Register user with default USER role if none provided."""
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

    def create_token(self, identity_id: str) -> p.Result[str]:
        """Create a token applying the configured default expiry."""
        match identity_id:
            case str() as identity if identity:
                identity_id = identity
            case _:
                return r[str].fail("Identity ID must be a non-empty string")
        return self._token_service.generate_jwt_token(
            user_id=identity_id,
            expires_in_minutes=self._config.expiry_minutes,
        )

    def execute(self) -> p.Result[bool]:
        """Facade marker method - use authenticate_user / register_user instead."""
        return r[bool].fail(
            "FlextAuth is a focused service - use specific methods like authenticate() instead",
        )


__all__: list[str] = ["FlextAuth"]
