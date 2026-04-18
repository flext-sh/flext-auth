"""FLEXT Auth API - Generic authentication with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuth class with SOLID principles.

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
    p,
    r,
    u,
)
from flext_auth._service_mixins import FlextAuthProviderConcernMixin
from flext_auth._service_mixins_identity import FlextAuthIdentityMixin
from flext_auth._service_mixins_session import FlextAuthSessionMixin
from flext_auth._service_mixins_token import FlextAuthTokenMixin
from flext_core import FlextContainer


class FlextAuth(
    FlextAuthProviderConcernMixin,
    FlextAuthIdentityMixin,
    FlextAuthTokenMixin,
    FlextAuthSessionMixin,
):
    """Flexible authentication service using flext-core patterns.

    Thread-safe singleton service with:
    - Railway-oriented programming via r[T]
    - Flexible DI with FlextContainer
    - Event-driven architecture with FlextDispatcher
    - Complete provider ecosystem with registry
    - Flexible token lifecycle management
    - Python 3.13+ type safety throughout
    """

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
        service_name: str | None = None,
    ) -> None:
        """Initialize with dependency injection and event bus."""
        if settings is not None:
            self._config = settings
        else:
            self._config = FlextAuthSettings()
        self._registry = FlextAuthRegistry()
        self._dispatcher = FlextContainer.shared().dispatcher().unwrap()
        self._service_name = service_name if service_name is not None else "flext_auth"
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
    def get_global(cls) -> Self:
        """Thread-safe singleton pattern with configuration."""
        instance = cls._instance
        if isinstance(instance, cls):
            return instance
        with cls._lock:
            locked_instance = cls._instance
            if isinstance(locked_instance, cls):
                return locked_instance
            instance = cls(service_name="flext_auth")
            cls._instance = instance
            return instance

    @classmethod
    def quick_start(cls, *, create_admin_user: bool = True) -> Self:
        """Quick start factory with default configuration.

        Args:
        create_admin_user: Whether to provision the demo admin user

        Returns:
        Initialized FlextAuth instance

        """
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

    def execute(self) -> p.Result[bool]:
        """Flexible execute implementation with railway orchestration."""
        return r[bool].fail(
            "FlextAuth is a focused service - use specific methods like authenticate() instead",
        )


auth = FlextAuth

__all__: list[str] = ["FlextAuth", "auth"]
