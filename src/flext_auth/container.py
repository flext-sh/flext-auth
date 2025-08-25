"""FLEXT Auth Container - Single FlextAuthContainer class inheriting from FlextCore.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module implements the Flext[Area][Module] pattern with a single FlextAuthContainer
class that inherits from FlextContainer and provides all authentication service
management functionality through methods rather than standalone functions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import (
    FlextCommands,
    FlextContainer,
    FlextResult,
    FlextServiceKey,
    get_typed,
    register_typed,
)

from .config import FlextAuthConfig
from .jwt import FlextJWTService
from .password import FlextPasswordService
from .session import InMemorySessionRepository
from .user import InMemoryUserRepository

if TYPE_CHECKING:
    from .auth import FlextAuthService  # noqa: PLC0415

# Import Union types to avoid circular imports
from .flext_auth_types import SessionRepositoryType, UserRepositoryType


class FlextAuthContainer(FlextContainer):
    """Authentication container service inheriting from FlextContainer.

    This class implements the Flext[Area][Module] pattern, providing all authentication
    service management functionality through instance methods. It extends FlextContainer
    with auth-specific service keys, configuration, and convenience methods.

    All functionality that was previously implemented as standalone functions
    is now available as methods of this class, maintaining the same API surface
    but following the inheritance-based architectural pattern.

    Attributes:
        AUTH_CONFIG_KEY: Service key for FlextAuthConfig.
        PASSWORD_SERVICE_KEY: Service key for FlextPasswordService.
        JWT_SERVICE_KEY: Service key for FlextJWTService.
        USER_REPOSITORY_KEY: Service key for user repository.
        SESSION_REPOSITORY_KEY: Service key for session repository.
        AUTH_SERVICE_KEY: Service key for main auth service.
        COMMAND_BUS_KEY: Service key for command bus.

    Example:
        Basic container setup:

        >>> container = FlextAuthContainer()
        >>> result = container.configure_auth_services()
        >>> print(result.is_success)
        True

        Custom configuration:

        >>> config = FlextAuthConfig()
        >>> container = FlextAuthContainer()
        >>> result = container.configure_auth_services(config=config)
        >>> auth_service = container.get_auth_service()

    """

    # =============================================================================
    # SERVICE KEYS - Class constants for type-safe service registration
    # =============================================================================

    AUTH_CONFIG_KEY = FlextServiceKey[FlextAuthConfig]("flext_auth_config")
    PASSWORD_SERVICE_KEY = FlextServiceKey[FlextPasswordService]("password_service")
    JWT_SERVICE_KEY = FlextServiceKey[FlextJWTService]("jwt_service")
    USER_REPOSITORY_KEY = FlextServiceKey[UserRepositoryType]("user_repository")
    SESSION_REPOSITORY_KEY = FlextServiceKey[SessionRepositoryType]("session_repository")
    AUTH_SERVICE_KEY = FlextServiceKey["FlextAuthService"]("auth_service")
    COMMAND_BUS_KEY = FlextServiceKey[FlextCommands.Bus]("command_bus")

    def __init__(self) -> None:
        """Initialize FlextAuthContainer with enhanced authentication capabilities."""
        super().__init__()
        self.logger.info("Initializing FlextAuthContainer with authentication services")

    # =============================================================================
    # CONTAINER CONFIGURATION - Instance methods
    # =============================================================================

    def create_default_config(self) -> FlextAuthConfig:
        """Create default FlextAuth configuration."""
        config = FlextAuthConfig()
        # Set development defaults
        if hasattr(config, "environment"):
            config.environment = "development"
        if hasattr(config, "jwt_secret_key"):
            config.jwt_secret_key = "dev-secret-key-change-in-production"  # noqa: S105
        return config

    def register_core_services(
        self,
        config: FlextAuthConfig,
    ) -> FlextResult[tuple[FlextPasswordService, FlextJWTService]]:
        """Register core services (config, password, JWT)."""
        # Register configuration first
        register_result = register_typed(self.AUTH_CONFIG_KEY, config)
        if not register_result.success:
            return FlextResult.fail(
                f"Failed to register auth config: {register_result.error}"
            )

        # Register password service
        password_service = FlextPasswordService()
        register_result = register_typed(self.PASSWORD_SERVICE_KEY, password_service)
        if not register_result.success:
            return FlextResult.fail(
                f"Failed to register password service: {register_result.error}"
            )

        # Register JWT service
        jwt_service = FlextJWTService(
            secret_key=config.jwt_secret_key or "dev-secret-key-change-in-production",
        )
        register_result = register_typed(self.JWT_SERVICE_KEY, jwt_service)
        if not register_result.success:
            return FlextResult.fail(
                f"Failed to register JWT service: {register_result.error}"
            )

        return FlextResult.ok((password_service, jwt_service))

    def register_repositories(
        self,
        user_repository: UserRepositoryType | None,
        session_repository: SessionRepositoryType | None,
    ) -> FlextResult[tuple[UserRepositoryType, SessionRepositoryType]]:
        """Register repositories with defaults if None."""
        # Register user repository
        final_user_repo = user_repository or InMemoryUserRepository()
        register_result = register_typed(self.USER_REPOSITORY_KEY, final_user_repo)
        if not register_result.success:
            return FlextResult.fail(
                f"Failed to register user repository: {register_result.error}"
            )

        # Register session repository
        final_session_repo = session_repository or InMemorySessionRepository()
        register_result = register_typed(self.SESSION_REPOSITORY_KEY, final_session_repo)
        if not register_result.success:
            return FlextResult.fail(
                f"Failed to register session repository: {register_result.error}"
            )

        return FlextResult.ok((final_user_repo, final_session_repo))

    def register_auth_service(
        self,
        user_repository: UserRepositoryType,
        session_repository: SessionRepositoryType,
        password_service: FlextPasswordService,
        jwt_service: FlextJWTService,
    ) -> FlextResult[None]:
        """Register main auth service."""
        from .auth import FlextAuthService  # noqa: PLC0415

        # Use the new create_default method instead of old constructor
        auth_service = FlextAuthService.create_default(
            user_repository=user_repository,
            session_repository=session_repository,
            password_service=password_service,
            jwt_service=jwt_service,
            config=None,  # Will use default config
        )
        register_result = register_typed(self.AUTH_SERVICE_KEY, auth_service)
        if not register_result.success:
            return FlextResult.fail(
                f"Failed to register auth service: {register_result.error}"
            )

        return FlextResult.ok(None)

    def register_command_bus(
        self,
        user_repository: UserRepositoryType,
        password_service: FlextPasswordService,
        jwt_service: FlextJWTService,
    ) -> FlextResult[None]:
        """Register command bus and CQRS handlers."""
        try:
            # Create and register command bus
            command_bus = FlextCommands.Bus()
            register_result = register_typed(self.COMMAND_BUS_KEY, command_bus)
            if not register_result.success:
                return FlextResult.fail(
                    f"Failed to register command bus: {register_result.error}"
                )

            # Register authentication command handlers
            from .commands import register_auth_commands  # noqa: PLC0415

            handler_register_result = register_auth_commands(
                command_bus,
                user_repository,
                password_service,
                jwt_service,
            )
            if not handler_register_result.success:
                return FlextResult.fail(
                    f"Failed to register auth command handlers: {handler_register_result.error}"
                )

            return FlextResult.ok(None)
        except Exception as e:
            return FlextResult.fail(f"Failed to setup CQRS commands: {e}")

    def configure_auth_services(
        self,
        config: FlextAuthConfig | None = None,
        user_repository: UserRepositoryType | None = None,
        session_repository: SessionRepositoryType | None = None,
    ) -> FlextResult[None]:
        """Configure FlextAuth services in this container."""
        config = config or self.create_default_config()

        # Register core services
        core_result = self.register_core_services(config)
        if core_result.is_failure:
            return FlextResult[None].fail(core_result.error or "Failed to register core services")
        password_service, jwt_service = core_result.value

        # Register repositories
        repo_result = self.register_repositories(user_repository, session_repository)
        if repo_result.is_failure:
            return FlextResult[None].fail(repo_result.error or "Failed to register repositories")
        final_user_repo, final_session_repo = repo_result.value

        # Register auth service
        auth_result = self.register_auth_service(
            final_user_repo,
            final_session_repo,
            password_service,
            jwt_service,
        )
        if auth_result.is_failure:
            return FlextResult[None].fail(auth_result.error or "Failed to register auth service")

        # Register command bus
        command_result = self.register_command_bus(
            final_user_repo,
            password_service,
            jwt_service,
        )
        if command_result.is_failure:
            return FlextResult[None].fail(command_result.error or "Failed to register command bus")

        return FlextResult[None].ok(None)

    def get_auth_services(self) -> FlextResult[dict[str, object]]:
        """Get all registered FlextAuth services from this container.

        Returns:
            Dictionary with all registered services or error

        """
        services: dict[str, object] = {}

        # Use safe service collection checking success first
        config_result = get_typed(self.AUTH_CONFIG_KEY, FlextAuthConfig)
        if config_result.success:
            services["config"] = config_result.value

        password_result = get_typed(self.PASSWORD_SERVICE_KEY, FlextPasswordService)
        if password_result.success:
            services["password_service"] = password_result.value

        jwt_result = get_typed(self.JWT_SERVICE_KEY, FlextJWTService)
        if jwt_result.success:
            services["jwt_service"] = jwt_result.value

        # Get repositories - use get_typed for consistency with other services
        try:
            # Using types imported at module top-level

            user_repo_result = get_typed(self.USER_REPOSITORY_KEY, UserRepositoryType)  # type: ignore[type-abstract]
            if user_repo_result.success:
                services["user_repository"] = user_repo_result.value

            session_repo_result = get_typed(self.SESSION_REPOSITORY_KEY, SessionRepositoryType)  # type: ignore[type-abstract]
            if session_repo_result.success:
                services["session_repository"] = session_repo_result.value
        except Exception:
            # Fallback to generic get method if get_typed fails with union types
            user_repo_fallback = self.get(str(self.USER_REPOSITORY_KEY))
            if user_repo_fallback.success:
                services["user_repository"] = user_repo_fallback.value

            session_repo_fallback = self.get(str(self.SESSION_REPOSITORY_KEY))
            if session_repo_fallback.success:
                services["session_repository"] = session_repo_fallback.value

        # Get auth service (TYPE_CHECKING import resolved at runtime)
        from .auth import FlextAuthService  # noqa: PLC0415

        auth_result = get_typed(self.AUTH_SERVICE_KEY, FlextAuthService)
        if auth_result.success:
            services["auth_service"] = auth_result.value

        # Get command bus (optional) - check success
        command_result = get_typed(self.COMMAND_BUS_KEY, FlextCommands.Bus)
        if command_result.success:
            services["command_bus"] = command_result.value

        return FlextResult[dict[str, object]].ok(services)

    # =============================================================================
    # CONVENIENCE METHODS - Easy service access
    # =============================================================================

    def get_auth_service(self) -> FlextResult[FlextAuthService]:
        """Get authenticated FlextAuthService from this container."""
        from .auth import FlextAuthService  # noqa: PLC0415

        return get_typed(self.AUTH_SERVICE_KEY, FlextAuthService)

    def get_password_service(self) -> FlextResult[FlextPasswordService]:
        """Get FlextPasswordService from this container."""
        return get_typed(self.PASSWORD_SERVICE_KEY, FlextPasswordService)

    def get_jwt_service(self) -> FlextResult[FlextJWTService]:
        """Get FlextJWTService from this container."""
        return get_typed(self.JWT_SERVICE_KEY, FlextJWTService)

    def get_command_bus(self) -> FlextResult[FlextCommands.Bus | None]:
        """Get FlextCommands.Bus from this container."""
        try:
            bus_result = get_typed(self.COMMAND_BUS_KEY, FlextCommands.Bus)
            if bus_result.success:
                return FlextResult[FlextCommands.Bus | None].ok(bus_result.value)
            return FlextResult[FlextCommands.Bus | None].fail(
                bus_result.error or "Command bus not available",
            )
        except Exception as e:
            return FlextResult[FlextCommands.Bus | None].fail(
                f"Command bus not available: {e}",
            )


# =============================================================================
# LEGACY COMPATIBILITY ALIASES - Function aliases to class methods
# =============================================================================

# Global container instance for backward compatibility
_global_auth_container = FlextAuthContainer()


# Alias functions that delegate to the global container instance
def configure_flext_auth_container(
    container: FlextContainer | None = None,
    config: FlextAuthConfig | None = None,
    user_repository: UserRepositoryType | None = None,
    session_repository: SessionRepositoryType | None = None,
) -> FlextResult[FlextContainer]:
    """Configure FlextAuth services in the DI container (legacy function)."""
    target_container = container or _global_auth_container
    if isinstance(target_container, FlextAuthContainer):
        result = target_container.configure_auth_services(config, user_repository, session_repository)
        if result.is_success:
            return FlextResult[FlextContainer].ok(target_container)
        return FlextResult[FlextContainer].fail(result.error or "Configuration failed")
    # Fallback for regular FlextContainer
    return FlextResult[FlextContainer].fail("Container must be FlextAuthContainer")


def get_flext_auth_services(
    container: FlextContainer | None = None,
) -> FlextResult[dict[str, object]]:
    """Get all registered FlextAuth services from container (legacy function)."""
    if isinstance(container, FlextAuthContainer):
        return container.get_auth_services()
    return _global_auth_container.get_auth_services()


def get_auth_service() -> FlextResult[FlextAuthService]:
    """Get authenticated FlextAuthService from global container (legacy function)."""
    return _global_auth_container.get_auth_service()


def get_password_service() -> FlextResult[FlextPasswordService]:
    """Get FlextPasswordService from global container (legacy function)."""
    return _global_auth_container.get_password_service()


def get_jwt_service() -> FlextResult[FlextJWTService]:
    """Get FlextJWTService from global container (legacy function)."""
    return _global_auth_container.get_jwt_service()


def get_command_bus() -> FlextResult[FlextCommands.Bus | None]:
    """Get FlextCommands.Bus from global container (legacy function)."""
    return _global_auth_container.get_command_bus()


__all__ = [
    "FlextAuthContainer",  # 🎯 MAIN CLASS: Single class following Flext[Area][Module] pattern
    # =============================================================================
    # TYPE SUPPORT - For type annotations (not classes)
    # =============================================================================
    "SessionRepositoryType",
    "UserRepositoryType",
    # =============================================================================
    # LEGACY COMPATIBILITY ALIASES - Backward compatibility functions
    # =============================================================================
    "configure_flext_auth_container",  # → FlextAuthContainer.configure_auth_services()
    "get_auth_service",               # → FlextAuthContainer.get_auth_service()
    "get_command_bus",                # → FlextAuthContainer.get_command_bus()
    "get_flext_auth_services",         # → FlextAuthContainer.get_auth_services()
    "get_jwt_service",                # → FlextAuthContainer.get_jwt_service()
    "get_password_service",           # → FlextAuthContainer.get_password_service()
]
