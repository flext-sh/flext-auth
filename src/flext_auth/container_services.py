"""FLEXT Auth Container Services - DI Integration with flext-core.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module implements REAL dependency injection using FlextContainer from flext-core.
It consolidates ALL service implementations to eliminate duplications and provides
a single source of truth for service registration and retrieval.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import (
    FlextContainer,
    FlextResult,
    FlextServiceKey,
    get_flext_container,
    get_typed,
    register_typed,
)

from flext_auth.config import FlextAuthConfig
from flext_auth.jwt import FlextJWTService
from flext_auth.password_service import FlextPasswordService
from flext_auth.session import InMemorySessionRepository
from flext_auth.user import InMemoryUserRepository

if TYPE_CHECKING:
    from flext_auth.auth import FlextAuthService


# =============================================================================
# SERVICE KEYS - Type-safe service registration
# =============================================================================

# Import Union types to avoid circular imports
from flext_auth.types import SessionRepositoryType, UserRepositoryType

AUTH_CONFIG_KEY = FlextServiceKey[FlextAuthConfig]("flext_auth_config")
PASSWORD_SERVICE_KEY = FlextServiceKey[FlextPasswordService]("password_service")
JWT_SERVICE_KEY = FlextServiceKey[FlextJWTService]("jwt_service")
USER_REPOSITORY_KEY = FlextServiceKey[UserRepositoryType]("user_repository")
SESSION_REPOSITORY_KEY = FlextServiceKey[SessionRepositoryType]("session_repository")
AUTH_SERVICE_KEY = FlextServiceKey["FlextAuthService"]("auth_service")

# Import FlextCommands from flext-core - using current API only
from flext_core import FlextCommands

COMMAND_BUS_KEY = FlextServiceKey[FlextCommands.Bus]("command_bus")


# =============================================================================
# CONTAINER CONFIGURATION - Single source of truth
# =============================================================================


def configure_flext_auth_container(
    container: FlextContainer | None = None,
    config: FlextAuthConfig | None = None,
    user_repository: UserRepositoryType | None = None,
    session_repository: SessionRepositoryType | None = None,
) -> FlextResult[FlextContainer]:
    """Configure FlextAuth services in the DI container.

    This function consolidates ALL service registration to eliminate duplications
    and provide a single configuration point for the entire authentication system.

    Args:
        container: Optional existing container (creates new if None)
        config: Optional auth configuration (creates default if None)
        user_repository: Optional user repository (in-memory or PostgreSQL, creates in-memory if None)
        session_repository: Optional session repository (in-memory or PostgreSQL, creates in-memory if None)

    Returns:
        FlextResult containing configured container or error

    """
    if container is None:
        container = get_flext_container()

    if config is None:
        config = FlextAuthConfig(
            app_name="FlextAuth",
            version="1.0.0",
            environment="development",
            password_min_length=8,
            password_max_length=128,
            bcrypt_rounds=12,
            max_login_attempts=5,
            lockout_duration_minutes=30,
            session_timeout_hours=24,
            max_concurrent_sessions=5,
            rate_limit_per_minute=60,
            auth_rate_limit_per_minute=5,
            access_token_expire_minutes=30,
            refresh_token_expire_days=7,
            jwt_secret_key="dev-secret-key-change-in-production",
        )

    # Register configuration first
    register_result = register_typed(AUTH_CONFIG_KEY, config)
    if not register_result.success:
        return FlextResult[FlextContainer].fail(
            f"Failed to register auth config: {register_result.error}"
        )

    # Register password service
    password_service = FlextPasswordService()
    register_result = register_typed(PASSWORD_SERVICE_KEY, password_service)
    if not register_result.success:
        return FlextResult[FlextContainer].fail(
            f"Failed to register password service: {register_result.error}"
        )

    # Register JWT service
    jwt_service = FlextJWTService(
        secret_key=config.jwt_secret_key or "dev-secret-key-change-in-production"
    )
    register_result = register_typed(JWT_SERVICE_KEY, jwt_service)
    if not register_result.success:
        return FlextResult[FlextContainer].fail(
            f"Failed to register JWT service: {register_result.error}"
        )

    # Register repositories (in-memory by default for flexibility)
    if user_repository is None:
        user_repository = InMemoryUserRepository()
    register_result = register_typed(USER_REPOSITORY_KEY, user_repository)
    if not register_result.success:
        return FlextResult[FlextContainer].fail(
            f"Failed to register user repository: {register_result.error}"
        )

    if session_repository is None:
        session_repository = InMemorySessionRepository()
    register_result = register_typed(SESSION_REPOSITORY_KEY, session_repository)
    if not register_result.success:
        return FlextResult[FlextContainer].fail(
            f"Failed to register session repository: {register_result.error}"
        )

    # Register main auth service (imported here to avoid circular imports)
    from flext_auth.auth import FlextAuthService, FlextAuthServiceDependencies

    dependencies = FlextAuthServiceDependencies(
        user_repository=user_repository,
        session_repository=session_repository,
        password_service=password_service,
        jwt_service=jwt_service,
        config=None,  # Will use container-registered config
    )

    auth_service = FlextAuthService(dependencies)
    register_result = register_typed(AUTH_SERVICE_KEY, auth_service)
    if not register_result.success:
        return FlextResult[FlextContainer].fail(
            f"Failed to register auth service: {register_result.error}"
        )

    # Register command bus and CQRS handlers
    try:
        # Create and register command bus
        command_bus = FlextCommands.Bus()
        register_result = register_typed(COMMAND_BUS_KEY, command_bus)
        if not register_result.success:
            return FlextResult[FlextContainer].fail(
                f"Failed to register command bus: {register_result.error}"
            )

        # Register authentication command handlers (import here to avoid circular import)
        from flext_auth.commands import register_auth_commands

        handler_register_result = register_auth_commands(
            command_bus, user_repository, password_service, jwt_service
        )
        if not handler_register_result.success:
            return FlextResult[FlextContainer].fail(
                f"Failed to register auth command handlers: {handler_register_result.error}"
            )

    except Exception as e:
        return FlextResult[FlextContainer].fail(f"Failed to setup CQRS commands: {e}")

    return FlextResult[FlextContainer].ok(container)


def get_flext_auth_services(
    container: FlextContainer | None = None,
) -> FlextResult[dict[str, object]]:
    """Get all registered FlextAuth services from container.

    Returns:
        Dictionary with all registered services or error

    """
    if container is None:
        container = get_flext_container()

    services: dict[str, object] = {}

    # Get each service using type-safe keys
    from flext_core import get_typed

    config_result = get_typed(AUTH_CONFIG_KEY, FlextAuthConfig)
    if config_result.success:
        services["config"] = config_result.value

    password_result = get_typed(PASSWORD_SERVICE_KEY, FlextPasswordService)
    if password_result.success:
        services["password_service"] = password_result.value

    jwt_result = get_typed(JWT_SERVICE_KEY, FlextJWTService)
    if jwt_result.success:
        services["jwt_service"] = jwt_result.value

    # Get repositories using proper FlextContainer.get() API
    try:
        user_repo_result = container.get(str(USER_REPOSITORY_KEY))
        if user_repo_result.success:
            services["user_repository"] = user_repo_result.value

        session_repo_result = container.get(str(SESSION_REPOSITORY_KEY))
        if session_repo_result.success:
            services["session_repository"] = session_repo_result.value
    except Exception:
        # Fallback if container access fails
        pass

    # Import here to avoid circular imports
    from flext_auth.auth import FlextAuthService

    auth_service_result = get_typed(AUTH_SERVICE_KEY, FlextAuthService)
    if auth_service_result.success:
        services["auth_service"] = auth_service_result.value

    # Get command bus
    try:
        command_bus_result = get_typed(COMMAND_BUS_KEY, FlextCommands.Bus)
        if command_bus_result.success:
            services["command_bus"] = command_bus_result.value
    except Exception:
        # Command bus is optional in service collection
        pass

    return FlextResult[dict[str, object]].ok(services)


# =============================================================================
# CONVENIENCE FUNCTIONS - Easy service access
# =============================================================================


def get_auth_service() -> FlextResult[FlextAuthService]:
    """Get authenticated FlextAuthService from global container."""
    from flext_auth.auth import FlextAuthService

    return get_typed(AUTH_SERVICE_KEY, FlextAuthService)


def get_password_service() -> FlextResult[FlextPasswordService]:
    """Get FlextPasswordService from global container."""
    return get_typed(PASSWORD_SERVICE_KEY, FlextPasswordService)


def get_jwt_service() -> FlextResult[FlextJWTService]:
    """Get FlextJWTService from global container."""
    return get_typed(JWT_SERVICE_KEY, FlextJWTService)


def get_command_bus() -> FlextResult[FlextCommands.Bus | None]:
    """Get FlextCommands.Bus from global container."""
    try:
        bus_result = get_typed(COMMAND_BUS_KEY, FlextCommands.Bus)
        if bus_result.success:
            return FlextResult[FlextCommands.Bus | None].ok(bus_result.value)
        return FlextResult[FlextCommands.Bus | None].fail(
            bus_result.error or "Command bus not available"
        )
    except Exception as e:
        return FlextResult[FlextCommands.Bus | None].fail(
            f"Command bus not available: {e}"
        )


__all__ = [
    "AUTH_CONFIG_KEY",
    "AUTH_SERVICE_KEY",
    "COMMAND_BUS_KEY",
    "JWT_SERVICE_KEY",
    "PASSWORD_SERVICE_KEY",
    "SESSION_REPOSITORY_KEY",
    "USER_REPOSITORY_KEY",
    "configure_flext_auth_container",
    "get_auth_service",
    "get_command_bus",
    "get_flext_auth_services",
    "get_jwt_service",
    "get_password_service",
]
