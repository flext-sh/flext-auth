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
    FlextCommands,
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

# FlextCommands already imported at top

COMMAND_BUS_KEY = FlextServiceKey[FlextCommands.Bus]("command_bus")


# =============================================================================
# CONTAINER CONFIGURATION - Single source of truth
# =============================================================================


def _create_default_config() -> FlextAuthConfig:
    """Create default FlextAuth configuration."""
    return FlextAuthConfig(
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
        jwt_secret_key="dev-secret-key-change-in-production",  # noqa: S106
    )


def _register_core_services(
    config: FlextAuthConfig,
) -> FlextResult[tuple[FlextPasswordService, FlextJWTService]]:
    """Register core services (config, password, JWT)."""
    # Register configuration first
    register_result = register_typed(AUTH_CONFIG_KEY, config)
    if not register_result.success:
        return FlextResult.fail(
            f"Failed to register auth config: {register_result.error}"
        )

    # Register password service
    password_service = FlextPasswordService()
    register_result = register_typed(PASSWORD_SERVICE_KEY, password_service)
    if not register_result.success:
        return FlextResult.fail(
            f"Failed to register password service: {register_result.error}"
        )

    # Register JWT service
    jwt_service = FlextJWTService(
        secret_key=config.jwt_secret_key or "dev-secret-key-change-in-production",
    )
    register_result = register_typed(JWT_SERVICE_KEY, jwt_service)
    if not register_result.success:
        return FlextResult.fail(
            f"Failed to register JWT service: {register_result.error}"
        )

    return FlextResult.ok((password_service, jwt_service))


def _register_repositories(
    user_repository: UserRepositoryType | None,
    session_repository: SessionRepositoryType | None,
) -> FlextResult[tuple[UserRepositoryType, SessionRepositoryType]]:
    """Register repositories with defaults if None."""
    # Register user repository
    final_user_repo = user_repository or InMemoryUserRepository()
    register_result = register_typed(USER_REPOSITORY_KEY, final_user_repo)
    if not register_result.success:
        return FlextResult.fail(
            f"Failed to register user repository: {register_result.error}"
        )

    # Register session repository
    final_session_repo = session_repository or InMemorySessionRepository()
    register_result = register_typed(SESSION_REPOSITORY_KEY, final_session_repo)
    if not register_result.success:
        return FlextResult.fail(
            f"Failed to register session repository: {register_result.error}"
        )

    return FlextResult.ok((final_user_repo, final_session_repo))


def _register_auth_service(
    user_repository: UserRepositoryType,
    session_repository: SessionRepositoryType,
    password_service: FlextPasswordService,
    jwt_service: FlextJWTService,
) -> FlextResult[None]:
    """Register main auth service."""
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
        return FlextResult.fail(
            f"Failed to register auth service: {register_result.error}"
        )

    return FlextResult.ok(None)


def _register_command_bus(
    user_repository: UserRepositoryType,
    password_service: FlextPasswordService,
    jwt_service: FlextJWTService,
) -> FlextResult[None]:
    """Register command bus and CQRS handlers."""
    try:
        # Create and register command bus
        command_bus = FlextCommands.Bus()
        register_result = register_typed(COMMAND_BUS_KEY, command_bus)
        if not register_result.success:
            return FlextResult.fail(
                f"Failed to register command bus: {register_result.error}"
            )

        # Register authentication command handlers
        from flext_auth.commands import register_auth_commands

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


def configure_flext_auth_container(
    container: FlextContainer | None = None,
    config: FlextAuthConfig | None = None,
    user_repository: UserRepositoryType | None = None,
    session_repository: SessionRepositoryType | None = None,
) -> FlextResult[FlextContainer]:
    """Configure FlextAuth services in the DI container."""
    container = container or get_flext_container()
    config = config or _create_default_config()

    # Register core services
    core_result = _register_core_services(config)
    if core_result.is_failure:
        return FlextResult[FlextContainer].fail(core_result.error)
    password_service, jwt_service = core_result.value

    # Register repositories
    repo_result = _register_repositories(user_repository, session_repository)
    if repo_result.is_failure:
        return FlextResult[FlextContainer].fail(repo_result.error)
    final_user_repo, final_session_repo = repo_result.value

    # Register auth service
    auth_result = _register_auth_service(
        final_user_repo,
        final_session_repo,
        password_service,
        jwt_service,
    )
    if auth_result.is_failure:
        return FlextResult[FlextContainer].fail(auth_result.error)

    # Register command bus
    command_result = _register_command_bus(
        final_user_repo,
        password_service,
        jwt_service,
    )
    if command_result.is_failure:
        return FlextResult[FlextContainer].fail(command_result.error)

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

    # Use unwrap_or pattern for cleaner service collection
    config = get_typed(AUTH_CONFIG_KEY, FlextAuthConfig).unwrap_or(None)
    if config:
        services["config"] = config

    password_service = get_typed(PASSWORD_SERVICE_KEY, FlextPasswordService).unwrap_or(
        None
    )
    if password_service:
        services["password_service"] = password_service

    jwt_service = get_typed(JWT_SERVICE_KEY, FlextJWTService).unwrap_or(None)
    if jwt_service:
        services["jwt_service"] = jwt_service

    # Get repositories - use unwrap_or for cleaner handling
    user_repo = container.get(str(USER_REPOSITORY_KEY)).unwrap_or(None)
    if user_repo:
        services["user_repository"] = user_repo

    session_repo = container.get(str(SESSION_REPOSITORY_KEY)).unwrap_or(None)
    if session_repo:
        services["session_repository"] = session_repo

    # Get auth service (TYPE_CHECKING import resolved at runtime)
    from flext_auth.auth import FlextAuthService

    auth_service = get_typed(AUTH_SERVICE_KEY, FlextAuthService).unwrap_or(None)
    if auth_service:
        services["auth_service"] = auth_service

    # Get command bus (optional) - use unwrap_or
    command_bus = get_typed(COMMAND_BUS_KEY, FlextCommands.Bus).unwrap_or(None)
    if command_bus:
        services["command_bus"] = command_bus

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
            bus_result.error or "Command bus not available",
        )
    except Exception as e:
        return FlextResult[FlextCommands.Bus | None].fail(
            f"Command bus not available: {e}",
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
