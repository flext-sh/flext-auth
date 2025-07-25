"""🚨 ARCHITECTURAL COMPLIANCE: ELIMINATED DUPLICATE DI Container.

REFATORADO COMPLETO:
- REMOVIDA duplicação de FlextBaseDIContainer
- USA APENAS FlextContainer oficial do flext-core
- Mantém apenas utilitários auth-específicos
- SEM fallback, backward compatibility ou código duplicado

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextContainer, get_logger

from flext_auth.config import AppConfig
from flext_auth.repositories.session_repository import InMemorySessionRepository
from flext_auth.repositories.user_repository import InMemoryUserRepository
from flext_auth.services.auth_service import FlextAuthService
from flext_auth.services.jwt_service import FlextJWTService
from flext_auth.services.password_service import FlextPasswordService

logger = get_logger(__name__)


# ==================== AUTH-SPECIFIC DI UTILITIES ====================

_auth_container_instance: FlextContainer | None = None


def get_auth_container() -> FlextContainer:
    """Get AUTH-specific DI container instance.

    Returns:
        FlextContainer: Official container from flext-core.

    """
    global _auth_container_instance
    if _auth_container_instance is None:
        _auth_container_instance = FlextContainer()
    return _auth_container_instance


def configure_auth_dependencies() -> None:
    """Configure AUTH dependencies using official FlextContainer."""
    container = get_auth_container()

    try:
        # Create configuration
        settings = AppConfig()
        container.register("AuthSettings", settings)

        # Create repositories (using in-memory for now, can be configured for PostgreSQL)
        user_repo = InMemoryUserRepository()
        session_repo = InMemorySessionRepository()
        container.register("UserRepository", user_repo)
        container.register("SessionRepository", session_repo)

        # Create services
        password_service = FlextPasswordService()
        jwt_service = FlextJWTService(
            secret_key=settings.jwt.secret_key,
            algorithm=settings.jwt.algorithm,
            access_token_expire_minutes=settings.jwt.access_token_expire_minutes,
            refresh_token_expire_days=settings.jwt.refresh_token_expire_days,
        )

        auth_service = FlextAuthService(
            user_repository=user_repo,
            session_repository=session_repo,
            password_service=password_service,
            jwt_service=jwt_service,
            max_failed_attempts=settings.security.max_failed_attempts,
            lockout_duration_minutes=settings.security.lockout_duration_minutes,
            session_expire_hours=settings.security.session_expire_hours,
            max_concurrent_sessions=settings.security.max_concurrent_sessions,
        )

        container.register("FlextPasswordService", password_service)
        container.register("FlextJWTService", jwt_service)
        container.register("FlextAuthService", auth_service)

        logger.info("AUTH dependencies configured successfully")

    except (ImportError, AttributeError, ValueError, TypeError):
        logger.exception("Failed to configure AUTH dependencies")


def get_auth_service_instance(service_name: str) -> FlextAuthService | None:
    """Get auth service from container.

    Args:
        service_name: Name of service to retrieve.

    Returns:
        Service instance or None if not found.

    """
    container = get_auth_container()
    result = container.get(service_name)

    if result.is_success:
        return result.data

    logger.warning("Auth service '%s' not found: %s", service_name, result.error)
    return None


# Initialize auth dependencies on module import
configure_auth_dependencies()
