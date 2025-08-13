"""FLEXT Auth - Enterprise Authentication Library for FLEXT ecosystem.

This module provides comprehensive authentication and authorization services for the
FLEXT ecosystem, implementing enterprise-grade security patterns with Clean Architecture
and Domain-Driven Design principles.

The library is reorganized following PEP8 strict naming patterns with consolidated
modules providing clean, organized access to authentication functionality including
JWT token management, password hashing, session management, and role-based access control.

Architecture:
    - auth_config: Configuration management and type definitions
    - auth_models: Domain entities, value objects, and repository patterns
    - auth_services: Service layer with password, JWT, and application services
    - auth_decorators: Decorators and mixins for authentication aspects
    - auth_validation: Input validation and field management
    - auth_session: Session management and repository patterns
    - auth_utilities: Helper functions and utility classes
    - auth_exceptions: Authentication-specific exception hierarchy
    - auth_app: Main authentication service and application layer

Features:
    - JWT token generation and validation
    - Secure password hashing with bcrypt
    - Session management with configurable storage
    - Role-based access control (RBAC)
    - Multi-factor authentication support
    - Enterprise security compliance

Example:
    Basic authentication setup and usage:

    >>> from flext_auth import FlextAuth, create_auth_config
    >>> config = create_auth_config(jwt_secret="your-secret-key")
    >>> auth = FlextAuth(config)
    >>> result = auth.authenticate("username", "password")
    >>> if result.is_success:
    ...     print(f"Token: {result.data}")

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import importlib.metadata
from typing import ClassVar

from flext_core import FlextResult
from flext_core.loggings import FlextLoggerFactory

# =============================================================================
# REORGANIZED IMPORTS - From consolidated PEP8 modules
# =============================================================================

# Configuration and types
from flext_auth.auth_config import (
    DEFAULT_DEV_SECRET,
    DEFAULT_JWT_SECRET,
    FlextAuthApplicationConfig,
    FlextAuthConfig,
    create_auth_config,
    create_development_config,
    create_production_config,
)

# Domain models
from flext_auth.auth_models import (
    FlextHashedPassword,
    FlextJWTClaims,
    FlextLoginAttempt,
    FlextPermission,
    FlextPlainPassword,
    FlextRole,
    FlextSecurityContext,
    FlextSession,
    FlextSessionStatus,
    FlextUser,
    FlextUserEmail,
    FlextUserRole,
    FlextUserStatus,
    FlextUsername,
    InMemoryUserRepository,
    UserRepository,
)

# Services layer
from flext_auth.auth_services import (
    FlextAuthenticationService,
    FlextAuthorizationService,
    FlextJWTService,
    FlextPasswordService,
    FlextSessionService,
)

# Decorators and mixins
from flext_auth.auth_decorators import (
    FlextAuthMixin,
    FlextAuthSessionMixin,
    FlextAuthUserMixin,
    flext_auth_permission_required,
    flext_auth_required,
    flext_auth_role_required,
)

# Validation and fields
from flext_auth.auth_validation import (
    FlextAuthFieldSchema,
    FlextAuthValidators,
    validate_complete_user_registration,
    validate_email,
    validate_password,
    validate_password_strength,
    validate_username,
)

# Session management
from flext_auth.auth_session import (
    InMemorySessionRepository,
    SessionRepository,
)

# Utilities
from flext_auth.auth_utilities import (
    generate_secure_password,
    generate_secure_token,
    get_utc_now,
    is_strong_password,
    mask_sensitive_data,
)

# Exceptions
from flext_auth.auth_exceptions import (
    FlextAccountInactiveError,
    FlextAccountLockedError,
    FlextAuthError,
    FlextAuthenticationError,
    FlextAuthorizationError,
    FlextExpiredSessionError,
    FlextExpiredTokenError,
    FlextInsufficientPermissionError,
    FlextInvalidCredentialsError,
    FlextInvalidSessionError,
    FlextInvalidTokenError,
    FlextPasswordValidationError,
    FlextPermissionError,
    FlextRoleRequiredError,
    FlextSessionError,
    FlextTokenError,
    FlextValidationError,
)

# Main application service
from flext_auth.auth_app import (
    FlextAuthService,
    FlextAuthServiceConfig,
    FlextAuthServiceDependencies,
    create_auth_service,
)

# =============================================================================
# VERSION AND METADATA
# =============================================================================

try:
    __version__ = importlib.metadata.version("flext-auth")
except Exception:
    __version__ = "unknown"

# Logger
_logger = FlextLoggerFactory.get_logger(__name__)

# =============================================================================
# GLOBAL CONFIGURATION
# =============================================================================


class FlextAuthGlobalConfig:
    """Global configuration for FLEXT Auth library."""

    DEFAULT_CONFIG: ClassVar[FlextAuthConfig] = FlextAuthConfig()

    @classmethod
    def get_default_config(cls) -> FlextAuthConfig:
        """Get the default global configuration."""
        return cls.DEFAULT_CONFIG

    @classmethod
    def set_default_config(cls, config: FlextAuthConfig) -> None:
        """Set the default global configuration."""
        cls.DEFAULT_CONFIG = config


# =============================================================================
# QUICK START FUNCTIONS
# =============================================================================


def flext_auth_quick_start(jwt_secret: str = DEFAULT_JWT_SECRET) -> FlextAuthService:
    """Quick start function to create a configured authentication service.

    Args:
        jwt_secret: JWT secret key for token signing

    Returns:
        Configured FlextAuthService ready for use

    """
    return create_auth_service(jwt_secret)


def flext_auth_create_development_service() -> FlextAuthService:
    """Create development authentication service with default settings."""
    return create_auth_service("dev-secret-key-32-chars-minimum-length")


# =============================================================================
# EXPORTS - Complete API surface
# =============================================================================

__all__: list[str] = [
    "FlextAuthConfig",
    "FlextAuthApplicationConfig",
    "FlextAuthGlobalConfig",
    "create_auth_config",
    "create_development_config",
    "create_production_config",
    "FlextUser",
    "FlextUserRole",
    "FlextUserStatus",
    "FlextSession",
    "FlextSessionStatus",
    "FlextRole",
    "FlextPermission",
    "FlextLoginAttempt",
    "FlextUsername",
    "FlextUserEmail",
    "FlextPlainPassword",
    "FlextHashedPassword",
    "FlextJWTClaims",
    "FlextSecurityContext",
    "FlextAuthService",
    "FlextAuthServiceConfig",
    "FlextAuthServiceDependencies",
    "FlextAuthenticationService",
    "FlextAuthorizationService",
    "FlextSessionService",
    "FlextPasswordService",
    "FlextJWTService",
    "UserRepository",
    "InMemoryUserRepository",
    "SessionRepository",
    "InMemorySessionRepository",
    "flext_auth_required",
    "flext_auth_role_required",
    "flext_auth_permission_required",
    "FlextAuthMixin",
    "FlextAuthUserMixin",
    "FlextAuthSessionMixin",
    "FlextAuthValidators",
    "FlextAuthFieldSchema",
    "validate_username",
    "validate_email",
    "validate_password",
    "validate_password_strength",
    "validate_complete_user_registration",
    "generate_secure_token",
    "generate_secure_password",
    "get_utc_now",
    "is_strong_password",
    "mask_sensitive_data",
    "FlextAuthError",
    "FlextAuthenticationError",
    "FlextAuthorizationError",
    "FlextTokenError",
    "FlextSessionError",
    "FlextPermissionError",
    "FlextValidationError",
    "FlextInvalidCredentialsError",
    "FlextAccountLockedError",
    "FlextAccountInactiveError",
    "FlextInvalidTokenError",
    "FlextExpiredTokenError",
    "FlextInvalidSessionError",
    "FlextExpiredSessionError",
    "FlextInsufficientPermissionError",
    "FlextRoleRequiredError",
    "FlextPasswordValidationError",
    "flext_auth_quick_start",
    "flext_auth_create_development_service",
    "DEFAULT_JWT_SECRET",
    "DEFAULT_DEV_SECRET",
    "FlextResult",
    "annotations",
    "ClassVar",
    "FlextLoggerFactory",
    "create_auth_service",
]
