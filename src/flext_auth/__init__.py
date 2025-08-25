"""Enterprise authentication library for FLEXT ecosystem.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import importlib.metadata

# ==============================================================================
# VERSION AND METADATA
# ==============================================================================

try:
    __version__ = importlib.metadata.version("flext-auth")
except Exception:
    __version__ = "unknown"

__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())

# ==============================================================================
# CORE AUTHENTICATION SERVICE
# ==============================================================================

# Main application service - using the full-featured implementation
from .auth import (
    FlextAuthService,
    FlextAuthServiceConfig,
    FlextAuthServiceDependencies,
    FlextUserRegistrationData,
)

# Simple auth service factory
from .app import (
    create_auth_service,
)

# =============================================================================
# CONFIGURATION AND TYPES
# =============================================================================

from flext_core import FlextResult

from .config import (
    AppConfig,
    DatabaseConfig,
    FlextAuthApplicationConfig,
    FlextAuthConfig,
    JWTConfig,
    SecurityConfig,
    ServerConfig,
    create_auth_config,
    create_development_config,
    create_production_config,
    validate_production_config,
)

# =============================================================================
# DECORATORS AND MIXINS
# =============================================================================

from .decorators import (
    FlextAuthMixin,
    FlextAuthSessionMixin,
    FlextAuthUserMixin,
    flext_auth_permission_required,
    flext_auth_required,
    flext_auth_role_required,
)

# =============================================================================
# EXCEPTIONS
# =============================================================================

from .exceptions import (
    FlextAccountInactiveError,
    FlextAccountLockedError,
    FlextAuthenticationError,
    FlextAuthError,
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

# =============================================================================
# SERVICES LAYER
# =============================================================================

from .services import (
    FlextAuthenticationService,
    FlextAuthorizationService,
    FlextSessionService,
)

from .password import FlextPasswordService

# =============================================================================
# REPOSITORIES
# =============================================================================

from .repositories import (
    FlextSessionRepository,
    FlextUserRepository,
    SimplePostgreSQLSessionRepository,
    SimplePostgreSQLUserRepository,
    create_postgresql_pool,
    initialize_database_schema,
)
from .session import InMemorySessionRepository
from .user import InMemoryUserRepository

# =============================================================================
# UTILITIES
# =============================================================================

# from .utilities import FlextAuthUtilities  # Not exposed in public API
from .api import (
    generate_secure_password,
    generate_secure_token,
    get_utc_now,
    is_strong_password,
    mask_sensitive_data,
)

# =============================================================================
# VALIDATION AND FIELDS
# =============================================================================

from .validation import (
    FlextAuthValidators,
)

# Import validation functions from main API
from .api import (
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
)

# =============================================================================
# CONSTANTS
# =============================================================================

from .constants import (
    DEFAULT_DEV_SECRET,
    DEFAULT_JWT_SECRET,
    FlextAuthConstants,
    FlextAuthSemanticConstants,
)

# =============================================================================
# HELPERS AND PUBLIC UTILITY FUNCTIONS
# =============================================================================

# Helper functions using main API
from .api import (
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_jwt,
    flext_auth_verify_password,
)

# =============================================================================
# DOMAIN MODELS
# =============================================================================

from .models import (
    FlextHashedPassword,
    FlextJWTClaims,
    FlextLoginAttempt,
    FlextPlainPassword,
    FlextSecurityContext,
    FlextSession,
    FlextSessionStatus,
    FlextUser,
    FlextUserEmail,
    FlextUsername,
    FlextUserStatus,
    FlextUserRole,
    FlextRole,
    FlextPermission,
)

# =============================================================================
# DOMAIN VALUE OBJECTS
# =============================================================================

from .values import (
    FlextAuthToken,
    FlextIPAddress,
    FlextRefreshToken,
    FlextSessionToken,
    FlextUserAgent,
)

# =============================================================================
# APPLICATION SERVICES
# =============================================================================

# from .application_services import (
#     # AppFlextAuthenticationService,  # Commented out - not accessed
#     # AppFlextAuthorizationService,   # Commented out - not accessed
#     # AppFlextSessionService,         # Commented out - not accessed
# )

# =============================================================================
# API FACADE
# =============================================================================

from .api import FlextAuth

# =============================================================================
# CURRENT API CONSTANTS AND TYPES
# =============================================================================

from .api import (
    ADMIN_ROLE,
    USER_ROLE,
    FlextAuthRole,
    FlextAuthPermissions,
    FlextAuthUserData,
    FlextAuthSessionData,
    FlextAuthTokenData,
    FlextAuthHeaders,
    FlextAuthClaims,
)

# Role aliases using current entities
# FlextUserRole already imported above at line 182

FLEXT_AUTH_ADMIN = FlextUserRole.ADMIN.value
FLEXT_AUTH_USER = FlextUserRole.USER.value
FLEXT_AUTH_GUEST = "guest"  # Not in current entities, using string literal

# =============================================================================
# JWT SERVICE
# =============================================================================

from .jwt import FlextJWTService

# =============================================================================
# TYPE ALIASES AND PROTOCOLS
# =============================================================================

from .flext_auth_types import (
    SessionRepositoryType,
    UserRepositoryType,
    TEmail,
    TPassword,
    TUsername,
)

# =============================================================================
# COMMAND HANDLERS AND CQRS
# =============================================================================

from .commands import register_auth_commands

# =============================================================================
# TYPE DEFINITIONS
# =============================================================================

from .typings import FlextAuthValidationResultType

# =============================================================================
# MODULAR CLIENT CLASS (Flext[Area][Module] Pattern)
# =============================================================================

from .client import (
    FlextAuthClient,
    flext_auth_client_authenticate_user,
    flext_auth_client_generate_jwt,
    flext_auth_client_hash_password,
    flext_auth_client_quick_start,
    flext_auth_client_validate_email,
    flext_auth_client_verify_password,
)

# =============================================================================
# DEPENDENCY INJECTION CONTAINER
# =============================================================================

from .container import (
    configure_flext_auth_container,
    get_auth_service,
    get_command_bus,
    get_flext_auth_services,
    get_jwt_service,
    get_password_service,
)

# =============================================================================
# EXPORTS - Complete API surface
# =============================================================================

__all__: list[str] = [
    # Version and metadata
    "__version__",
    "__version_info__",
    # Core types
    "FlextResult",
    # MAIN MODULAR CLIENT (Flext[Area][Module] pattern)
    "FlextAuthClient",
    # Public facade and config
    "FlextAuth",
    "FlextAuthConfig",
    "FlextAuthApplicationConfig",
    "AppConfig",
    "DatabaseConfig",
    "JWTConfig",
    "SecurityConfig",
    "ServerConfig",
    "create_auth_config",
    "create_development_config",
    "create_production_config",
    "validate_production_config",
    # Core domain models
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
    # Main services
    "FlextAuthService",
    "FlextAuthServiceConfig",
    "FlextAuthServiceDependencies",
    "FlextUserRegistrationData",
    "FlextAuthenticationService",
    "FlextAuthorizationService",
    "FlextSessionService",
    "FlextPasswordService",
    "FlextJWTService",
    # Repositories
    "FlextUserRepository",
    "InMemoryUserRepository",
    "FlextSessionRepository",
    "InMemorySessionRepository",
    "SimplePostgreSQLSessionRepository",
    "SimplePostgreSQLUserRepository",
    "create_postgresql_pool",
    "initialize_database_schema",
    # Repository types
    "SessionRepositoryType",
    "UserRepositoryType",
    # Type definitions
    "FlextAuthValidationResultType",
    "TEmail",
    "TPassword",
    "TUsername",
    # Decorators and mixins
    "flext_auth_required",
    "flext_auth_role_required",
    "flext_auth_permission_required",
    "FlextAuthMixin",
    "FlextAuthUserMixin",
    "FlextAuthSessionMixin",
    # Validation
    "FlextAuthValidators",
    # Utilities
    "generate_secure_token",
    "generate_secure_password",
    "get_utc_now",
    "is_strong_password",
    "mask_sensitive_data",
    # Exceptions
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
    # Helper functions
    "flext_auth_quick_start",
    # "flext_auth_create_development_service",  # Function not present in module
    # Constants
    "DEFAULT_JWT_SECRET",
    "DEFAULT_DEV_SECRET",
    "FlextAuthConstants",
    "FlextAuthSemanticConstants",
    # Factory functions
    "create_auth_service",
    # Command handlers
    "register_auth_commands",
    # DI Container functions
    "configure_flext_auth_container",
    "get_auth_service",
    "get_command_bus",
    "get_flext_auth_services",
    "get_jwt_service",
    "get_password_service",
    # FlextAuthClient legacy compatibility functions
    "flext_auth_client_authenticate_user",
    "flext_auth_client_generate_jwt",
    "flext_auth_client_hash_password",
    "flext_auth_client_quick_start",
    "flext_auth_client_validate_email",
    "flext_auth_client_verify_password",
    # Role constants and type definitions
    "ADMIN_ROLE",
    "USER_ROLE",
    "FLEXT_AUTH_ADMIN",
    "FLEXT_AUTH_USER",
    "FLEXT_AUTH_GUEST",
    "FlextAuthRole",
    "FlextAuthPermissions",
    "FlextAuthUserData",
    "FlextAuthSessionData",
    "FlextAuthTokenData",
    "FlextAuthHeaders",
    "FlextAuthClaims",
    # Helper surface (only functions that actually exist)
    "flext_auth_hash_password",
    "flext_auth_verify_password",
    "flext_auth_generate_jwt",
    "flext_auth_validate_jwt",
    "flext_auth_validate_email",
    "flext_auth_validate_password_strength",
    # Batch operations removed - not implemented in consolidated API
    # Domain value objects
    "FlextAuthToken",
    "FlextIPAddress",
    "FlextRefreshToken",
    "FlextSessionToken",
    "FlextUserAgent",
]
