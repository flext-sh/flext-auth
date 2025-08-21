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
from flext_auth.auth import (
    FlextAuthService,
    FlextAuthServiceConfig,
    FlextAuthServiceDependencies,
    FlextUserRegistrationData,
)

# Simple auth service factory
from flext_auth.app import (
    create_auth_service,
)

# =============================================================================
# CONFIGURATION AND TYPES
# =============================================================================

from flext_core import FlextResult

from flext_auth.config import (
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

from flext_auth.decorators import (
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

from flext_auth.exceptions import (
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

from flext_auth.services import (
    FlextAuthenticationService,
    FlextAuthorizationService,
    FlextSessionService,
)

from flext_auth.password_service import FlextPasswordService

# =============================================================================
# REPOSITORIES
# =============================================================================

from flext_auth.repositories_simple import FlextSessionRepository, FlextUserRepository
from flext_auth.session import InMemorySessionRepository
from flext_auth.user import InMemoryUserRepository

# =============================================================================
# UTILITIES
# =============================================================================

# from flext_auth.utilities import FlextAuthUtilities  # Not exposed in public API
from flext_auth.api import (
    generate_secure_password,
    generate_secure_token,
    get_utc_now,
    is_strong_password,
    mask_sensitive_data,
)

# =============================================================================
# VALIDATION AND FIELDS
# =============================================================================

from flext_auth.validation import (
    FlextAuthValidators,
)

# Import validation functions from main API
from flext_auth.api import (
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
)

# =============================================================================
# CONSTANTS
# =============================================================================

from flext_auth.constants import (
    DEFAULT_DEV_SECRET,
    DEFAULT_JWT_SECRET,
    FlextAuthConstants,
)

# =============================================================================
# HELPERS AND PUBLIC UTILITY FUNCTIONS
# =============================================================================

# Helper functions using main API
from flext_auth.api import (
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_jwt,
    flext_auth_verify_password,
)

# =============================================================================
# DOMAIN MODELS
# =============================================================================

from flext_auth.models import (
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

from flext_auth.value_objects import (
    FlextAuthToken,
    FlextIPAddress,
    FlextRefreshToken,
    FlextSessionToken,
    FlextUserAgent,
)

# =============================================================================
# APPLICATION SERVICES
# =============================================================================

# from flext_auth.application_services import (
#     # AppFlextAuthenticationService,  # Commented out - not accessed
#     # AppFlextAuthorizationService,   # Commented out - not accessed
#     # AppFlextSessionService,         # Commented out - not accessed
# )

# =============================================================================
# API FACADE
# =============================================================================

from flext_auth.api import FlextAuth

# =============================================================================
# CURRENT API CONSTANTS AND TYPES
# =============================================================================

from flext_auth.api import (
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

from flext_auth.jwt import FlextJWTService

# =============================================================================
# EXPORTS - Complete API surface
# =============================================================================

__all__: list[str] = [
    # Version and metadata
    "__version__",
    "__version_info__",
    # Core types
    "FlextResult",
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
    # Factory functions
    "create_auth_service",
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
