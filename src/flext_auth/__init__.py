"""FLEXT Auth - Enterprise authentication library following flext-core patterns.

Architectural foundation for authentication in the FLEXT ecosystem with type-safe
error handling, domain modeling, session management, and JWT token operations
following Clean Architecture and Domain-Driven Design principles.

Architecture:
    Foundation: FlextConstants, FlextResult integration
    Domain: User, Session, Role entities with business logic
    Application: FlextAuth main service, authentication workflows, validation
    Infrastructure: FlextAuthConfig, dependency injection support
    Support: Convenience functions and API compatibility methods

Key Components:
    FlextAuth: Main authentication service with unified API
    User, Session, Role, Credential, AuthToken: Domain models directly from flext-core patterns
    FlextAuthConfig: Type-safe configuration with environment variable support
    FlextConstants: Authentication domain constants and error codes from flext-core

Examples:
    Zero-configuration authentication::

        >>> from flext_auth import FlextAuth
        >>> auth = FlextAuth()
        >>> register_result = auth.register_user("john", "john@example.com", "password123")
        >>> if register_result.success:
        ...     user = register_result.value
        ...     print(f"User created: {user.username}")

    Configuration-based authentication::

        >>> from flext_auth import FlextAuthConfig, FlextAuth
        >>> config_result = FlextAuthConfig.create_for_environment("production", bcrypt_rounds=14)
        >>> if config_result.success:
        ...     auth = FlextAuth(config=config_result.value)
        ...     auth_result = auth.authenticate_user("john", "password123")

Notes:
    - All operations return FlextResult[T] for composable error handling
    - Domain entities inherit from flext-core FlextModels patterns
    - Configuration supports environment variables and validation
    - Authentication follows Clean Architecture and DDD principles
    - JWT tokens include proper expiration and validation
    - Session management with automatic cleanup and security policies

"""

from __future__ import annotations

# =============================================================================
# FOUNDATION LAYER - Import first, no dependencies on other auth modules
# =============================================================================

from flext_auth.__version__ import *

# Import FlextResult for convenience functions
from flext_core import FlextResult

# =============================================================================
# DOMAIN LAYER - Depends only on Foundation layer
# =============================================================================

from flext_auth.models import (
    AuthToken,
    Credential,
    Password,
    Role,
    Session,
    User,
    authenticate_user,
    create_session,
    create_user,
)

# =============================================================================
# INFRASTRUCTURE LAYER - Depends on Application + Domain + Foundation
# =============================================================================

from flext_auth.config import FlextAuthConfig

# =============================================================================
# SUPPORT LAYER - Main facade and convenience functions
# =============================================================================

from flext_auth.auth import FlextAuth

# =============================================================================
# FLEXT-CORE DIRECT USAGE - No wrappers, use patterns directly
# =============================================================================

# Users should use FlextAuth directly or flext-core patterns:
# - FlextAuth() for main functionality
# - FlextAuthConfig.create_for_environment() for configuration
# - Password(value="...").hash_password() for password hashing
# - AuthToken.create_jwt_token() for JWT generation
# - FlextModels.EmailAddress() for email validation


# =============================================================================
# EXPORTS - Direct from flext-core patterns, no complex aggregation
# =============================================================================

__all__ = [
    # Core authentication
    "FlextAuth",
    "FlextAuthConfig", 
    # Domain models
    "User",
    "Session", 
    "Role",
    "Password",
    "Credential", 
    "AuthToken",
    # Domain functions
    "create_user",
    "authenticate_user",
    "create_session",
    # Foundation
    "__version__",
    "FlextResult",
]
