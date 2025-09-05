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

# Import FlextResult for convenience functions
from flext_core import FlextConstants, FlextResult

# =============================================================================
# FOUNDATION LAYER - Import first, no dependencies on other auth modules
# =============================================================================
from flext_auth.__version__ import __version__

# =============================================================================
# SUPPORT LAYER - Main facade and convenience functions
# =============================================================================
from flext_auth.auth import (
    AuthCommands,
    AuthenticatorProtocol,
    AuthRequest,
    CommandHandlerProtocol,
    FlextAuth,
    QuickStartRequest,
)

# =============================================================================
# INFRASTRUCTURE LAYER - Depends on Application + Domain + Foundation
# =============================================================================
from flext_auth.config import (
    EnvironmentConfigRequest,
    FlextAuthConfig,
    FlextAuthConfigParams,
)

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
    UserCreationRequest,
    authenticate_user,
    create_session,
    create_user,
)

# =============================================================================
# FLEXT-CORE DIRECT USAGE - No wrappers, use patterns directly
# =============================================================================

# =============================================================================
# CONVENIENCE FUNCTIONS - For backward compatibility and examples
# =============================================================================


def flext_auth_quick_start(
    *,
    create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
    REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
    REDACTED_LDAP_BIND_PASSWORD_password: str = getattr(
        getattr(FlextConstants, "Auth", None),
        "DEFAULT_ADMIN_PASSWORD",
        "AdminPassword123!",  # noqa: S107
    ),
) -> FlextAuth[object]:
    """Quick start convenience function for examples and testing.

    Args:
        create_REDACTED_LDAP_BIND_PASSWORD: Whether to create REDACTED_LDAP_BIND_PASSWORD user
        REDACTED_LDAP_BIND_PASSWORD_username: Admin username
        REDACTED_LDAP_BIND_PASSWORD_password: Admin password

    Returns:
        FlextAuth instance with optional REDACTED_LDAP_BIND_PASSWORD user

    """
    return FlextAuth.quick_start(
        create_REDACTED_LDAP_BIND_PASSWORD=create_REDACTED_LDAP_BIND_PASSWORD,
        REDACTED_LDAP_BIND_PASSWORD_username=REDACTED_LDAP_BIND_PASSWORD_username,
        REDACTED_LDAP_BIND_PASSWORD_password=REDACTED_LDAP_BIND_PASSWORD_password,
    )


# Wrapper functions removed - use FlextAuth directly for better performance and less complexity
# Example: auth = FlextAuth(); auth.hash_password(password)
# Example: auth = FlextAuth(); auth.verify_password(password, hashed)
# Example: auth = FlextAuth(); auth.generate_token(user_id)
# Example: auth = FlextAuth(); auth.verify_token(token)


# Secure generation functions removed - use FlextUtilities from flext-core instead
# Example: from flext_core import FlextUtilities; FlextUtilities.generate_secure_string(length)
# Example: from flext_core import FlextUtilities; FlextUtilities.generate_uuid()


# Additional compatibility aliases and classes
# Factory function removed - use FlextAuth() directly


# Placeholder decorators removed - use FlextDecorators from flext-core
# Example: from flext_core import FlextDecorators; @FlextDecorators.require_auth


# FlextPasswordService removed - use FlextAuth directly or FlextSecurity from flext-core
# Example: auth = FlextAuth(); auth.hash_password(password)
# Example: from flext_core import FlextSecurity; FlextSecurity.hash_password(password)


# FlextAuthTypes removed - use FlextModels.EmailAddress and standard types directly
# Example: from flext_core.models import FlextModels; email: FlextModels.EmailAddress


# =============================================================================
# EXPORTS - Direct from flext-core patterns, no complex aggregation
# =============================================================================

__all__ = [
    # Auth layer protocols and commands
    "AuthCommands",
    # Request/Parameter objects for type-safe API usage
    "AuthRequest",
    "AuthToken",
    "AuthenticatorProtocol",
    "CommandHandlerProtocol",
    "Credential",
    "EnvironmentConfigRequest",
    # Core authentication
    "FlextAuth",
    "FlextAuthConfig",
    "FlextAuthConfigParams",
    "FlextResult",
    "Password",
    "QuickStartRequest",
    "Role",
    "Session",
    # Domain models
    "User",
    "UserCreationRequest",
    # Foundation
    "__version__",
    "authenticate_user",
    "create_session",
    # Domain functions
    "create_user",
    # Convenience functions (reduced from 11 to 1 - eliminating wrappers)
    "flext_auth_quick_start",
]
