"""Simple API for FLEXT Auth - Easy adoption interface.

REFACTORED:
    Uses flext-core 0.7.0 patterns with zero code duplication.
Provides a simple interface for common authentication operations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth.user_service import UserService
from flext_core.config import get_container
from flext_core.domain.types import ServiceResult

if TYPE_CHECKING:
    from flext_auth.config import AuthSettings
    from flext_auth.domain.entities import User
    from flext_auth.domain.value_objects import AuthToken


def setup_auth(settings: AuthSettings | None = None) -> ServiceResult[bool]:
    """Set up authentication system with provided settings.

    Args:
        settings: Authentication settings to use. If None, defaults will be loaded.

    Returns:
        ServiceResult indicating success or failure of setup.

    Raises:
        ImportError: If required authentication modules are not available.

    """
    try:
        from flext_auth.infrastructure.config import get_auth_settings

        if settings is None:
            settings = get_auth_settings()

        # Configure DI container
        container = get_container()
        settings.configure_dependencies(container)

        return ServiceResult.ok(True)

    except Exception as e:
        return ServiceResult.fail(f"Failed to setup auth: {e}")


def create_user(username: str, email: str, password: str, roles: list[str] | None = None) -> ServiceResult[User]:
    """Create a new user with specified credentials.

    Args:
        username: Unique username for the user.
        email: Email address for the user.
        password: Plain text password (will be hashed).
        roles: Optional list of roles to assign to user.

    Returns:
        ServiceResult containing the created User or error details.

    Raises:
        Exception: If user creation fails due to system errors.

    """
    try:
        container = get_container()
        container.resolve(UserService)

        # This would need to be implemented in UserService
        # For now, return a placeholder
        return ServiceResult.fail("User creation not yet implemented")

    except Exception as e:
        return ServiceResult.fail(f"Failed to create user: {e}")


def authenticate_user(username: str, password: str) -> ServiceResult[AuthToken]:
    """Authenticate user with username and password.

    Args:
        username: Username to authenticate.
        password: Password to verify.

    Returns:
        ServiceResult containing AuthToken if successful or error details.

    Raises:
        Exception: If authentication fails due to system errors.

    """
    try:
        container = get_container()
        container.resolve("AuthService")

        # This would need to be implemented in AuthService
        # For now, return a placeholder
        return ServiceResult.fail("Authentication not yet implemented")

    except Exception as e:
        return ServiceResult.fail(f"Failed to authenticate user: {e}")


def validate_token(token: str) -> ServiceResult[User]:
    """Validate authentication token and return user.

    Args:
        token: JWT token to validate.

    Returns:
        ServiceResult containing User if token is valid or error details.

    Raises:
        Exception: If token validation fails due to system errors.

    """
    try:
        container = get_container()
        container.resolve("TokenService")

        # This would need to be implemented in TokenService
        # For now, return a placeholder
        return ServiceResult.fail("Token validation not yet implemented")

    except Exception as e:
        return ServiceResult.fail(f"Failed to validate token: {e}")


def revoke_token(token: str) -> ServiceResult[bool]:
    """Revoke authentication token.

    Args:
        token: JWT token to revoke.

    Returns:
        ServiceResult indicating success or failure of revocation.

    Raises:
        Exception: If token revocation fails due to system errors.

    """
    try:
        container = get_container()
        container.resolve("TokenService")

        # This would need to be implemented in TokenService
        # For now, return a placeholder
        return ServiceResult.fail("Token revocation not yet implemented")

    except Exception as e:
        return ServiceResult.fail(f"Failed to revoke token: {e}")


def get_user_by_id(user_id: str) -> ServiceResult[User]:
    """Retrieve user by ID.

    Args:
        user_id: Unique identifier for the user.

    Returns:
        ServiceResult containing User if found or error details.

    Raises:
        Exception: If user retrieval fails due to system errors.

    """
    try:
        container = get_container()
        container.resolve("UserService")

        # This would need to be implemented in UserService
        # For now, return a placeholder
        return ServiceResult.fail("User retrieval not yet implemented")

    except Exception as e:
        return ServiceResult.fail(f"Failed to get user: {e}")


__all__ = [
    "authenticate_user",
    "create_user",
    "get_user_by_id",
    "revoke_token",
    "setup_auth",
    "validate_token",
]
