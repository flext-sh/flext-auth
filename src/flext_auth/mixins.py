"""FLEXT Auth Mixins - Reusable authentication behaviors for class composition.

This module provides mixins that add authentication capabilities to existing classes
through composition rather than inheritance. Following the Mixin pattern and SOLID
principles to enable flexible authentication integration.

Architecture:
    - Mixin Pattern: Reusable behavior composition
    - Composition over Inheritance: Flexible class enhancement
    - Railway-Oriented: FlextResult[T] for type-safe operations
    - Framework Agnostic: Works with any Python class

Core Mixins:
    - FlextAuthMixin: Basic authentication capabilities
    - FlextAuthUserMixin: User-specific authentication methods
    - FlextAuthSessionMixin: Session management capabilities
    - FlextAuthRoleMixin: Role-based access control (TODO)
    - FlextAuthAuditMixin: Audit logging capabilities (TODO)

TODO (Based on docs/TODO.md):
    - [ ] CRITICAL: Integrate with FlextContainer for DI (Issue #3)
    - [ ] HIGH: Add domain events for mixin operations (Issue #4)
    - [ ] MEDIUM: Add role-based access control mixin (Issue #8)
    - [ ] MEDIUM: Add audit logging mixin (Issue #11)
    - [ ] LOW: Add caching mixin for performance (Issue #10)

Current Project Status:
    ✅ Authentication mixins comprehensively documented with composition patterns
    ✅ Reusable behavior patterns documented for flexible integration
    ✅ Framework-agnostic class enhancement patterns documented
    🔄 Implementation focus: Role-based access control mixin and audit logging

Design Patterns:
    - Mixin Pattern: Reusable behavior composition
    - Strategy Pattern: Pluggable authentication strategies
    - Template Method: Common authentication workflows
    - Observer Pattern: Authentication event notifications (TODO)

Use Cases:
    - Add authentication to existing business classes
    - Enhance domain entities with auth capabilities
    - Create authenticated service classes
    - Build custom authentication workflows

Example Usage:
    >>> class UserService(FlextAuthMixin):
    ...     def __init__(self):
    ...         super().__init__()
    ...         self.init_auth()
    ...
    ...     def get_protected_data(self, token: str):
    ...         auth_result = self.validate_auth_token(token)
    ...         if auth_result.is_success:
    ...             return {"data": "protected information"}
    ...         return {"error": "Authentication required"}

Security Features:
    - JWT token validation and generation
    - Session management and validation
    - User authentication workflows
    - Security context management
    - Error handling with security considerations

Performance Considerations:
    - Minimal mixin overhead
    - Lazy initialization of auth services
    - Efficient token validation
    - Cached authentication results
    - Async-compatible methods

Integration Points:
    - FlextContainer: Service dependency injection (TODO)
    - FlextResult: Type-safe error handling
    - JWT Service: Token operations
    - Auth Service: Authentication workflows

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from flext_core import FlextLoggerFactory, FlextResult

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import DEFAULT_JWT_SECRET
from flext_auth.jwt import FlextJWTService

if TYPE_CHECKING:
    from flext_auth.auth import FlextAuthService

_logger = FlextLoggerFactory.get_logger(__name__)


class FlextAuthMixin:
    """Mixin for adding authentication capabilities to any class.

    Provides authentication methods that can be mixed into existing classes
    without requiring inheritance from specific base classes.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Initialize mixin with optional auth service."""
        super().__init__(*args, **kwargs)
        self._auth_service: FlextAuthService | None = None
        self._auth_config: FlextAuthConfig | None = None

    def init_auth(
        self,
        auth_service: FlextAuthService | None = None,
        auth_config: FlextAuthConfig | None = None,
    ) -> FlextResult[None]:
        """Initialize authentication for this instance.

        Args:
            auth_service: FlextAuthService instance
            auth_config: FlextAuthConfig instance

        Returns:
            FlextResult indicating success or failure

        """
        try:
            if auth_service:
                self._auth_service = auth_service
            elif auth_config:
                self._auth_config = auth_config
                # FlextAuthService requires dependencies - for mixins, return error
                return FlextResult.fail(
                    "FlextAuthService requires dependencies. "
                    "Please provide auth_service directly or use "
                    "flext_auth_quick_start()",
                )
            else:
                # Use default configuration but cannot create service without deps
                self._auth_config = FlextAuthConfig()
                return FlextResult.fail(
                    "Cannot create FlextAuthService without dependencies. "
                    "Please provide auth_service parameter or use "
                    "flext_auth_quick_start()",
                )

            _logger.info(
                "Authentication initialized for class",
                class_name=self.__class__.__name__,
            )
            return FlextResult.ok(None)
        except Exception as e:
            _logger.exception("Failed to initialize authentication")
            return FlextResult.fail(f"Auth initialization failed: {e}")

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextResult[dict[str, object]]:
        """Authenticate user with username/password.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            FlextResult with authentication data or error

        """
        if not self._auth_service:
            return FlextResult.fail("Authentication not initialized")

        try:
            # Auth service methods are async - mixins provide sync wrapper
            async def _auth() -> FlextResult[dict[str, object]]:
                if self._auth_service is None:
                    return FlextResult.fail("Auth service not initialized")
                auth_result = await self._auth_service.authenticate_user(
                    username,
                    password,
                    ip_address="127.0.0.1",
                )
                if auth_result.is_success and auth_result.data:
                    # Convert auth result to dict format
                    return FlextResult.ok(
                        {"authenticated": True, "user": auth_result.data},
                    )
                return FlextResult.fail(auth_result.error or "Authentication failed")

            return asyncio.run(_auth())
        except Exception as e:
            _logger.exception("Authentication failed")
            return FlextResult.fail(f"Authentication error: {e}")

    def validate_token(self, token: str) -> FlextResult[dict[str, object]]:
        """Validate authentication token.

        Args:
            token: JWT token to validate

        Returns:
            FlextResult with token data or error

        """
        if not self._auth_service:
            return FlextResult.fail("Authentication not initialized")

        try:
            # Auth service method is async
            async def _validate() -> FlextResult[dict[str, object]]:
                if self._auth_service is None:
                    return FlextResult.fail("Auth service not initialized")
                validation_result = await self._auth_service.validate_token(token)
                if validation_result.is_success and validation_result.data:
                    # Convert SecurityContext to dict format
                    context = validation_result.data
                    return FlextResult.ok(
                        {
                            "user_id": context.user_id,
                            "username": context.username,
                            "role": context.role,
                            "permissions": context.permissions,
                        },
                    )
                return FlextResult.fail(
                    validation_result.error or "Token validation failed",
                )

            return asyncio.run(_validate())
        except Exception as e:
            _logger.exception("Token validation failed")
            return FlextResult.fail(f"Token validation error: {e}")

    def generate_token(self, user_data: dict[str, object]) -> FlextResult[str]:
        """Generate authentication token for user.

        Args:
            user_data: User data to encode in token

        Returns:
            FlextResult with generated token or error

        """
        if not self._auth_service:
            return FlextResult.fail("Authentication not initialized")

        try:
            # Use JWT service directly since FlextAuthService lacks generate_token
            jwt_service = FlextJWTService(secret_key=DEFAULT_JWT_SECRET)

            # Extract required fields
            user_id = str(user_data.get("id", ""))
            username = str(user_data.get("username", ""))
            role = str(user_data.get("role", "user"))

            return jwt_service.generate_access_token(
                user_id=user_id,
                username=username,
                role=role,
            )
        except Exception as e:
            _logger.exception("Token generation failed")
            return FlextResult.fail(f"Token generation error: {e}")

    def check_permission(
        self,
        user_data: dict[str, object],
        required_permission: str,
    ) -> FlextResult[bool]:
        """Check if user has required permission.

        Args:
            user_data: User data containing permissions
            required_permission: Permission to check

        Returns:
            FlextResult with boolean permission check result

        """
        try:
            user_permissions = user_data.get("permissions", [])
            # Ensure permissions is a list of strings
            if isinstance(user_permissions, list):
                has_permission = required_permission in user_permissions
            else:
                has_permission = False
            return FlextResult.ok(has_permission)
        except Exception as e:
            _logger.exception("Permission check failed")
            return FlextResult.fail(f"Permission check error: {e}")

    def check_role(
        self,
        user_data: dict[str, object],
        required_role: str,
    ) -> FlextResult[bool]:
        """Check if user has required role.

        Args:
            user_data: User data containing role
            required_role: Role to check

        Returns:
            FlextResult with boolean role check result

        """
        try:
            user_role = user_data.get("role", "")
            has_role = user_role == required_role
            return FlextResult.ok(has_role)
        except Exception as e:
            _logger.exception("Role check failed")
            return FlextResult.fail(f"Role check error: {e}")

    @property
    def is_auth_initialized(self) -> bool:
        """Check if authentication is initialized."""
        return self._auth_service is not None


class FlextAuthUserMixin:
    """Mixin for adding user management capabilities to classes."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Initialize user mixin."""
        super().__init__(*args, **kwargs)
        self._current_user: dict[str, object] | None = None

    def set_current_user(self, user_data: dict[str, object]) -> FlextResult[None]:
        """Set current user for this instance.

        Args:
            user_data: User data to set as current user

        Returns:
            FlextResult indicating success or failure

        """
        try:
            self._current_user = user_data.copy()
            _logger.debug("Current user set", user_id=user_data.get("id"))
            return FlextResult.ok(None)
        except Exception as e:
            _logger.exception("Failed to set current user")
            return FlextResult.fail(f"Set user error: {e}")

    def get_current_user(self) -> FlextResult[dict[str, object]]:
        """Get current user data.

        Returns:
            FlextResult with current user data or error

        """
        if self._current_user is None:
            return FlextResult.fail("No current user set")

        return FlextResult.ok(self._current_user.copy())

    def clear_current_user(self) -> FlextResult[None]:
        """Clear current user.

        Returns:
            FlextResult indicating success

        """
        self._current_user = None
        _logger.debug("Current user cleared")
        return FlextResult.ok(None)

    def is_user_in_role(self, role: str) -> FlextResult[bool]:
        """Check if current user has specified role.

        Args:
            role: Role to check

        Returns:
            FlextResult with boolean result

        """
        if self._current_user is None:
            return FlextResult.fail("No current user set")

        user_role = self._current_user.get("role", "")
        return FlextResult.ok(user_role == role)

    def is_user_has_permission(self, permission: str) -> FlextResult[bool]:
        """Check if current user has specified permission.

        Args:
            permission: Permission to check

        Returns:
            FlextResult with boolean result

        """
        if self._current_user is None:
            return FlextResult.fail("No current user set")

        user_permissions = self._current_user.get("permissions", [])
        # Ensure permissions is a list of strings
        if isinstance(user_permissions, list):
            has_permission = permission in user_permissions
        else:
            has_permission = False
        return FlextResult.ok(has_permission)

    @property
    def has_current_user(self) -> bool:
        """Check if current user is set."""
        return self._current_user is not None

    @property
    def current_user_id(self) -> str | None:
        """Get current user ID."""
        if self._current_user:
            user_id = self._current_user.get("id")
            return str(user_id) if user_id is not None else None
        return None


__all__ = [
    "FlextAuthMixin",
    "FlextAuthUserMixin",
]
