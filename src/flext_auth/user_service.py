"""FLEXT Auth User Service - Focused user management operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextCore

from flext_auth.config import FlextAuthConfig
from flext_auth.managers import FlextAuthManagers
from flext_auth.models import FlextAuthModels
from flext_auth.utilities import FlextAuthUtilities


class FlextAuthUserService(FlextCore.Service):
    """Focused service for user management operations with complete flext-core integration."""

    def __init__(
        self, config: FlextAuthConfig, dispatcher: FlextCore.Dispatcher
    ) -> None:
        """Initialize user service with flext-core integration."""
        super().__init__()
        self._config = config
        self._dispatcher = dispatcher
        self._user_manager = FlextAuthManagers.FlextAuthUserManager(config)
        self._audit_logger = FlextAuthManagers.FlextAuthAuditLogger(config, dispatcher)
        self._utils = FlextAuthUtilities()

    def execute(self) -> FlextCore.Result[object]:
        """Execute method for FlextCore.Service interface.

        User service doesn't use generic execute pattern.
        Use specific user management methods instead.
        """
        return FlextCore.Result[object].fail(
            "FlextAuthUserService is focused - use specific user methods like create_user()"
        )

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextCore.Result[FlextAuthModels.User]:
        """Authenticate a user with username and password.

        Args:
            username: User's username
            password: User's password

        Returns:
            FlextCore.Result containing authenticated User or error

        """
        # Get user by username
        user_result = self.get_user_by_username(username)
        if user_result.is_failure:
            return FlextCore.Result[FlextAuthModels.User].fail("Invalid credentials")

        user = user_result.value

        # Verify password
        verify_result = FlextAuthUtilities.PasswordProcessing.verify_password(
            password, user.password_hash
        )

        if not verify_result:
            return FlextCore.Result[FlextAuthModels.User].fail("Invalid credentials")

        # Update last login
        user.record_successful_login()

        return FlextCore.Result[FlextAuthModels.User].ok(user)

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: FlextCore.Types.StringList | None = None,
        **extra_fields: object,
    ) -> FlextCore.Result[FlextAuthModels.User]:
        """Create a new user account with password hashing."""
        # Hash password using flext-auth utilities
        hash_result = FlextAuthUtilities.PasswordProcessing.hash_password(password)
        if hash_result.is_failure:
            return FlextCore.Result[FlextAuthModels.User].fail(hash_result.error)

        # Prepare extra fields
        user_extra_fields = dict[str, object](extra_fields)
        if roles is not None:
            user_extra_fields["roles"] = roles

        return self._user_manager.create_user(
            username=username,
            email=email,
            password_hash=hash_result.value,
            **user_extra_fields,
        )

    def get_user(self, user_id: str) -> FlextCore.Result[FlextAuthModels.User]:
        """Get user by ID."""
        return self._user_manager.get_user(user_id)

    def get_user_by_username(
        self, username: str
    ) -> FlextCore.Result[FlextAuthModels.User]:
        """Get user by username."""
        return self._user_manager.get_user_by_username(username)

    def update_user(
        self,
        user_id: str,
        **updates: object,
    ) -> FlextCore.Result[FlextAuthModels.User]:
        """Update user information."""
        return self._user_manager.update_user(user_id, **updates)

    def delete_user(self, user_id: str) -> FlextCore.Result[None]:
        """Delete a user account."""
        return self._user_manager.delete_user(user_id)

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> FlextCore.Result[None]:
        """Change a user's password with validation."""
        # Get user
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return FlextCore.Result[None].fail(user_result.error)

        user = user_result.value

        # Verify current password
        verify_result = user.verify_password(current_password)
        if verify_result.is_failure or not verify_result.value:
            self._audit_logger.log_password_change_failure(
                username=user.username,
                reason="invalid_current_password",
            )
            return FlextCore.Result[None].fail("Current password is incorrect")

        # Validate new password
        validation_result = FlextAuthUtilities.PasswordProcessing.validate_password(
            new_password
        )
        if validation_result.is_failure:
            return FlextCore.Result[None].fail(validation_result.error)

        # Set new password
        set_result = user.set_password(new_password)
        if set_result.is_failure:
            return FlextCore.Result[None].fail(set_result.error)

        # Log success
        self._audit_logger.log_password_change_success(user.username)
        return FlextCore.Result.ok(None)

    def reset_password(self, user_id: str, new_password: str) -> FlextCore.Result[None]:
        """Reset a user's password (REDACTED_LDAP_BIND_PASSWORD operation)."""
        # Get user
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return FlextCore.Result[None].fail(user_result.error)

        user = user_result.value

        # Validate new password
        validation_result = FlextAuthUtilities.PasswordProcessing.validate_password(
            new_password
        )
        if validation_result.is_failure:
            return FlextCore.Result[None].fail(validation_result.error)

        # Set new password
        set_result = user.set_password(new_password)
        if set_result.is_failure:
            return FlextCore.Result[None].fail(set_result.error)

        # Log reset
        self._audit_logger.log_password_reset(user.username)
        return FlextCore.Result.ok(None)

    def authorize_user(
        self,
        user_id: str,
        permission: str,
        resource: str | None = None,
    ) -> FlextCore.Result[bool]:
        """Check if a user has a specific permission."""
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return FlextCore.Result[bool].fail(user_result.error)

        user = user_result.value
        has_permission = permission in user.permissions

        # Log authorization check
        self._audit_logger.log_authorization_check(
            username=user.username,
            resource=resource or "",
            action=permission,
            allowed=has_permission,
        )

        return FlextCore.Result[bool].ok(has_permission)

    def get_user_permissions(
        self, user_id: str
    ) -> FlextCore.Result[FlextCore.Types.StringList]:
        """Get all permissions for a user."""
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return FlextCore.Result[FlextCore.Types.StringList].fail(user_result.error)

        return FlextCore.Result[FlextCore.Types.StringList].ok(
            user_result.value.permissions
        )

    def get_user_roles(
        self, user_id: str
    ) -> FlextCore.Result[FlextCore.Types.StringList]:
        """Get all roles for a user."""
        user_result = self._user_manager.get_user(user_id)
        if user_result.is_failure:
            return FlextCore.Result[FlextCore.Types.StringList].fail(user_result.error)

        return FlextCore.Result[FlextCore.Types.StringList].ok(user_result.value.roles)

    def add_user_role(self, user_id: str, role: str) -> FlextCore.Result[None]:
        """Add a role to a user."""
        return self._user_manager.add_user_role(user_id, role)

    def remove_user_role(self, user_id: str, role: str) -> FlextCore.Result[None]:
        """Remove a role from a user."""
        return self._user_manager.remove_user_role(user_id, role)

    def add_user_permission(
        self, user_id: str, permission: str
    ) -> FlextCore.Result[None]:
        """Add a permission to a user."""
        return self._user_manager.add_user_permission(user_id, permission)

    def remove_user_permission(
        self, user_id: str, permission: str
    ) -> FlextCore.Result[None]:
        """Remove a permission from a user."""
        return self._user_manager.remove_user_permission(user_id, permission)


__all__ = ["FlextAuthUserService"]
