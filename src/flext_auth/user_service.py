"""FLEXT Auth Identity Service - Generic identity management with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuthIdentityService class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDispatcher, FlextResult, FlextService

from flext_auth.config import FlextAuthConfig
from flext_auth.managers import FlextAuthManagers
from flext_auth.models import FlextAuthModels
from flext_auth.utilities import FlextAuthUtilities


class FlextAuthIdentityService(FlextService):
    """Generic identity service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    SOLID principles with dependency injection and railway error handling.
    """

    def __init__(self, config: FlextAuthConfig, dispatcher: FlextDispatcher) -> None:
        """Generic initialization with dependency injection."""
        super().__init__()
        self._config, self._dispatcher = config, dispatcher
        self._identity_manager = FlextAuthManagers.FlextAuthUserManager(config)
        self._audit_logger = FlextAuthManagers.FlextAuthAuditLogger(config, dispatcher)
        self._utils = FlextAuthUtilities()

    def execute(self) -> FlextResult[object]:
        """Railway-oriented execute with focused service pattern."""
        return FlextResult.fail(
            "Use specific identity methods: create_identity, authenticate_identity, etc."
        )

    def authenticate_identity(
        self,
        name: str,
        credential: str,
    ) -> FlextResult[FlextAuthModels.Identity]:
        """Railway-oriented identity authentication."""
        return (
            self.get_identity_by_name(name)
            .flat_map(lambda identity: FlextResult.ok((identity, credential)))
            .flat_map(
                lambda ic: FlextResult.ok(ic[0])
                if ic[0].verify_credential(ic[1]).value
                else FlextResult.fail("Invalid credentials")
            )
            .map(lambda identity: (identity.record_successful_access(), identity)[1])
        )

    def create_identity(
        self,
        name: str,
        contact: str,
        credential: str,
        roles: list[str] | None = None,
        **extra_fields: object,
    ) -> FlextResult[FlextAuthModels.Identity]:
        """Railway-oriented identity creation with credential hashing."""
        return FlextAuthUtilities.PasswordProcessing.hash_password(credential).flat_map(
            lambda ch: self._identity_manager.create_user(
                username=name,
                email=contact,
                password_hash=ch,
                roles=roles or [],
                **extra_fields,
            )
        )

    # =========================================================================
    # CONSOLIDATED IDENTITY OPERATIONS
    # =========================================================================

    def get_identity(self, identity_id: str) -> FlextResult[FlextAuthModels.Identity]:
        """Get identity by ID."""
        return self._identity_manager.get_user(identity_id)

    def get_identity_by_name(self, name: str) -> FlextResult[FlextAuthModels.Identity]:
        """Get identity by name."""
        return self._identity_manager.get_user_by_username(name)

    def update_identity(
        self, identity_id: str, **updates: object
    ) -> FlextResult[FlextAuthModels.Identity]:
        """Update identity information."""
        return self._identity_manager.update_user(identity_id, **updates)

    def delete_identity(self, identity_id: str) -> FlextResult[None]:
        """Delete identity."""
        return self._identity_manager.delete_user(identity_id)

    def change_credential(
        self,
        identity_id: str,
        current_credential: str,
        new_credential: str,
    ) -> FlextResult[None]:
        """Railway-oriented credential change with validation."""
        return (
            self._identity_manager.get_user(identity_id)
            .flat_map(
                lambda identity: (
                    FlextResult.ok(identity)
                    if identity.verify_credential(current_credential).value
                    else FlextResult.fail("Current credential is incorrect")
                )
            )
            .flat_map(
                lambda identity: FlextAuthUtilities.PasswordProcessing.validate_password(
                    new_credential
                ).map(lambda _: identity)
            )
            .map(
                lambda identity: (
                    identity.set_credential(new_credential),
                    self._audit_logger.log_password_change_success(identity.name),
                )[0]
            )
            .map(lambda _: None)
        )

    def reset_credential(
        self, identity_id: str, new_credential: str
    ) -> FlextResult[None]:
        """Railway-oriented credential reset for REDACTED_LDAP_BIND_PASSWORD operations."""
        return (
            self._identity_manager.get_user(identity_id)
            .flat_map(
                lambda identity: FlextAuthUtilities.PasswordProcessing.validate_password(
                    new_credential
                ).map(lambda _: identity)
            )
            .map(
                lambda identity: (
                    identity.set_credential(new_credential),
                    self._audit_logger.log_password_reset(identity.name),
                )[0]
            )
            .map(lambda _: None)
        )

    # =========================================================================
    # GENERIC AUTHORIZATION AND PERMISSION OPERATIONS
    # =========================================================================

    def authorize_identity(
        self,
        identity_id: str,
        permission: str,
        resource: str | None = None,
    ) -> FlextResult[bool]:
        """Railway-oriented authorization with audit logging."""
        return (
            self._identity_manager.get_user(identity_id)
            .map(lambda identity: (identity, permission in identity.permissions))
            .map(
                lambda ip: (
                    self._audit_logger.log_authorization_check(
                        username=ip[0].name,
                        resource=resource or "",
                        action=permission,
                        allowed=ip[1],
                    ),
                    ip[1],
                )[1]
            )
        )

    def get_identity_permissions(self, identity_id: str) -> FlextResult[list[str]]:
        """Get identity permissions with railway pattern."""
        return self._identity_manager.get_user(identity_id).map(
            lambda identity: identity.permissions
        )

    def get_identity_roles(self, identity_id: str) -> FlextResult[list[str]]:
        """Get identity roles with railway pattern."""
        return self._identity_manager.get_user(identity_id).map(
            lambda identity: identity.roles
        )

    # Consolidated role/permission management
    def add_identity_role(self, identity_id: str, role: str) -> FlextResult[None]:
        """Add role to identity."""
        return self._identity_manager.add_user_role(identity_id, role)

    def remove_identity_role(self, identity_id: str, role: str) -> FlextResult[None]:
        """Remove role from identity."""
        return self._identity_manager.remove_user_role(identity_id, role)

    def add_identity_permission(
        self, identity_id: str, permission: str
    ) -> FlextResult[None]:
        """Add permission to identity."""
        return self._identity_manager.add_user_permission(identity_id, permission)

    def remove_identity_permission(
        self, identity_id: str, permission: str
    ) -> FlextResult[None]:
        """Remove permission from identity."""
        return self._identity_manager.remove_user_permission(identity_id, permission)

    def get_identity_by_id(
        self, identity_id: str
    ) -> FlextResult[FlextAuthModels.Identity | None]:
        """Get identity by ID."""
        return self._identity_manager.get_user_by_id(identity_id)


__all__ = ["FlextAuthIdentityService"]
