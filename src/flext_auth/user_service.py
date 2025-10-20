"""FLEXT Auth Identity Service - Generic identity management with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuthIdentityService class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDispatcher, FlextResult, FlextService

from flext_auth.config import FlextAuthConfig
from flext_auth.managers import (
    FlextAuthManagers,
    ServiceManagerMixin,
)
from flext_auth.models import FlextAuthModels
from flext_auth.utilities import FlextAuthUtilities


class FlextAuthIdentityService(ServiceManagerMixin, FlextService[object]):
    """Generic identity service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    SOLID principles with dependency injection and railway error handling.
    """

    def __init__(self, config: FlextAuthConfig, dispatcher: FlextDispatcher) -> None:
        """Generic initialization with dependency injection."""
        super().__init__()
        self._init_managers(config, dispatcher)

    @property
    def identity_manager(self) -> FlextAuthManagers.FlextAuthUserManager:
        """Direct access to identity manager for client orchestration."""
        return self._user_manager

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
            self._user_manager.get_user_by_username(name)
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
        return FlextAuthUtilities.hash_credential(credential).flat_map(
            lambda ch: self._user_manager.create_user(
                username=name,
                email=contact,
                password_hash=ch,
                roles=roles or [],
                **extra_fields,
            )
        )

    # =========================================================================
    # COMPLEX CREDENTIAL OPERATIONS (Non-Thin Wrappers)
    # =========================================================================

    def change_credential(
        self,
        identity_id: str,
        current_credential: str,
        new_credential: str,
    ) -> FlextResult[None]:
        """Railway-oriented credential change with validation."""
        return (
            self._user_manager.get_user(identity_id)
            .flat_map(
                lambda identity: (
                    FlextResult.ok(identity)
                    if identity.verify_credential(current_credential).value
                    else FlextResult.fail("Current credential is incorrect")
                )
            )
            .flat_map(
                lambda identity: FlextAuthUtilities.validate_credential_strength(
                    new_credential
                ).map(lambda r: identity if r.get("is_valid") else None)
            )
            .map(
                lambda identity: (
                    identity.set_credential(new_credential),
                    self._audit_logger.log_password_change_success(
                        identity.name if identity else ""
                    ),
                )[0]
                if identity
                else None
            )
            .map(lambda _: None)
        )

    def reset_credential(
        self, identity_id: str, new_credential: str
    ) -> FlextResult[None]:
        """Railway-oriented credential reset for REDACTED_LDAP_BIND_PASSWORD operations."""
        return (
            self._user_manager.get_user(identity_id)
            .flat_map(
                lambda identity: FlextAuthUtilities.validate_credential_strength(
                    new_credential
                ).map(lambda r: identity if r.get("is_valid") else None)
            )
            .map(
                lambda identity: (
                    identity.set_credential(new_credential),
                    self._audit_logger.log_password_reset(
                        identity.name if identity else ""
                    ),
                )[0]
                if identity
                else None
            )
            .map(lambda _: None)
        )

    # =========================================================================
    # COMPLEX AUTHORIZATION WITH AUDIT LOGGING
    # =========================================================================

    def authorize_identity(
        self,
        identity_id: str,
        permission: str,
        resource: str | None = None,
    ) -> FlextResult[bool]:
        """Railway-oriented authorization with audit logging."""
        return (
            self._user_manager.get_user(identity_id)
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


__all__ = ["FlextAuthIdentityService"]
