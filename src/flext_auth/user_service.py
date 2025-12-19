"""FLEXT Auth Identity Service - Generic identity management with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuthIdentityService class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flext_core import FlextDispatcher, r, s
from pydantic import ValidationError

from flext_auth.managers import (
    FlextAuthManagers,
    ServiceManagerMixin,
)
from flext_auth.models import FlextAuthModels as m
from flext_auth.settings import FlextAuthSettings
from flext_auth.utilities import u


class FlextAuthIdentityService(ServiceManagerMixin, s[object]):
    """Generic identity service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    SOLID principles with dependency injection and railway error handling.
    """

    def __init__(
        self, *, config: FlextAuthSettings, dispatcher: FlextDispatcher
    ) -> None:
        """Generic initialization with dependency injection."""
        super().__init__()
        self._init_managers(config, dispatcher)

    @property
    def identity_manager(self) -> FlextAuthManagers.FlextAuthUserManager:
        """Direct access to identity manager for client orchestration."""
        return self.user_manager

    @identity_manager.setter
    def identity_manager(self, value: FlextAuthManagers.FlextAuthUserManager) -> None:
        """Set identity manager (for service composition)."""
        self.user_manager = value

    def execute(self, **_kwargs: object) -> r[object]:
        """Railway-oriented execute with focused service pattern."""
        return r[object].fail(
            "Use specific identity methods: create_identity, authenticate_identity, etc.",
        )

    def authenticate_identity(
        self,
        name: str,
        credential: str,
    ) -> r[m.Identity]:
        """Railway-oriented identity authentication with account lockout."""
        return (
            self.user_manager.get_user_by_username(name)
            .flat_map(lambda identity: r.ok((identity, credential)))
            .flat_map(
                lambda ic: (
                    # Check if account is locked
                    r.fail(
                        "Account is locked due to too many failed attempts",
                    )
                    if ic[0].is_locked()
                    else r.ok(ic)
                ),
            )
            .flat_map(
                lambda ic: ic[0]
                .verify_credential(ic[1])
                .flat_map(
                    lambda is_valid: (
                        # Success: reset failed attempts and unlock
                        r.ok(ic[0].with_successful_access())
                        if is_valid
                        # Failure: increment failed attempts and lock if threshold reached
                        else (
                            self._handle_failed_attempt(ic[0]).flat_map(
                                lambda _: r.fail("Invalid credentials"),
                            )
                        )
                    ),
                ),
            )
        )

    def create_identity(
        self,
        name: str,
        contact: str,
        credential: str,
        roles: list[str] | None = None,
        **_extra_fields: object,
    ) -> r[m.Identity]:
        """Railway-oriented identity creation with credential hashing."""
        if roles is None:
            user_roles: list[str] = []
        else:
            user_roles = roles
        # Normalize email to lowercase for consistency
        if not isinstance(contact, str):
            return r[m.Identity].fail("Contact must be a string")
        normalized_contact = contact.lower()

        # Validate using Pydantic model to ensure proper validation errors
        try:
            request = m.IdentityRequest(
                name=name,
                contact=normalized_contact,
                credential=credential,
                roles=user_roles,
            )
        except ValidationError as e:
            # Convert ValidationError to FlextResult with error message
            error_messages = []
            for error in e.errors():
                field = (
                    error.get("loc", ("unknown",))[0] if error.get("loc") else "unknown"
                )
                msg = error.get("msg", "Validation error")
                error_messages.append(f"{field}: {msg}")
            error_msg = "; ".join(error_messages) if error_messages else str(e)
            return r[m.Identity].fail(error_msg)
        except Exception as e:
            return r[m.Identity].fail(str(e))

        # Validate credential strength before hashing
        strength_result = u.validate_credential_strength(credential)
        if strength_result.is_failure:
            return r[m.Identity].fail(
                strength_result.error or "Credential strength validation failed",
            )
        strength_data = strength_result.value
        if not strength_data["is_valid"]:
            errors = strength_data.get("errors", ())
            error_msg = (
                "; ".join(errors)
                if errors
                else "Credential does not meet strength requirements"
            )
            return r[m.Identity].fail(error_msg)

        # Create user with basic fields - extra_fields not currently supported
        # due to type constraints in the manager interface
        return u.hash_credential(credential).flat_map(
            lambda ch: self.user_manager.create_user(
                username=request.name,
                email=request.contact,
                password_hash=ch,
                roles=request.roles,
            ),
        )

    # =========================================================================
    # COMPLEX CREDENTIAL OPERATIONS (Non-Thin Wrappers)
    # =========================================================================

    def change_credential(
        self,
        identity_id: str,
        current_credential: str,
        new_credential: str,
    ) -> r[bool]:
        """Railway-oriented credential change with validation."""
        return (
            self.user_manager.get_user(identity_id)
            .flat_map(
                lambda identity: identity.verify_credential(
                    current_credential,
                ).flat_map(
                    lambda is_valid: r.ok(identity)
                    if is_valid
                    else r.fail("Current credential is incorrect"),
                ),
            )
            .flat_map(
                lambda identity: u.validate_credential_strength(
                    new_credential,
                ).flat_map(
                    lambda validation_result: r.ok(identity)
                    if validation_result["is_valid"]
                    else r.fail(
                        "New credential does not meet strength requirements",
                    ),
                ),
            )
            .flat_map(
                lambda identity: identity.set_credential(new_credential).map(
                    lambda _: (
                        self.audit_logger.log_password_change_success(identity.name),
                        True,
                    )[1],
                ),
            )
        )

    def reset_credential(self, identity_id: str, new_credential: str) -> r[bool]:
        """Railway-oriented credential reset for REDACTED_LDAP_BIND_PASSWORD operations."""
        return (
            self.user_manager.get_user(identity_id)
            .flat_map(
                lambda identity: u.validate_credential_strength(
                    new_credential,
                ).flat_map(
                    lambda validation_result: r.ok(identity)
                    if validation_result["is_valid"]
                    else r.fail(
                        "New credential does not meet strength requirements",
                    ),
                ),
            )
            .flat_map(
                lambda identity: identity.set_credential(new_credential).map(
                    lambda _: (
                        self.audit_logger.log_password_reset(identity.name),
                        True,
                    )[1],
                ),
            )
        )

    # =========================================================================
    # ACCOUNT LOCKOUT HANDLING
    # =========================================================================

    def _handle_failed_attempt(self, identity: m.Identity) -> r[bool]:
        """Handle failed authentication attempt with lockout logic."""
        identity.failed_attempts += 1
        max_attempts = self._config.max_attempts

        if identity.failed_attempts >= max_attempts:
            lockout_duration = timedelta(minutes=self._config.lockout_duration_minutes)
            identity.locked_until = datetime.now(UTC) + lockout_duration
            self.audit_logger.log_auth_failure(
                username=identity.name,
                provider="internal",
                reason=f"Account locked after {identity.failed_attempts} failed attempts",
            )
        else:
            self.audit_logger.log_auth_failure(
                username=identity.name,
                provider="internal",
                reason=f"Invalid credentials ({identity.failed_attempts}/{max_attempts} attempts)",
            )

        # Update user in storage
        return self.user_manager.update_user(
            identity.unique_id,
            failed_attempts=identity.failed_attempts,
            locked_until=identity.locked_until,
        ).map(lambda _: True)

    # =========================================================================
    # COMPLEX AUTHORIZATION WITH AUDIT LOGGING
    # =========================================================================

    def authorize_identity(
        self,
        identity_id: str,
        permission: str,
        resource: str | None = None,
    ) -> r[bool]:
        """Railway-oriented authorization with audit logging."""
        return (
            self.user_manager.get_user(identity_id)
            .map(lambda identity: (identity, permission in identity.permissions))
            .map(
                lambda ip: (
                    self.audit_logger.log_authorization_check(
                        username=ip[0].name,
                        resource=resource if resource is not None else "",
                        action=permission,
                        allowed=ip[1],
                    ),
                    ip[1],
                )[1],
            )
        )


__all__ = ["FlextAuthIdentityService"]
