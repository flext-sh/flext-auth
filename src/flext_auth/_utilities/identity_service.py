"""FLEXT Auth Identity Service - Generic identity management with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuthIdentityService class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import override

from pydantic import ValidationError

from flext_auth import (
    FlextAuthSettings,
    FlextAuthUtilitiesManagers,
    c,
    m,
    p,
    s,
    t,
)
from flext_core import r


class FlextAuthIdentityService(s[bool]):
    """Generic identity service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    SOLID principles with dependency injection and railway error handling.
    """

    def __init__(self, *, config: FlextAuthSettings, dispatcher: p.Dispatcher) -> None:
        """Generic initialization with dependency injection."""
        super().__init__()
        self._managers = FlextAuthUtilitiesManagers.ServiceManagers(config, dispatcher)

    @property
    def identity_manager(self) -> FlextAuthUtilitiesManagers.FlextAuthUserManager:
        """Direct access to identity manager for client orchestration."""
        return self._managers.user_manager

    def authenticate_identity(
        self,
        name: str,
        credential: str,
    ) -> r[m.Auth.AuthIdentity]:
        """Railway-oriented identity authentication with account lockout."""
        identity_result = self.identity_manager.get_user_by_username(name)
        if identity_result.is_failure:
            return r[m.Auth.AuthIdentity].fail(identity_result.error)
        identity = identity_result.value
        if identity.is_locked():
            return r[m.Auth.AuthIdentity].fail(
                "Account is locked due to too many failed attempts",
            )
        verification_result = identity.verify_credential(credential)
        if verification_result.is_failure:
            return r[m.Auth.AuthIdentity].fail(verification_result.error)
        if verification_result.value:
            return r[m.Auth.AuthIdentity].ok(identity.with_successful_access())
        failed_attempt_result = self._handle_failed_attempt(identity)
        if failed_attempt_result.is_failure:
            return r[m.Auth.AuthIdentity].fail(failed_attempt_result.error)
        return r[m.Auth.AuthIdentity].fail("Invalid credentials")

    def authorize_identity(
        self,
        identity_id: str,
        permission: str,
        resource: str | None = None,
    ) -> r[bool]:
        """Railway-oriented authorization with audit logging."""
        return (
            self.identity_manager
            .get_user(identity_id)
            .map(lambda identity: (identity, permission in identity.permissions))
            .map(
                lambda ip: self._log_authorization_result(
                    ip[0],
                    permission,
                    resource,
                    allowed=ip[1],
                ),
            )
        )

    def change_credential(
        self,
        identity_id: str,
        current_credential: str,
        new_credential: str,
    ) -> r[bool]:
        """Railway-oriented credential change with validation."""
        identity_result = self.identity_manager.get_user(identity_id)
        if identity_result.is_failure:
            return r[bool].fail(identity_result.error)
        identity = identity_result.value
        verify_result = identity.verify_credential(current_credential)
        if verify_result.is_failure:
            return r[bool].fail(verify_result.error)
        if not verify_result.value:
            return r[bool].fail("Current credential is incorrect")
        if len(new_credential) < c.Auth.CREDENTIAL_MIN_LENGTH:
            return r[bool].fail(
                f"New credential must be at least {c.Auth.CREDENTIAL_MIN_LENGTH} characters long",
            )
        set_result = identity.set_credential(new_credential)
        return set_result.fold(
            on_failure=lambda exc: r[bool].fail(exc),
            on_success=lambda _: r[bool].ok(
                self._log_success("Password change successful", identity.name),
            ),
        )

    def create_identity(
        self,
        name: str,
        contact: str,
        credential: str,
        roles: t.StrSequence | None = None,
    ) -> r[m.Auth.AuthIdentity]:
        """Railway-oriented identity creation with credential hashing."""
        if roles is None:
            user_roles: t.StrSequence = []
        else:
            user_roles = roles
        normalized_contact = contact.lower()
        try:
            request = m.Auth.AuthIdentityRequest(
                name=name,
                contact=normalized_contact,
                credential=credential,
                roles=user_roles,
            )
        except ValidationError as exc:
            error_messages: t.StrSequence = [
                f"{error.get('loc', ('unknown',))[0] if error.get('loc') else 'unknown'}: {error.get('msg', 'Validation error')}"
                for error in exc.errors()
            ]
            error_msg = "; ".join(error_messages) if error_messages else str(exc)
            return r[m.Auth.AuthIdentity].fail(error_msg)
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as exc:
            return r[m.Auth.AuthIdentity].fail(str(exc))
        if len(credential) < c.Auth.CREDENTIAL_MIN_LENGTH:
            return r[m.Auth.AuthIdentity].fail(
                f"Credential must be at least {c.Auth.CREDENTIAL_MIN_LENGTH} characters long",
            )
        return (
            r[str]
            .ok(m.Auth.PasswordUtil.hash_password(credential))
            .flat_map(
                lambda ch: self.identity_manager.create_user(
                    username=request.name,
                    email=request.contact,
                    password_hash=ch,
                    roles=request.roles,
                ),
            )
        )

    @override
    def execute(self) -> r[bool]:
        """Railway-oriented execute with focused service pattern."""
        return r[bool].fail(
            "Use specific identity methods: create_identity, authenticate_identity, etc.",
        )

    def reset_credential(self, identity_id: str, new_credential: str) -> r[bool]:
        """Railway-oriented credential reset for REDACTED_LDAP_BIND_PASSWORD operations."""
        identity_result = self.identity_manager.get_user(identity_id)
        if identity_result.is_failure:
            return r[bool].fail(identity_result.error)
        identity = identity_result.value
        if len(new_credential) < c.Auth.CREDENTIAL_MIN_LENGTH:
            return r[bool].fail(
                f"New credential must be at least {c.Auth.CREDENTIAL_MIN_LENGTH} characters long",
            )
        set_result = identity.set_credential(new_credential)
        return set_result.fold(
            on_failure=lambda exc: r[bool].fail(exc),
            on_success=lambda _: r[bool].ok(
                self._log_success("Password reset successful", identity.name),
            ),
        )

    def _handle_failed_attempt(self, identity: m.Auth.AuthIdentity) -> r[bool]:
        """Handle failed authentication attempt with lockout logic."""
        identity.failed_attempts += 1
        max_attempts = c.Auth.AuthSecurity.MAX_LOGIN_ATTEMPTS
        if identity.failed_attempts >= max_attempts:
            lockout_duration = timedelta(
                minutes=c.Auth.AuthSecurity.LOCKOUT_DURATION_MINUTES,
            )
            identity.locked_until = datetime.now(UTC) + lockout_duration
            self.logger.warning(
                "Authentication failure",
                username=identity.name,
                provider="internal",
                reason=f"Account locked after {identity.failed_attempts} failed attempts",
            )
        else:
            self.logger.warning(
                "Authentication failure",
                username=identity.name,
                provider="internal",
                reason=f"Invalid credentials ({identity.failed_attempts}/{max_attempts} attempts)",
            )
        return self.identity_manager.update_user(
            identity.unique_id,
            failed_attempts=identity.failed_attempts,
            locked_until=identity.locked_until,
        ).map(lambda _: True)

    def _log_authorization_result(
        self,
        identity: m.Auth.AuthIdentity,
        permission: str,
        resource: str | None,
        *,
        allowed: bool,
    ) -> bool:
        """Log authorization result and return decision."""
        self.logger.debug(
            "Authorization check",
            username=identity.name,
            resource=resource if resource is not None else "",
            action=permission,
            allowed=allowed,
        )
        return allowed

    def _log_success(self, message: str, identity_name: str) -> bool:
        """Log service success message and return truthy sentinel."""
        self.logger.info(message, identity=identity_name)
        return True


__all__ = ["FlextAuthIdentityService"]
