"""FLEXT Auth Identity Service - Generic identity management with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuthIdentityService class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import override

from flext_core import FlextService as s, p, r
from pydantic import ValidationError

from flext_auth import FlextAuthManagers, FlextAuthSettings, ServiceManagers, c, m


class FlextAuthIdentityService(s[bool]):
    """Generic identity service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    SOLID principles with dependency injection and railway error handling.
    """

    def __init__(self, *, config: FlextAuthSettings, dispatcher: p.CommandBus) -> None:
        """Generic initialization with dependency injection."""
        super().__init__()
        self._managers = ServiceManagers(config, dispatcher)

    @property
    def identity_manager(self) -> FlextAuthManagers.FlextAuthUserManager:
        """Direct access to identity manager for client orchestration."""
        return self._managers.user_manager

    def authenticate_identity(
        self, name: str, credential: str
    ) -> r[m.Auth.AuthIdentity]:
        """Railway-oriented identity authentication with account lockout."""
        return (
            self.identity_manager
            .get_user_by_username(name)
            .flat_map(lambda identity: r.ok((identity, credential)))
            .flat_map(
                lambda ic: (
                    r.fail("Account is locked due to too many failed attempts")
                    if ic[0].is_locked()
                    else r.ok(ic)
                )
            )
            .flat_map(
                lambda ic: (
                    ic[0]
                    .verify_credential(ic[1])
                    .flat_map(
                        lambda is_valid: (
                            r.ok(ic[0].with_successful_access())
                            if is_valid
                            else self._handle_failed_attempt(ic[0]).flat_map(
                                lambda _: r.fail("Invalid credentials")
                            )
                        )
                    )
                )
            )
        )

    def authorize_identity(
        self, identity_id: str, permission: str, resource: str | None = None
    ) -> r[bool]:
        """Railway-oriented authorization with audit logging."""
        return (
            self.identity_manager
            .get_user(identity_id)
            .map(lambda identity: (identity, permission in identity.permissions))
            .map(
                lambda ip: self._log_authorization_result(
                    ip[0], permission, resource, allowed=ip[1]
                )
            )
        )

    def change_credential(
        self, identity_id: str, current_credential: str, new_credential: str
    ) -> r[bool]:
        """Railway-oriented credential change with validation."""
        return (
            self.identity_manager
            .get_user(identity_id)
            .flat_map(
                lambda identity: identity.verify_credential(
                    current_credential
                ).flat_map(
                    lambda is_valid: (
                        r.ok(identity)
                        if is_valid
                        else r.fail("Current credential is incorrect")
                    )
                )
            )
            .flat_map(
                lambda identity: (
                    r.ok(identity)
                    if len(new_credential) >= c.Auth.CREDENTIAL_MIN_LENGTH
                    else r.fail(
                        f"New credential must be at least {c.Auth.CREDENTIAL_MIN_LENGTH} characters long"
                    )
                )
            )
            .flat_map(
                lambda identity: identity.set_credential(new_credential).map(
                    lambda _: self._log_success(
                        "Password change successful", identity.name
                    )
                )
            )
        )

    def create_identity(
        self, name: str, contact: str, credential: str, roles: list[str] | None = None
    ) -> r[m.Auth.AuthIdentity]:
        """Railway-oriented identity creation with credential hashing."""
        if roles is None:
            user_roles: list[str] = []
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
        except ValidationError as e:
            error_messages: list[str] = []
            for error in e.errors():
                field = (
                    error.get("loc", ("unknown",))[0] if error.get("loc") else "unknown"
                )
                msg = error.get("msg", "Validation error")
                error_messages.append(f"{field}: {msg}")
            error_msg = "; ".join(error_messages) if error_messages else str(e)
            return r[m.Auth.AuthIdentity].fail(error_msg)
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as e:
            return r[m.Auth.AuthIdentity].fail(str(e))
        if len(credential) < c.Auth.CREDENTIAL_MIN_LENGTH:
            return r[m.Auth.AuthIdentity].fail(
                f"Credential must be at least {c.Auth.CREDENTIAL_MIN_LENGTH} characters long"
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
                )
            )
        )

    @override
    def execute(self) -> r[bool]:
        """Railway-oriented execute with focused service pattern."""
        return r[bool].fail(
            "Use specific identity methods: create_identity, authenticate_identity, etc."
        )

    @identity_manager.setter
    def identity_manager(self, value: FlextAuthManagers.FlextAuthUserManager) -> None:
        """Set identity manager (for service composition)."""
        self._managers.user_manager = value

    def reset_credential(self, identity_id: str, new_credential: str) -> r[bool]:
        """Railway-oriented credential reset for REDACTED_LDAP_BIND_PASSWORD operations."""
        return (
            self.identity_manager
            .get_user(identity_id)
            .flat_map(
                lambda identity: (
                    r.ok(identity)
                    if len(new_credential) >= c.Auth.CREDENTIAL_MIN_LENGTH
                    else r.fail(
                        f"New credential must be at least {c.Auth.CREDENTIAL_MIN_LENGTH} characters long"
                    )
                )
            )
            .flat_map(
                lambda identity: identity.set_credential(new_credential).map(
                    lambda _: self._log_success(
                        "Password reset successful", identity.name
                    )
                )
            )
        )

    def _handle_failed_attempt(self, identity: m.Auth.AuthIdentity) -> r[bool]:
        """Handle failed authentication attempt with lockout logic."""
        identity.failed_attempts += 1
        max_attempts = self._managers.config.max_attempts
        if identity.failed_attempts >= max_attempts:
            lockout_duration = timedelta(
                minutes=self._managers.config.lockout_duration_minutes
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
