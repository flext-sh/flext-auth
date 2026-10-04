"""FLEXT Auth identity service.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import timedelta

from flext_api import r

from flext_auth import c, m, p, s, t, u


class FlextAuthIdentityService(s):
    """Identity service using flext-core patterns and railway-oriented programming."""

    def __init__(
        self,
        *,
        dispatcher: p.Dispatcher,
        managers: u.Auth.ServiceManagers | None = None,
    ) -> None:
        """Initialize with dependency injection."""
        super().__init__()
        self._managers = (
            managers if managers is not None else u.Auth.ServiceManagers(dispatcher)
        )

    @property
    def identity_manager(self) -> u.Auth.FlextAuthUserManager:
        """Direct access to identity manager for client orchestration."""
        return self._managers.user_manager

    def _handle_failed_attempt(self, identity: m.Auth.AuthIdentity) -> p.Result[bool]:
        """Count the failed attempt, lock after the configured limit, and persist it.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        identity.failed_attempts += 1
        attempts = identity.failed_attempts
        max_attempts = c.Auth.SECURITY_MAX_LOGIN_ATTEMPTS
        locked = attempts >= max_attempts
        if locked:
            identity.locked_until = u.generate_datetime_utc() + timedelta(
                minutes=c.Auth.SECURITY_LOCKOUT_DURATION_MINUTES,
            )
        self.logger.warning(
            "Authentication failure",
            username=identity.name,
            provider="internal",
            reason=f"Account locked after {attempts} failed attempts"
            if locked
            else f"Invalid credentials ({attempts}/{max_attempts} attempts)",
        )
        return self.identity_manager.update_user(
            identity.unique_id,
            failed_attempts=identity.failed_attempts,
            locked_until=identity.locked_until,
        ).map(lambda _: True)

    def authenticate_identity(
        self,
        name: str,
        credential: str,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Railway-oriented identity authentication with account lockout.

        Returns:
            The resulting ``p.Result[m.Auth.AuthIdentity]``.
        """
        identity_result = self.identity_manager.fetch_user_by_username(name)
        if identity_result.failure:
            return r[m.Auth.AuthIdentity].fail(identity_result.error)
        identity = identity_result.value
        if identity.locked():
            return r[m.Auth.AuthIdentity].fail(
                "Account is locked due to too many failed attempts",
            )
        verification_result = identity.verify_credential(credential)
        if verification_result.success and verification_result.value:
            return r[m.Auth.AuthIdentity].ok(identity.with_successful_access())
        if verification_result.failure:
            return r[m.Auth.AuthIdentity].fail(verification_result.error)
        failed_attempt_result = self._handle_failed_attempt(identity)
        error_message = (
            failed_attempt_result.error
            if failed_attempt_result.failure
            else "Invalid credentials"
        )
        return r[m.Auth.AuthIdentity].fail(error_message)

    def authorize_identity(
        self,
        identity_id: str,
        permission: str,
        resource: str | None = None,
    ) -> p.Result[bool]:
        """Railway-oriented authorization with audit logging.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        return self.identity_manager.fetch_user(identity_id).map(
            lambda identity: self._log_authorization(identity, permission, resource),
        )

    def _log_authorization(
        self,
        identity: m.Auth.AuthIdentity,
        permission: str,
        resource: str | None,
    ) -> bool:
        """Log the authorization decision and return it.

        Returns:
            The resulting ``bool``.
        """
        allowed = permission in identity.permissions
        self.logger.debug(
            "Authorization check",
            username=identity.name,
            resource=resource if resource is not None else "",
            action=permission,
            allowed=allowed,
        )
        return allowed

    def change_credential(
        self,
        identity_id: str,
        current_credential: str,
        new_credential: str,
    ) -> p.Result[bool]:
        """Railway-oriented credential change with validation.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        result: p.Result[bool]
        min_length = c.Auth.CREDENTIAL_MIN_LENGTH
        identity_result = self.identity_manager.fetch_user(identity_id)
        if identity_result.failure:
            result = r[bool].fail(identity_result.error)
        else:
            identity = identity_result.value
            verify_result = identity.verify_credential(current_credential)
            if verify_result.failure:
                result = r[bool].fail(verify_result.error)
            elif not verify_result.value:
                result = r[bool].fail("Current credential is incorrect")
            elif len(new_credential) < min_length:
                result = r[bool].fail(
                    f"New credential must be at least {min_length} characters long",
                )
            else:
                set_result = identity.update_credential(new_credential)
                if set_result.failure:
                    result = r[bool].fail(set_result.error)
                else:
                    self.logger.info(
                        "Password change successful",
                        identity=identity.name,
                    )
                    result = r[bool].ok(value=True)
        return result

    def create_identity(
        self,
        name: str,
        contact: str,
        credential: str,
        roles: t.StrSequence | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Railway-oriented identity creation with credential hashing.

        Returns:
            The resulting ``p.Result[m.Auth.AuthIdentity]``.
        """
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
        except c.ValidationError as exc:
            error_messages: t.StrSequence = [
                f"{(error.get('loc') or ('unknown',))[0]}: "
                f"{error.get('msg', 'Validation error')}"
                for error in exc.errors()
            ]
            error_msg = "; ".join(error_messages) if error_messages else str(exc)
            return r[m.Auth.AuthIdentity].fail(error_msg)
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[m.Auth.AuthIdentity].fail(str(exc), exception=exc)
        min_length = c.Auth.CREDENTIAL_MIN_LENGTH
        if len(credential) < min_length:
            return r[m.Auth.AuthIdentity].fail(
                f"Credential must be at least {min_length} characters long",
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

    def reset_credential(self, identity_id: str, new_credential: str) -> p.Result[bool]:
        """Railway-oriented credential reset for admin operations.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        identity_result = self.identity_manager.fetch_user(identity_id)
        if identity_result.failure:
            return r[bool].fail(identity_result.error)
        identity = identity_result.value
        min_length = c.Auth.CREDENTIAL_MIN_LENGTH
        if len(new_credential) < min_length:
            return r[bool].fail(
                f"New credential must be at least {min_length} characters long",
            )
        set_result = identity.update_credential(new_credential)
        if set_result.failure:
            return r[bool].fail(set_result.error)
        self.logger.info("Password reset successful", identity=identity.name)
        return r[bool].ok(value=True)


__all__: t.MutableSequenceOf[str] = ["FlextAuthIdentityService"]
