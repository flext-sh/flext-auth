"""FLEXT Auth identity service.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import timedelta

from flext_auth import c, m, p, r, s, t, u


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

        Args:
            identity: Identity whose failed attempt to record.

        Returns:
            Success once the attempt state is persisted.

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

        Args:
            name: Account name to authenticate.
            credential: Plain credential for the account.

        Returns:
            The authenticated identity; failure when the account is
            unknown, locked, or the credential does not match.

        """
        identity_result = self.identity_manager.fetch_user_by_username(name)
        if identity_result.failure:
            return r[m.Auth.AuthIdentity].from_failure(identity_result)
        identity = identity_result.value
        if identity.locked():
            return r[m.Auth.AuthIdentity].fail(
                "Account is locked due to too many failed attempts",
            )
        verification_result = identity.verify_credential(credential)
        if verification_result.failure:
            return r[m.Auth.AuthIdentity].from_failure(verification_result)
        if verification_result.value:
            identity.with_successful_access()
            return self.identity_manager.update_user(
                identity.unique_id,
                last_access=identity.last_access,
                failed_attempts=identity.failed_attempts,
                locked_until=identity.locked_until,
            )
        failed_attempt_result = self._handle_failed_attempt(identity)
        if failed_attempt_result.failure:
            return r[m.Auth.AuthIdentity].from_failure(failed_attempt_result)
        return r[m.Auth.AuthIdentity].fail("Invalid credentials")

    def authorize_identity(
        self,
        identity_id: str,
        permission: str,
        resource: str | None = None,
    ) -> p.Result[bool]:
        """Railway-oriented authorization with audit logging.

        Args:
            identity_id: Identity whose permissions to check.
            permission: Permission name required for the action.
            resource: Optional resource the action targets.

        Returns:
            Whether the identity holds the permission; failure when the
            identity cannot be fetched.

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

        Args:
            identity: Identity being authorized.
            permission: Permission name required for the action.
            resource: Optional resource the action targets.

        Returns:
            Whether the identity holds the permission.

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

        Args:
            identity_id: Identity whose credential changes.
            current_credential: Current plain credential to verify first.
            new_credential: Replacement credential, at least the configured
                minimum length.

        Returns:
            Success once the new credential hash is stored; failure when
            the identity is unknown, the current credential is wrong, or
            the replacement is too short.

        """
        identity_result = self.identity_manager.fetch_user(identity_id)
        if identity_result.failure:
            return r[bool].from_failure(identity_result)
        identity = identity_result.value
        verify_result = identity.verify_credential(current_credential)
        if verify_result.failure:
            return verify_result
        if not verify_result.value:
            return r[bool].fail("Current credential is incorrect")
        result = self._persist_credential(identity, new_credential)
        if result.success:
            self.logger.info("Password change successful", identity=identity.name)
        return result

    def create_identity(
        self,
        name: str,
        contact: str,
        credential: str,
        roles: t.StrSequence | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Railway-oriented identity creation with credential hashing.

        Args:
            name: Unique account name for the new identity.
            contact: Contact address, normalized to lowercase.
            credential: Plain credential to validate and hash.
            roles: Optional role names; defaults to no extra roles.

        Returns:
            The created identity entity; failure on validation errors or
            when the credential is below the minimum length.

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

        Args:
            identity_id: Identity whose credential is reset.
            new_credential: Replacement credential, at least the configured
                minimum length.

        Returns:
            Success once the new credential hash is stored; failure when
            the identity is unknown or the credential is too short.

        """
        identity_result = self.identity_manager.fetch_user(identity_id)
        if identity_result.failure:
            return r[bool].from_failure(identity_result)
        identity = identity_result.value
        result = self._persist_credential(identity, new_credential)
        if result.success:
            self.logger.info("Password reset successful", identity=identity.name)
        return result

    def _persist_credential(
        self,
        identity: m.Auth.AuthIdentity,
        credential: str,
    ) -> p.Result[bool]:
        """Validate, hash and persist a replacement through the existing manager.

        Returns:
            Success after storage; the original hashing or storage failure otherwise.

        """
        min_length = c.Auth.CREDENTIAL_MIN_LENGTH
        if len(credential) < min_length:
            return r[bool].fail(
                f"New credential must be at least {min_length} characters long",
            )
        return identity.update_credential(credential).flat_map(
            lambda _: self.identity_manager.update_user(
                identity.unique_id,
                credential_hash=identity.credential_hash,
            ).map(lambda _: True),
        )


__all__: t.MutableSequenceOf[str] = ["FlextAuthIdentityService"]
