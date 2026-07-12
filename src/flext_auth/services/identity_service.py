"""FLEXT Auth identity service."""

from __future__ import annotations

from typing import override

from flext_api import r

from flext_auth import c, m, p, s, t
from flext_auth._utilities.identity_audit import FlextAuthIdentityAudit
from flext_auth._utilities.managers import FlextAuthUtilitiesManagers


class FlextAuthIdentityService(s, FlextAuthIdentityAudit):
    """Identity service using flext-core patterns and railway-oriented programming."""

    def __init__(
        self,
        *,
        dispatcher: p.Dispatcher,
        managers: FlextAuthUtilitiesManagers.ServiceManagers | None = None,
    ) -> None:
        """Initialize with dependency injection."""
        super().__init__()
        self._managers = (
            managers
            if managers is not None
            else FlextAuthUtilitiesManagers.ServiceManagers(dispatcher)
        )

    @property
    @override
    def identity_manager(self) -> FlextAuthUtilitiesManagers.FlextAuthUserManager:
        """Direct access to identity manager for client orchestration."""
        return self._managers.user_manager

    def authenticate_identity(
        self,
        name: str,
        credential: str,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Railway-oriented identity authentication with account lockout."""
        identity_result = self.identity_manager.get_user_by_username(name)
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
    ) -> p.Result[bool]:
        """Railway-oriented credential change with validation."""
        result: p.Result[bool]
        identity_result = self.identity_manager.get_user(identity_id)
        if identity_result.failure:
            result = r[bool].fail(identity_result.error)
        else:
            identity = identity_result.value
            verify_result = identity.verify_credential(current_credential)
            if verify_result.failure:
                result = r[bool].fail(verify_result.error)
            elif not verify_result.value:
                result = r[bool].fail("Current credential is incorrect")
            elif len(new_credential) < c.Auth.CREDENTIAL_MIN_LENGTH:
                result = r[bool].fail(
                    f"New credential must be at least {c.Auth.CREDENTIAL_MIN_LENGTH} characters long",
                )
            else:
                set_result = identity.update_credential(new_credential)
                if set_result.failure:
                    result = r[bool].fail(set_result.error)
                else:
                    result = r[bool].ok(
                        self._log_success("Password change successful", identity.name),
                    )
        return result

    def create_identity(
        self,
        name: str,
        contact: str,
        credential: str,
        roles: t.StrSequence | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
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
        except c.ValidationError as exc:
            error_messages: t.StrSequence = [
                f"{error.get('loc', ('unknown',))[0] if error.get('loc') else 'unknown'}: {error.get('msg', 'Validation error')}"
                for error in exc.errors()
            ]
            error_msg = "; ".join(error_messages) if error_messages else str(exc)
            return r[m.Auth.AuthIdentity].fail(error_msg)
        except c.EXC_BROAD_IO_TYPE as exc:
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
    def execute(self) -> p.Result[p.Base]:
        """Railway-oriented execute with focused service pattern."""
        return r[p.Base].fail(
            "Use specific identity methods: create_identity, authenticate_identity, etc.",
        )

    def reset_credential(self, identity_id: str, new_credential: str) -> p.Result[bool]:
        """Railway-oriented credential reset for REDACTED_LDAP_BIND_PASSWORD operations."""
        identity_result = self.identity_manager.get_user(identity_id)
        if identity_result.failure:
            return r[bool].fail(identity_result.error)
        identity = identity_result.value
        if len(new_credential) < c.Auth.CREDENTIAL_MIN_LENGTH:
            return r[bool].fail(
                f"New credential must be at least {c.Auth.CREDENTIAL_MIN_LENGTH} characters long",
            )
        set_result = identity.update_credential(new_credential)
        if set_result.failure:
            return r[bool].fail(set_result.error)
        return r[bool].ok(
            self._log_success("Password reset successful", identity.name),
        )


__all__: t.MutableSequenceOf[str] = [
    "FlextAuthIdentityService",
]
