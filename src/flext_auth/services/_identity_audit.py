"""Identity service audit and lockout helpers."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Protocol

from flext_auth import c, m, p, t, u


class _IdentityManager(Protocol):
    def update_user(
        self,
        user_id: str,
        **updates: t.Scalar | t.StrSequence | datetime | None,
    ) -> p.Result[m.Auth.AuthIdentity]: ...


class FlextAuthIdentityAudit:
    if TYPE_CHECKING:

        @property
        def logger(self) -> p.Logger:
            """Logger supplied by the service facade."""
            raise NotImplementedError

        @property
        def identity_manager(self) -> _IdentityManager:
            """Identity manager supplied by the concrete service facade."""
            raise NotImplementedError

    def _handle_failed_attempt(self, identity: m.Auth.AuthIdentity) -> p.Result[bool]:
        """Handle failed authentication attempt with lockout logic."""
        identity.failed_attempts += 1
        max_attempts = c.Auth.SECURITY_MAX_LOGIN_ATTEMPTS
        if identity.failed_attempts >= max_attempts:
            lockout_duration = timedelta(
                minutes=c.Auth.SECURITY_LOCKOUT_DURATION_MINUTES,
            )
            identity.locked_until = u.generate_datetime_utc() + lockout_duration
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


__all__: t.MutableSequenceOf[str] = ["FlextAuthIdentityAudit"]
