"""Authentication identity protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_auth import p, t

if TYPE_CHECKING:
    from datetime import datetime


class FlextAuthProtocolsAuthIdentity:
    @runtime_checkable
    class Identity(p.Service[bool], Protocol):
        """Protocol for identity/user-like objects in authentication.

        Structural typing interface for identity objects. Models implement
        this protocol through attribute matching (structural typing).
        """

        id: str
        "Unique identity identifier."
        name: str
        "Identity name/username."
        contact: str
        "Contact information (e.g., email)."
        is_active: bool
        "Active status."
        roles: t.StrSequence
        "Identity roles."
        failed_attempts: int
        "Failed login attempts count."
        locked_until: t.Auth.DateTimeValue
        "Lock expiration time (datetime.min means not locked)."

        @property
        def email(self) -> str:
            """Alias for contact property (backward compatibility)."""
            ...

        @property
        def username(self) -> str:
            """Alias for name property (backward compatibility)."""
            ...

        def locked(self) -> bool:
            """Check if identity is locked."""
            ...

        def update_credential(self, credential: str) -> p.Result[bool]:
            """Set credential with secure hashing."""
            ...

        def verify_credential(
            self,
            credential: str,
        ) -> p.Result[bool]:
            """Verify credential against stored hash."""
            ...

    @runtime_checkable
    class User(Identity, Protocol):
        """Protocol for user-like objects in authentication.

        Extends Identity with user-specific methods. Maintains
        backward compatibility with existing User interface.
        """

        @property
        def can_login(self) -> bool:
            """Whether user can attempt login."""
            ...

        def record_failed_login(self) -> None:
            """Record failed login attempt and apply lockout if needed."""
            ...

        def record_successful_login(self) -> None:
            """Record successful login and reset failed attempts."""
            ...

    @runtime_checkable
    class IdentityManager(Protocol):
        """Protocol for identity manager mutation used by identity services."""

        def update_user(
            self,
            user_id: str,
            **updates: t.Scalar | t.StrSequence | datetime | None,
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]:
            """Update an identity and return the resulting identity."""
            ...


__all__: list[str] = ["FlextAuthProtocolsAuthIdentity"]
