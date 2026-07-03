"""Authentication identity protocols."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_api import p

from flext_auth import t


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
            """Check if user can attempt login."""
            ...

        def record_failed_login(self) -> None:
            """Record failed login attempt and apply lockout if needed."""
            ...

        def record_successful_login(self) -> None:
            """Record successful login and reset failed attempts."""
            ...


__all__: list[str] = ["FlextAuthProtocolsAuthIdentity"]
