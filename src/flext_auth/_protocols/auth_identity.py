"""Authentication identity protocols.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import p

if TYPE_CHECKING:
    from datetime import datetime

    from flext_auth import t


class FlextAuthProtocolsAuthIdentity:
    """Protocol namespace for identities and identity managers."""

    @runtime_checkable
    class Identity(p.HasModelDump, Protocol):
        """Protocol for identity/user-like objects in authentication.

        Structural typing interface for identity objects. Models implement
        this protocol through attribute matching (structural typing).
        """

        unique_id: str
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
        locked_until: datetime
        "Lock expiration time (datetime.min means not locked)."
        last_access: datetime
        credential_hash: str
        token: str
        session_id: str
        permissions: t.StrSequence

        def with_successful_access(self) -> FlextAuthProtocolsAuthIdentity.Identity: ...

        def locked(self) -> bool:
            """Check if identity is locked.

            Returns:
                Whether the lockout window is still in effect.

            """
            ...

        def update_credential(self, credential: str) -> p.Result[bool]:
            """Set credential with secure hashing.

            Args:
                credential: Plain credential to hash and store.

            Returns:
                Success once the hash is stored.

            """
            ...

        def verify_credential(self, credential: str) -> p.Result[bool]:
            """Verify credential against stored hash.

            Args:
                credential: Plain credential to check.

            Returns:
                Whether the credential matches the stored hash.

            """
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

        def fetch_user(
            self, user_id: str
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]: ...

        def fetch_user_by_username(
            self, username: str
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]: ...

        def create_user(
            self,
            username: str,
            email: str,
            password_hash: str,
            roles: t.StrSequence | None = None,
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]: ...

        def update_user(
            self,
            user_id: str,
            **updates: t.Scalar | t.StrSequence | datetime | None,
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]:
            """Update an identity and return the resulting identity.

            Args:
                user_id: Identifier of the identity to update.
                **updates: Field values to merge; ``None`` values are
                    skipped.

            Returns:
                The refreshed identity entity.

            """
            ...


__all__: list[str] = ["FlextAuthProtocolsAuthIdentity"]
