"""Auth user manager create operation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar
from uuid import uuid4

from flext_api import r, u

from flext_auth import m, p, t
from flext_auth._utilities._managers import FlextAuthUserManagerWrite

if TYPE_CHECKING:
    from collections.abc import MutableMapping
    from datetime import datetime


class FlextAuthUserManagerCreate(FlextAuthUserManagerWrite):
    """User manager extension adding identity creation."""

    IdentityExtras: ClassVar[type[m.Auth.UserIdentityExtras]] = (
        m.Auth.UserIdentityExtras
    )
    _users: MutableMapping[str, t.Auth.ManagersUserData]

    def create_user(
        self,
        username: str,
        email: str,
        password_hash: str,
        roles: t.StrSequence | None = None,
        **extra_fields: t.Scalar | t.StrSequence | datetime | None,
    ) -> p.Result[p.Auth.Identity]:
        """Create a new user.

        Args:
            username: Unique account name for the identity.
            email: Contact address, normalized to lowercase.
            password_hash: Pre-hashed credential to store.
            roles: Explicit roles, or the model-owned defaults when omitted.
            **extra_fields: Optional identity extras such as permissions
                or profile fields.

        Returns:
            The created identity entity; failure when the username or
            contact is already registered.

        """
        normalized_email = email.lower()
        duplicate_identity_exists = username in self._users or any(
            isinstance(existing_user_data.get("contact"), str)
            and str(existing_user_data.get("contact")).lower() == normalized_email
            for existing_user_data in self._users.values()
        )
        if duplicate_identity_exists:
            return r[p.Auth.Identity].fail("Identity already exists")

        user_id = str(uuid4())
        now = u.now()
        if roles is not None:
            extra_fields["roles"] = roles
        normalized_identity_extras = self.IdentityExtras.model_validate(
            extra_fields,
        ).model_dump(exclude_none=True)
        user = m.Auth.AuthIdentity.model_validate({
            "unique_id": user_id,
            "name": username,
            "contact": normalized_email,
            "credential_hash": password_hash,
            **normalized_identity_extras,
        })
        storage_data: t.Auth.ManagersUserData = {
            "unique_id": user.unique_id,
            "name": user.name,
            "contact": user.contact,
            "credential_hash": user.credential_hash,
            "full_name": user.full_name,
            "is_active": user.is_active,
            "roles": list(user.roles),
            "permissions": list(user.permissions),
            "failed_attempts": user.failed_attempts,
            "locked_until": user.locked_until,
            "last_access": user.last_access,
            "token": user.token,
            "session_id": user.session_id,
            "id": user_id,
            "identity_id": user_id,
            "created_at": now,
            "updated_at": now,
        }
        self._users[username] = storage_data
        return r[p.Auth.Identity].ok(user)


__all__: list[str] = ["FlextAuthUserManagerCreate"]
