"""Auth user manager read operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_api import r
from flext_auth import e, m, p, t

if TYPE_CHECKING:
    from collections.abc import MutableMapping
    from datetime import datetime


class FlextAuthUserManagerRead:
    _users: MutableMapping[str, t.Auth.ManagersUserData]

    def get_user(self, user_id: str) -> p.Result[p.Auth.AuthIdentity]:
        """Get user by ID."""
        return self._find_user_by_id(user_id).map(
            lambda ud: self._create_identity_from_storage(ud[1]),
        )

    def get_user_by_id(self, user_id: str) -> p.Result[p.Auth.AuthIdentity]:
        """Get a user by their ID."""
        return self._find_user_by_id(user_id).map(
            lambda ud: self._create_identity_from_storage(ud[1]),
        )

    def get_user_by_username(self, username: str) -> p.Result[p.Auth.AuthIdentity]:
        """Get user by username."""
        if username not in self._users:
            return e.fail_not_found("User", "", result_type=r[p.Auth.AuthIdentity])
        storage_data = self._users[username]
        user = self._create_identity_from_storage(storage_data)
        return r[p.Auth.AuthIdentity].ok(user)

    def _create_identity_from_storage(
        self,
        storage_data: t.Auth.ManagersUserData,
    ) -> p.Auth.AuthIdentity:
        """Create Identity model from storage data, filtering out non-model fields."""
        identity_data: t.MutableMappingKV[str, t.JsonPayload | datetime] = {
            field: storage_data[field]
            for field in m.Auth.AuthIdentity.model_fields
            if field in storage_data
        }
        identity_data["unique_id"] = self._extract_identity_id(storage_data)
        identity: m.Auth.AuthIdentity = m.Auth.AuthIdentity.model_validate(
            identity_data,
        )
        return identity

    def _extract_identity_id(
        self,
        storage_data: t.Auth.ManagersUserData,
    ) -> str:
        """Extract identity ID from storage data with fast fail."""
        for field in ("unique_id", "id", "identity_id"):
            value = storage_data.get(field)
            match value:
                case str() as identity_id if identity_id:
                    return identity_id
                case _:
                    continue
        msg = "Storage data missing required 'unique_id', 'id', or 'identity_id' field"
        raise ValueError(msg)

    def _find_user_by_id(
        self,
        user_id: str,
    ) -> p.Result[t.Pair[str, t.Auth.ManagersUserData]]:
        """Find user by ID (either identity_id, unique_id, or id field).

        Eliminates duplication across 7 methods.
        """
        for username, user_data in self._users.items():
            if (
                user_data.get("identity_id") == user_id
                or user_data.get("unique_id") == user_id
                or user_data.get("id") == user_id
            ):
                return r[tuple[str, t.Auth.ManagersUserData]].ok((
                    username,
                    user_data,
                ))
        return e.fail_not_found(
            "User",
            "",
            result_type=r[tuple[str, t.Auth.ManagersUserData]],
        )


__all__: list[str] = ["FlextAuthUserManagerRead"]
