"""Auth user manager mutation operations."""

from __future__ import annotations

from collections.abc import MutableMapping
from datetime import datetime

from flext_api import r, u

from flext_auth import m, p, t
from flext_auth._utilities._managers.user_read import FlextAuthUserManagerRead


class FlextAuthUserManagerWrite(FlextAuthUserManagerRead):
    _users: MutableMapping[str, t.Auth.ManagersUserData]

    def add_user_permission(self, user_id: str, permission: str) -> p.Result[bool]:
        """Add permission to user."""
        return self._modify_user_list_field(
            user_id,
            "permissions",
            permission,
            add=True,
        )

    def add_user_role(self, user_id: str, role: str) -> p.Result[bool]:
        """Add role to user."""
        return self._modify_user_list_field(user_id, "roles", role, add=True)

    def delete_user(self, user_id: str) -> p.Result[bool]:
        """Delete user."""
        result = self._find_user_by_id(user_id)
        if result.failure:
            return r[bool].fail(result.error or "Unknown error")
        user_key, _ = result.value
        del self._users[user_key]
        return r[bool].ok(value=True)

    def remove_user_permission(self, user_id: str, permission: str) -> p.Result[bool]:
        """Remove permission from user."""
        return self._modify_user_list_field(
            user_id,
            "permissions",
            permission,
            add=False,
        )

    def remove_user_role(self, user_id: str, role: str) -> p.Result[bool]:
        """Remove role from user."""
        return self._modify_user_list_field(user_id, "roles", role, add=False)

    def update_user(
        self,
        user_id: str,
        **updates: t.Scalar | t.StrSequence | datetime | None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Update user data."""
        filtered_updates: t.Auth.ManagersUserData = {
            k: v for k, v in updates.items() if v is not None
        }
        return self._find_user_by_id(user_id).map(
            lambda ud: (
                ud[1].update(filtered_updates),
                ud[1].update({"updated_at": u.now()}),
                self._create_identity_from_storage(ud[1]),
            )[2],
        )

    def _apply_list_modification(
        self,
        user_data: t.Auth.ManagersUserData,
        field: str,
        value: str,
        *,
        add: bool = True,
    ) -> None:
        """Apply list modification atomically."""
        field_list_value = user_data.get(field)
        if not isinstance(field_list_value, list):
            msg = f"u.Field '{field}' must be a list for modification"
            raise TypeError(msg)
        if add and value not in field_list_value:
            field_list_value.append(value)
        elif not add and value in field_list_value:
            field_list_value.remove(value)

    def _modify_user_list_field(
        self,
        user_id: str,
        field: str,
        value: str,
        *,
        add: bool = True,
    ) -> p.Result[bool]:
        """Add or remove value from user list field (roles/permissions).

        Generic list field modifier - eliminates duplication in 4 methods.
        """
        user_result = self._find_user_by_id(user_id)
        if user_result.failure:
            return r[bool].fail(user_result.error or "User not found")
        _, user_data = user_result.unwrap()
        self._apply_list_modification(user_data, field, value, add=add)
        return r[bool].ok(True)


__all__: list[str] = ["FlextAuthUserManagerWrite"]
