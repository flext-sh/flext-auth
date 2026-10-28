"""Auth user manager mutation operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_api import r, u

from flext_auth import m
from flext_auth._utilities._managers import FlextAuthUserManagerRead

if TYPE_CHECKING:
    from datetime import datetime

    from flext_auth import p, t


class FlextAuthUserManagerWrite(FlextAuthUserManagerRead):
    """User manager mutation operations over the in-memory user store."""

    _users: MutableMapping[str, t.Auth.ManagersUserData]

    def add_user_permission(self, user_id: str, permission: str) -> p.Result[bool]:
        """Add permission to user.

        Args:
            user_id: Identity, unique, or storage ID to modify.
            permission: Permission name to append when absent.

        Returns:
            Success once the permission list is updated.

        """
        return self._modify_user_list_field(
            user_id,
            "permissions",
            permission,
            add=True,
        )

    def add_user_role(self, user_id: str, role: str) -> p.Result[bool]:
        """Add role to user.

        Args:
            user_id: Identity, unique, or storage ID to modify.
            role: Role name to append when absent.

        Returns:
            Success once the role list is updated.

        """
        return self._modify_user_list_field(user_id, "roles", role, add=True)

    def delete_user(self, user_id: str) -> p.Result[bool]:
        """Delete user.

        Args:
            user_id: Identity, unique, or storage ID to remove.

        Returns:
            Success once the user record is deleted; failure when the ID
            is unknown.

        """
        result = self._find_user_by_id(user_id)
        if result.failure:
            return r[bool].from_failure(result)
        user_key, _ = result.value
        del self._users[user_key]
        return r[bool].ok(value=True)

    def remove_user_permission(self, user_id: str, permission: str) -> p.Result[bool]:
        """Remove permission from user.

        Args:
            user_id: Identity, unique, or storage ID to modify.
            permission: Permission name to remove when present.

        Returns:
            Success once the permission list is updated.

        """
        return self._modify_user_list_field(
            user_id,
            "permissions",
            permission,
            add=False,
        )

    def remove_user_role(self, user_id: str, role: str) -> p.Result[bool]:
        """Remove role from user.

        Args:
            user_id: Identity, unique, or storage ID to modify.
            role: Role name to remove when present.

        Returns:
            Success once the role list is updated.

        """
        return self._modify_user_list_field(user_id, "roles", role, add=False)

    def update_user(
        self,
        user_id: str,
        **updates: t.Scalar | Sequence[str] | datetime | None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Update user data.

        Args:
            user_id: Identity, unique, or storage ID to update.
            **updates: Field values to merge; ``None`` values are skipped.

        Returns:
            The refreshed identity entity; failure when the ID is unknown.

        """
        filtered_updates: t.Auth.ManagersUserData = {
            k: v for k, v in updates.items() if v is not None
        }
        lookup = self._find_user_by_id(user_id)
        if lookup.failure:
            return r[m.Auth.AuthIdentity].from_failure(lookup)
        _, stored = lookup.value
        filtered_updates["updated_at"] = u.now()
        validated = lookup.map(
            lambda _: self._create_identity_from_storage({
                **stored,
                **filtered_updates,
            }),
        )
        if validated.success:
            stored.update(filtered_updates)
        return validated

    @staticmethod
    def _apply_list_modification(
        user_data: t.Auth.ManagersUserData,
        field: str,
        value: str,
        *,
        add: bool = True,
    ) -> None:
        """Apply list modification atomically.

        Args:
            user_data: Raw storage record holding the list field.
            field: Name of the list field to modify.
            value: Value to append or remove.
            add: Append the value when true, remove it when false.

        Raises:
            TypeError: If the target field does not hold a list.

        """
        field_list_value = user_data.get(field)
        if not isinstance(field_list_value, list):
            msg = f"m.Field '{field}' must be a list for modification"
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

        Args:
            user_id: Identity, unique, or storage ID to modify.
            field: Name of the list field to modify.
            value: Value to append or remove.
            add: Append the value when true, remove it when false.

        Returns:
            Success once the list field is updated; failure when the user
            ID is unknown.

        """
        user_result = self._find_user_by_id(user_id)
        if user_result.failure:
            return r[bool].from_failure(user_result)
        _, user_data = user_result.unwrap()
        self._apply_list_modification(user_data, field, value, add=add)
        return r[bool].ok(value=True)


__all__: list[str] = ["FlextAuthUserManagerWrite"]
