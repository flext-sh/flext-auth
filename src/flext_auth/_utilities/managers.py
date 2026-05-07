"""FLEXT Auth Managers - Authentication and authorization management services.

Provides centralized management for authentication tokens, user sessions,
and authorization policies. Implements Railway-Oriented Programming patterns
for robust error handling and composable authentication workflows.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
    Sequence,
)
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar
from uuid import uuid4

from flext_api import r

from flext_auth import e, m, p, t
from flext_auth._utilities._managers.auth_managers_session import (
    FlextAuthSessionManagers,
)
from flext_auth._utilities._managers.rate_limiter import FlextAuthRateLimiterManagers
from flext_core import FlextContext, u

if TYPE_CHECKING:
    from flext_auth.settings import FlextAuthSettings


class FlextAuthUtilitiesManagers(
    FlextAuthSessionManagers, FlextAuthRateLimiterManagers
):
    """Namespace class for all authentication managers following FLEXT patterns.

    This namespace class contains all manager implementations as nested classes,
    providing a single import point while maintaining clean separation of concerns.
    """

    _context_type: ClassVar[p.ContextType] = FlextContext

    class ServiceManagers:
        """Manager composition helper for auth services."""

        __slots__ = (
            "dispatcher",
            "rate_limiter",
            "session_manager",
            "settings",
            "user_manager",
        )

        def __init__(
            self, settings: FlextAuthSettings, dispatcher: p.Dispatcher
        ) -> None:
            """Initialize all standard managers used by services."""
            self.settings = settings
            self.dispatcher = dispatcher
            self.user_manager = FlextAuthUtilitiesManagers.FlextAuthUserManager(
                settings
            )
            self.session_manager = FlextAuthUtilitiesManagers.FlextAuthSessionManager(
                settings
            )
            self.rate_limiter = FlextAuthUtilitiesManagers.FlextAuthRateLimiter(
                settings,
                dispatcher,
            )

    def execute(self) -> p.Result[bool]:
        """Execute method for s interface.

        FlextAuthUtilitiesManagers is a namespace class - use specific manager classes instead.
        """
        return r[bool].fail(
            "FlextAuthUtilitiesManagers is a namespace class - use specific manager classes like FlextAuthUserManager",
        )

    class FlextAuthUserManager:
        """User management business logic.

        Handles user CRUD operations, role/permission management, and user data persistence.
        Uses newer FlextSettings features for complete integration.
        """

        config: FlextAuthSettings
        logger: p.Logger
        context: p.Context
        _users: MutableMapping[str, t.Auth.ManagersUserData]
        _DATETIME_ADAPTER: ClassVar[u.TypeAdapter[datetime]] = u.TypeAdapter(datetime)
        _MIN_DATETIME: ClassVar[datetime] = datetime.min.replace(tzinfo=UTC)

        class IdentityExtras(m.BaseModel):
            """Normalized optional extras for identity creation."""

            _MIN_DATETIME: ClassVar[datetime] = datetime.min.replace(tzinfo=UTC)

            full_name: str | None = None
            is_active: bool | None = None
            roles: t.StrSequence | None = None
            permissions: t.StrSequence | None = None
            failed_attempts: int | None = None
            locked_until: datetime | None = None
            last_access: datetime | None = None
            token: str | None = None
            session_id: str | None = None

            @u.field_validator("roles", "permissions", mode="before")
            @classmethod
            def normalize_str_sequence(
                cls,
                value: t.Scalar | t.StrSequence | datetime | None,
            ) -> t.StrSequence | None:
                """Normalize sequence-like values to strict string sequences."""
                if value is None:
                    return None
                if isinstance(value, Sequence) and not isinstance(
                    value, t.STR_BINARY_TYPES
                ):
                    return list(value)
                return []

            @u.field_validator("failed_attempts", mode="before")
            @classmethod
            def normalize_failed_attempts(
                cls,
                value: t.Scalar | t.StrSequence | datetime | None,
            ) -> int | None:
                """Normalize failed attempts from int-like values."""
                if value is None:
                    return None
                if isinstance(value, int):
                    return max(value, 0)
                if isinstance(value, str) and value.isdigit():
                    return int(value)
                return 0

            @u.field_validator("locked_until", "last_access", mode="before")
            @classmethod
            def normalize_datetime(
                cls,
                value: t.Scalar | t.StrSequence | datetime | None,
            ) -> datetime | None:
                """Normalize datetime-like values with deterministic fallback."""
                if value is None:
                    return None
                match value:
                    case datetime() as datetime_value:
                        return datetime_value
                    case str() as datetime_str:
                        try:
                            return datetime.fromisoformat(datetime_str)
                        except ValueError:
                            return cls._MIN_DATETIME
                    case _:
                        return cls._MIN_DATETIME

        def __init__(self, settings: FlextAuthSettings) -> None:
            """Initialize user manager with configuration."""
            super().__init__()
            self.config = settings
            self.logger = u.fetch_logger(__name__)
            self.context = FlextAuthUtilitiesManagers._context_type.create()
            self._users: MutableMapping[str, t.Auth.ManagersUserData] = {}

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

        def create_user(
            self,
            username: str,
            email: str,
            password_hash: str,
            **extra_fields: t.Scalar | t.StrSequence | datetime | None,
        ) -> p.Result[m.Auth.AuthIdentity]:
            """Create a new user."""
            normalized_email = email.lower()
            duplicate_identity_exists = username in self._users or any(
                isinstance(existing_user_data.get("contact"), str)
                and str(existing_user_data.get("contact")).lower() == normalized_email
                for existing_user_data in self._users.values()
            )
            if duplicate_identity_exists:
                return r[m.Auth.AuthIdentity].fail("Identity already exists")

            user_id = str(uuid4())
            now = datetime.now(UTC)
            normalized_identity_extras = self.IdentityExtras.model_validate(
                extra_fields
            ).model_dump(exclude_none=True)
            user = m.Auth.AuthIdentity.model_validate(
                {
                    "unique_id": user_id,
                    "name": username,
                    "contact": normalized_email,
                    "credential_hash": password_hash,
                    **normalized_identity_extras,
                },
            )
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
            return r[m.Auth.AuthIdentity].ok(user)

        def delete_user(self, user_id: str) -> p.Result[bool]:
            """Delete user."""
            result = self._find_user_by_id(user_id)
            if result.failure:
                return r[bool].fail(result.error or "Unknown error")
            user_key, _ = result.value
            del self._users[user_key]
            return r[bool].ok(value=True)

        def get_user(self, user_id: str) -> p.Result[m.Auth.AuthIdentity]:
            """Get user by ID."""
            return self._find_user_by_id(user_id).map(
                lambda ud: self._create_identity_from_storage(ud[1]),
            )

        def get_user_by_id(self, user_id: str) -> p.Result[m.Auth.AuthIdentity]:
            """Get a user by their ID."""
            return self._find_user_by_id(user_id).map(
                lambda ud: self._create_identity_from_storage(ud[1]),
            )

        def get_user_by_username(self, username: str) -> p.Result[m.Auth.AuthIdentity]:
            """Get user by username."""
            if username not in self._users:
                return e.fail_not_found("User", "", result_type=r[m.Auth.AuthIdentity])
            storage_data = self._users[username]
            user = self._create_identity_from_storage(storage_data)
            return r[m.Auth.AuthIdentity].ok(user)

        def remove_user_permission(
            self, user_id: str, permission: str
        ) -> p.Result[bool]:
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
                    ud[1].update({"updated_at": datetime.now(UTC)}),
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

        def _create_identity_from_storage(
            self,
            storage_data: t.Auth.ManagersUserData,
        ) -> m.Auth.AuthIdentity:
            """Create Identity model from storage data, filtering out non-model fields."""
            identity_data: t.MutableMappingKV[str, t.JsonPayload | datetime] = {
                field: storage_data[field]
                for field in m.Auth.AuthIdentity.model_fields
                if field in storage_data
            }
            identity_data["unique_id"] = self._extract_identity_id(storage_data)
            return m.Auth.AuthIdentity.model_validate(identity_data)

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
                "User", "", result_type=r[tuple[str, t.Auth.ManagersUserData]]
            )

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
