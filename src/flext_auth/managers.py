"""FLEXT Auth Managers - Authentication and authorization management services.

Provides centralized management for authentication tokens, user sessions,
and authorization policies. Implements Railway-Oriented Programming patterns
for robust error handling and composable authentication workflows.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from flext_core import FlextContainer, FlextContext, FlextLogger, FlextRegistry, r, t, u

from flext_auth import FlextAuthSettings, m, p


class ServiceManagers:
    """Manager composition helper for auth services.

    Provides centralized manager initialization and access without
    requiring multiple inheritance. Services use composition pattern
    instead of mixin inheritance to avoid basedpyright
    reportUnsafeMultipleInheritance errors.

    Usage:
        self._managers = ServiceManagers(config, dispatcher)
        user = self._managers.user_manager.get_user(id)
    """

    __slots__ = (
        "config",
        "dispatcher",
        "rate_limiter",
        "session_manager",
        "user_manager",
    )

    def __init__(self, config: FlextAuthSettings, dispatcher: p.CommandBus) -> None:
        """Initialize all standard managers used by services."""
        self.config = config
        self.dispatcher = dispatcher
        self.user_manager = FlextAuthManagers.FlextAuthUserManager(config)
        self.session_manager = FlextAuthManagers.FlextAuthSessionManager(config)
        self.rate_limiter = FlextAuthManagers.FlextAuthRateLimiter(config, dispatcher)


class FlextAuthManagers:
    """Namespace class for all authentication managers following FLEXT patterns.

    This namespace class contains all manager implementations as nested classes,
    providing a single import point while maintaining clean separation of concerns.
    """

    def execute(self) -> r:
        """Execute method for FlextService interface.

        FlextAuthManagers is a namespace class - use specific manager classes instead.
        """
        return r.fail(
            "FlextAuthManagers is a namespace class - use specific manager classes like FlextAuthUserManager"
        )

    class FlextAuthUserManager:
        """User management business logic.

        Handles user CRUD operations, role/permission management, and user data persistence.
        Uses newer FlextSettings features for complete integration.
        """

        _config: FlextAuthSettings
        logger: p.StructlogLogger
        _context: p.Context
        _users: dict[str, dict[str, object]]

        def __init__(self, config: FlextAuthSettings) -> None:
            """Initialize user manager with configuration."""
            super().__init__()
            self._config = config
            self.logger = FlextLogger(__name__)
            self._context = FlextContext()
            self._users = {}

        def add_user_permission(self, user_id: str, permission: str) -> r[bool]:
            """Add permission to user."""
            return self._modify_user_list_field(
                user_id, "permissions", permission, add=True
            )

        def add_user_role(self, user_id: str, role: str) -> r[bool]:
            """Add role to user."""
            return self._modify_user_list_field(user_id, "roles", role, add=True)

        def create_user(
            self,
            username: str,
            email: str,
            password_hash: str,
            **extra_fields: str | int | bool | list[str] | datetime | None,
        ) -> r[m.Auth.AuthIdentity]:
            """Create a new user."""
            if username in self._users:
                return r[m.Auth.AuthIdentity].fail("Identity already exists")
            normalized_email = email.lower()
            for existing_user_data in self._users.values():
                existing_contact = existing_user_data.get("contact", "")
                match existing_contact:
                    case str() as existing_contact_str if (
                        existing_contact_str.lower() == normalized_email
                    ):
                        return r[m.Auth.AuthIdentity].fail("Identity already exists")
                    case _:
                        pass
            user_id = str(uuid4())
            unique_id: str = str(user_id)
            name: str = str(username)
            contact: str = str(email)
            credential_hash: str = str(password_hash)
            full_name: str = ""
            is_active: bool = True
            roles: list[str] = []
            permissions: list[str] = []
            failed_attempts: int = 0
            locked_until: datetime = datetime.min.replace(tzinfo=UTC)
            last_access: datetime = datetime.min.replace(tzinfo=UTC)
            token: str = ""
            session_id: str = ""
            for k, v in extra_fields.items():
                if k == "full_name":
                    full_name = str(v) if v is not None else ""
                elif k == "is_active":
                    is_active = bool(v)
                elif k == "roles":
                    roles = [str(item) for item in v] if u.is_list(v) else []
                elif k == "permissions":
                    permissions = [str(item) for item in v] if u.is_list(v) else []
                elif k == "failed_attempts":
                    match v:
                        case int() as int_value:
                            failed_attempts = int(int_value)
                        case str() as str_value if str_value.isdigit():
                            failed_attempts = int(str_value)
                        case _:
                            failed_attempts = 0
                elif k == "locked_until":
                    if isinstance(v, datetime):
                        locked_until = v
                    else:
                        match v:
                            case str() as locked_until_str:
                                try:
                                    locked_until = datetime.fromisoformat(
                                        locked_until_str
                                    )
                                except ValueError:
                                    locked_until = datetime.min.replace(tzinfo=UTC)
                            case _:
                                locked_until = datetime.min.replace(tzinfo=UTC)
                elif k == "last_access":
                    if isinstance(v, datetime):
                        last_access = v
                    else:
                        match v:
                            case str() as last_access_str:
                                try:
                                    last_access = datetime.fromisoformat(
                                        last_access_str
                                    )
                                except ValueError:
                                    last_access = datetime.min.replace(tzinfo=UTC)
                            case _:
                                last_access = datetime.min.replace(tzinfo=UTC)
                elif k == "token":
                    token = str(v) if v is not None else ""
                elif k == "session_id":
                    session_id = str(v) if v is not None else ""
            storage_data: dict[str, object] = {
                "unique_id": unique_id,
                "name": name,
                "contact": contact,
                "credential_hash": credential_hash,
                "full_name": full_name,
                "is_active": is_active,
                "roles": roles,
                "permissions": permissions,
                "failed_attempts": failed_attempts,
                "locked_until": locked_until,
                "last_access": last_access,
                "token": token,
                "session_id": session_id,
                "id": user_id,
                "identity_id": user_id,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            }
            self._users[username] = storage_data
            identity_dict = {
                "unique_id": unique_id,
                "name": name,
                "contact": contact,
                "credential_hash": credential_hash,
                "full_name": full_name,
                "is_active": is_active,
                "roles": roles,
                "permissions": permissions,
                "failed_attempts": failed_attempts,
                "locked_until": locked_until,
                "last_access": last_access,
                "token": token,
                "session_id": session_id,
            }
            user = m.Auth.AuthIdentity.model_validate(identity_dict)
            return r[m.Auth.AuthIdentity].ok(user)

        def delete_user(self, user_id: str) -> r[bool]:
            """Delete user."""
            result = self._find_user_by_id(user_id)
            if result.is_failure:
                return r[bool].fail(result.error or "Unknown error")
            user_key, _ = result.value
            del self._users[user_key]
            return r[bool].ok(value=True)

        def get_user(self, user_id: str) -> r[m.Auth.AuthIdentity]:
            """Get user by ID."""
            return self._find_user_by_id(user_id).map(
                lambda ud: self._create_identity_from_storage(ud[1])
            )

        def get_user_by_id(self, user_id: str) -> r[m.Auth.AuthIdentity]:
            """Get a user by their ID."""
            return self._find_user_by_id(user_id).map(
                lambda ud: self._create_identity_from_storage(ud[1])
            )

        def get_user_by_username(self, username: str) -> r[m.Auth.AuthIdentity]:
            """Get user by username."""
            if username not in self._users:
                return r[m.Auth.AuthIdentity].fail("User not found")
            storage_data = self._users[username]
            user = self._create_identity_from_storage(storage_data)
            return r[m.Auth.AuthIdentity].ok(user)

        def remove_user_permission(self, user_id: str, permission: str) -> r[bool]:
            """Remove permission from user."""
            return self._modify_user_list_field(
                user_id, "permissions", permission, add=False
            )

        def remove_user_role(self, user_id: str, role: str) -> r[bool]:
            """Remove role from user."""
            return self._modify_user_list_field(user_id, "roles", role, add=False)

        def update_user(
            self,
            user_id: str,
            **updates: str | int | bool | list[str] | datetime | None,
        ) -> r[m.Auth.AuthIdentity]:
            """Update user data."""
            return self._find_user_by_id(user_id).map(
                lambda ud: (
                    ud[1].update(updates),
                    ud[1].update({"updated_at": datetime.now(UTC)}),
                    self._create_identity_from_storage(ud[1]),
                )[2]
            )

        def _apply_list_modification(
            self,
            user_data: dict[str, object],
            field: str,
            value: str,
            *,
            add: bool = True,
        ) -> None:
            """Apply list modification atomically."""
            field_list_value = user_data.get(field)
            if not u.is_list(field_list_value):
                msg = f"Field '{field}' must be a list for modification"
                raise TypeError(msg)
            field_list = field_list_value
            if add and value not in field_list:
                field_list.append(value)
            elif not add and value in field_list:
                field_list.remove(value)

        def _apply_list_modification_and_return_true(
            self,
            user_data: dict[str, object],
            field: str,
            value: str,
            *,
            add: bool,
        ) -> bool:
            """Apply list mutation and return success sentinel."""
            self._apply_list_modification(user_data, field, value, add=add)
            return True

        def _create_identity_from_storage(
            self, storage_data: Mapping[str, object]
        ) -> m.Auth.AuthIdentity:
            """Create Identity model from storage data, filtering out non-model fields."""
            identity_id = self._extract_identity_id(storage_data)
            name_value = self._validate_required_field(storage_data, "name", str)
            if not name_value:
                msg = "Storage data 'name' must be a non-empty string"
                raise ValueError(msg)
            contact_value = self._validate_required_field(storage_data, "contact", str)
            if not contact_value:
                msg = "Storage data 'contact' must be a non-empty string"
                raise ValueError(msg)
            credential_hash = self._validate_required_field(
                storage_data, "credential_hash", str
            )
            is_active = self._validate_required_field(storage_data, "is_active", bool)
            roles_raw = storage_data.get("roles", [])
            permissions_raw = storage_data.get("permissions", [])
            roles: list[str] = []
            permissions: list[str] = []
            if u.is_list(roles_raw):
                roles = [role for role in roles_raw if isinstance(role, str)]
            if u.is_list(permissions_raw):
                permissions = [
                    permission
                    for permission in permissions_raw
                    if isinstance(permission, str)
                ]
            identity_data: dict[str, object] = {
                "unique_id": identity_id,
                "name": name_value,
                "contact": contact_value,
                "credential_hash": credential_hash,
                "is_active": is_active,
                "roles": roles,
                "permissions": permissions,
            }
            valid_identity_fields = {
                "unique_id",
                "name",
                "contact",
                "credential_hash",
                "is_active",
                "roles",
                "permissions",
                "full_name",
                "failed_attempts",
                "locked_until",
                "last_access",
            }
            for field in (
                "full_name",
                "failed_attempts",
                "locked_until",
                "last_access",
            ):
                if field in storage_data:
                    field_type = (
                        str
                        if field == "full_name"
                        else int
                        if field == "failed_attempts"
                        else datetime
                    )
                    field_value = storage_data.get(field)
                    if u.is_type(field_value, field_type):
                        if field in {"locked_until", "last_access"}:
                            if field_value is None:
                                identity_data[field] = datetime.min.replace(tzinfo=UTC)
                            else:
                                identity_data[field] = field_value
                        else:
                            identity_data[field] = field_value
            filtered_identity_data = {
                k: v for k, v in identity_data.items() if k in valid_identity_fields
            }
            return m.Auth.AuthIdentity.model_validate(filtered_identity_data)

        def _extract_identity_id(self, storage_data: Mapping[str, object]) -> str:
            """Extract identity ID from storage data with fast fail."""
            for field in ("unique_id", "id", "identity_id"):
                value = storage_data.get(field)
                match value:
                    case str() as identity_id if identity_id:
                        return identity_id
                    case _:
                        pass
            msg = "Storage data missing required 'unique_id', 'id', or 'identity_id' field"
            raise ValueError(msg)

        def _find_user_by_id(self, user_id: str) -> r[tuple[str, dict[str, object]]]:
            """Find user by ID (either identity_id, unique_id, or id field).

            Eliminates duplication across 7 methods.
            """
            for username, user_data in self._users.items():
                if (
                    user_data.get("identity_id") == user_id
                    or user_data.get("unique_id") == user_id
                    or user_data.get("id") == user_id
                ):
                    return r[tuple[str, dict[str, t.ContainerValue]]].ok((
                        username,
                        user_data,
                    ))
            return r[tuple[str, dict[str, t.ContainerValue]]].fail("User not found")

        def _modify_user_list_field(
            self, user_id: str, field: str, value: str, *, add: bool = True
        ) -> r[bool]:
            """Add or remove value from user list field (roles/permissions).

            Generic list field modifier - eliminates duplication in 4 methods.
            """
            return self._find_user_by_id(user_id).map(
                lambda ud: self._apply_list_modification_and_return_true(
                    ud[1], field, value, add=add
                )
            )

        def _validate_required_field[T](
            self,
            storage_data: Mapping[str, object],
            field: str,
            field_type: type[T],
        ) -> T:
            """Validate and extract required field with type checking."""
            value = storage_data.get(field)
            if not isinstance(value, field_type):
                msg = f"Storage data '{field}' must be a {field_type.__name__}"
                raise TypeError(msg)
            return value

    class FlextAuthSessionManager:
        """Session management business logic.

        Handles user session creation, validation, and cleanup.
        Uses newer FlextSettings features for complete integration.
        """

        def __init__(self, config: FlextAuthSettings) -> None:
            """Initialize session manager with configuration."""
            super().__init__()
            self._config = config
            self.logger = FlextLogger(__name__)
            self._context = FlextContext()
            self._dispatcher: t.RegisterableService = (
                FlextContainer.get_global().get("command_bus").unwrap()
            )
            self._sessions: dict[str, dict[str, object]] = {}

        def cleanup_expired_sessions(self) -> r[int]:
            """Clean up expired sessions and return count of cleaned sessions."""
            cleaned_count = 0
            sessions_to_check = list(self._sessions.keys())
            for session_id in sessions_to_check:
                session_data = self._sessions[session_id]
                if not self._is_session_active(session_data):
                    end_result = self.end_session_by_id(session_id)
                    if end_result.is_success:
                        cleaned_count += 1
            return r[int].ok(cleaned_count)

        def create_session(
            self,
            user_id: str,
            token: str,
            expires_in_minutes: int = 60,
            ip_address: str | None = None,
            user_agent: str | None = None,
        ) -> r[m.Auth.Session]:
            """Create a new session."""
            session_id = str(uuid4())
            expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)
            session_data: dict[str, object] = {
                "id": session_id,
                "unique_id": session_id,
                "identity_id": user_id,
                "session_token": token,
                "expires_at": expires_at,
                "is_active": True,
                "last_accessed": datetime.now(UTC),
                "ip_address": ip_address or "",
                "user_agent": user_agent or "",
            }
            self._sessions[session_id] = session_data
            session = m.Auth.Session(
                identity_id=str(session_data["identity_id"]),
                session_token=str(session_data["session_token"]),
                expires_at=session_data["expires_at"]
                if isinstance(session_data["expires_at"], datetime)
                else datetime.fromisoformat(str(session_data["expires_at"])),
                is_active=bool(session_data.get("is_active", True)),
                ip_address=str(session_data.get("ip_address", "")),
                user_agent=str(session_data.get("user_agent", "")),
                last_accessed=session_data["last_accessed"]
                if "last_accessed" in session_data
                and isinstance(session_data["last_accessed"], datetime)
                else datetime.now(UTC),
            )
            return r[m.Auth.Session].ok(session)

        def end_all_sessions(self, user_id: str) -> r[bool]:
            """End all sessions for a user."""
            return self.end_session(user_id)

        def end_session(self, user_id: str) -> r[bool]:
            """End all sessions for a user."""
            found = False
            for session_data in self._sessions.values():
                identity_id_value = session_data.get("identity_id")
                match identity_id_value:
                    case str() as identity_id_value_str if (
                        identity_id_value_str == user_id
                    ):
                        session_data["is_active"] = False
                        found = True
                    case _:
                        pass
            if found:
                return r[bool].ok(value=True)
            return r[bool].fail("No sessions found for user")

        def end_session_by_id(self, session_id: str) -> r[bool]:
            """End a specific session."""
            if session_id in self._sessions:
                self._sessions[session_id]["is_active"] = False
                return r[bool].ok(value=True)
            return r[bool].fail("Session not found")

        def get_active_sessions(self, user_id: str) -> r[list[m.Auth.Session]]:
            """Get all active sessions for a user."""
            sessions: list[m.Auth.Session] = []
            for session_id, session_data in self._sessions.items():
                identity_id_value = session_data.get("identity_id")
                match identity_id_value:
                    case str() as identity_id_value_str if (
                        identity_id_value_str == user_id
                        and self._is_session_active(session_data)
                    ):
                        session = m.Auth.Session(
                            identity_id=str(session_data["identity_id"]),
                            session_token=str(session_data["session_token"]),
                            expires_at=session_data["expires_at"]
                            if isinstance(session_data["expires_at"], datetime)
                            else datetime.fromisoformat(
                                str(session_data["expires_at"])
                            ),
                            is_active=bool(session_data.get("is_active", True)),
                            ip_address=str(session_data.get("ip_address", "")),
                            user_agent=str(session_data.get("user_agent", "")),
                            last_accessed=session_data["last_accessed"]
                            if "last_accessed" in session_data
                            and isinstance(session_data["last_accessed"], datetime)
                            else datetime.now(UTC),
                        )
                        session.unique_id = session_id
                        sessions.append(session)
                    case _:
                        pass
            return r[list[m.Auth.Session]].ok(sessions)

        def get_total_active_sessions(self) -> int:
            """Get total count of active sessions."""
            return sum(
                1
                for session in self._sessions.values()
                if self._is_session_active(session)
            )

        def _is_session_active(self, session_data: Mapping[str, object]) -> bool:
            """Check if session is active and not expired.

            Eliminates duplication of expiration check (appeared 2+ times).
            """
            expires_at_value = session_data.get("expires_at")
            if not isinstance(expires_at_value, datetime):
                return False
            expires_at = expires_at_value
            is_active_value = session_data.get("is_active")
            match is_active_value:
                case bool() as active:
                    is_active = active
                case _:
                    return False
            return is_active and expires_at > datetime.now(UTC)

    class FlextAuthAuditLogger:
        """Audit logging business logic.

        Records authentication and authorization events for compliance and debugging.
        Uses newer FlextSettings features for complete integration.
        """

        _EVENT_AUTH_SUCCESS = "auth_success"
        _EVENT_AUTH_FAILURE = "auth_failure"
        _EVENT_TOKEN_VALIDATION_SUCCESS = "token_validation_success"
        _EVENT_TOKEN_VALIDATION_FAILURE = "token_validation_failure"
        _EVENT_TOKEN_REFRESH_SUCCESS = "token_refresh_success"
        _EVENT_TOKEN_REFRESH_FAILURE = "token_refresh_failure"
        _EVENT_TOKEN_CREATION_SUCCESS = "token_creation_success"
        _EVENT_TOKEN_CREATION_FAILURE = "token_creation_failure"
        _EVENT_USER_LOGOUT = "user_logout"
        _EVENT_PASSWORD_CHANGE_SUCCESS = "password_change_success"
        _EVENT_PASSWORD_CHANGE_FAILURE = "password_change_failure"
        _EVENT_PASSWORD_RESET = "password_reset"
        _EVENT_AUTHORIZATION_GRANTED = "authorization_granted"
        _EVENT_AUTHORIZATION_DENIED = "authorization_denied"

        def __init__(self, config: FlextAuthSettings, dispatcher: p.CommandBus) -> None:
            """Initialize audit logger with configuration."""
            super().__init__()
            self._config = config
            self._dispatcher = dispatcher
            self.logger = FlextLogger(__name__)
            self._context = FlextContext()
            self._logs: list[dict[str, object]] = []

        def get_logs(
            self,
            user_id: str | None = None,
            event_type: str | None = None,
            start_date: datetime | None = None,
            end_date: datetime | None = None,
            limit: int = 100,
        ) -> r[list[Mapping[str, object]]]:
            """Get audit logs with optional filtering."""
            filtered_logs: list[Mapping[str, object]] = []
            for log in self._logs:
                if user_id is not None:
                    username_value = log.get("username")
                    log_user_id_value = log.get("user_id")
                    match username_value:
                        case str() as username if username == user_id:
                            username_matches = True
                        case _:
                            username_matches = False
                    match log_user_id_value:
                        case str() as log_user_id if log_user_id == user_id:
                            log_user_matches = True
                        case _:
                            log_user_matches = False
                    if not username_matches and (not log_user_matches):
                        continue
                if event_type is not None:
                    log_event_type = log.get("event_type")
                    match log_event_type:
                        case str() as log_event if log_event == event_type:
                            pass
                        case _:
                            continue
                if start_date is not None:
                    log_timestamp = log.get("timestamp")
                    if (
                        not isinstance(log_timestamp, datetime)
                        or log_timestamp < start_date
                    ):
                        continue
                if end_date is not None:
                    log_timestamp = log.get("timestamp")
                    if (
                        not isinstance(log_timestamp, datetime)
                        or log_timestamp > end_date
                    ):
                        continue
                filtered_logs.append(log)
            return r[list[t.ContainerValue]].ok(filtered_logs[-limit:])

        def get_total_log_entries(self) -> int:
            """Get total count of log entries."""
            return len(self._logs)

        def log_auth_failure(
            self,
            username: str,
            provider: str,
            reason: str,
            **extra: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Log failed authentication."""
            self.log_event(
                self._EVENT_AUTH_FAILURE,
                username=username,
                provider=provider,
                reason=reason,
                **extra,
            )

        def log_auth_success(
            self,
            username: str,
            provider: str,
            **extra: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Log successful authentication."""
            self.log_event(
                self._EVENT_AUTH_SUCCESS, username=username, provider=provider, **extra
            )

        def log_authorization_check(
            self,
            username: str,
            resource: str,
            action: str,
            *,
            allowed: bool,
            **extra: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Log authorization check."""
            event_type = (
                self._EVENT_AUTHORIZATION_GRANTED
                if allowed
                else self._EVENT_AUTHORIZATION_DENIED
            )
            self.log_event(
                event_type, username=username, resource=resource, action=action, **extra
            )

        def log_event(
            self,
            event_type: str,
            **data: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Generic event logging - single method replaces 11 specific methods.

            Usage:
                self.log_event(self._EVENT_AUTH_SUCCESS, username="user", provider="jwt")
                self.log_event(self._EVENT_TOKEN_VALIDATION_FAILURE, reason="expired")
            """
            self._log_event(event_type, **data)

        def log_password_change_failure(
            self,
            username: str,
            reason: str,
            **extra: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Log failed password change."""
            self.log_event(
                self._EVENT_PASSWORD_CHANGE_FAILURE,
                username=username,
                reason=reason,
                **extra,
            )

        def log_password_change_success(
            self, username: str, **extra: str | int | bool | list[str] | datetime | None
        ) -> None:
            """Log successful password change."""
            self.log_event(
                self._EVENT_PASSWORD_CHANGE_SUCCESS, username=username, **extra
            )

        def log_password_reset(
            self, username: str, **extra: str | int | bool | list[str] | datetime | None
        ) -> None:
            """Log password reset."""
            self.log_event(self._EVENT_PASSWORD_RESET, username=username, **extra)

        def log_token_creation(
            self,
            user_id: str | None = None,
            token_type: str | None = None,
            *,
            success: bool = True,
            **extra: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Log token creation attempt."""
            event_type = (
                self._EVENT_TOKEN_CREATION_SUCCESS
                if success
                else self._EVENT_TOKEN_CREATION_FAILURE
            )
            self.log_event(event_type, user_id=user_id, token_type=token_type, **extra)

        def log_token_refresh(
            self,
            username: str | None = None,
            *,
            success: bool = True,
            **extra: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Log token refresh attempt."""
            event_type = (
                self._EVENT_TOKEN_REFRESH_SUCCESS
                if success
                else self._EVENT_TOKEN_REFRESH_FAILURE
            )
            self.log_event(event_type, username=username, **extra)

        def log_token_validation(
            self,
            username: str | None = None,
            *,
            success: bool = True,
            **extra: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Log token validation attempt."""
            event_type = (
                self._EVENT_TOKEN_VALIDATION_SUCCESS
                if success
                else self._EVENT_TOKEN_VALIDATION_FAILURE
            )
            self.log_event(event_type, username=username, **extra)

        def log_user_logout(
            self, username: str, **extra: str | int | bool | list[str] | datetime | None
        ) -> None:
            """Log user logout."""
            self.log_event(self._EVENT_USER_LOGOUT, username=username, **extra)

        def _log_event(
            self,
            event_type: str,
            **data: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Log an audit event."""
            log_entry: dict[str, object] = {
                "id": str(uuid4()),
                "event_type": event_type,
                "timestamp": datetime.now(UTC),
                **data,
            }
            self._logs.append(log_entry)
            self.logger.info("Audit event: %s", event_type)

    class FlextAuthRateLimiter:
        """Rate limiting business logic.

        Prevents brute force attacks by limiting authentication attempts.
        Uses newer FlextSettings features for complete integration.
        """

        def __init__(self, config: FlextAuthSettings, dispatcher: p.CommandBus) -> None:
            """Initialize rate limiter with configuration."""
            super().__init__()
            self._config = config
            self._dispatcher = dispatcher
            self.logger = FlextLogger(__name__)
            self._context = FlextContext()
            self._registry = FlextRegistry(dispatcher=dispatcher)
            self._attempts: dict[str, dict[str, object]] = {}
            self._max_attempts = 5
            self._window_minutes = 15

        def check_rate_limit(self, username: str) -> r[bool]:
            """Check if user is within rate limits.

            Returns:
                r[bool]: True if within limits, False if exceeded, error on failure

            """
            now = datetime.now(UTC)
            if username not in self._attempts:
                return r[bool].ok(value=True)
            recent_attempts = self._cleanup_window(username, now)
            if username not in self._attempts:
                self._attempts[username] = {}
            self._attempts[username]["attempts"] = recent_attempts
            if len(recent_attempts) >= self._max_attempts:
                return r[bool].fail("Too many failed attempts. Please try again later.")
            return r[bool].ok(value=True)

        def get_total_failed_attempts(self) -> int:
            """Get total count of failed attempts across all users."""
            return sum(len(attempts) for attempts in self._attempts.values())

        def record_failed_attempt(self, username: str) -> None:
            """Record a failed authentication attempt."""
            now = datetime.now(UTC)
            if username not in self._attempts:
                self._attempts[username] = {"attempts": []}
            attempts_raw = self._attempts[username].get("attempts")
            attempts_list: list[datetime]
            if u.is_list(attempts_raw):
                attempts_list = [
                    attempt for attempt in attempts_raw if isinstance(attempt, datetime)
                ]
            else:
                attempts_list = []
                self._attempts[username]["attempts"] = attempts_list
            attempts_list.append(now)
            recent_attempts = self._cleanup_window(username, now)
            self._attempts[username]["attempts"] = recent_attempts

        def _cleanup_window(self, username: str, now: datetime) -> list[datetime]:
            """Clean up attempts outside the time window.

            Generic pattern used in 2 methods - eliminates duplication.
            """
            window_start = now - timedelta(minutes=self._window_minutes)
            attempt_data = self._attempts.get(username)
            if not isinstance(attempt_data, Mapping):
                return []
            attempts_value = attempt_data.get("attempts")
            if not u.is_list(attempts_value):
                return []
            return [
                attempt
                for attempt in attempts_value
                if isinstance(attempt, datetime) and attempt > window_start
            ]
