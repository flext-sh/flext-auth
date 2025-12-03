"""FLEXT Auth Managers - Core business logic managers for authentication.

This module provides the core business logic managers that handle user management,
session management, audit logging, and rate limiting for the flext-auth library.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from flext_core import (
    FlextContext,
    FlextDispatcher,
    FlextLogger,
    FlextRegistry,
    FlextResult,
    FlextService,
)

from flext_auth.config import FlextAuthConfig
from flext_auth.models import FlextAuthModels


class ServiceManagerMixin:
    """Common manager initialization mixin for all auth services.

    Eliminates 3x duplication of manager initialization across
    user_service, token_service, and session_service.

    This mixin provides the single source of truth for manager setup.
    """

    def init_managers(
        self, config: FlextAuthConfig, dispatcher: FlextDispatcher
    ) -> None:
        """Initialize all standard managers used by services.

        Called by service __init__ methods to set up managers once.
        """
        self._config = config
        self._dispatcher = dispatcher
        self.user_manager = FlextAuthManagers.FlextAuthUserManager(config)
        self.session_manager = FlextAuthManagers.FlextAuthSessionManager(config)
        self.audit_logger = FlextAuthManagers.FlextAuthAuditLogger(config, dispatcher)
        self.rate_limiter = FlextAuthManagers.FlextAuthRateLimiter(config, dispatcher)


class FlextAuthManagers(FlextService[object]):
    """Namespace class for all authentication managers following FLEXT patterns.

    This namespace class contains all manager implementations as nested classes,
    providing a single import point while maintaining clean separation of concerns.
    """

    def execute(self, **_kwargs: object) -> r[object]:
        """Execute method for FlextService interface.

        FlextAuthManagers is a namespace class - use specific manager classes instead.
        """
        return r[object].fail(
            "FlextAuthManagers is a namespace class - use specific manager classes like FlextAuthUserManager"
        )

    class FlextAuthUserManager:
        """User management business logic.

        Handles user CRUD operations, role/permission management, and user data persistence.
        Uses newer FlextConfig features for complete integration.
        """

        def __init__(self, config: FlextAuthConfig) -> None:
            """Initialize user manager with configuration."""
            super().__init__()
            self._config = config
            self.logger = FlextLogger(__name__)
            self._context = FlextContext()
            self._users: dict[
                str, dict[str, object]
            ] = {}  # In production, use database (dict for dynamic key access)

        def _find_user_by_id(
            self, user_id: str
        ) -> r[tuple[str, dict[str, object]]]:
            """Find user by ID (either identity_id, unique_id, or id field).

            Eliminates duplication across 7 methods.
            """
            for username, user_data in self._users.items():
                if (
                    user_data.get("identity_id") == user_id
                    or user_data.get("unique_id") == user_id
                    or user_data.get("id") == user_id
                ):
                    return FlextResult.ok((username, user_data))
            return FlextResult.fail("User not found")

        def _modify_user_list_field(
            self, user_id: str, field: str, value: str, *, add: bool = True
        ) -> r[bool]:
            """Add or remove value from user list field (roles/permissions).

            Generic list field modifier - eliminates duplication in 4 methods.
            """
            return self._find_user_by_id(user_id).map(
                lambda ud: (
                    self._apply_list_modification(ud[1], field, value, add=add),
                    True,
                )[1]
            )

        def _extract_identity_id(self, storage_data: dict[str, object]) -> str:
            """Extract identity ID from storage data with fast fail."""
            for field in ("unique_id", "id", "identity_id"):
                value = storage_data.get(field)
                if isinstance(value, str) and value:
                    return value
            msg = "Storage data missing required 'unique_id', 'id', or 'identity_id' field"
            raise ValueError(msg)

        def _validate_required_field(
            self,
            storage_data: dict[str, object],
            field: str,
            field_type: type[str | bool | list],
        ) -> str | bool | list:
            """Validate and extract required field with type checking."""
            value = storage_data.get(field)
            if not isinstance(value, field_type):
                msg = f"Storage data '{field}' must be a {field_type.__name__}"
                raise TypeError(msg)
            return value

        def _create_identity_from_storage(
            self, storage_data: dict[str, object]
        ) -> FlextAuthModels.Identity:
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
            roles = self._validate_required_field(storage_data, "roles", list)
            permissions = self._validate_required_field(
                storage_data, "permissions", list
            )

            identity_data: dict[str, object] = {
                "unique_id": identity_id,
                "name": name_value,
                "contact": contact_value,
                "credential_hash": credential_hash,
                "is_active": is_active,
                "roles": roles,
                "permissions": permissions,
            }

            # Add optional fields if present and valid
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
                        else (int if field == "failed_attempts" else datetime)
                    )
                    field_value = storage_data.get(field)
                    if isinstance(field_value, field_type):
                        # For datetime fields, ensure they're not None
                        if field in {"locked_until", "last_access"}:
                            # If None in storage, use datetime.min as default
                            if field_value is None:
                                identity_data[field] = datetime.min.replace(tzinfo=UTC)
                            else:
                                identity_data[field] = field_value
                        else:
                            identity_data[field] = field_value

            filtered_identity_data = {
                k: v for k, v in identity_data.items() if k in valid_identity_fields
            }
            return FlextAuthModels.Identity(**filtered_identity_data)

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
            if not isinstance(field_list_value, list):
                msg = f"Field '{field}' must be a list for modification"
                raise TypeError(msg)
            field_list = field_list_value
            if add and value not in field_list:
                field_list.append(value)
            elif not add and value in field_list:
                field_list.remove(value)

        def create_user(
            self,
            username: str,
            email: str,
            password_hash: str,
            **extra_fields: str | int | bool | list[str] | datetime | None,
        ) -> r[FlextAuthModels.Identity]:
            """Create a new user."""
            if username in self._users:
                return r[FlextAuthModels.Identity].fail(
                    "Identity already exists"
                )
            # Check for duplicate email (contact)
            normalized_email = email.lower() if isinstance(email, str) else email
            for existing_user_data in self._users.values():
                existing_contact = existing_user_data.get("contact", "")
                if (
                    isinstance(existing_contact, str)
                    and existing_contact.lower() == normalized_email
                ):
                    return r[FlextAuthModels.Identity].fail(
                        "Identity already exists"
                    )

            user_id = str(uuid4())
            # Build user data with only Identity model fields (no extras)
            # Use unique_id (not id) as that's the Entity field name
            identity_data: dict[str, str | int | bool | list[str] | datetime | None] = {
                "unique_id": user_id,
                "name": username,
                "contact": email,
                "credential_hash": password_hash,
            }

            # Add only valid Identity model fields from extra_fields
            # Filter to ensure only valid fields are included
            valid_identity_fields = {
                "is_active",
                "roles",
                "permissions",
                "full_name",
                "failed_attempts",
                "locked_until",
                "last_access",
            }
            filtered_extra = {
                k: v for k, v in extra_fields.items() if k in valid_identity_fields
            }
            identity_data.update(filtered_extra)

            # Set defaults for required fields if not provided
            if "is_active" not in identity_data:
                identity_data["is_active"] = True
            if "roles" not in identity_data:
                identity_data["roles"] = []
            if "permissions" not in identity_data:
                identity_data["permissions"] = []

            # Store full data with timestamps in internal storage
            # Also store id and identity_id for backward compatibility
            storage_data: dict[str, object] = {
                **identity_data,
                "id": user_id,  # Store id for backward compatibility
                "identity_id": user_id,  # Store identity_id for backward compatibility
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            }
            self._users[username] = storage_data

            # Create Identity model with only valid fields (no extras)
            user = FlextAuthModels.Identity(**identity_data)
            return r[FlextAuthModels.Identity].ok(user)

        def get_user(self, user_id: str) -> r[FlextAuthModels.Identity]:
            """Get user by ID."""
            return self._find_user_by_id(user_id).map(
                lambda ud: self._create_identity_from_storage(ud[1])
            )

        def get_user_by_username(
            self, username: str
        ) -> r[FlextAuthModels.Identity]:
            """Get user by username."""
            if username not in self._users:
                return r[FlextAuthModels.Identity].fail("User not found")

            storage_data = self._users[username]
            user = self._create_identity_from_storage(storage_data)
            return r[FlextAuthModels.Identity].ok(user)

        def update_user(
            self,
            user_id: str,
            **updates: str | int | bool | list[str] | datetime | None,
        ) -> r[FlextAuthModels.Identity]:
            """Update user data."""
            return self._find_user_by_id(user_id).map(
                lambda ud: (
                    ud[1].update(updates),
                    ud[1].update({"updated_at": datetime.now(UTC)}),
                    self._create_identity_from_storage(ud[1]),
                )[2]
            )

        def delete_user(self, user_id: str) -> r[bool]:
            """Delete user."""
            result = self._find_user_by_id(user_id)
            if result.is_success:
                username = result.unwrap()[0]
                del self._users[username]
                return r[bool].ok(True)
            return r[bool].fail(result.error or "Unknown error")

        def add_user_role(self, user_id: str, role: str) -> r[bool]:
            """Add role to user."""
            return self._modify_user_list_field(user_id, "roles", role, add=True)

        def remove_user_role(self, user_id: str, role: str) -> r[bool]:
            """Remove role from user."""
            return self._modify_user_list_field(user_id, "roles", role, add=False)

        def add_user_permission(
            self, user_id: str, permission: str
        ) -> r[bool]:
            """Add permission to user."""
            return self._modify_user_list_field(
                user_id, "permissions", permission, add=True
            )

        def remove_user_permission(
            self, user_id: str, permission: str
        ) -> r[bool]:
            """Remove permission from user."""
            return self._modify_user_list_field(
                user_id, "permissions", permission, add=False
            )

        def get_user_by_id(self, user_id: str) -> r[FlextAuthModels.Identity]:
            """Get a user by their ID."""
            return self._find_user_by_id(user_id).map(
                lambda ud: self._create_identity_from_storage(ud[1])
            )

    class FlextAuthSessionManager:
        """Session management business logic.

        Handles user session creation, validation, and cleanup.
        Uses newer FlextConfig features for complete integration.
        """

        def __init__(self, config: FlextAuthConfig) -> None:
            """Initialize session manager with configuration."""
            super().__init__()
            self._config = config
            self.logger = FlextLogger(__name__)
            self._context = FlextContext()
            self._dispatcher = FlextDispatcher()
            self._sessions: dict[
                str, dict[str, object]
            ] = {}  # In production, use Redis/database (dict for dynamic key access)

        def _is_session_active(self, session_data: dict[str, object]) -> bool:
            """Check if session is active and not expired.

            Eliminates duplication of expiration check (appeared 2+ times).
            """
            expires_at_value = session_data.get("expires_at")
            if not isinstance(expires_at_value, datetime):
                return False
            expires_at = expires_at_value

            is_active_value = session_data.get("is_active")
            if not isinstance(is_active_value, bool):
                return False
            is_active = is_active_value

            return is_active and expires_at > datetime.now(UTC)

        def create_session(
            self,
            user_id: str,
            token: str,
            expires_in_minutes: int = 60,
            ip_address: str | None = None,
            user_agent: str | None = None,
        ) -> r[FlextAuthModels.Session]:
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
            # Extract required fields for Session model
            session = FlextAuthModels.Session(
                identity_id=str(session_data["identity_id"]),
                session_token=str(session_data["session_token"]),
                expires_at=session_data["expires_at"],
                is_active=bool(session_data.get("is_active", True)),
                ip_address=str(session_data.get("ip_address", "")),
                user_agent=str(session_data.get("user_agent", "")),
                last_accessed=session_data.get("last_accessed", datetime.now(UTC)),
            )
            return r[FlextAuthModels.Session].ok(session)

        def get_active_sessions(
            self, user_id: str
        ) -> r[list[FlextAuthModels.Session]]:
            """Get all active sessions for a user."""
            sessions: list[FlextAuthModels.Session] = []
            for session_id, session_data in self._sessions.items():
                identity_id_value = session_data.get("identity_id")
                if (
                    isinstance(identity_id_value, str)
                    and identity_id_value == user_id
                    and self._is_session_active(session_data)
                ):
                    # Extract only fields that Session model accepts
                    session = FlextAuthModels.Session(
                        identity_id=str(session_data["identity_id"]),
                        session_token=str(session_data["session_token"]),
                        expires_at=session_data["expires_at"],
                        is_active=bool(session_data.get("is_active", True)),
                        ip_address=str(session_data.get("ip_address", "")),
                        user_agent=str(session_data.get("user_agent", "")),
                        last_accessed=session_data.get(
                            "last_accessed", datetime.now(UTC)
                        ),
                    )
                    # Set unique_id from session_id
                    session.unique_id = session_id
                    sessions.append(session)
            return r[list[FlextAuthModels.Session]].ok(sessions)

        def end_session(self, user_id: str) -> r[bool]:
            """End all sessions for a user."""
            found = False
            for session_data in self._sessions.values():
                identity_id_value = session_data.get("identity_id")
                if isinstance(identity_id_value, str) and identity_id_value == user_id:
                    session_data["is_active"] = False
                    found = True

            if found:
                return r[bool].ok(True)
            return r[bool].fail("No sessions found for user")

        def end_session_by_id(self, session_id: str) -> r[bool]:
            """End a specific session."""
            if session_id in self._sessions:
                self._sessions[session_id]["is_active"] = False
                return r[bool].ok(True)

            return r[bool].fail("Session not found")

        def end_all_sessions(self, user_id: str) -> r[bool]:
            """End all sessions for a user."""
            return self.end_session(user_id)

        def get_total_active_sessions(self) -> int:
            """Get total count of active sessions."""
            return sum(
                1
                for session in self._sessions.values()
                if self._is_session_active(session)
            )

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

    class FlextAuthAuditLogger:
        """Audit logging business logic.

        Records authentication and authorization events for compliance and debugging.
        Uses newer FlextConfig features for complete integration.
        """

        # Event type constants - consolidates 11 methods into constants
        # Note: These are event type identifiers, not passwords
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

        def __init__(
            self, config: FlextAuthConfig, dispatcher: FlextDispatcher
        ) -> None:
            """Initialize audit logger with configuration."""
            super().__init__()
            self._config = config
            self._dispatcher = dispatcher
            self.logger = FlextLogger(__name__)
            self._context = FlextContext()
            self._logs: list[dict[str, object]] = []  # In production, use database

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

        # Convenience shortcuts for backward compatibility (thin wrappers)
        def log_auth_success(
            self,
            username: str,
            provider: str,
            **extra: str | int | bool | list[str] | datetime | None,
        ) -> None:
            """Log successful authentication."""
            self.log_event(
                self._EVENT_AUTH_SUCCESS,
                username=username,
                provider=provider,
                **extra,
            )

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

        def log_user_logout(
            self, username: str, **extra: str | int | bool | list[str] | datetime | None
        ) -> None:
            """Log user logout."""
            self.log_event(self._EVENT_USER_LOGOUT, username=username, **extra)

        def log_password_change_success(
            self, username: str, **extra: str | int | bool | list[str] | datetime | None
        ) -> None:
            """Log successful password change."""
            self.log_event(
                self._EVENT_PASSWORD_CHANGE_SUCCESS, username=username, **extra
            )

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

        def log_password_reset(
            self, username: str, **extra: str | int | bool | list[str] | datetime | None
        ) -> None:
            """Log password reset."""
            self.log_event(self._EVENT_PASSWORD_RESET, username=username, **extra)

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

        def get_total_log_entries(self) -> int:
            """Get total count of log entries."""
            return len(self._logs)

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
            self.logger.info(f"Audit event: {event_type}")

        def get_logs(
            self,
            user_id: str | None = None,
            event_type: str | None = None,
            start_date: datetime | None = None,
            end_date: datetime | None = None,
            limit: int = 100,
        ) -> r[list[dict[str, object]]]:
            """Get audit logs with optional filtering."""
            # Filter logs based on criteria
            filtered_logs: list[dict[str, object]] = []

            for log in self._logs:
                # Filter by user_id
                if user_id is not None:
                    username_value = log.get("username")
                    log_user_id_value = log.get("user_id")
                    if not (
                        isinstance(username_value, str) and username_value == user_id
                    ) and not (
                        isinstance(log_user_id_value, str)
                        and log_user_id_value == user_id
                    ):
                        continue

                # Filter by event_type
                if event_type is not None:
                    log_event_type = log.get("event_type")
                    if (
                        not isinstance(log_event_type, str)
                        or log_event_type != event_type
                    ):
                        continue

                # Filter by start_date
                if start_date is not None:
                    log_timestamp = log.get("timestamp")
                    if (
                        not isinstance(log_timestamp, datetime)
                        or log_timestamp < start_date
                    ):
                        continue

                # Filter by end_date
                if end_date is not None:
                    log_timestamp = log.get("timestamp")
                    if (
                        not isinstance(log_timestamp, datetime)
                        or log_timestamp > end_date
                    ):
                        continue

                filtered_logs.append(log)

            # Apply limit and return
            return r[list[dict[str, object]]].ok(filtered_logs[-limit:])

    class FlextAuthRateLimiter:
        """Rate limiting business logic.

        Prevents brute force attacks by limiting authentication attempts.
        Uses newer FlextConfig features for complete integration.
        """

        def __init__(
            self, config: FlextAuthConfig, dispatcher: FlextDispatcher
        ) -> None:
            """Initialize rate limiter with configuration."""
            super().__init__()
            self._config = config
            self._dispatcher = dispatcher
            self.logger = FlextLogger(__name__)
            self._context = FlextContext()
            self._registry = FlextRegistry(dispatcher)
            self._attempts: dict[
                str, dict[str, object]
            ] = {}  # username -> attempt data (dict for dynamic key access)
            self._max_attempts = 5
            self._window_minutes = 15

        def _cleanup_window(self, username: str, now: datetime) -> list[datetime]:
            """Clean up attempts outside the time window.

            Generic pattern used in 2 methods - eliminates duplication.
            """
            window_start = now - timedelta(minutes=self._window_minutes)
            attempt_data = self._attempts.get(username)
            if not isinstance(attempt_data, dict):
                return []
            attempts_value = attempt_data.get("attempts")
            if not isinstance(attempts_value, list):
                return []
            return [
                attempt
                for attempt in attempts_value
                if isinstance(attempt, datetime) and attempt > window_start
            ]

        def check_rate_limit(self, username: str) -> r[bool]:
            """Check if user is within rate limits.

            Returns:
                r[bool]: True if within limits, False if exceeded, error on failure

            """
            now = datetime.now(UTC)

            if username not in self._attempts:
                return r[bool].ok(True)

            # Filter attempts within the window
            recent_attempts = self._cleanup_window(username, now)
            if username not in self._attempts:
                self._attempts[username] = {}
            self._attempts[username]["attempts"] = (
                recent_attempts  # Update stored attempts
            )

            if len(recent_attempts) >= self._max_attempts:
                return r[bool].fail(
                    "Too many failed attempts. Please try again later."
                )

            return r[bool].ok(True)

        def record_failed_attempt(self, username: str) -> None:
            """Record a failed authentication attempt."""
            now = datetime.now(UTC)

            if username not in self._attempts:
                self._attempts[username] = {"attempts": []}

            attempts_list = self._attempts[username].get("attempts")
            if not isinstance(attempts_list, list):
                attempts_list = []
                self._attempts[username]["attempts"] = attempts_list
            attempts_list.append(now)

            # Clean up old entries
            recent_attempts = self._cleanup_window(username, now)
            self._attempts[username]["attempts"] = recent_attempts

        def get_total_failed_attempts(self) -> int:
            """Get total count of failed attempts across all users."""
            return sum(len(attempts) for attempts in self._attempts.values())
