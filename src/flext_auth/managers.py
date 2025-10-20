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
    FlextBus,
    FlextContext,
    FlextDispatcher,
    FlextLogger,
    FlextProcessors,
    FlextRegistry,
    FlextResult,
    FlextService,
)

from flext_auth.config import FlextAuthConfig
from flext_auth.models import FlextAuthModels
from flext_auth.typings import FlextAuthTypes


class ServiceManagerMixin:
    """Common manager initialization mixin for all auth services.

    Eliminates 3x duplication of manager initialization across
    user_service, token_service, and session_service.

    This mixin provides the single source of truth for manager setup.
    """

    def _init_managers(
        self, config: FlextAuthConfig, dispatcher: FlextDispatcher
    ) -> None:
        """Initialize all standard managers used by services.

        Called by service __init__ methods to set up managers once.
        """
        self._config = config
        self._dispatcher = dispatcher
        self._user_manager = FlextAuthManagers.FlextAuthUserManager(config)
        self._session_manager = FlextAuthManagers.FlextAuthSessionManager(config)
        self._audit_logger = FlextAuthManagers.FlextAuthAuditLogger(config, dispatcher)
        self._rate_limiter = FlextAuthManagers.FlextAuthRateLimiter(config, dispatcher)


class FlextAuthManagers(FlextService[object]):
    """Namespace class for all authentication managers following FLEXT patterns.

    This namespace class contains all manager implementations as nested classes,
    providing a single import point while maintaining clean separation of concerns.
    """

    def execute(self) -> FlextResult[object]:
        """Execute method for FlextService interface.

        FlextAuthManagers is a namespace class - use specific manager classes instead.
        """
        return FlextResult[object].fail(
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
            self._bus = FlextBus()
            self._users: dict[
                str, FlextAuthTypes.Managers.UserData
            ] = {}  # In production, use database

        def _find_user_by_id(
            self, user_id: str
        ) -> FlextResult[tuple[str, FlextAuthTypes.Managers.UserData]]:
            """Find user by ID (either identity_id or id field).

            Eliminates duplication across 7 methods.
            """
            for username, user_data in self._users.items():
                if (
                    user_data.get("identity_id") == user_id
                    or user_data.get("id") == user_id
                ):
                    return FlextResult.ok((username, user_data))
            return FlextResult.fail("User not found")

        def _modify_user_list_field(
            self, user_id: str, field: str, value: str, *, add: bool = True
        ) -> FlextResult[None]:
            """Add or remove value from user list field (roles/permissions).

            Generic list field modifier - eliminates duplication in 4 methods.
            """
            return self._find_user_by_id(user_id).map(
                lambda ud: self._apply_list_modification(ud[1], field, value, add=add)
            )

        def _apply_list_modification(
            self,
            user_data: FlextAuthTypes.Managers.UserData,
            field: str,
            value: str,
            *,
            add: bool = True,
        ) -> None:
            """Apply list modification atomically."""
            field_list = user_data.get(field, [])
            if isinstance(field_list, list):
                if add and value not in field_list:
                    field_list.append(value)
                elif not add and value in field_list:
                    field_list.remove(value)

        def create_user(
            self,
            username: str,
            email: str,
            password_hash: str,
            **extra_fields: object,
        ) -> FlextResult[FlextAuthModels.Identity]:
            """Create a new user."""
            if username in self._users:
                return FlextResult[FlextAuthModels.Identity].fail(
                    "Identity already exists"
                )

            user_id = str(uuid4())
            user_data = {
                "id": user_id,  # For base class compatibility
                "name": username,
                "contact": email,
                "credential_hash": password_hash,
                "is_active": extra_fields.get("is_active", True),
                "roles": extra_fields.get("roles", []),
                "permissions": extra_fields.get("permissions", []),
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            }

            self._users[username] = user_data
            user = FlextAuthModels.Identity(**user_data)
            return FlextResult[FlextAuthModels.Identity].ok(user)

        def get_user(self, user_id: str) -> FlextResult[FlextAuthModels.Identity]:
            """Get user by ID."""
            return self._find_user_by_id(user_id).map(
                lambda ud: FlextAuthModels.Identity(**ud[1])
            )

        def get_user_by_username(
            self, username: str
        ) -> FlextResult[FlextAuthModels.Identity]:
            """Get user by username."""
            if username not in self._users:
                return FlextResult[FlextAuthModels.Identity].fail("User not found")

            user_data = self._users[username]
            user = FlextAuthModels.Identity(**user_data)
            return FlextResult[FlextAuthModels.Identity].ok(user)

        def update_user(
            self, user_id: str, **updates: object
        ) -> FlextResult[FlextAuthModels.Identity]:
            """Update user data."""
            return self._find_user_by_id(user_id).map(
                lambda ud: (
                    ud[1].update(updates),
                    ud[1].update({"updated_at": datetime.now(UTC)}),
                    FlextAuthModels.Identity(**ud[1]),
                )[2]
            )

        def delete_user(self, user_id: str) -> FlextResult[None]:
            """Delete user."""
            result = self._find_user_by_id(user_id)
            if result.is_success:
                username = result.unwrap()[0]
                del self._users[username]
            return result.map(lambda _: None)

        def add_user_role(self, user_id: str, role: str) -> FlextResult[None]:
            """Add role to user."""
            return self._modify_user_list_field(user_id, "roles", role, add=True)

        def remove_user_role(self, user_id: str, role: str) -> FlextResult[None]:
            """Remove role from user."""
            return self._modify_user_list_field(user_id, "roles", role, add=False)

        def add_user_permission(
            self, user_id: str, permission: str
        ) -> FlextResult[None]:
            """Add permission to user."""
            return self._modify_user_list_field(
                user_id, "permissions", permission, add=True
            )

        def remove_user_permission(
            self, user_id: str, permission: str
        ) -> FlextResult[None]:
            """Remove permission from user."""
            return self._modify_user_list_field(
                user_id, "permissions", permission, add=False
            )

        def get_user_by_id(
            self, _user_id: str
        ) -> FlextResult[FlextAuthModels.Identity | None]:
            """Get a user by their ID."""
            # In a real implementation, this would query a database
            # For now, return None as this is a placeholder
            return FlextResult[FlextAuthModels.Identity | None].ok(None)

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
            self._bus = FlextBus()
            self._dispatcher = FlextDispatcher()
            self._sessions: dict[
                str, dict[str, object]
            ] = {}  # In production, use Redis/database

        def _is_session_active(
            self, session_data: FlextAuthTypes.Managers.SessionData
        ) -> bool:
            """Check if session is active and not expired.

            Eliminates duplication of expiration check (appeared 2+ times).
            """
            expires_at = session_data.get("expires_at")
            is_active = session_data.get("is_active", False)
            return (
                bool(is_active)
                and isinstance(expires_at, datetime)
                and expires_at > datetime.now(UTC)
            )

        def create_session(
            self,
            user_id: str,
            token: str,
            expires_in_minutes: int = 60,
        ) -> FlextResult[FlextAuthModels.Session]:
            """Create a new session."""
            session_id = str(uuid4())
            expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)

            session_data = {
                "id": session_id,
                "identity_id": user_id,
                "session_token": token,
                "expires_at": expires_at,
                "is_active": True,
                "last_accessed": datetime.now(UTC),
            }

            self._sessions[session_id] = session_data
            session = FlextAuthModels.Session(**session_data)
            return FlextResult[FlextAuthModels.Session].ok(session)

        def get_active_sessions(
            self, user_id: str
        ) -> FlextResult[list[FlextAuthModels.Session]]:
            """Get all active sessions for a user."""
            sessions = [
                FlextAuthModels.Session(**session_data)
                for session_data in self._sessions.values()
                if session_data.get("identity_id") == user_id
                and self._is_session_active(session_data)
            ]
            return FlextResult[list[FlextAuthModels.Session]].ok(sessions)

        def end_session(self, user_id: str) -> FlextResult[None]:
            """End all sessions for a user."""
            for session_data in self._sessions.values():
                if session_data["identity_id"] == user_id:
                    session_data["is_active"] = False

            return FlextResult[None].ok(None)

        def end_session_by_id(self, session_id: str) -> FlextResult[None]:
            """End a specific session."""
            if session_id in self._sessions:
                self._sessions[session_id]["is_active"] = False
                return FlextResult[None].ok(None)

            return FlextResult[None].fail("Session not found")

        def end_all_sessions(self, user_id: str) -> FlextResult[None]:
            """End all sessions for a user."""
            return self.end_session(user_id)

        def get_total_active_sessions(self) -> int:
            """Get total count of active sessions."""
            return sum(
                1
                for session in self._sessions.values()
                if self._is_session_active(session)
            )

    class FlextAuthAuditLogger:
        """Audit logging business logic.

        Records authentication and authorization events for compliance and debugging.
        Uses newer FlextConfig features for complete integration.
        """

        # Event type constants - consolidates 11 methods into constants
        # Note: These are event type identifiers, not passwords - S105 suppression
        _EVENT_AUTH_SUCCESS = "auth_success"
        _EVENT_AUTH_FAILURE = "auth_failure"
        _EVENT_TOKEN_VALIDATION_SUCCESS = "token_validation_success"  # noqa: S105
        _EVENT_TOKEN_VALIDATION_FAILURE = "token_validation_failure"  # noqa: S105
        _EVENT_TOKEN_REFRESH_SUCCESS = "token_refresh_success"  # noqa: S105
        _EVENT_TOKEN_REFRESH_FAILURE = "token_refresh_failure"  # noqa: S105
        _EVENT_TOKEN_CREATION_SUCCESS = "token_creation_success"  # noqa: S105
        _EVENT_TOKEN_CREATION_FAILURE = "token_creation_failure"  # noqa: S105
        _EVENT_USER_LOGOUT = "user_logout"
        _EVENT_PASSWORD_CHANGE_SUCCESS = "password_change_success"  # noqa: S105
        _EVENT_PASSWORD_CHANGE_FAILURE = "password_change_failure"  # noqa: S105
        _EVENT_PASSWORD_RESET = "password_reset"  # noqa: S105
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
            self._bus = FlextBus()
            self._processors = FlextProcessors()
            self._logs: list[
                FlextAuthTypes.Managers.LogEntry
            ] = []  # In production, use database

        def log_event(self, event_type: str, **data: object) -> None:
            """Generic event logging - single method replaces 11 specific methods.

            Usage:
                self.log_event(self._EVENT_AUTH_SUCCESS, username="user", provider="jwt")
                self.log_event(self._EVENT_TOKEN_VALIDATION_FAILURE, reason="expired")
            """
            self._log_event(event_type, **data)

        # Convenience shortcuts for backward compatibility (thin wrappers)
        def log_auth_success(
            self, username: str, provider: str, **extra: object
        ) -> None:
            """Log successful authentication."""
            self.log_event(
                self._EVENT_AUTH_SUCCESS, username=username, provider=provider, **extra
            )

        def log_auth_failure(
            self, username: str, provider: str, reason: str, **extra: object
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
            self, username: str | None = None, *, success: bool = True, **extra: object
        ) -> None:
            """Log token validation attempt."""
            event_type = (
                self._EVENT_TOKEN_VALIDATION_SUCCESS
                if success
                else self._EVENT_TOKEN_VALIDATION_FAILURE
            )
            self.log_event(event_type, username=username, **extra)

        def log_token_refresh(
            self, username: str | None = None, *, success: bool = True, **extra: object
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
            **extra: object,
        ) -> None:
            """Log token creation attempt."""
            event_type = (
                self._EVENT_TOKEN_CREATION_SUCCESS
                if success
                else self._EVENT_TOKEN_CREATION_FAILURE
            )
            self.log_event(event_type, user_id=user_id, token_type=token_type, **extra)

        def log_user_logout(self, username: str, **extra: object) -> None:
            """Log user logout."""
            self.log_event(self._EVENT_USER_LOGOUT, username=username, **extra)

        def log_password_change_success(self, username: str, **extra: object) -> None:
            """Log successful password change."""
            self.log_event(
                self._EVENT_PASSWORD_CHANGE_SUCCESS, username=username, **extra
            )

        def log_password_change_failure(
            self, username: str, reason: str, **extra: object
        ) -> None:
            """Log failed password change."""
            self.log_event(
                self._EVENT_PASSWORD_CHANGE_FAILURE,
                username=username,
                reason=reason,
                **extra,
            )

        def log_password_reset(self, username: str, **extra: object) -> None:
            """Log password reset."""
            self.log_event(self._EVENT_PASSWORD_RESET, username=username, **extra)

        def log_authorization_check(
            self,
            username: str,
            resource: str,
            action: str,
            *,
            allowed: bool,
            **extra: object,
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

        def _log_event(self, event_type: str, **data: object) -> None:
            """Log an audit event."""
            log_entry = {
                "id": str(uuid4()),
                "event_type": event_type,
                "timestamp": datetime.now(UTC),
                **data,
            }
            self._logs.append(log_entry)
            self.logger.info(f"Audit event: {event_type}", **log_entry)

        def get_logs(
            self,
            user_id: str | None = None,
            event_type: str | None = None,
            start_date: datetime | None = None,
            end_date: datetime | None = None,
            limit: int = 100,
        ) -> FlextResult[list[dict[str, object]]]:
            """Get audit logs with optional filtering."""
            # Filter logs based on criteria
            filtered_logs = self._logs

            if user_id is not None:
                filtered_logs = [
                    log
                    for log in filtered_logs
                    if log.get("username") == user_id or log.get("user_id") == user_id
                ]

            if event_type is not None:
                filtered_logs = [
                    log for log in filtered_logs if log.get("event_type") == event_type
                ]

            if start_date is not None:
                filtered_logs = [
                    log
                    for log in filtered_logs
                    if log.get("timestamp")
                    and isinstance(log["timestamp"], datetime)
                    and log["timestamp"] >= start_date
                ]

            if end_date is not None:
                filtered_logs = [
                    log
                    for log in filtered_logs
                    if log.get("timestamp")
                    and isinstance(log["timestamp"], datetime)
                    and log["timestamp"] <= end_date
                ]

            # Apply limit and return
            return FlextResult[list[dict[str, object]]].ok(filtered_logs[-limit:])

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
            self._bus = FlextBus()
            self._registry = FlextRegistry(dispatcher)
            self._attempts: dict[
                str, FlextAuthTypes.Managers.AttemptData
            ] = {}  # username -> list of timestamps
            self._max_attempts = 5
            self._window_minutes = 15

        def _cleanup_window(self, username: str, now: datetime) -> list[datetime]:
            """Clean up attempts outside the time window.

            Generic pattern used in 2 methods - eliminates duplication.
            """
            window_start = now - timedelta(minutes=self._window_minutes)
            return [
                attempt
                for attempt in self._attempts.get(username, [])
                if attempt > window_start
            ]

        def check_rate_limit(self, username: str) -> FlextResult[None]:
            """Check if user is within rate limits."""
            now = datetime.now(UTC)

            if username not in self._attempts:
                return FlextResult[None].ok(None)

            # Filter attempts within the window
            recent_attempts = self._cleanup_window(username, now)
            self._attempts[username] = recent_attempts  # Update stored attempts

            if len(recent_attempts) >= self._max_attempts:
                return FlextResult[None].fail(
                    "Too many failed attempts. Please try again later."
                )

            return FlextResult[None].ok(None)

        def record_failed_attempt(self, username: str) -> None:
            """Record a failed authentication attempt."""
            now = datetime.now(UTC)

            if username not in self._attempts:
                self._attempts[username] = []

            self._attempts[username].append(now)

            # Clean up old entries
            self._attempts[username] = self._cleanup_window(username, now)

        def get_total_failed_attempts(self) -> int:
            """Get total count of failed attempts across all users."""
            return sum(len(attempts) for attempts in self._attempts.values())
