"""FLEXT Auth Managers - Core business logic managers for authentication.

This module provides the core business logic managers that handle user management,
session management, audit logging, and rate limiting for the flext-auth library.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from flext_auth.config import FlextAuthConfig
from flext_auth.models import FlextAuthModels
from flext_core import (
    FlextBus,
    FlextContext,
    FlextDispatcher,
    FlextLogger,
    FlextProcessors,
    FlextRegistry,
    FlextResult,
    FlextTypes,
)


class FlextAuthUserManager:
    """User management business logic.

    Handles user CRUD operations, role/permission management, and user data persistence.
    Uses newer FlextConfig features for complete integration.
    """

    def __init__(self, config: FlextAuthConfig) -> None:
        """Initialize user manager with configuration."""
        self._config = config
        self._logger = FlextLogger(__name__)
        self._context = FlextContext()
        self._bus = FlextBus()
        self._users: FlextTypes.NestedDict = {}  # In production, use database

    def create_user(
        self,
        username: str,
        email: str,
        password_hash: str,
        **extra_fields: object,
    ) -> FlextResult[FlextAuthModels.User]:
        """Create a new user."""
        if username in self._users:
            return FlextResult[FlextAuthModels.User].fail("User already exists")

        user_id = str(uuid4())
        user_data = {
            "id": user_id,
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "active": True,
            "roles": [],
            "permissions": [],
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
            **extra_fields,
        }

        self._users[username] = user_data
        user = FlextAuthModels.User(**user_data)
        return FlextResult[FlextAuthModels.User].ok(user)

    def get_user(self, user_id: str) -> FlextResult[FlextAuthModels.User]:
        """Get user by ID."""
        for user_data in self._users.values():
            if user_data["id"] == user_id:
                user = FlextAuthModels.User(**user_data)
                return FlextResult[FlextAuthModels.User].ok(user)

        return FlextResult[FlextAuthModels.User].fail("User not found")

    def get_user_by_username(self, username: str) -> FlextResult[FlextAuthModels.User]:
        """Get user by username."""
        if username not in self._users:
            return FlextResult[FlextAuthModels.User].fail("User not found")

        user_data = self._users[username]
        user = FlextAuthModels.User(**user_data)
        return FlextResult[FlextAuthModels.User].ok(user)

    def update_user(
        self, user_id: str, **updates: object
    ) -> FlextResult[FlextAuthModels.User]:
        """Update user data."""
        for user_data in self._users.values():
            if user_data["id"] == user_id:
                user_data.update(updates)
                user_data["updated_at"] = datetime.now(UTC)
                user = FlextAuthModels.User(**user_data)
                return FlextResult[FlextAuthModels.User].ok(user)

        return FlextResult[FlextAuthModels.User].fail("User not found")

    def delete_user(self, user_id: str) -> FlextResult[None]:
        """Delete user."""
        for username, user_data in self._users.items():
            if user_data["id"] == user_id:
                del self._users[username]
                return FlextResult[None].ok(None)

        return FlextResult[None].fail("User not found")

    def add_user_role(self, user_id: str, role: str) -> FlextResult[None]:
        """Add role to user."""
        for user_data in self._users.values():
            if user_data["id"] == user_id:
                if role not in user_data["roles"]:
                    user_data["roles"].append(role)
                return FlextResult[None].ok(None)

        return FlextResult[None].fail("User not found")

    def remove_user_role(self, user_id: str, role: str) -> FlextResult[None]:
        """Remove role from user."""
        for user_data in self._users.values():
            if user_data["id"] == user_id:
                if role in user_data["roles"]:
                    user_data["roles"].remove(role)
                return FlextResult[None].ok(None)

        return FlextResult[None].fail("User not found")

    def add_user_permission(self, user_id: str, permission: str) -> FlextResult[None]:
        """Add permission to user."""
        for user_data in self._users.values():
            if user_data["id"] == user_id:
                if permission not in user_data["permissions"]:
                    user_data["permissions"].append(permission)
                return FlextResult[None].ok(None)

        return FlextResult[None].fail("User not found")

    def remove_user_permission(
        self, user_id: str, permission: str
    ) -> FlextResult[None]:
        """Remove permission from user."""
        for user_data in self._users.values():
            if user_data["id"] == user_id:
                if permission in user_data["permissions"]:
                    user_data["permissions"].remove(permission)
                return FlextResult[None].ok(None)

        return FlextResult[None].fail("User not found")


class FlextAuthSessionManager:
    """Session management business logic.

    Handles user session creation, validation, and cleanup.
    Uses newer FlextConfig features for complete integration.
    """

    def __init__(self, config: FlextAuthConfig) -> None:
        """Initialize session manager with configuration."""
        self._config = config
        self._logger = FlextLogger(__name__)
        self._context = FlextContext()
        self._bus = FlextBus()
        self._dispatcher = FlextDispatcher()
        self._sessions: FlextTypes.NestedDict = {}  # In production, use Redis/database

    def create_session(
        self,
        user_id: str,
        token: str,
        expires_in_minutes: int = 60,
    ) -> FlextResult[FlextAuthModels.AuthSession]:
        """Create a new session."""
        session_id = str(uuid4())
        expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)

        session_data = {
            "id": session_id,
            "user_id": user_id,
            "token": token,
            "created_at": datetime.now(UTC),
            "expires_at": expires_at,
            "active": True,
        }

        self._sessions[session_id] = session_data
        session = FlextAuthModels.AuthSession(**session_data)
        return FlextResult[FlextAuthModels.AuthSession].ok(session)

    def get_active_sessions(
        self, user_id: str
    ) -> FlextResult[list[FlextAuthModels.AuthSession]]:
        """Get all active sessions for a user."""
        sessions = []
        for session_data in self._sessions.values():
            if (
                session_data["user_id"] == user_id
                and session_data["active"]
                and session_data["expires_at"] > datetime.now(UTC)
            ):
                session = FlextAuthModels.AuthSession(**session_data)
                sessions.append(session)

        return FlextResult[list[FlextAuthModels.AuthSession]].ok(sessions)

    def end_session(self, user_id: str) -> FlextResult[None]:
        """End all sessions for a user."""
        for session_data in self._sessions.values():
            if session_data["user_id"] == user_id:
                session_data["active"] = False

        return FlextResult[None].ok(None)

    def end_session_by_id(self, session_id: str) -> FlextResult[None]:
        """End a specific session."""
        if session_id in self._sessions:
            self._sessions[session_id]["active"] = False
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
            if session["active"] and session["expires_at"] > datetime.now(UTC)
        )


class FlextAuthAuditLogger:
    """Audit logging business logic.

    Records authentication and authorization events for compliance and debugging.
    Uses newer FlextConfig features for complete integration.
    """

    def __init__(self, config: FlextAuthConfig) -> None:
        """Initialize audit logger with configuration."""
        self._config = config
        self._logger = FlextLogger(__name__)
        self._context = FlextContext()
        self._bus = FlextBus()
        self._processors = FlextProcessors()
        self._logs: list[FlextTypes.NestedDict] = []  # In production, use database

    def log_auth_success(self, username: str, provider: str, **extra: object) -> None:
        """Log successful authentication."""
        self._log_event("auth_success", username=username, provider=provider, **extra)

    def log_auth_failure(
        self, username: str, provider: str, reason: str, **extra: object
    ) -> None:
        """Log failed authentication."""
        self._log_event(
            "auth_failure", username=username, provider=provider, reason=reason, **extra
        )

    def log_token_validation(
        self, username: str | None = None, *, success: bool = True, **extra: object
    ) -> None:
        """Log token validation attempt."""
        event_type = (
            "token_validation_success" if success else "token_validation_failure"
        )
        self._log_event(event_type, username=username, **extra)

    def log_token_refresh(
        self, username: str | None = None, *, success: bool = True, **extra: object
    ) -> None:
        """Log token refresh attempt."""
        event_type = "token_refresh_success" if success else "token_refresh_failure"
        self._log_event(event_type, username=username, **extra)

    def log_token_creation(
        self,
        user_id: str | None = None,
        token_type: str | None = None,
        *,
        success: bool = True,
        **extra: object,
    ) -> None:
        """Log token creation attempt."""
        event_type = "token_creation_success" if success else "token_creation_failure"
        self._log_event(event_type, user_id=user_id, token_type=token_type, **extra)

    def log_user_logout(self, username: str, **extra: object) -> None:
        """Log user logout."""
        self._log_event("user_logout", username=username, **extra)

    def log_password_change_success(self, username: str, **extra: object) -> None:
        """Log successful password change."""
        self._log_event("password_change_success", username=username, **extra)

    def log_password_change_failure(self, username: str, reason: str, **extra: object) -> None:
        """Log failed password change."""
        self._log_event(
            "password_change_failure", username=username, reason=reason, **extra
        )

    def log_password_reset(self, username: str, **extra: object) -> None:
        """Log password reset."""
        self._log_event("password_reset", username=username, **extra)

    def log_authorization_check(
        self, username: str, resource: str, action: str, allowed: bool, **extra
    ) -> None:
        """Log authorization check."""
        event_type = "authorization_granted" if allowed else "authorization_denied"
        self._log_event(
            event_type, username=username, resource=resource, action=action, **extra
        )

    def get_logs(
        self, limit: int = 100, **filters: object
    ) -> FlextResult[list[FlextTypes.NestedDict]]:
        """Get audit logs with optional filtering."""
        logs = self._logs[-limit:]  # Get most recent logs
        # Apply filters if provided
        if filters:
            filtered_logs = [
                log for log in logs if all(log.get(k) == v for k, v in filters.items())
            ]
            logs = filtered_logs

        return FlextResult[list[FlextTypes.NestedDict]].ok(logs)

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
        self._logger.info(f"Audit event: {event_type}", extra=log_entry)


class FlextAuthRateLimiter:
    """Rate limiting business logic.

    Prevents brute force attacks by limiting authentication attempts.
    Uses newer FlextConfig features for complete integration.
    """

    def __init__(self, config: FlextAuthConfig) -> None:
        """Initialize rate limiter with configuration."""
        self._config = config
        self._logger = FlextLogger(__name__)
        self._context = FlextContext()
        self._bus = FlextBus()
        self._registry = FlextRegistry()
        self._attempts: FlextTypes.NestedDict = {}  # username -> list of timestamps
        self._max_attempts = 5  # Configurable
        self._window_minutes = 15  # Configurable

    def check_rate_limit(self, username: str) -> FlextResult[None]:
        """Check if user is within rate limits."""
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=self._window_minutes)

        if username not in self._attempts:
            return FlextResult[None].ok(None)

        # Filter attempts within the window
        recent_attempts = [
            attempt for attempt in self._attempts[username] if attempt > window_start
        ]

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
        window_start = now - timedelta(minutes=self._window_minutes)
        self._attempts[username] = [
            attempt for attempt in self._attempts[username] if attempt > window_start
        ]

    def get_total_failed_attempts(self) -> int:
        """Get total count of failed attempts across all users."""
        return sum(len(attempts) for attempts in self._attempts.values())
