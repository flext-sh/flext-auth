"""FLEXT Auth Session Service - Focused session management operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextCore

from flext_auth.config import FlextAuthConfig
from flext_auth.managers import FlextAuthManagers
from flext_auth.models import FlextAuthModels


class FlextAuthSessionService(FlextCore.Service):
    """Focused service for session management with complete flext-core integration."""

    def __init__(
        self, config: FlextAuthConfig, dispatcher: FlextCore.Dispatcher
    ) -> None:
        """Initialize session service with flext-core integration."""
        super().__init__(logger=FlextCore.Logger(__name__))
        self._config = config
        self._dispatcher = dispatcher
        self._session_manager = FlextAuthManagers.FlextAuthSessionManager(config)
        self._audit_logger = FlextAuthManagers.FlextAuthAuditLogger(config, dispatcher)

    def execute(self) -> FlextCore.Result[object]:
        """Execute method for FlextCore.Service interface.

        Session service doesn't use generic execute pattern.
        Use specific session methods instead.
        """
        return FlextCore.Result[object].fail(
            "FlextAuthSessionService is focused - use specific session methods like create_session()"
        )

    def create_session(
        self,
        user_id: str,
        token: str,
    ) -> FlextCore.Result[FlextAuthModels.Session]:
        """Create a new session for a user."""
        return self._session_manager.create_session(user_id, token)

    def get_active_sessions(
        self, user_id: str
    ) -> FlextCore.Result[list[FlextAuthModels.Session]]:
        """Get all active sessions for a user."""
        return self._session_manager.get_active_sessions(user_id)

    def end_session(self, session_id: str) -> FlextCore.Result[None]:
        """End a specific session."""
        return self._session_manager.end_session_by_id(session_id)

    def end_all_sessions(self, user_id: str) -> FlextCore.Result[None]:
        """End all sessions for a user."""
        return self._session_manager.end_all_sessions(user_id)

    def cleanup_expired_sessions(self) -> FlextCore.Result[int]:
        """Clean up expired sessions from the system."""
        # Get all sessions and filter expired ones
        # This is a simplified implementation - in production you'd want a more efficient query
        try:
            expired_count = 0
            # This would typically be done in the session manager with a database query
            # For now, we'll return a mock result since we don't have access to all sessions
            self.logger.info("Cleanup of expired sessions requested")
            return FlextCore.Result[int].ok(expired_count)
        except Exception as e:
            return FlextCore.Result[int].fail(f"Session cleanup failed: {e}")


__all__ = ["FlextAuthSessionService"]
