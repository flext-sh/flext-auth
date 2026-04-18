"""Session concern mixin for the FlextAuth service facade."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from flext_auth import m, p

if TYPE_CHECKING:
    from flext_auth.services.session_service import FlextAuthSessionService


class FlextAuthSessionMixin:
    """Session operations concern: cleanup, retrieval, logout, and revoke."""

    _session_service: FlextAuthSessionService

    def cleanup_expired_sessions(self) -> p.Result[int]:
        """Clean up expired sessions and return affected count."""
        return self._session_service.cleanup_expired_sessions()

    def get_user_sessions(self, user_id: str) -> p.Result[Sequence[m.Auth.Session]]:
        """Get active sessions for a user."""
        return self._session_service.session_manager.get_active_sessions(user_id)

    def logout_user(self, session_id: str) -> p.Result[bool]:
        """Logout user by session ID."""
        return self._session_service.session_manager.end_session_by_id(session_id)

    def revoke_session(self, session_id: str) -> p.Result[bool]:
        """Revoke a session by ID."""
        return self._session_service.session_manager.end_session_by_id(session_id)
