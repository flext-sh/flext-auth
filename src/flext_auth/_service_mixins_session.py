"""Session service mixin concern for FlextAuth.

Handles user session lifecycle (creation, retrieval, logout, revocation).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from flext_cli import m, p


class FlextAuthSessionMixin:
    """Session operations mixin.

    Provides user session management (cleanup, retrieval, logout, revocation).
    """

    def cleanup_expired_sessions(self) -> p.Result[int]:
        """Clean up expired sessions.

        Returns:
        Number of sessions cleaned up

        """
        return self._session_service.cleanup_expired_sessions()

    def get_user_sessions(self, user_id: str) -> p.Result[Sequence[m.Auth.Session]]:
        """Get user sessions."""
        return self._session_service.session_manager.get_active_sessions(user_id)

    def logout_user(self, session_id: str) -> p.Result[bool]:
        """Logout user by session ID."""
        return self._session_service.session_manager.end_session_by_id(session_id)

    def revoke_session(self, session_id: str) -> p.Result[bool]:
        """Revoke a session."""
        return self._session_service.session_manager.end_session_by_id(session_id)
