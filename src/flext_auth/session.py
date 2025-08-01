"""Session repository interfaces and implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime

from flext_core import FlextResult

from flext_auth.domain.entities import FlextSession, FlextSessionStatus


class SessionRepository(ABC):
    """Abstract repository for session operations."""

    @abstractmethod
    async def save(self, session: FlextSession) -> FlextResult[FlextSession]:
        """Save session to repository."""

    @abstractmethod
    async def get_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID."""

    @abstractmethod
    async def get_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Get all sessions for a user."""

    @abstractmethod
    async def get_active_sessions(
        self,
        user_id: str,
    ) -> FlextResult[list[FlextSession]]:
        """Get active sessions for a user."""

    @abstractmethod
    async def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke a specific session."""

    @abstractmethod
    async def revoke_all_user_sessions(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user."""

    @abstractmethod
    async def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Remove expired sessions."""

    @abstractmethod
    async def delete(self, session_id: str) -> FlextResult[bool]:
        """Delete session from repository."""


class InMemorySessionRepository(SessionRepository):
    """In-memory session repository for testing and development."""

    def __init__(self) -> None:
        """Initialize empty session storage."""
        self._sessions: dict[str, FlextSession] = {}
        self._user_sessions: dict[str, list[str]] = {}  # user_id -> [session_ids]

    # Async methods implementing the interface
    async def save(self, session: FlextSession) -> FlextResult[FlextSession]:
        """Save session to memory."""
        try:
            # Save session (entities are immutable, cannot modify last_accessed)
            self._sessions[session.id] = session

            # Update user sessions index
            if session.user_id not in self._user_sessions:
                self._user_sessions[session.user_id] = []

            if session.id not in self._user_sessions[session.user_id]:
                self._user_sessions[session.user_id].append(session.id)

            return FlextResult.ok(session)

        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to save session: {e}")

    def find_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID (sync version)."""
        try:
            session = self._sessions.get(session_id)
            return FlextResult.ok(session)
        except (KeyError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to get session by ID: {e}")

    def revoke_all_sessions_for_user(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user (sync version)."""
        try:
            session_ids = self._user_sessions.get(user_id, [])
            revoked_count = 0

            for session_id in session_ids:
                if session_id in self._sessions:
                    session = self._sessions[session_id]
                    if session.status == FlextSessionStatus.ACTIVE:
                        # Create revoked session
                        revoked_session = FlextSession(
                            id=session.id,
                            user_id=session.user_id,
                            access_token=session.access_token,
                            refresh_token=session.refresh_token,
                            expires_at=session.expires_at,
                            ip_address=session.ip_address,
                            user_agent=session.user_agent,
                            status=FlextSessionStatus.REVOKED,
                            created_at=session.created_at,
                            last_accessed=datetime.now(UTC),
                        )
                        self._sessions[session_id] = revoked_session
                        revoked_count += 1

            return FlextResult.ok(revoked_count)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to revoke all user sessions: {e}")

    # Sync method for compatibility with existing code
    def save_sync(self, session: FlextSession) -> FlextResult[FlextSession]:
        """Save session synchronously for compatibility."""
        try:
            self._sessions[session.id] = session
            if session.user_id not in self._user_sessions:
                self._user_sessions[session.user_id] = []
            if session.id not in self._user_sessions[session.user_id]:
                self._user_sessions[session.user_id].append(session.id)
            return FlextResult.ok(session)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to save session: {e}")

    async def get_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID."""
        try:
            session = self._sessions.get(session_id)
            return FlextResult.ok(session)
        except (KeyError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to get session by ID: {e}")

    async def get_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Get all sessions for a user."""
        try:
            session_ids = self._user_sessions.get(user_id, [])
            sessions = [
                self._sessions[sid] for sid in session_ids if sid in self._sessions
            ]

            # Clean up broken references
            valid_ids = [s.id for s in sessions]
            self._user_sessions[user_id] = valid_ids

            return FlextResult.ok(sessions)
        except (KeyError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to get sessions by user ID: {e}")

    async def get_active_sessions(
        self,
        user_id: str,
    ) -> FlextResult[list[FlextSession]]:
        """Get active sessions for a user."""
        try:
            all_sessions_result = await self.get_by_user_id(user_id)
            if not all_sessions_result.is_success:
                return all_sessions_result

            active_sessions = [
                s for s in (all_sessions_result.data or []) if s.is_valid()
            ]

            return FlextResult.ok(active_sessions)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to get active sessions: {e}")

    async def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke a specific session."""
        try:
            session = self._sessions.get(session_id)
            if not session:
                return FlextResult.ok(data=False)

            revoked_session = session.revoke()
            self._sessions[session_id] = revoked_session
            return FlextResult.ok(data=True)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to revoke session: {e}")

    async def revoke_all_user_sessions(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user."""
        try:
            sessions_result = await self.get_by_user_id(user_id)
            if not sessions_result.is_success:
                return FlextResult.fail(
                    f"Failed to get user sessions: {sessions_result.error}",
                )

            revoked_count = 0
            for session in sessions_result.data or []:
                if session.status == FlextSessionStatus.ACTIVE:
                    revoked_session = session.revoke()
                    self._sessions[session.id] = revoked_session
                    revoked_count += 1

            return FlextResult.ok(revoked_count)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to revoke all user sessions: {e}")

    async def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Remove expired sessions."""
        try:
            expired_ids = []
            now = datetime.now(UTC)

            for session_id, session in self._sessions.items():
                if session.expires_at <= now:
                    expired_ids.append(session_id)

            # Remove expired sessions
            for session_id in expired_ids:
                if session_id in self._sessions:
                    session = self._sessions.pop(session_id)
                    if (
                        session.user_id in self._user_sessions
                        and session_id in self._user_sessions[session.user_id]
                    ):
                        self._user_sessions[session.user_id].remove(session_id)

            return FlextResult.ok(len(expired_ids))
        except (KeyError, ValueError, TypeError, AttributeError, OSError) as e:
            return FlextResult.fail(f"Failed to cleanup expired sessions: {e}")

    async def delete(self, session_id: str) -> FlextResult[bool]:
        """Delete session from memory."""
        try:
            session = self._sessions.pop(session_id, None)
            if not session:
                return FlextResult.ok(data=False)

            # Remove from user sessions index
            if (
                session.user_id in self._user_sessions
                and session_id in self._user_sessions[session.user_id]
            ):
                self._user_sessions[session.user_id].remove(session_id)

            return FlextResult.ok(data=True)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to delete session: {e}")


# PostgreSQL implementation removed to eliminate code duplication
# Use InMemorySessionRepository for development or implement when actually needed
