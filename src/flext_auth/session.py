"""FLEXT Auth Session - Session management and repository patterns.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import abstractmethod
from datetime import UTC, datetime
from typing import override

from flext_core import FlextResult

from .constants import FlextAuthSemanticConstants
from .models import FlextSession, FlextSessionStatus
from .repositories import FlextSessionRepository

# =============================================================================
# SESSION REPOSITORY PATTERNS - Abstract data access
# =============================================================================


class SessionRepository(FlextSessionRepository):
    """Abstract repository for session operations."""

    @abstractmethod
    async def save(self, entity: FlextSession) -> FlextResult[FlextSession]:
        """Save session to repository (async)."""

    @abstractmethod
    @override
    def get_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID (sync for flext-core compliance)."""

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Find all sessions for a user."""

    @abstractmethod
    def revoke_all_sessions_for_user(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user."""

    @abstractmethod
    async def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Clean up expired sessions."""

    @abstractmethod
    async def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke a specific session by ID."""

    # Async methods expected by service layer
    async def get_by_id(
        self,
        entity_id: str,
    ) -> FlextResult[FlextSession | None]:  # pragma: no cover - thin adapter
        return self.find_by_id(entity_id)

    async def get_by_user_id(
        self,
        user_id: str,
    ) -> FlextResult[list[FlextSession]]:  # pragma: no cover - thin adapter
        return self.find_by_user_id(user_id)

    async def revoke_all_user_sessions(
        self,
        user_id: str,
    ) -> FlextResult[int]:  # pragma: no cover - thin adapter
        return self.revoke_all_sessions_for_user(user_id)


class InMemorySessionRepository(FlextSessionRepository):
    """In-memory session repository implementation."""

    def __init__(self) -> None:
        """Initialize empty session storage."""
        self._sessions: dict[str, FlextSession] = {}

    async def save(self, entity: FlextSession) -> FlextResult[FlextSession]:
        """Save session to memory (async)."""
        try:
            self._sessions[str(entity.id)] = entity
            return FlextResult[FlextSession].ok(entity)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextSession].fail(f"Failed to save session: {e}")

    @override
    def get_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID (sync for flext-core compliance)."""
        try:
            session = self._sessions.get(session_id)
            # Only return active sessions
            if session and session.status == "active":
                return FlextResult[FlextSession | None].ok(session)
            return FlextResult[FlextSession | None].ok(None)
        except (KeyError, ValueError, TypeError) as e:
            return FlextResult[FlextSession | None].fail(f"Failed to find session: {e}")

    def find_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Find all sessions for a user."""
        try:
            user_sessions = [
                session
                for session in self._sessions.values()
                if session.user_id == user_id and session.status == "active"
            ]
            return FlextResult[list[FlextSession]].ok(user_sessions)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[FlextSession]].fail(
                f"Failed to find user sessions: {e}",
            )

    def revoke_all_sessions_for_user(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user."""
        try:
            revoked_count = 0
            for session_id, session in list(self._sessions.items()):
                if (
                    session.user_id == user_id
                    and session.status == FlextSessionStatus.ACTIVE
                ):
                    revoked_session = session.revoke()
                    self._sessions[session_id] = revoked_session
                    revoked_count += 1

            return FlextResult[int].ok(revoked_count)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[int].fail(f"Failed to revoke user sessions: {e}")

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Clean up expired sessions (sync for flext-core compliance)."""
        try:
            now = datetime.now(UTC)
            expired_sessions: list[str] = []
            for session_id, session in self._sessions.items():
                if (
                    session.expires_at <= now
                    or session.status == FlextSessionStatus.EXPIRED
                ):
                    expired_sessions.append(session_id)
            for session_id in expired_sessions:
                del self._sessions[session_id]
            return FlextResult[int].ok(len(expired_sessions))
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[int].fail(f"Failed to cleanup expired sessions: {e}")

    @override
    def delete(self, session_id: str) -> FlextResult[None]:
        """Delete session by ID (sync for flext-core compliance)."""
        try:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return FlextResult[None].ok(None)
            return FlextResult[None].fail("Session not found")
        except Exception as e:
            return FlextResult[None].fail(f"Failed to delete session: {e}")

    @override
    def find_all(self) -> FlextResult[list[FlextSession]]:
        """Find all sessions (sync for flext-core compliance)."""
        try:
            return FlextResult[list[FlextSession]].ok(list(self._sessions.values()))
        except Exception as e:
            return FlextResult[list[FlextSession]].fail(f"Failed to find all sessions: {e}")

    def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke a specific session (sync for flext-core compliance)."""
        try:
            if session_id in self._sessions:
                session = self._sessions[session_id]
                self._sessions[session_id] = session.revoke()
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail("Session not found")
        except Exception as e:
            return FlextResult[bool].fail(f"Failed to revoke session: {e}")


    def get_active_session_count(self, user_id: str) -> FlextResult[int]:
        """Get count of active sessions for a user."""
        try:
            active_count = sum(
                1
                for session in self._sessions.values()
                if session.user_id == user_id
                and session.status == FlextSessionStatus.ACTIVE
                and session.expires_at > datetime.now(UTC)
            )
            return FlextResult[int].ok(active_count)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[int].fail(f"Failed to count active sessions: {e}")

    # Required FlextSessionRepository abstract methods
    async def delete(self, entity_id: str) -> FlextResult[bool]:
        """Delete session from memory."""
        try:
            if entity_id in self._sessions:
                del self._sessions[entity_id]
                return FlextResult[bool].ok(FlextAuthSemanticConstants.SUCCESS)
            return FlextResult[bool].ok(FlextAuthSemanticConstants.FAILURE)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"Failed to delete session: {e}")

    async def cleanup_expired(self) -> FlextResult[int]:
        """Cleanup expired sessions - async version."""
        return await self.cleanup_expired_sessions()

    async def find_all(self) -> FlextResult[list[FlextSession]]:
        """Find all sessions - implementing core Repository pattern."""
        try:
            sessions = list(self._sessions.values())
            return FlextResult[list[FlextSession]].ok(sessions)
        except Exception as e:
            return FlextResult[list[FlextSession]].fail(f"Failed to get all sessions: {e}")


# =============================================================================
# EXPORTS - Clean session API
# =============================================================================

__all__: list[str] = [
    "InMemorySessionRepository",
    # Repository Patterns
    "SessionRepository",
]
