"""FLEXT Auth Session - Session management and repository patterns.

This module provides session management functionality following PEP8 strict naming patterns.
It consolidates session repository interfaces and implementations with comprehensive
session lifecycle management for the FLEXT authentication ecosystem.

Architecture:
    - Infrastructure Layer: Session persistence and management
    - Repository Pattern: Abstract data access with multiple implementations
    - Railway-Oriented: FlextResult[T] for type-safe error handling
    - Domain-Driven: Operates on FlextSession domain entities

Core Components:
    Session Management:
    - Session lifecycle management
    - Active session tracking
    - Session expiration and cleanup
    - Concurrent session limits enforcement

    Repository Patterns:
    - SessionRepository: Abstract session repository interface
    - InMemorySessionRepository: Fast in-memory storage for development/testing

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime

from flext_core import FlextResult

from flext_auth.models import FlextSession, FlextSessionStatus

# =============================================================================
# SESSION REPOSITORY PATTERNS - Abstract data access
# =============================================================================


class SessionRepository(ABC):
    """Abstract repository for session operations."""

    @abstractmethod
    async def save(self, session: FlextSession) -> FlextResult[FlextSession]:
        """Save session to repository (async)."""

    @abstractmethod
    def find_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Find session by ID."""

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Find all sessions for a user."""

    @abstractmethod
    def revoke_all_sessions_for_user(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user."""

    @abstractmethod
    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Clean up expired sessions."""

    # Compatibility async methods expected by service layer
    async def get_by_id(
        self,
        session_id: str,
    ) -> FlextResult[FlextSession | None]:  # pragma: no cover - thin adapter
        return self.find_by_id(session_id)

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


class InMemorySessionRepository(SessionRepository):
    """In-memory session repository for testing and development."""

    def __init__(self) -> None:
        """Initialize empty session storage."""
        self._sessions: dict[str, FlextSession] = {}

    async def save(self, session: FlextSession) -> FlextResult[FlextSession]:
        """Save session to memory (async)."""
        try:
            self._sessions[session.id] = session
            return FlextResult.ok(session)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to save session: {e}")

    def find_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Find session by ID."""
        try:
            session = self._sessions.get(session_id)
            return FlextResult.ok(session)
        except (KeyError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to find session: {e}")

    def find_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Find all sessions for a user."""
        try:
            user_sessions = [
                session
                for session in self._sessions.values()
                if session.user_id == user_id
            ]
            return FlextResult.ok(user_sessions)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to find user sessions: {e}")

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

            return FlextResult.ok(revoked_count)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to revoke user sessions: {e}")

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Clean up expired sessions."""
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
            return FlextResult.ok(len(expired_sessions))
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to cleanup expired sessions: {e}")

    # Additional async compatibility methods used by refactored service
    async def get_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        return self.find_by_id(session_id)

    async def get_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        return self.find_by_user_id(user_id)

    async def revoke_session(self, session_id: str) -> FlextResult[bool]:
        try:
            if session_id in self._sessions:
                session = self._sessions[session_id]
                self._sessions[session_id] = session.revoke()
                return FlextResult.ok(data=True)
            return FlextResult.ok(data=False)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to revoke session: {e}")

    async def revoke_all_user_sessions(self, user_id: str) -> FlextResult[int]:
        return self.revoke_all_sessions_for_user(user_id)

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
            return FlextResult.ok(active_count)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to count active sessions: {e}")


# =============================================================================
# EXPORTS - Clean session API
# =============================================================================

__all__: list[str] = [
    "InMemorySessionRepository",
    # Repository Patterns
    "SessionRepository",
]
