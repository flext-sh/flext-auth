"""FLEXT Auth Session System - Single consolidated session management system.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

SINGLE CONSOLIDATED MODULE following FLEXT architectural patterns.
All session functionality consolidated into FlextAuthSessionSystem.
"""

from __future__ import annotations

from abc import abstractmethod
from datetime import UTC, datetime
from typing import ClassVar, override

from flext_core import FlextDomainService, FlextResult

from .models import FlextSession, FlextSessionStatus
from .repositories import FlextSessionRepository


class FlextAuthSessionSystem(FlextDomainService[dict]):
    """SINGLE CONSOLIDATED CLASS for all session functionality.

    Following FLEXT architectural patterns - consolidates ALL session functionality
    including repository patterns, implementations, and session management into one main class
    with nested classes for organization.

    CONSOLIDATED CLASSES: SessionRepository + InMemorySessionRepository + FlextAuthSessionSystem
    """

    # ==========================================================================
    # CONSTANTS AND CONFIGURATION
    # ==========================================================================

    # Session management constants
    DEFAULT_SESSION_TIMEOUT_HOURS: ClassVar[int] = 24
    MAX_CONCURRENT_SESSIONS_PER_USER: ClassVar[int] = 5
    CLEANUP_BATCH_SIZE: ClassVar[int] = 100

    # ==========================================================================
    # NESTED CLASSES FOR ORGANIZATION
    # ==========================================================================

    class SessionRepository(FlextSessionRepository):
        """Nested abstract repository for session operations."""

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

        # Async adapter for service layer compatibility
        async def get_by_id_async(
            self,
            entity_id: str,
        ) -> FlextResult[FlextSession | None]:  # pragma: no cover - thin adapter
            return self.get_by_id(entity_id)

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
        """Nested in-memory session repository implementation."""

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
                    success_value = True
                    return FlextResult[bool].ok(success_value)
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

        # Async delete method for repository interface
        async def delete_async(self, entity_id: str) -> FlextResult[bool]:
            """Delete session from memory (async version)."""
            sync_result = self.delete(entity_id)
            if sync_result.success:
                success_value = True
                return FlextResult[bool].ok(success_value)
            return FlextResult[bool].fail(sync_result.error or "Failed to delete session")

        async def cleanup_expired(self) -> FlextResult[int]:
            """Cleanup expired sessions - async version."""
            return await self.cleanup_expired_sessions()

        # Async find_all method for repository interface
        async def find_all_async(self) -> FlextResult[list[FlextSession]]:
            """Find all sessions - async version."""
            return self.find_all()

    # ==========================================================================
    # MAIN CONSOLIDATED CLASS IMPLEMENTATION
    # ==========================================================================

    def __init__(self, repository: SessionRepository | None = None) -> None:
        """Initialize session system with optional repository."""
        self._repository = repository or self.InMemorySessionRepository()
        super().__init__()

    def execute(self) -> FlextResult[dict]:
        """Execute session system validation and return system info."""
        return FlextResult[dict].ok({
            "repository_type": type(self._repository).__name__,
            "default_timeout_hours": self.DEFAULT_SESSION_TIMEOUT_HOURS,
            "max_concurrent_sessions": self.MAX_CONCURRENT_SESSIONS_PER_USER,
            "status": "initialized"
        })

    # ==========================================================================
    # PUBLIC API METHODS - Session management operations
    # ==========================================================================

    def create_session(
        self,
        user_id: str,
        expires_in_hours: int | None = None,
        metadata: dict[str, str] | None = None,
    ) -> FlextResult[FlextSession]:
        """Create a new session for user."""
        try:
            expires_in = expires_in_hours or self.DEFAULT_SESSION_TIMEOUT_HOURS
            expires_at = datetime.now(UTC).replace(
                hour=datetime.now(UTC).hour + expires_in
            )

            session = FlextSession(
                user_id=user_id,
                expires_at=expires_at,
                status=FlextSessionStatus.ACTIVE,
                metadata=metadata or {}
            )

            return FlextResult[FlextSession].ok(session)
        except Exception as e:
            return FlextResult[FlextSession].fail(f"Failed to create session: {e}")

    def get_session(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID."""
        return self._repository.get_by_id(session_id)

    def get_user_sessions(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Get all active sessions for user."""
        return self._repository.find_by_user_id(user_id)

    def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke specific session."""
        return self._repository.revoke_session(session_id)

    def revoke_all_user_sessions(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for user."""
        return self._repository.revoke_all_sessions_for_user(user_id)

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Cleanup expired sessions."""
        return self._repository.cleanup_expired_sessions()

    def get_active_session_count(self, user_id: str) -> FlextResult[int]:
        """Get count of active sessions for user."""
        if hasattr(self._repository, "get_active_session_count"):
            return self._repository.get_active_session_count(user_id)

        # Fallback implementation
        sessions_result = self.get_user_sessions(user_id)
        if not sessions_result.success:
            return FlextResult[int].fail(sessions_result.error)

        active_count = len([
            s for s in sessions_result.value
            if s.status == FlextSessionStatus.ACTIVE and s.expires_at > datetime.now(UTC)
        ])
        return FlextResult[int].ok(active_count)


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Following FLEXT pattern
# =============================================================================

# Export nested classes for external access (backward compatibility)
SessionRepository = FlextAuthSessionSystem.SessionRepository
InMemorySessionRepository = FlextAuthSessionSystem.InMemorySessionRepository

__all__: list[str] = [
    "FlextAuthSessionSystem",
    # Backward compatibility
    "InMemorySessionRepository",
    "SessionRepository",
]
