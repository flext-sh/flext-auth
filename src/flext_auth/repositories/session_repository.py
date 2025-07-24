"""Session repository interfaces and implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from flext_auth.core import ServiceResult
from flext_auth.domain.entities import Session, SessionStatus


class SessionRepository(ABC):
    """Abstract repository for session operations."""

    @abstractmethod
    async def save(self, session: Session) -> ServiceResult[Session]:
        """Save session to repository."""

    @abstractmethod
    async def get_by_id(self, session_id: str) -> ServiceResult[Session | None]:
        """Get session by ID."""

    @abstractmethod
    async def get_by_user_id(self, user_id: str) -> ServiceResult[list[Session]]:
        """Get all sessions for a user."""

    @abstractmethod
    async def get_active_sessions(self, user_id: str) -> ServiceResult[list[Session]]:
        """Get active sessions for a user."""

    @abstractmethod
    async def revoke_session(self, session_id: str) -> ServiceResult[bool]:
        """Revoke a specific session."""

    @abstractmethod
    async def revoke_all_user_sessions(self, user_id: str) -> ServiceResult[int]:
        """Revoke all sessions for a user."""

    @abstractmethod
    async def cleanup_expired_sessions(self) -> ServiceResult[int]:
        """Remove expired sessions."""

    @abstractmethod
    async def delete(self, session_id: str) -> ServiceResult[bool]:
        """Delete session from repository."""


class InMemorySessionRepository(SessionRepository):
    """In-memory session repository for testing and development."""

    def __init__(self) -> None:
        """Initialize empty session storage."""
        self._sessions: dict[str, Session] = {}
        self._user_sessions: dict[str, list[str]] = {}  # user_id -> [session_ids]

    async def save(self, session: Session) -> ServiceResult[Session]:
        """Save session to memory."""
        try:
            # Update last accessed
            session.last_accessed = datetime.now(UTC)

            # Save session
            self._sessions[session.id] = session

            # Update user sessions index
            if session.user_id not in self._user_sessions:
                self._user_sessions[session.user_id] = []

            if session.id not in self._user_sessions[session.user_id]:
                self._user_sessions[session.user_id].append(session.id)

            return ServiceResult.ok(session)

        except Exception as e:
            return ServiceResult.fail(f"Failed to save session: {e}")

    async def get_by_id(self, session_id: str) -> ServiceResult[Session | None]:
        """Get session by ID."""
        try:
            session = self._sessions.get(session_id)
            return ServiceResult.ok(session)
        except Exception as e:
            return ServiceResult.fail(f"Failed to get session by ID: {e}")

    async def get_by_user_id(self, user_id: str) -> ServiceResult[list[Session]]:
        """Get all sessions for a user."""
        try:
            session_ids = self._user_sessions.get(user_id, [])
            sessions = [
                self._sessions[sid] for sid in session_ids if sid in self._sessions
            ]

            # Clean up broken references
            valid_ids = [s.id for s in sessions]
            self._user_sessions[user_id] = valid_ids

            return ServiceResult.ok(sessions)
        except Exception as e:
            return ServiceResult.fail(f"Failed to get sessions by user ID: {e}")

    async def get_active_sessions(self, user_id: str) -> ServiceResult[list[Session]]:
        """Get active sessions for a user."""
        try:
            all_sessions_result = await self.get_by_user_id(user_id)
            if not all_sessions_result.is_success:
                return all_sessions_result

            active_sessions = [s for s in all_sessions_result.data if s.is_valid()]

            return ServiceResult.ok(active_sessions)
        except Exception as e:
            return ServiceResult.fail(f"Failed to get active sessions: {e}")

    async def revoke_session(self, session_id: str) -> ServiceResult[bool]:
        """Revoke a specific session."""
        try:
            session = self._sessions.get(session_id)
            if not session:
                return ServiceResult.ok(False)

            session.revoke()
            return ServiceResult.ok(True)
        except Exception as e:
            return ServiceResult.fail(f"Failed to revoke session: {e}")

    async def revoke_all_user_sessions(self, user_id: str) -> ServiceResult[int]:
        """Revoke all sessions for a user."""
        try:
            sessions_result = await self.get_by_user_id(user_id)
            if not sessions_result.is_success:
                return ServiceResult.fail(
                    f"Failed to get user sessions: {sessions_result.error}"
                )

            revoked_count = 0
            for session in sessions_result.data:
                if session.status == SessionStatus.ACTIVE:
                    session.revoke()
                    revoked_count += 1

            return ServiceResult.ok(revoked_count)
        except Exception as e:
            return ServiceResult.fail(f"Failed to revoke all user sessions: {e}")

    async def cleanup_expired_sessions(self) -> ServiceResult[int]:
        """Remove expired sessions."""
        try:
            expired_ids = []
            now = datetime.now(UTC)

            for session_id, session in self._sessions.items():
                if session.expires_at <= now:
                    expired_ids.append(session_id)

            # Remove expired sessions
            for session_id in expired_ids:
                session = self._sessions.pop(session_id, None)
                if session and session.user_id in self._user_sessions:
                    if session_id in self._user_sessions[session.user_id]:
                        self._user_sessions[session.user_id].remove(session_id)

            return ServiceResult.ok(len(expired_ids))
        except Exception as e:
            return ServiceResult.fail(f"Failed to cleanup expired sessions: {e}")

    async def delete(self, session_id: str) -> ServiceResult[bool]:
        """Delete session from memory."""
        try:
            session = self._sessions.pop(session_id, None)
            if not session:
                return ServiceResult.ok(False)

            # Remove from user sessions index
            if session.user_id in self._user_sessions:
                if session_id in self._user_sessions[session.user_id]:
                    self._user_sessions[session.user_id].remove(session_id)

            return ServiceResult.ok(True)
        except Exception as e:
            return ServiceResult.fail(f"Failed to delete session: {e}")


class PostgreSQLSessionRepository(SessionRepository):
    """PostgreSQL session repository implementation."""

    def __init__(self, connection_url: str) -> None:
        """Initialize PostgreSQL repository."""
        self.connection_url = connection_url
        self._connection_pool: Any = None

    async def _get_connection(self) -> Any:
        """Get database connection from pool."""
        if not self._connection_pool:
            try:
                import asyncpg

                self._connection_pool = await asyncpg.create_pool(
                    self.connection_url,
                    min_size=1,
                    max_size=10,
                    command_timeout=60,
                )
            except ImportError as e:
                raise ImportError(
                    "asyncpg is required for PostgreSQL repository"
                ) from e
            except Exception as e:
                raise RuntimeError(f"Failed to create connection pool: {e}") from e

        return await self._connection_pool.acquire()

    async def _release_connection(self, connection: Any) -> None:
        """Release connection back to pool."""
        if self._connection_pool:
            await self._connection_pool.release(connection)

    async def _ensure_tables(self) -> ServiceResult[bool]:
        """Ensure session tables exist."""
        try:
            connection = await self._get_connection()

            try:
                await connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sessions (
                        id VARCHAR(255) PRIMARY KEY,
                        user_id VARCHAR(255) NOT NULL,
                        access_token TEXT NOT NULL,
                        refresh_token TEXT,
                        status VARCHAR(50) NOT NULL DEFAULT 'active',
                        ip_address INET,
                        user_agent TEXT,
                        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        last_accessed TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                    );

                    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
                    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
                    CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
                """
                )

                return ServiceResult.ok(True)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to ensure tables: {e}")

    async def save(self, session: Session) -> ServiceResult[Session]:
        """Save session to PostgreSQL."""
        try:
            table_result = await self._ensure_tables()
            if not table_result.is_success:
                return ServiceResult.fail(f"Table setup failed: {table_result.error}")

            connection = await self._get_connection()

            try:
                session.last_accessed = datetime.now(UTC)

                await connection.execute(
                    """
                    INSERT INTO sessions (
                        id, user_id, access_token, refresh_token, status,
                        ip_address, user_agent, expires_at, created_at, last_accessed
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (id) DO UPDATE SET
                        access_token = EXCLUDED.access_token,
                        refresh_token = EXCLUDED.refresh_token,
                        status = EXCLUDED.status,
                        expires_at = EXCLUDED.expires_at,
                        last_accessed = EXCLUDED.last_accessed
                """,
                    session.id,
                    session.user_id,
                    session.access_token,
                    session.refresh_token,
                    session.status.value,
                    session.ip_address,
                    session.user_agent,
                    session.expires_at,
                    session.created_at,
                    session.last_accessed,
                )

                return ServiceResult.ok(session)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to save session: {e}")

    async def get_by_id(self, session_id: str) -> ServiceResult[Session | None]:
        """Get session by ID from PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                row = await connection.fetchrow(
                    "SELECT * FROM sessions WHERE id = $1", session_id
                )

                if not row:
                    return ServiceResult.ok(None)

                session = self._row_to_session(row)
                return ServiceResult.ok(session)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to get session by ID: {e}")

    async def get_by_user_id(self, user_id: str) -> ServiceResult[list[Session]]:
        """Get all sessions for a user from PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                rows = await connection.fetch(
                    "SELECT * FROM sessions WHERE user_id = $1 ORDER BY created_at DESC",
                    user_id,
                )

                sessions = [self._row_to_session(row) for row in rows]
                return ServiceResult.ok(sessions)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to get sessions by user ID: {e}")

    async def get_active_sessions(self, user_id: str) -> ServiceResult[list[Session]]:
        """Get active sessions for a user from PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                rows = await connection.fetch(
                    """
                    SELECT * FROM sessions
                    WHERE user_id = $1
                    AND status = 'active'
                    AND expires_at > NOW()
                    ORDER BY created_at DESC
                """,
                    user_id,
                )

                sessions = [self._row_to_session(row) for row in rows]
                return ServiceResult.ok(sessions)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to get active sessions: {e}")

    async def revoke_session(self, session_id: str) -> ServiceResult[bool]:
        """Revoke a specific session in PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                result = await connection.execute(
                    "UPDATE sessions SET status = 'revoked' WHERE id = $1", session_id
                )

                updated = result.split()[-1] == "1"
                return ServiceResult.ok(updated)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to revoke session: {e}")

    async def revoke_all_user_sessions(self, user_id: str) -> ServiceResult[int]:
        """Revoke all sessions for a user in PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                result = await connection.execute(
                    "UPDATE sessions SET status = 'revoked' WHERE user_id = $1 AND status = 'active'",
                    user_id,
                )

                count = int(result.split()[-1])
                return ServiceResult.ok(count)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to revoke all user sessions: {e}")

    async def cleanup_expired_sessions(self) -> ServiceResult[int]:
        """Remove expired sessions from PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                result = await connection.execute(
                    "DELETE FROM sessions WHERE expires_at <= NOW()"
                )

                count = int(result.split()[-1])
                return ServiceResult.ok(count)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to cleanup expired sessions: {e}")

    async def delete(self, session_id: str) -> ServiceResult[bool]:
        """Delete session from PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                result = await connection.execute(
                    "DELETE FROM sessions WHERE id = $1", session_id
                )

                deleted = result.split()[-1] == "1"
                return ServiceResult.ok(deleted)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to delete session: {e}")

    def _row_to_session(self, row: Any) -> Session:
        """Convert database row to Session entity."""
        return Session(
            id=row["id"],
            user_id=row["user_id"],
            access_token=row["access_token"],
            refresh_token=row["refresh_token"],
            status=SessionStatus(row["status"]),
            ip_address=str(row["ip_address"]) if row["ip_address"] else None,
            user_agent=row["user_agent"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
            last_accessed=row["last_accessed"],
        )

    async def close(self) -> None:
        """Close database connection pool."""
        if self._connection_pool:
            await self._connection_pool.close()
