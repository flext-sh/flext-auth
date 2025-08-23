"""FLEXT Auth Repositories - SIMPLIFIED REAL production implementation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

SIMPLIFIED REAL PRODUCTION REPOSITORIES - NO MOCKS, NO FAKES.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, cast

from flext_core import FlextEntityId, FlextResult, FlextTimestamp

from flext_auth.entities import FlextUser, FlextUserRole, FlextUserStatus
from flext_auth.models import FlextSession, FlextSessionStatus

if TYPE_CHECKING:
    pass
else:
    try:
        import asyncpg
    except ImportError:
        asyncpg = None


class AsyncPGPool(Protocol):
    """Protocol for asyncpg connection pool - REAL typing without Any."""

    def acquire(self) -> AsyncPGConnectionContext:
        """Acquire connection from pool."""
        ...


class AsyncPGConnectionContext(Protocol):
    """Protocol for asyncpg connection context manager - REAL typing."""

    async def __aenter__(self) -> AsyncPGConnection:
        """Enter context manager."""
        ...

    async def __aexit__(
        self,
        exc_type: object,
        exc_val: object,
        exc_tb: object,
    ) -> None:
        """Exit context manager."""
        ...


class AsyncPGConnection(Protocol):
    """Protocol for asyncpg connection - REAL typing without Any."""

    async def execute(self, query: str, *args: object) -> str:
        """Execute query returning result string."""
        ...

    async def fetchval(self, query: str, *args: object) -> object:
        """Fetch single value."""
        ...

    async def fetchrow(self, query: str, *args: object) -> AsyncPGRecord | None:
        """Fetch single row."""
        ...

    async def fetch(self, query: str, *args: object) -> list[AsyncPGRecord]:
        """Fetch multiple rows."""
        ...


class AsyncPGRecord(Protocol):
    """Protocol for asyncpg record - REAL typing with proper types."""

    def __getitem__(self, key: str) -> str | int | datetime | None:
        """Get field value by name with proper database types."""
        ...


class FlextUserRepository(ABC):
    """Abstract repository for REAL production user operations."""

    @abstractmethod
    async def save(self, user: FlextUser) -> FlextResult[FlextUser]:
        """Save user to REAL production storage."""

    @abstractmethod
    async def get_by_id(self, user_id: str) -> FlextResult[FlextUser | None]:
        """Get user by ID from REAL production storage."""

    @abstractmethod
    async def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username from REAL production storage."""

    @abstractmethod
    async def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email from REAL production storage."""

    @abstractmethod
    async def delete(self, user_id: str) -> FlextResult[bool]:
        """Delete user from REAL production storage."""

    @abstractmethod
    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[list[FlextUser]]:
        """List users from REAL production storage with pagination."""

    @abstractmethod
    async def count_users(
        self,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[int]:
        """Count users in REAL production storage."""


class FlextSessionRepository(ABC):
    """Abstract repository for REAL production session operations."""

    @abstractmethod
    async def save(self, session: FlextSession) -> FlextResult[FlextSession]:
        """Save session to REAL production storage."""

    @abstractmethod
    async def get_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID from REAL production storage."""

    @abstractmethod
    async def get_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Get all sessions for user from REAL production storage."""

    @abstractmethod
    async def delete(self, session_id: str) -> FlextResult[bool]:
        """Delete session from REAL production storage."""

    @abstractmethod
    async def cleanup_expired(self) -> FlextResult[int]:
        """Cleanup expired sessions from REAL production storage."""

    @abstractmethod
    async def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke a specific session by ID."""

    @abstractmethod
    async def revoke_all_user_sessions(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user."""

    @abstractmethod
    async def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Cleanup expired sessions - alias for cleanup_expired."""


class SimplePostgreSQLUserRepository(FlextUserRepository):
    """SIMPLIFIED PostgreSQL user repository - REAL implementation."""

    def __init__(self, connection_pool: AsyncPGPool) -> None:
        """Initialize with REAL PostgreSQL connection pool."""
        self._pool = connection_pool

    async def save(self, user: FlextUser) -> FlextResult[FlextUser]:
        """Save user to REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                # Check if user already exists
                existing = await conn.fetchval(
                    "SELECT id FROM flext_users WHERE username = $1 OR email = $2",
                    user.username,
                    str(user.email),
                )

                if existing:
                    return FlextResult[FlextUser].fail(
                        f"User with username '{user.username}' or email '{user.email}' already exists",
                    )

                # Insert new user
                await conn.execute(
                    """
                    INSERT INTO flext_users (
                        id, username, email, password_hash, role, status,
                        failed_login_attempts, locked_until, last_login,
                        created_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                """,
                    str(user.id),
                    user.username,
                    str(user.email),
                    user.password_hash,
                    user.role.value,
                    user.status.value,
                    user.failed_login_attempts,
                    user.locked_until,
                    user.last_login,
                    user.created_at.root,
                    datetime.now(UTC),
                )

                # Return the user (simplified - just return the same user)
                return FlextResult[FlextUser].ok(user)

        except Exception as e:
            return FlextResult[FlextUser].fail(f"Database error saving user: {e}")

    async def get_by_id(self, user_id: str) -> FlextResult[FlextUser | None]:
        """Get user by ID from REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM flext_users WHERE id = $1",
                    user_id,
                )

                if not row:
                    return FlextResult[FlextUser | None].ok(None)

                user = self._row_to_user(row)
                return FlextResult[FlextUser | None].ok(user)

        except Exception as e:
            return FlextResult[FlextUser | None].fail(
                f"Database error getting user: {e}",
            )

    async def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username from REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM flext_users WHERE username = $1",
                    username,
                )

                if not row:
                    return FlextResult[FlextUser | None].ok(None)

                user = self._row_to_user(row)
                return FlextResult[FlextUser | None].ok(user)

        except Exception as e:
            return FlextResult[FlextUser | None].fail(
                f"Database error getting user: {e}",
            )

    async def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email from REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM flext_users WHERE email = $1",
                    email,
                )

                if not row:
                    return FlextResult[FlextUser | None].ok(None)

                user = self._row_to_user(row)
                return FlextResult[FlextUser | None].ok(user)

        except Exception as e:
            return FlextResult[FlextUser | None].fail(
                f"Database error getting user: {e}",
            )

    async def delete(self, user_id: str) -> FlextResult[bool]:
        """Delete user from REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM flext_users WHERE id = $1",
                    user_id,
                )
                return FlextResult[bool].ok(result == "DELETE 1")

        except Exception as e:
            return FlextResult[bool].fail(f"Database error deleting user: {e}")

    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[list[FlextUser]]:
        """List users from REAL PostgreSQL database with pagination."""
        try:
            async with self._pool.acquire() as conn:
                if status:
                    rows = await conn.fetch(
                        """
                        SELECT * FROM flext_users
                        WHERE status = $1
                        ORDER BY created_at DESC
                        LIMIT $2 OFFSET $3
                    """,
                        status.value,
                        limit,
                        offset,
                    )
                else:
                    rows = await conn.fetch(
                        """
                        SELECT * FROM flext_users
                        ORDER BY created_at DESC
                        LIMIT $1 OFFSET $2
                    """,
                        limit,
                        offset,
                    )

                users = [self._row_to_user(row) for row in rows]
                return FlextResult[list[FlextUser]].ok(users)

        except Exception as e:
            return FlextResult[list[FlextUser]].fail(
                f"Database error listing users: {e}",
            )

    async def count_users(
        self,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[int]:
        """Count users in REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                if status:
                    count = await conn.fetchval(
                        "SELECT COUNT(*) FROM flext_users WHERE status = $1",
                        status.value,
                    )
                else:
                    count = await conn.fetchval("SELECT COUNT(*) FROM flext_users")

                return FlextResult[int].ok(cast("int", count or 0))

        except Exception as e:
            return FlextResult[int].fail(f"Database error counting users: {e}")

    def _row_to_user(self, row: AsyncPGRecord) -> FlextUser:
        """Convert database row to FlextUser entity - REAL typing."""
        return FlextUser(
            id=FlextEntityId(str(row["id"])),
            username=str(row["username"]),
            email=str(row["email"]),
            password_hash=str(row["password_hash"]),
            role=FlextUserRole(str(row["role"])),
            status=FlextUserStatus(str(row["status"])),
            failed_login_attempts=cast("int", row["failed_login_attempts"] or 0),
            locked_until=cast("datetime | None", row["locked_until"]),
            last_login=cast("datetime | None", row["last_login"]),
            created_at=FlextTimestamp(cast("datetime", row["created_at"])),
            updated_at=FlextTimestamp(cast("datetime", row["updated_at"]))
            if row["updated_at"]
            else FlextTimestamp.now(),
        )


class SimplePostgreSQLSessionRepository(FlextSessionRepository):
    """SIMPLIFIED PostgreSQL session repository - REAL implementation."""

    def __init__(self, connection_pool: AsyncPGPool) -> None:
        """Initialize with REAL PostgreSQL connection pool."""
        self._pool = connection_pool

    async def save(self, session: FlextSession) -> FlextResult[FlextSession]:
        """Save session to REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO flext_sessions (
                        id, user_id, access_token, refresh_token, status,
                        ip_address, user_agent, expires_at, created_at, last_accessed
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (id) DO UPDATE SET
                        access_token = EXCLUDED.access_token,
                        refresh_token = EXCLUDED.refresh_token,
                        status = EXCLUDED.status,
                        last_accessed = EXCLUDED.last_accessed
                """,
                    str(session.id),
                    session.user_id,
                    session.access_token,
                    session.refresh_token,
                    session.status.value,
                    session.ip_address,
                    session.user_agent,
                    session.expires_at,
                    session.created_at.root,
                    session.last_accessed,
                )

                return FlextResult[FlextSession].ok(session)

        except Exception as e:
            return FlextResult[FlextSession].fail(f"Database error saving session: {e}")

    async def get_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID from REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM flext_sessions WHERE id = $1",
                    session_id,
                )

                if not row:
                    return FlextResult[FlextSession | None].ok(None)

                session = self._row_to_session(row)
                return FlextResult[FlextSession | None].ok(session)

        except Exception as e:
            return FlextResult[FlextSession | None].fail(
                f"Database error getting session: {e}",
            )

    async def get_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Get all sessions for user from REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT * FROM flext_sessions
                    WHERE user_id = $1 AND status = 'active'
                    ORDER BY last_accessed DESC
                """,
                    user_id,
                )

                sessions = [self._row_to_session(row) for row in rows]
                return FlextResult[list[FlextSession]].ok(sessions)

        except Exception as e:
            return FlextResult[list[FlextSession]].fail(
                f"Database error getting sessions: {e}",
            )

    async def delete(self, session_id: str) -> FlextResult[bool]:
        """Delete session from REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM flext_sessions WHERE id = $1",
                    session_id,
                )
                return FlextResult[bool].ok(result == "DELETE 1")

        except Exception as e:
            return FlextResult[bool].fail(f"Database error deleting session: {e}")

    async def cleanup_expired(self) -> FlextResult[int]:
        """Cleanup expired sessions from REAL PostgreSQL database."""
        try:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    """
                    DELETE FROM flext_sessions
                    WHERE expires_at < $1 OR status != 'active'
                """,
                    datetime.now(UTC),
                )

                # Extract number from "DELETE N" string
                count = int(result.split()[1]) if result.startswith("DELETE") else 0
                return FlextResult[int].ok(count)

        except Exception as e:
            return FlextResult[int].fail(f"Database error cleaning sessions: {e}")

    async def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke a specific session by ID."""
        try:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    """
                    UPDATE flext_sessions
                    SET status = 'revoked'
                    WHERE id = $1
                """,
                    session_id,
                )

                # Check if any rows were updated
                updated = (
                    result.endswith(" 1") if result.startswith("UPDATE") else False
                )
                return FlextResult[bool].ok(updated)

        except Exception as e:
            return FlextResult[bool].fail(f"Database error revoking session: {e}")

    async def revoke_all_user_sessions(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user."""
        try:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    """
                    UPDATE flext_sessions
                    SET status = 'revoked'
                    WHERE user_id = $1 AND status = 'active'
                """,
                    user_id,
                )

                # Extract number from "UPDATE N" string
                count = int(result.split()[1]) if result.startswith("UPDATE") else 0
                return FlextResult[int].ok(count)

        except Exception as e:
            return FlextResult[int].fail(f"Database error revoking user sessions: {e}")

    async def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Cleanup expired sessions - alias for cleanup_expired."""
        return await self.cleanup_expired()

    def _row_to_session(self, row: AsyncPGRecord) -> FlextSession:
        """Convert database row to FlextSession entity - REAL typing."""
        return FlextSession(
            id=FlextEntityId(str(row["id"])),
            user_id=str(row["user_id"]),
            access_token=str(row["access_token"]),
            refresh_token=str(row["refresh_token"]) if row["refresh_token"] else None,
            status=FlextSessionStatus(str(row["status"])),
            ip_address=str(row["ip_address"]) if row["ip_address"] else None,
            user_agent=str(row["user_agent"]) if row["user_agent"] else None,
            expires_at=cast("datetime", row["expires_at"]),
            created_at=FlextTimestamp(cast("datetime", row["created_at"])),
            last_accessed=cast("datetime", row["last_accessed"]),
        )


async def create_postgresql_pool(database_url: str) -> AsyncPGPool:
    """Create REAL PostgreSQL connection pool - proper typing."""
    if asyncpg is None:
        msg = "asyncpg is required for PostgreSQL support"
        raise ImportError(msg)

    pool = await asyncpg.create_pool(
        database_url,
        min_size=1,
        max_size=10,
        command_timeout=60,
    )
    return cast("AsyncPGPool", pool)


async def initialize_database_schema(pool: AsyncPGPool) -> FlextResult[None]:
    """Initialize REAL database schemas - proper typing."""
    try:
        async with pool.acquire() as conn:
            # Create users table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS flext_users (
                    id VARCHAR(255) PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMPTZ,
                    last_login TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                );
            """)

            # Create sessions table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS flext_sessions (
                    id VARCHAR(255) PRIMARY KEY,
                    user_id VARCHAR(255) NOT NULL,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT,
                    status VARCHAR(20) NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    last_accessed TIMESTAMPTZ NOT NULL
                );
            """)

        return FlextResult[None].ok(None)
    except Exception as e:
        return FlextResult[None].fail(f"Failed to initialize database: {e}")


__all__ = [
    "FlextSessionRepository",
    "FlextUserRepository",
    "SimplePostgreSQLSessionRepository",
    "SimplePostgreSQLUserRepository",
    "create_postgresql_pool",
    "initialize_database_schema",
]
