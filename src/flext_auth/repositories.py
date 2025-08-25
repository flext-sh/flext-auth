"""FLEXT Auth Repositories - SIMPLIFIED REAL production implementation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

SIMPLIFIED REAL PRODUCTION REPOSITORIES - NO MOCKS, NO FAKES.
"""

from __future__ import annotations

import asyncio
from abc import abstractmethod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from flext_core import (
    FlextEntityId,
    FlextProtocols,
    FlextResult,
    FlextTimestamp,
)

from .entities import FlextUser, FlextUserRole, FlextUserStatus
from .flext_auth_types import SessionRepositoryProtocol, UserRepositoryProtocol
from .models import FlextSession, FlextSessionStatus

if TYPE_CHECKING:
    import asyncpg  # type: ignore[import-untyped]
else:
    try:
        import asyncpg
    except ImportError:
        asyncpg = None  # type: ignore[assignment]


# FLEXT MIGRATION: Use FlextProtocols.Infrastructure.Connection for database pool
class AsyncPGPool(FlextProtocols.Infrastructure.Connection):
    """Protocol for asyncpg connection pool - REAL typing without Any.

    FLEXT REFACTORING: Migrated from local Protocol to FlextProtocols.Infrastructure.Connection
    to eliminate Protocol duplication and ensure architectural compliance.
    """

    @abstractmethod
    def acquire(self) -> AsyncPGConnectionContext:
        """Acquire connection from pool."""
        ...


# FLEXT MIGRATION: Use FlextProtocols.Infrastructure.Connection for connection context
class AsyncPGConnectionContext(FlextProtocols.Infrastructure.Connection):
    """Protocol for asyncpg connection context manager - REAL typing.

    FLEXT REFACTORING: Migrated from local Protocol to FlextProtocols.Infrastructure.Connection
    to eliminate Protocol duplication and ensure architectural compliance.
    """

    @abstractmethod
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


# FLEXT MIGRATION: Use FlextProtocols.Infrastructure.Connection for database connection
class AsyncPGConnection(FlextProtocols.Infrastructure.Connection):
    """Protocol for asyncpg connection - REAL typing without Any.

    FLEXT REFACTORING: Migrated from local Protocol to FlextProtocols.Infrastructure.Connection
    to eliminate Protocol duplication and ensure architectural compliance.
    """

    @abstractmethod
    async def execute(self, query: str, *args: object) -> str:
        """Execute query returning result string."""
        ...

    @abstractmethod
    async def fetchval(self, query: str, *args: object) -> object:
        """Fetch single value."""
        ...

    @abstractmethod
    async def fetchrow(self, query: str, *args: object) -> AsyncPGRecord | None:
        """Fetch single row."""
        ...

    @abstractmethod
    async def fetch(self, query: str, *args: object) -> list[AsyncPGRecord]:
        """Fetch multiple rows."""
        ...


# FLEXT MIGRATION: Use FlextProtocols.Infrastructure.Connection for database record
class AsyncPGRecord(FlextProtocols.Infrastructure.Connection):
    """Protocol for asyncpg record - REAL typing with proper types.

    FLEXT REFACTORING: Migrated from local Protocol to FlextProtocols.Infrastructure.Connection
    to eliminate Protocol duplication and ensure architectural compliance.
    """

    @abstractmethod
    def __getitem__(self, key: str) -> str | int | datetime | None:
        """Get field value by name with proper database types."""
        ...


# ✅ CORRECT - Use centralized repository protocol from types.py
# Replaces duplicate protocol definition with import from centralized types
FlextUserRepository = UserRepositoryProtocol


# ✅ CORRECT - Use centralized repository protocol from types.py
# Replaces duplicate protocol definition with import from centralized types
FlextSessionRepository = SessionRepositoryProtocol


class SimplePostgreSQLUserRepository(FlextUserRepository):
    """SIMPLIFIED PostgreSQL user repository - REAL implementation."""

    def __init__(self, connection_pool: AsyncPGPool) -> None:
        """Initialize with REAL PostgreSQL connection pool."""
        self._pool = connection_pool

    def save(self, entity: FlextUser) -> FlextResult[FlextUser]:
        """Save user to REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_save() -> FlextResult[FlextUser]:
            try:
                async with self._pool.acquire() as conn:
                    # Check if user already exists
                    existing = await conn.fetchval(
                        "SELECT id FROM flext_users WHERE username = $1 OR email = $2",
                        entity.username,
                        str(entity.email),
                    )

                    if existing:
                        return FlextResult[FlextUser].fail(
                            f"User with username '{entity.username}' or email '{entity.email}' already exists",
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
                        str(entity.id),
                        entity.username,
                        str(entity.email),
                        entity.password_hash,
                        entity.role.value,
                        entity.status.value,
                        entity.failed_login_attempts,
                        entity.locked_until,
                        entity.last_login,
                        entity.created_at.root,
                        datetime.now(UTC),
                    )

                    # Return the user (simplified - just return the same user)
                    return FlextResult[FlextUser].ok(entity)

            except Exception as e:
                return FlextResult[FlextUser].fail(f"Database error saving user: {e}")

        try:
            return asyncio.run(_async_save())
        except Exception as e:
            return FlextResult[FlextUser].fail(f"AsyncIO error: {e}")

    def get_by_id(self, entity_id: str) -> FlextResult[FlextUser | None]:
        """Get user by ID from REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_get_by_id() -> FlextResult[FlextUser | None]:
            try:
                async with self._pool.acquire() as conn:
                    row = await conn.fetchrow(
                        "SELECT * FROM flext_users WHERE id = $1",
                        entity_id,
                    )

                    if not row:
                        return FlextResult[FlextUser | None].ok(None)

                    user = self._row_to_user(row)
                    return FlextResult[FlextUser | None].ok(user)

            except Exception as e:
                return FlextResult[FlextUser | None].fail(
                    f"Database error getting user: {e}",
                )

        try:
            return asyncio.run(_async_get_by_id())
        except Exception as e:
            return FlextResult[FlextUser | None].fail(f"AsyncIO error: {e}")

    def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username from REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_get_by_username() -> FlextResult[FlextUser | None]:
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

        try:
            return asyncio.run(_async_get_by_username())
        except Exception as e:
            return FlextResult[FlextUser | None].fail(f"AsyncIO error: {e}")

    def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email from REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_get_by_email() -> FlextResult[FlextUser | None]:
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

        try:
            return asyncio.run(_async_get_by_email())
        except Exception as e:
            return FlextResult[FlextUser | None].fail(f"AsyncIO error: {e}")

    def delete(self, entity_id: str) -> FlextResult[None]:
        """Delete user from REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_delete() -> FlextResult[None]:
            try:
                async with self._pool.acquire() as conn:
                    result = await conn.execute(
                        "DELETE FROM flext_users WHERE id = $1",
                        entity_id,
                    )
                    if result == "DELETE 1":
                        return FlextResult[None].ok(None)
                    return FlextResult[None].fail("User not found")

            except Exception as e:
                return FlextResult[None].fail(f"Database error deleting user: {e}")

        try:
            return asyncio.run(_async_delete())
        except Exception as e:
            return FlextResult[None].fail(f"AsyncIO error: {e}")

    def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[list[FlextUser]]:
        """List users from REAL PostgreSQL database with pagination (sync interface with async implementation)."""
        async def _async_list_users() -> FlextResult[list[FlextUser]]:
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

        try:
            return asyncio.run(_async_list_users())
        except Exception as e:
            return FlextResult[list[FlextUser]].fail(f"AsyncIO error: {e}")

    def count_users(
        self,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[int]:
        """Count users in REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_count_users() -> FlextResult[int]:
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

        try:
            return asyncio.run(_async_count_users())
        except Exception as e:
            return FlextResult[int].fail(f"AsyncIO error: {e}")

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

    def find_all(self) -> FlextResult[list[FlextUser]]:
        """Find all users - implementing core Repository pattern (sync interface with async implementation)."""
        async def _async_find_all() -> FlextResult[list[FlextUser]]:
            try:
                async with self._pool.acquire() as conn:
                    rows = await conn.fetch("SELECT * FROM flext_users")
                    users = [self._row_to_user(row) for row in rows]
                    return FlextResult[list[FlextUser]].ok(users)
            except Exception as e:
                return FlextResult[list[FlextUser]].fail(f"Database error: {e}")

        try:
            return asyncio.run(_async_find_all())
        except Exception as e:
            return FlextResult[list[FlextUser]].fail(f"AsyncIO error: {e}")


class SimplePostgreSQLSessionRepository(FlextSessionRepository):
    """SIMPLIFIED PostgreSQL session repository - REAL implementation."""

    def __init__(self, connection_pool: AsyncPGPool) -> None:
        """Initialize with REAL PostgreSQL connection pool."""
        self._pool = connection_pool

    def save(self, entity: FlextSession) -> FlextResult[FlextSession]:
        """Save session to REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_save() -> FlextResult[FlextSession]:
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
                        str(entity.id),
                        entity.user_id,
                        entity.access_token,
                        entity.refresh_token,
                        entity.status.value,
                        entity.ip_address,
                        entity.user_agent,
                        entity.expires_at,
                        entity.created_at.root,
                        entity.last_accessed,
                    )

                    return FlextResult[FlextSession].ok(entity)

            except Exception as e:
                return FlextResult[FlextSession].fail(f"Database error saving session: {e}")

        try:
            return asyncio.run(_async_save())
        except Exception as e:
            return FlextResult[FlextSession].fail(f"AsyncIO error: {e}")

    def get_by_id(self, entity_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID from REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_get_by_id() -> FlextResult[FlextSession | None]:
            try:
                async with self._pool.acquire() as conn:
                    row = await conn.fetchrow(
                        "SELECT * FROM flext_sessions WHERE id = $1",
                        entity_id,
                    )

                    if not row:
                        return FlextResult[FlextSession | None].ok(None)

                    session = self._row_to_session(row)
                    return FlextResult[FlextSession | None].ok(session)

            except Exception as e:
                return FlextResult[FlextSession | None].fail(
                    f"Database error getting session: {e}",
                )

        try:
            return asyncio.run(_async_get_by_id())
        except Exception as e:
            return FlextResult[FlextSession | None].fail(f"AsyncIO error: {e}")

    def get_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Get all sessions for user from REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_get_by_user_id() -> FlextResult[list[FlextSession]]:
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

        try:
            return asyncio.run(_async_get_by_user_id())
        except Exception as e:
            return FlextResult[list[FlextSession]].fail(f"AsyncIO error: {e}")

    def delete(self, entity_id: str) -> FlextResult[None]:
        """Delete session from REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_delete() -> FlextResult[None]:
            try:
                async with self._pool.acquire() as conn:
                    result = await conn.execute(
                        "DELETE FROM flext_sessions WHERE id = $1",
                        entity_id,
                    )
                    if result == "DELETE 1":
                        return FlextResult[None].ok(None)
                    return FlextResult[None].fail("Session not found")

            except Exception as e:
                return FlextResult[None].fail(f"Database error deleting session: {e}")

        try:
            return asyncio.run(_async_delete())
        except Exception as e:
            return FlextResult[None].fail(f"AsyncIO error: {e}")

    def cleanup_expired(self) -> FlextResult[int]:
        """Cleanup expired sessions from REAL PostgreSQL database (sync interface with async implementation)."""
        async def _async_cleanup_expired() -> FlextResult[int]:
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

        try:
            return asyncio.run(_async_cleanup_expired())
        except Exception as e:
            return FlextResult[int].fail(f"AsyncIO error: {e}")

    def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke a specific session by ID (sync interface with async implementation)."""
        async def _async_revoke_session() -> FlextResult[bool]:
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

        try:
            return asyncio.run(_async_revoke_session())
        except Exception as e:
            return FlextResult[bool].fail(f"AsyncIO error: {e}")

    def revoke_all_user_sessions(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user (sync interface with async implementation)."""
        async def _async_revoke_all_user_sessions() -> FlextResult[int]:
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

        try:
            return asyncio.run(_async_revoke_all_user_sessions())
        except Exception as e:
            return FlextResult[int].fail(f"AsyncIO error: {e}")

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Cleanup expired sessions - alias for cleanup_expired (sync interface)."""
        return self.cleanup_expired()

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

    def find_all(self) -> FlextResult[list[FlextSession]]:
        """Find all sessions - implementing core Repository pattern (sync interface with async implementation)."""
        async def _async_find_all() -> FlextResult[list[FlextSession]]:
            try:
                async with self._pool.acquire() as conn:
                    rows = await conn.fetch("SELECT * FROM flext_sessions")
                    sessions = [self._row_to_session(row) for row in rows]
                    return FlextResult[list[FlextSession]].ok(sessions)
            except Exception as e:
                return FlextResult[list[FlextSession]].fail(f"Database error: {e}")

        try:
            return asyncio.run(_async_find_all())
        except Exception as e:
            return FlextResult[list[FlextSession]].fail(f"AsyncIO error: {e}")


def create_postgresql_pool(database_url: str) -> AsyncPGPool:
    """Create REAL PostgreSQL connection pool - proper typing (sync interface with async implementation)."""
    async def _async_create_pool() -> AsyncPGPool:
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

    return asyncio.run(_async_create_pool())


def initialize_database_schema(pool: AsyncPGPool) -> FlextResult[None]:
    """Initialize REAL database schemas - proper typing (sync interface with async implementation)."""
    async def _async_initialize_schema() -> FlextResult[None]:
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

    try:
        return asyncio.run(_async_initialize_schema())
    except Exception as e:
        return FlextResult[None].fail(f"AsyncIO error: {e}")


__all__ = [
    "FlextSessionRepository",
    "FlextUserRepository",
    "SimplePostgreSQLSessionRepository",
    "SimplePostgreSQLUserRepository",
    "create_postgresql_pool",
    "initialize_database_schema",
]
