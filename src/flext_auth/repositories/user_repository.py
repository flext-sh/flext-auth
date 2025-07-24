"""User repository interfaces and implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from flext_auth.core import ServiceResult
from flext_auth.domain.entities import User, UserStatus


class UserRepository(ABC):
    """Abstract repository for user operations."""

    @abstractmethod
    async def save(self, user: User) -> ServiceResult[User]:
        """Save user to repository."""

    @abstractmethod
    async def get_by_id(self, user_id: str) -> ServiceResult[User | None]:
        """Get user by ID."""

    @abstractmethod
    async def get_by_username(self, username: str) -> ServiceResult[User | None]:
        """Get user by username."""

    @abstractmethod
    async def get_by_email(self, email: str) -> ServiceResult[User | None]:
        """Get user by email."""

    @abstractmethod
    async def delete(self, user_id: str) -> ServiceResult[bool]:
        """Delete user from repository."""

    @abstractmethod
    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        status: UserStatus | None = None,
    ) -> ServiceResult[list[User]]:
        """List users with pagination and filtering."""

    @abstractmethod
    async def count_users(self, status: UserStatus | None = None) -> ServiceResult[int]:
        """Count users with optional status filter."""


class InMemoryUserRepository(UserRepository):
    """In-memory user repository for testing and development."""

    def __init__(self) -> None:
        """Initialize empty user storage."""
        self._users: dict[str, User] = {}
        self._username_index: dict[str, str] = {}  # username -> user_id
        self._email_index: dict[str, str] = {}  # email -> user_id

    async def save(self, user: User) -> ServiceResult[User]:
        """Save user to memory."""
        try:
            # Update timestamp
            user.updated_at = datetime.now(UTC)

            # Check for username conflicts
            existing_username = self._username_index.get(user.username.lower())
            if existing_username and existing_username != user.id:
                return ServiceResult.fail(f"Username '{user.username}' already exists")

            # Check for email conflicts
            existing_email = self._email_index.get(str(user.email).lower())
            if existing_email and existing_email != user.id:
                return ServiceResult.fail(f"Email '{user.email}' already exists")

            # Save user
            self._users[user.id] = user
            self._username_index[user.username.lower()] = user.id
            self._email_index[str(user.email).lower()] = user.id

            return ServiceResult.ok(user)

        except Exception as e:
            return ServiceResult.fail(f"Failed to save user: {e}")

    async def get_by_id(self, user_id: str) -> ServiceResult[User | None]:
        """Get user by ID."""
        try:
            user = self._users.get(user_id)
            return ServiceResult.ok(user)
        except Exception as e:
            return ServiceResult.fail(f"Failed to get user by ID: {e}")

    async def get_by_username(self, username: str) -> ServiceResult[User | None]:
        """Get user by username."""
        try:
            user_id = self._username_index.get(username.lower())
            if not user_id:
                return ServiceResult.ok(None)

            user = self._users.get(user_id)
            return ServiceResult.ok(user)
        except Exception as e:
            return ServiceResult.fail(f"Failed to get user by username: {e}")

    async def get_by_email(self, email: str) -> ServiceResult[User | None]:
        """Get user by email."""
        try:
            user_id = self._email_index.get(email.lower())
            if not user_id:
                return ServiceResult.ok(None)

            user = self._users.get(user_id)
            return ServiceResult.ok(user)
        except Exception as e:
            return ServiceResult.fail(f"Failed to get user by email: {e}")

    async def delete(self, user_id: str) -> ServiceResult[bool]:
        """Delete user from memory."""
        try:
            user = self._users.get(user_id)
            if not user:
                return ServiceResult.ok(False)

            # Remove from indexes
            self._username_index.pop(user.username.lower(), None)
            self._email_index.pop(str(user.email).lower(), None)

            # Remove user
            del self._users[user_id]

            return ServiceResult.ok(True)
        except Exception as e:
            return ServiceResult.fail(f"Failed to delete user: {e}")

    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        status: UserStatus | None = None,
    ) -> ServiceResult[list[User]]:
        """List users with pagination and filtering."""
        try:
            users = list(self._users.values())

            # Apply status filter
            if status:
                users = [u for u in users if u.status == status]

            # Sort by created_at (newest first)
            users.sort(key=lambda u: u.created_at, reverse=True)

            # Apply pagination
            end = offset + limit
            paginated_users = users[offset:end]

            return ServiceResult.ok(paginated_users)
        except Exception as e:
            return ServiceResult.fail(f"Failed to list users: {e}")

    async def count_users(self, status: UserStatus | None = None) -> ServiceResult[int]:
        """Count users with optional status filter."""
        try:
            if status:
                count = sum(1 for u in self._users.values() if u.status == status)
            else:
                count = len(self._users)

            return ServiceResult.ok(count)
        except Exception as e:
            return ServiceResult.fail(f"Failed to count users: {e}")


class PostgreSQLUserRepository(UserRepository):
    """PostgreSQL user repository implementation."""

    def __init__(self, connection_url: str) -> None:
        """Initialize PostgreSQL repository."""
        self.connection_url = connection_url
        self._connection_pool: Any = None

    async def _get_connection(self) -> Any:
        """Get database connection from pool."""
        if not self._connection_pool:
            try:
                import asyncpg

                # Create connection pool
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
        """Ensure user tables exist."""
        try:
            connection = await self._get_connection()

            try:
                await connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id VARCHAR(255) PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role VARCHAR(50) NOT NULL DEFAULT 'user',
                        status VARCHAR(50) NOT NULL DEFAULT 'active',
                        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                        locked_until TIMESTAMP WITH TIME ZONE,
                        last_login TIMESTAMP WITH TIME ZONE,
                        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                    );

                    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                    CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
                    CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
                """
                )

                return ServiceResult.ok(True)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to ensure tables: {e}")

    async def save(self, user: User) -> ServiceResult[User]:
        """Save user to PostgreSQL."""
        try:
            # Ensure tables exist
            table_result = await self._ensure_tables()
            if not table_result.is_success:
                return ServiceResult.fail(f"Table setup failed: {table_result.error}")

            connection = await self._get_connection()

            try:
                # Update timestamp
                user.updated_at = datetime.now(UTC)

                # Upsert user
                await connection.execute(
                    """
                    INSERT INTO users (
                        id, username, email, password_hash, role, status,
                        failed_login_attempts, locked_until, last_login,
                        created_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    ON CONFLICT (id) DO UPDATE SET
                        username = EXCLUDED.username,
                        email = EXCLUDED.email,
                        password_hash = EXCLUDED.password_hash,
                        role = EXCLUDED.role,
                        status = EXCLUDED.status,
                        failed_login_attempts = EXCLUDED.failed_login_attempts,
                        locked_until = EXCLUDED.locked_until,
                        last_login = EXCLUDED.last_login,
                        updated_at = EXCLUDED.updated_at
                """,
                    user.id,
                    user.username,
                    str(user.email),
                    user.password_hash,
                    user.role.value,
                    user.status.value,
                    user.failed_login_attempts,
                    user.locked_until,
                    user.last_login,
                    user.created_at,
                    user.updated_at,
                )

                return ServiceResult.ok(user)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to save user: {e}")

    async def get_by_id(self, user_id: str) -> ServiceResult[User | None]:
        """Get user by ID from PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                row = await connection.fetchrow(
                    "SELECT * FROM users WHERE id = $1", user_id
                )

                if not row:
                    return ServiceResult.ok(None)

                user = self._row_to_user(row)
                return ServiceResult.ok(user)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to get user by ID: {e}")

    async def get_by_username(self, username: str) -> ServiceResult[User | None]:
        """Get user by username from PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                row = await connection.fetchrow(
                    "SELECT * FROM users WHERE username = $1", username
                )

                if not row:
                    return ServiceResult.ok(None)

                user = self._row_to_user(row)
                return ServiceResult.ok(user)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to get user by username: {e}")

    async def get_by_email(self, email: str) -> ServiceResult[User | None]:
        """Get user by email from PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                row = await connection.fetchrow(
                    "SELECT * FROM users WHERE email = $1", email
                )

                if not row:
                    return ServiceResult.ok(None)

                user = self._row_to_user(row)
                return ServiceResult.ok(user)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to get user by email: {e}")

    async def delete(self, user_id: str) -> ServiceResult[bool]:
        """Delete user from PostgreSQL."""
        try:
            connection = await self._get_connection()

            try:
                result = await connection.execute(
                    "DELETE FROM users WHERE id = $1", user_id
                )

                # Check if any rows were affected
                deleted = result.split()[-1] == "1"
                return ServiceResult.ok(deleted)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to delete user: {e}")

    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        status: UserStatus | None = None,
    ) -> ServiceResult[list[User]]:
        """List users from PostgreSQL with pagination and filtering."""
        try:
            connection = await self._get_connection()

            try:
                if status:
                    rows = await connection.fetch(
                        """
                        SELECT * FROM users
                        WHERE status = $1
                        ORDER BY created_at DESC
                        LIMIT $2 OFFSET $3
                    """,
                        status.value,
                        limit,
                        offset,
                    )
                else:
                    rows = await connection.fetch(
                        """
                        SELECT * FROM users
                        ORDER BY created_at DESC
                        LIMIT $1 OFFSET $2
                    """,
                        limit,
                        offset,
                    )

                users = [self._row_to_user(row) for row in rows]
                return ServiceResult.ok(users)

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to list users: {e}")

    async def count_users(self, status: UserStatus | None = None) -> ServiceResult[int]:
        """Count users in PostgreSQL with optional status filter."""
        try:
            connection = await self._get_connection()

            try:
                if status:
                    count = await connection.fetchval(
                        "SELECT COUNT(*) FROM users WHERE status = $1", status.value
                    )
                else:
                    count = await connection.fetchval("SELECT COUNT(*) FROM users")

                return ServiceResult.ok(int(count))

            finally:
                await self._release_connection(connection)

        except Exception as e:
            return ServiceResult.fail(f"Failed to count users: {e}")

    def _row_to_user(self, row: Any) -> User:
        """Convert database row to User entity."""
        from flext_auth.domain.entities import UserRole, UserStatus

        return User(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            password_hash=row["password_hash"],
            role=UserRole(row["role"]),
            status=UserStatus(row["status"]),
            failed_login_attempts=row["failed_login_attempts"],
            locked_until=row["locked_until"],
            last_login=row["last_login"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def close(self) -> None:
        """Close database connection pool."""
        if self._connection_pool:
            await self._connection_pool.close()
