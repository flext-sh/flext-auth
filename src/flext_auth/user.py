"""FLEXT Auth User Management - Repository patterns for user persistence.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime

from flext_core import FlextResult

from flext_auth.domain_entities import FlextUser, FlextUserStatus


class UserRepository(ABC):
    """Abstract repository for user operations."""

    @abstractmethod
    async def save(self, user: FlextUser) -> FlextResult[FlextUser]:
        """Save user to repository."""

    @abstractmethod
    async def get_by_id(self, user_id: str) -> FlextResult[FlextUser | None]:
        """Get user by ID."""

    @abstractmethod
    async def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username."""

    @abstractmethod
    async def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email."""

    @abstractmethod
    async def delete(self, user_id: str) -> FlextResult[bool]:
        """Delete user from repository."""

    @abstractmethod
    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[list[FlextUser]]:
        """List users with pagination and filtering."""

    @abstractmethod
    async def count_users(
        self,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[int]:
        """Count users with optional status filter."""


class InMemoryUserRepository(UserRepository):
    """In-memory user repository for testing and development."""

    def __init__(self) -> None:
        """Initialize empty user storage."""
        self._users: dict[str, FlextUser] = {}
        self._username_index: dict[str, str] = {}  # username -> user_id
        self._email_index: dict[str, str] = {}  # email -> user_id

    async def save(self, user: FlextUser) -> FlextResult[FlextUser]:
        """Save user to memory."""
        try:
            # Check for username conflicts
            existing_username = self._username_index.get(user.username.lower())
            if existing_username and existing_username != user.id:
                return FlextResult[None].fail(f"Username '{user.username}' already exists")

            # Check for email conflicts
            existing_email = self._email_index.get(str(user.email).lower())
            if existing_email and existing_email != user.id:
                return FlextResult[None].fail(f"Email '{user.email}' already exists")

            # Create user with updated timestamp (entities are immutable)
            updated_user = FlextUser(
                id=user.id,
                username=user.username,
                email=user.email,
                password_hash=user.password_hash,
                role=user.role,
                status=user.status,
                failed_login_attempts=user.failed_login_attempts,
                locked_until=user.locked_until,
                last_login=user.last_login,
                created_at=user.created_at,
                updated_at=datetime.now(UTC),
            )

            # Save user
            self._users[str(updated_user.id)] = updated_user
            self._username_index[updated_user.username.lower()] = str(updated_user.id)
            self._email_index[str(updated_user.email).lower()] = str(updated_user.id)

            return FlextResult[None].ok(updated_user)

        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to save user: {e}")

    async def get_by_id(self, user_id: str) -> FlextResult[FlextUser | None]:
        """Get user by ID."""
        try:
            user = self._users.get(user_id)
            return FlextResult[None].ok(user)
        except (KeyError, ValueError, TypeError) as e:
            return FlextResult[None].fail(f"Failed to get user by ID: {e}")

    async def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username."""
        try:
            user_id = self._username_index.get(username.lower())
            if not user_id:
                return FlextResult[None].ok(None)

            user = self._users.get(user_id)
            return FlextResult[None].ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to get user by username: {e}")

    async def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email."""
        try:
            user_id = self._email_index.get(email.lower())
            if not user_id:
                return FlextResult[None].ok(None)

            user = self._users.get(user_id)
            return FlextResult[None].ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to get user by email: {e}")

    async def delete(self, user_id: str) -> FlextResult[bool]:
        """Delete user from memory."""
        try:
            user = self._users.get(user_id)
            if not user:
                return FlextResult[bool].ok(False)

            # Remove from indexes
            self._username_index.pop(user.username.lower(), None)
            self._email_index.pop(str(user.email).lower(), None)

            # Remove user
            del self._users[user_id]

            return FlextResult[bool].ok(True)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to delete user: {e}")

    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[list[FlextUser]]:
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

            return FlextResult[None].ok(paginated_users)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to list users: {e}")

    async def count_users(
        self,
        status: FlextUserStatus | None = None,
    ) -> FlextResult[int]:
        """Count users with optional status filter."""
        try:
            if status:
                count = sum(1 for u in self._users.values() if u.status == status)
            else:
                count = len(self._users)

            return FlextResult[None].ok(count)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to count users: {e}")


# PostgreSQL implementation removed to eliminate code duplication
# Use InMemoryUserRepository for development or implement when actually needed
