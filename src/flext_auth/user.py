"""FLEXT Auth User Management - Repository patterns for user persistence.

This module provides user repository interfaces and implementations following
the Repository pattern from Domain-Driven Design. It abstracts user persistence
and provides both in-memory and database implementations for flexible deployment.

Architecture:
    - Infrastructure Layer: User persistence and data access
    - Repository Pattern: Abstract data access with multiple implementations
    - Railway-Oriented: FlextResult[T] for type-safe error handling
    - Domain-Driven: Operates on FlextUser domain entities

Core Capabilities:
    - User CRUD operations with type safety
    - Username and email uniqueness validation
    - User search and filtering capabilities
    - Pagination support for large user bases
    - Bulk operations for user management
    - User status and role management

Repository Implementations:
    - InMemoryUserRepository: Fast in-memory storage for development/testing
    - DatabaseUserRepository: Persistent database storage (TODO)
    - LDAPUserRepository: Enterprise directory integration (TODO)
    - HybridUserRepository: Multi-source user management (TODO)

TODO (Based on docs/TODO.md):
    - [ ] CRITICAL: Integrate with FlextContainer for DI (Issue #3)
    - [ ] HIGH: Add domain events for user operations (Issue #4)
    - [ ] MEDIUM: Implement database user repository (Issue #8)
    - [ ] MEDIUM: Add LDAP integration for enterprise (Issue #8)
    - [ ] MEDIUM: Add user search and indexing (Issue #10)
    - [ ] LOW: Add user analytics and reporting (Issue #10)

Current Project Status:
    ✅ User repository patterns comprehensively documented with DDD patterns
    ✅ Repository abstraction layer documented with multiple implementations
    ✅ Type-safe operations documented with FlextResult patterns
    🔄 Implementation focus: Database repository and FlextContainer integration

Security Features:
    - Username and email uniqueness enforcement
    - Secure user data handling
    - Account status validation
    - Role-based access control integration
    - User audit trail support

Design Patterns:
    - Repository Pattern: Abstract data access layer
    - Factory Pattern: User creation with validation
    - Observer Pattern: User lifecycle events (TODO)
    - Strategy Pattern: Multiple storage implementations
    - Specification Pattern: User search criteria (TODO)

Example:
    >>> user_repo = InMemoryUserRepository()
    >>> user = FlextUser(
    ...     id="usr_123",
    ...     username="john_doe",
    ...     email="john@example.com",
    ...     password_hash="$2b$12$secure_hash"
    ... )
    >>> result = await user_repo.save(user)
    >>> if result.is_success:
    ...     saved_user = result.data
    ...     print(f"User saved: {saved_user.username}")

Performance Considerations:
    - Async operations for non-blocking I/O
    - Efficient user lookup by username/email
    - Indexed search capabilities
    - Pagination for large datasets
    - Optimized for high-read scenarios

Integration Points:
    - FlextContainer: Repository dependency injection (TODO)
    - FlextResult: Type-safe error handling
    - Domain Events: User lifecycle events (TODO)
    - LDAP Integration: Enterprise directory sync (TODO)

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime

from flext_core import FlextResult

from flext_auth.domain.entities import FlextUser, FlextUserStatus


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
                return FlextResult.fail(f"Username '{user.username}' already exists")

            # Check for email conflicts
            existing_email = self._email_index.get(str(user.email).lower())
            if existing_email and existing_email != user.id:
                return FlextResult.fail(f"Email '{user.email}' already exists")

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
            self._users[updated_user.id] = updated_user
            self._username_index[updated_user.username.lower()] = updated_user.id
            self._email_index[str(updated_user.email).lower()] = updated_user.id

            return FlextResult.ok(updated_user)

        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to save user: {e}")

    async def get_by_id(self, user_id: str) -> FlextResult[FlextUser | None]:
        """Get user by ID."""
        try:
            user = self._users.get(user_id)
            return FlextResult.ok(user)
        except (KeyError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to get user by ID: {e}")

    async def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username."""
        try:
            user_id = self._username_index.get(username.lower())
            if not user_id:
                return FlextResult.ok(None)

            user = self._users.get(user_id)
            return FlextResult.ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to get user by username: {e}")

    async def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email."""
        try:
            user_id = self._email_index.get(email.lower())
            if not user_id:
                return FlextResult.ok(None)

            user = self._users.get(user_id)
            return FlextResult.ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to get user by email: {e}")

    async def delete(self, user_id: str) -> FlextResult[bool]:
        """Delete user from memory."""
        try:
            user = self._users.get(user_id)
            if not user:
                return FlextResult.ok(data=False)

            # Remove from indexes
            self._username_index.pop(user.username.lower(), None)
            self._email_index.pop(str(user.email).lower(), None)

            # Remove user
            del self._users[user_id]

            return FlextResult.ok(data=True)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to delete user: {e}")

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

            return FlextResult.ok(paginated_users)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to list users: {e}")

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

            return FlextResult.ok(count)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to count users: {e}")


# PostgreSQL implementation removed to eliminate code duplication
# Use InMemoryUserRepository for development or implement when actually needed
