"""FLEXT Auth User Management - Repository patterns for user persistence.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextResult, FlextModels

from flext_auth.entities import FlextUser, FlextUserStatus
from flext_auth.repositories import FlextUserRepository


class InMemoryUserRepository(FlextUserRepository):
    """In-memory user repository implementation."""

    def __init__(self) -> None:
        """Initialize empty user storage."""
        self._users: dict[str, FlextUser] = {}
        self._username_index: dict[str, str] = {}  # username -> user_id
        self._email_index: dict[str, str] = {}  # email -> user_id

    def save(self, entity: FlextUser) -> FlextResult[FlextUser]:
        """Save user to memory."""
        try:
            # Check for username conflicts
            existing_username = self._username_index.get(entity.username.lower())
            if existing_username and existing_username != entity.id:
                return FlextResult[FlextUser].fail(
                    f"Username '{entity.username}' already exists",
                )

            # Check for email conflicts
            existing_email = self._email_index.get(str(entity.email).lower())
            if existing_email and existing_email != entity.id:
                return FlextResult[FlextUser].fail(
                    f"Email '{entity.email}' already exists",
                )

            # Create user with updated timestamp (entities are immutable)
            updated_user = FlextUser(
                id=entity.id,
                username=entity.username,
                email=entity.email,
                password_hash=entity.password_hash,
                role=entity.role,
                status=entity.status,
                failed_login_attempts=entity.failed_login_attempts,
                locked_until=entity.locked_until,
                last_login=entity.last_login,
                created_at=entity.created_at,
                updated_at=FlextModels.Timestamp(datetime.now(UTC)),
            )

            # Save user
            self._users[str(updated_user.id)] = updated_user
            self._username_index[updated_user.username.lower()] = str(updated_user.id)
            self._email_index[str(updated_user.email).lower()] = str(updated_user.id)

            return FlextResult[FlextUser].ok(updated_user)

        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextUser].fail(f"Failed to save user: {e}")

    def get_by_id(self, entity_id: str) -> FlextResult[FlextUser | None]:
        """Get user by ID."""
        try:
            user = self._users.get(entity_id)
            return FlextResult[FlextUser | None].ok(user)
        except (KeyError, ValueError, TypeError) as e:
            return FlextResult[FlextUser | None].fail(f"Failed to get user by ID: {e}")

    def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username."""
        try:
            user_id = self._username_index.get(username.lower())
            if not user_id:
                return FlextResult[FlextUser | None].ok(None)

            user = self._users.get(user_id)
            return FlextResult[FlextUser | None].ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextUser | None].fail(
                f"Failed to get user by username: {e}",
            )

    @override
    def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email."""
        try:
            user_id = self._email_index.get(email.lower())
            if not user_id:
                return FlextResult[FlextUser | None].ok(None)

            user = self._users.get(user_id)
            return FlextResult[FlextUser | None].ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextUser | None].fail(
                f"Failed to get user by email: {e}",
            )

    @override
    def delete(self, entity_id: str) -> FlextResult[None]:
        """Delete user from memory."""
        try:
            user = self._users.get(entity_id)
            if not user:
                return FlextResult[None].fail("User not found")

            # Remove from indexes
            self._username_index.pop(user.username.lower(), None)
            self._email_index.pop(str(user.email).lower(), None)

            # Remove user
            del self._users[entity_id]

            return FlextResult[None].ok(None)
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

            return FlextResult[list[FlextUser]].ok(paginated_users)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[FlextUser]].fail(f"Failed to list users: {e}")

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

            return FlextResult[int].ok(count)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[int].fail(f"Failed to count users: {e}")

    # =============================================================================
    # SYNC METHODS FOR COMMAND HANDLERS (CQRS requires sync handlers)
    # =============================================================================

    def save_sync(self, entity: FlextUser) -> FlextResult[FlextUser]:
        """Save user to memory (sync version for CQRS commands)."""
        try:
            # Check for username conflicts
            existing_username = self._username_index.get(entity.username.lower())
            if existing_username and existing_username != str(entity.id):
                return FlextResult[FlextUser].fail(
                    f"Username '{entity.username}' already exists",
                )

            # Check for email conflicts
            existing_email = self._email_index.get(str(entity.email).lower())
            if existing_email and existing_email != str(entity.id):
                return FlextResult[FlextUser].fail(
                    f"Email '{entity.email}' already exists",
                )

            # Create user with updated timestamp (entities are immutable)
            updated_user = FlextUser(
                id=entity.id,
                username=entity.username,
                email=entity.email,
                password_hash=entity.password_hash,
                role=entity.role,
                status=entity.status,
                failed_login_attempts=entity.failed_login_attempts,
                locked_until=entity.locked_until,
                last_login=entity.last_login,
                created_at=entity.created_at,
                updated_at=FlextModels.Timestamp(datetime.now(UTC)),
            )

            # Save user
            self._users[str(updated_user.id)] = updated_user
            self._username_index[updated_user.username.lower()] = str(updated_user.id)
            self._email_index[str(updated_user.email).lower()] = str(updated_user.id)

            return FlextResult[FlextUser].ok(updated_user)

        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextUser].fail(f"Failed to save user: {e}")

    def get_by_username_sync(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username (sync version for CQRS commands)."""
        try:
            user_id = self._username_index.get(username.lower())
            if not user_id:
                return FlextResult[FlextUser | None].ok(None)

            user = self._users.get(user_id)
            return FlextResult[FlextUser | None].ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextUser | None].fail(
                f"Failed to get user by username: {e}",
            )

    def get_by_email_sync(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email (sync version for CQRS commands)."""
        try:
            user_id = self._email_index.get(email.lower())
            if not user_id:
                return FlextResult[FlextUser | None].ok(None)

            user = self._users.get(user_id)
            return FlextResult[FlextUser | None].ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextUser | None].fail(
                f"Failed to get user by email: {e}",
            )

    def find_all(self) -> FlextResult[list[FlextUser]]:
        """Find all users - implementing core Repository pattern."""
        try:
            users = list(self._users.values())
            return FlextResult[list[FlextUser]].ok(users)
        except Exception as e:
            return FlextResult[list[FlextUser]].fail(f"Failed to get all users: {e}")


# PostgreSQL implementation removed to eliminate code duplication
# Use InMemoryUserRepository for development or implement when actually needed
