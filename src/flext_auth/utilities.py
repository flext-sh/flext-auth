"""FLEXT Auth Utilities - Utility functions for common authentication operations.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module provides utility functions and classes for common authentication
operations, following SOLID principles and reducing code duplication.
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_auth.entities import FlextUser
from flext_auth.flext_auth_types import UserRepositoryType


class FlextAuthUtilities:
    """Utility class with static methods for common auth operations."""

    @staticmethod
    def get_user_by_username_safe(
        repository: UserRepositoryType,
        username: str,
    ) -> FlextResult[FlextUser | None]:
        """Safely get user by username from either sync or async repository.

        This utility handles the Union type repository pattern by checking
        which type of repository we have and calling the appropriate method.
        For async repositories, it runs them in a sync context.

        Args:
            repository: Either InMemoryUserRepository or SimplePostgreSQLUserRepository
            username: Username to search for

        Returns:
            FlextResult containing user or None if not found

        """
        try:
            # Repositories are synchronous according to flext-core patterns
            return repository.get_by_username(username)

        except Exception as e:
            return FlextResult[FlextUser | None].fail(f"Repository error: {e}")

    @staticmethod
    def get_user_by_email_safe(
        repository: UserRepositoryType,
        email: str,
    ) -> FlextResult[FlextUser | None]:
        """Safely get user by email from either sync or async repository.

        Args:
            repository: Either InMemoryUserRepository or SimplePostgreSQLUserRepository
            email: Email to search for

        Returns:
            FlextResult containing user or None if not found

        """
        try:
            # Repositories are synchronous according to flext-core patterns
            return repository.get_by_email(email)

        except Exception as e:
            return FlextResult[FlextUser | None].fail(f"Repository error: {e}")

    @staticmethod
    def save_user_safe(
        repository: UserRepositoryType,
        user: FlextUser,
    ) -> FlextResult[FlextUser]:
        """Safely save user to either sync or async repository.

        Args:
            repository: Either InMemoryUserRepository or SimplePostgreSQLUserRepository
            user: User entity to save

        Returns:
            FlextResult containing saved user or error

        """
        try:
            # Repositories are synchronous according to flext-core patterns
            return repository.save(user)

        except Exception as e:
            return FlextResult[FlextUser].fail(f"Repository save error: {e}")

    @staticmethod
    def unwrap_or_false(result: FlextResult[bool]) -> bool:
        """Utility to unwrap FlextResult[bool] with False fallback.

        Uses modern FlextResult.unwrap_or() pattern for cleaner code.

        Args:
            result: FlextResult containing boolean value

        Returns:
            Boolean value or False if result failed

        """
        return result.unwrap_or(default=False)

    @staticmethod
    def unwrap_or_empty_string(result: FlextResult[str]) -> str:
        """Utility to unwrap FlextResult[str] with empty string fallback.

        Args:
            result: FlextResult containing string value

        Returns:
            String value or empty string if result failed

        """
        return result.unwrap_or("")

    @staticmethod
    def unwrap_or_none(result: FlextResult[object]) -> object | None:
        """Utility to unwrap FlextResult with None fallback.

        Args:
            result: FlextResult containing any value

        Returns:
            Value or None if result failed

        """
        return result.unwrap_or(None)

    @staticmethod
    def unwrap_or_zero(result: FlextResult[int]) -> int:
        """Utility to unwrap FlextResult[int] with 0 fallback.

        Args:
            result: FlextResult containing integer value

        Returns:
            Integer value or 0 if result failed

        """
        return result.unwrap_or(0)

    @staticmethod
    def unwrap_or_empty_list(result: FlextResult[list[object]]) -> list[object]:
        """Utility to unwrap FlextResult[list] with empty list fallback.

        Args:
            result: FlextResult containing list value

        Returns:
            List value or empty list if result failed

        """
        return result.unwrap_or([])

    @staticmethod
    def is_successful_auth(result: FlextResult[dict[str, object]]) -> bool:
        """Check if authentication result is successful using unwrap_or pattern.

        Args:
            result: Authentication result

        Returns:
            True if successful, False otherwise

        """
        return result.success and bool(result.unwrap_or({}))

    @staticmethod
    def is_valid_and_has_value(result: FlextResult[object]) -> bool:
        """Check if FlextResult is successful and has a truthy value.

        Replaces verbose pattern: result.success and result.value

        Args:
            result: FlextResult to check

        Returns:
            True if result is successful and has truthy value, False otherwise

        """
        return result.success and bool(result.value)

    @staticmethod
    def is_invalid_or_empty(result: FlextResult[object]) -> bool:
        """Check if FlextResult is failed or has no value.

        Replaces verbose pattern: not result.success or not result.value

        Args:
            result: FlextResult to check

        Returns:
            True if result is failed or has falsy value, False otherwise

        """
        return not result.success or not bool(result.value)

    @staticmethod
    def get_username_or_anonymous(result: FlextResult[dict[str, object]]) -> str:
        """Extract username from auth result or return 'anonymous'.

        Args:
            result: Authentication result

        Returns:
            Username or 'anonymous' if not found

        """
        auth_data = result.unwrap_or({})
        return str(auth_data.get("username", "anonymous"))


__all__ = [
    "FlextAuthUtilities",
]
