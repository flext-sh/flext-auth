"""FLEXT Auth Utilities - Utility functions for common authentication operations.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module provides utility functions and classes for common authentication
operations, following SOLID principles and reducing code duplication.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextResult

from flext_auth.entities import FlextUser

if TYPE_CHECKING:
    from flext_auth.types import UserRepositoryType


class FlextAuthUtilities:
    """Utility class with static methods for common auth operations."""

    @staticmethod
    def get_user_by_username_safe(
        repository: UserRepositoryType, username: str
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
            # Check if repository has sync method (InMemoryUserRepository)
            if hasattr(repository, "get_by_username_sync"):
                return repository.get_by_username_sync(username)

            # Otherwise use async method in sync context (SimplePostgreSQLUserRepository)
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(repository.get_by_username(username))
            except RuntimeError:
                # No event loop, create new one
                return asyncio.run(repository.get_by_username(username))

        except Exception as e:
            return FlextResult[FlextUser | None].fail(f"Repository error: {e}")

    @staticmethod
    def get_user_by_email_safe(
        repository: UserRepositoryType, email: str
    ) -> FlextResult[FlextUser | None]:
        """Safely get user by email from either sync or async repository.

        Args:
            repository: Either InMemoryUserRepository or SimplePostgreSQLUserRepository
            email: Email to search for

        Returns:
            FlextResult containing user or None if not found

        """
        try:
            # Check if repository has sync method (InMemoryUserRepository)
            if hasattr(repository, "get_by_email_sync"):
                return repository.get_by_email_sync(email)

            # Otherwise use async method in sync context (SimplePostgreSQLUserRepository)
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(repository.get_by_email(email))
            except RuntimeError:
                return asyncio.run(repository.get_by_email(email))

        except Exception as e:
            return FlextResult[FlextUser | None].fail(f"Repository error: {e}")

    @staticmethod
    def save_user_safe(
        repository: UserRepositoryType, user: FlextUser
    ) -> FlextResult[FlextUser]:
        """Safely save user to either sync or async repository.

        Args:
            repository: Either InMemoryUserRepository or SimplePostgreSQLUserRepository
            user: User entity to save

        Returns:
            FlextResult containing saved user or error

        """
        try:
            # Check if repository has sync method (InMemoryUserRepository)
            if hasattr(repository, "save_sync"):
                return repository.save_sync(user)

            # Otherwise use async method in sync context (SimplePostgreSQLUserRepository)
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(repository.save(user))
            except RuntimeError:
                return asyncio.run(repository.save(user))

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
        return result.unwrap_or(False)

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


__all__ = [
    "FlextAuthUtilities",
]
