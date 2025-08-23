"""FLEXT Auth Types - Type definitions and Union types for authentication system.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module defines all type aliases and Union types used throughout
the authentication system to avoid circular imports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from flext_core import FlextResult

if TYPE_CHECKING:
    from flext_auth.entities import FlextUser
    from flext_auth.models import FlextSession


# Protocol-based types for proper typing without circular imports
class UserRepositoryProtocol(Protocol):
    """Protocol for user repository implementations."""

    async def save(self, user: FlextUser) -> FlextResult[FlextUser]:
        """Save user to repository."""
        ...

    async def get_by_id(self, user_id: str) -> FlextResult[FlextUser | None]:
        """Get user by ID."""
        ...

    async def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username."""
        ...

    async def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email."""
        ...


class SessionRepositoryProtocol(Protocol):
    """Protocol for session repository implementations."""

    async def save(self, session: FlextSession) -> FlextResult[FlextSession]:
        """Save session to repository."""
        ...

    async def get_by_id(self, session_id: str) -> FlextResult[FlextSession | None]:
        """Get session by ID."""
        ...

    async def get_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Get all sessions for a user."""
        ...

    async def delete(self, session_id: str) -> FlextResult[bool]:
        """Delete session."""
        ...


# Type aliases using protocols
UserRepositoryType = UserRepositoryProtocol
SessionRepositoryType = SessionRepositoryProtocol

__all__ = [
    "SessionRepositoryProtocol",
    "SessionRepositoryType",
    "UserRepositoryProtocol",
    "UserRepositoryType",
]
