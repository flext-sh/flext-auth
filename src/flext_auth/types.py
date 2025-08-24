"""FLEXT Auth Types - Type definitions using centralized FlextProtocols.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module defines type aliases using ONLY FlextProtocols from flext-core
to eliminate protocol duplication and ensure architectural compliance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from flext_core import FlextResult

if TYPE_CHECKING:
    from flext_auth.entities import FlextUser
    from flext_auth.models import FlextSession

# ✅ CORRECT - Async repository protocols extending FlextProtocols foundation
# FlextProtocols.Domain.Repository is sync, so we create async variants that follow same pattern


class AsyncRepositoryProtocol[T](Protocol):
    """Async repository protocol following FlextProtocols.Domain.Repository pattern.

    This extends the synchronous FlextProtocols.Domain.Repository pattern to async,
    maintaining the same method signatures but with async/await.
    """

    async def save(self, entity: T) -> FlextResult[T]:
        """Save entity."""
        raise NotImplementedError

    async def get_by_id(self, entity_id: str) -> FlextResult[T | None]:
        """Get entity by ID."""
        raise NotImplementedError

    async def delete(self, entity_id: str) -> FlextResult[bool]:
        """Delete entity by ID."""
        raise NotImplementedError

    async def find_all(self) -> FlextResult[list[T]]:
        """Find all entities."""
        raise NotImplementedError


class UserRepositoryProtocol(AsyncRepositoryProtocol["FlextUser"]):
    """User repository using async FlextProtocols.Domain.Repository pattern."""

    # Additional user-specific methods beyond base AsyncRepository protocol
    async def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username."""
        raise NotImplementedError

    async def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email."""
        raise NotImplementedError


class SessionRepositoryProtocol(AsyncRepositoryProtocol["FlextSession"]):
    """Session repository using async FlextProtocols.Domain.Repository pattern.

    Inherits async methods (save, get_by_id, delete, find_all) from base AsyncRepository.
    Only defines session-specific additional methods.
    """

    # Additional session-specific methods beyond base AsyncRepository protocol
    async def get_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Get all sessions for a user."""
        raise NotImplementedError

    async def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke a specific session."""
        raise NotImplementedError

    async def revoke_all_user_sessions(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user."""
        raise NotImplementedError

    async def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Cleanup expired sessions and return count of cleaned sessions."""
        raise NotImplementedError


# Type aliases using protocols
UserRepositoryType = UserRepositoryProtocol
SessionRepositoryType = SessionRepositoryProtocol

# Authentication type aliases (consolidated from auth_types.py)
TEmail = str
TPassword = str
TUsername = str

__all__ = [
    "SessionRepositoryProtocol",
    "SessionRepositoryType",
    "UserRepositoryProtocol",
    "UserRepositoryType",
    # Authentication type aliases
    "TEmail",
    "TPassword",
    "TUsername",
]
