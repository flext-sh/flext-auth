"""FLEXT Auth Types - Type definitions using centralized FlextProtocols.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module defines type aliases using ONLY FlextProtocols from flext-core
to eliminate protocol duplication and ensure architectural compliance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextProtocols, FlextResult

if TYPE_CHECKING:
    from .entities import FlextUser
    from .models import FlextSession

# ✅ CORRECT - Async repository protocols extending FlextProtocols foundation
# FlextProtocols.Domain.Repository is sync, so we create async variants that follow same pattern


# FLEXT MIGRATION: Use FlextProtocols.Domain.Repository directly for sync patterns
# Option 2: Convert to synchronous patterns for 100% flext-core compliance
class SyncRepositoryProtocol[T](FlextProtocols.Domain.Repository[T]):
    """Sync repository protocol extending FlextProtocols.Domain.Repository.

    FLEXT REFACTORING: Converted from async to sync patterns for 100% flext-core compliance.
    All methods now use synchronous patterns matching FlextProtocols.Domain.Repository.
    """
    pass  # Inherits all sync methods from FlextProtocols.Domain.Repository


# FLEXT MIGRATION: Use sync repository protocol for 100% flext-core compliance
class UserRepositoryProtocol(SyncRepositoryProtocol["FlextUser"]):
    """User repository using sync FlextProtocols.Domain.Repository pattern.

    FLEXT REFACTORING: Converted from async to sync patterns for 100% flext-core compliance.
    Inherits sync methods (save, get_by_id, delete, find_all) from FlextProtocols.Domain.Repository.
    """

    # Additional user-specific methods beyond base Repository protocol
    def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username (sync)."""
        raise NotImplementedError

    def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email (sync)."""
        raise NotImplementedError


# FLEXT MIGRATION: Use sync repository protocol for 100% flext-core compliance
class SessionRepositoryProtocol(SyncRepositoryProtocol["FlextSession"]):
    """Session repository using sync FlextProtocols.Domain.Repository pattern.

    FLEXT REFACTORING: Converted from async to sync patterns for 100% flext-core compliance.
    Inherits sync methods (save, get_by_id, delete, find_all) from FlextProtocols.Domain.Repository.
    """

    # Additional session-specific methods beyond base Repository protocol
    def get_by_user_id(self, user_id: str) -> FlextResult[list[FlextSession]]:
        """Get all sessions for a user (sync)."""
        raise NotImplementedError

    def revoke_session(self, session_id: str) -> FlextResult[bool]:
        """Revoke a specific session (sync)."""
        raise NotImplementedError

    def revoke_all_user_sessions(self, user_id: str) -> FlextResult[int]:
        """Revoke all sessions for a user (sync)."""
        raise NotImplementedError

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Cleanup expired sessions and return count of cleaned sessions (sync)."""
        raise NotImplementedError


# Type aliases using sync protocols for flext-core compliance
UserRepositoryType = UserRepositoryProtocol
SessionRepositoryType = SessionRepositoryProtocol

# Authentication type aliases (consolidated from auth_types.py)
TEmail = str
TPassword = str
TUsername = str

__all__ = [
    "SessionRepositoryProtocol",
    "SessionRepositoryType",
    "SyncRepositoryProtocol",
    # Authentication type aliases
    "TEmail",
    "TPassword",
    "TUsername",
    "UserRepositoryProtocol",
    "UserRepositoryType",
]
