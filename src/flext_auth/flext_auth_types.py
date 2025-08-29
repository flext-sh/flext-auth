"""FLEXT Auth Types System - Single consolidated type system for authentication.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

SINGLE CONSOLIDATED MODULE following FLEXT architectural patterns.
All authentication type definitions consolidated into FlextAuthTypes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_core import FlextProtocols, FlextResult

if TYPE_CHECKING:
    from flext_auth.entities import FlextUser
    from flext_auth.models import FlextSession


class FlextAuthTypes:
    """SINGLE CONSOLIDATED CLASS for all authentication type definitions.

    Following FLEXT architectural patterns - consolidates ALL type definitions
    including protocols, repository interfaces, and type aliases into one main class
    with nested classes for organization.

    CONSOLIDATED CLASSES: SyncRepositoryProtocol + UserRepositoryProtocol + SessionRepositoryProtocol
    """

    # ==========================================================================
    # TYPE ALIASES - Authentication types
    # ==========================================================================

    # String type aliases (consolidated from auth_types.py)
    TEmail: ClassVar[type] = str
    TPassword: ClassVar[type] = str
    TUsername: ClassVar[type] = str

    # ==========================================================================
    # NESTED CLASSES FOR ORGANIZATION
    # ==========================================================================

    class SyncRepositoryProtocol[T](FlextProtocols.Domain.Repository[T]):
        """Nested sync repository protocol extending FlextProtocols.Domain.Repository.

        FLEXT REFACTORING: Converted from async to sync patterns for 100% flext-core compliance.
        All methods now use synchronous patterns matching FlextProtocols.Domain.Repository.
        """

        # Inherits all sync methods from FlextProtocols.Domain.Repository

    class UserRepositoryProtocol(SyncRepositoryProtocol["FlextUser"]):
        """Nested user repository using sync FlextProtocols.Domain.Repository pattern.

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

    class SessionRepositoryProtocol(SyncRepositoryProtocol["FlextSession"]):
        """Nested session repository using sync FlextProtocols.Domain.Repository pattern.

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

    # ==========================================================================
    # MAIN CONSOLIDATED CLASS IMPLEMENTATION - Pure static/class methods
    # ==========================================================================

    # ==========================================================================
    # TYPE ACCESS METHODS - Provide access to type definitions
    # ==========================================================================

    @classmethod
    def get_user_repository_protocol(cls) -> type[UserRepositoryProtocol]:
        """Get user repository protocol class."""
        return cls.UserRepositoryProtocol

    @classmethod
    def get_session_repository_protocol(cls) -> type[SessionRepositoryProtocol]:
        """Get session repository protocol class."""
        return cls.SessionRepositoryProtocol

    @classmethod
    def get_sync_repository_protocol(cls) -> type[SyncRepositoryProtocol[object]]:
        """Get sync repository protocol class."""
        return cls.SyncRepositoryProtocol

    @classmethod
    def get_email_type(cls) -> type:
        """Get email type alias."""
        return cls.TEmail

    @classmethod
    def get_password_type(cls) -> type:
        """Get password type alias."""
        return cls.TPassword

    @classmethod
    def get_username_type(cls) -> type:
        """Get username type alias."""
        return cls.TUsername


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Following FLEXT pattern
# =============================================================================

# Export nested classes for external access (backward compatibility)
SyncRepositoryProtocol = FlextAuthTypes.SyncRepositoryProtocol
UserRepositoryProtocol = FlextAuthTypes.UserRepositoryProtocol
SessionRepositoryProtocol = FlextAuthTypes.SessionRepositoryProtocol

# Type aliases using sync protocols for flext-core compliance
UserRepositoryType = FlextAuthTypes.UserRepositoryProtocol
SessionRepositoryType = FlextAuthTypes.SessionRepositoryProtocol

# Authentication type aliases (consolidated from auth_types.py)
TEmail = FlextAuthTypes.TEmail
TPassword = FlextAuthTypes.TPassword
TUsername = FlextAuthTypes.TUsername

__all__ = [
    "FlextAuthTypes",
    # Backward compatibility - nested classes
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
