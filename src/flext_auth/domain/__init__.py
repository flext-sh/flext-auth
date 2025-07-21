"""FLEXT AUTH Domain Layer - Pure business logic.

Using flext-core base classes and modern Python 3.13 patterns.
Zero code duplication with single source of truth.
"""

from __future__ import annotations

from flext_auth.domain.entities import Permission, Role, Session, User
from flext_auth.domain.value_objects import (
    HashedPassword,
    RefreshToken,
    SessionToken,
    UserEmail,
    Username,
    UserRole,
    UserStatus,
)

__all__ = [
    "HashedPassword",
    "Permission",
    "RefreshToken",
    # Entities
    "Role",
    "Session",
    "SessionToken",
    "User",
    "UserEmail",
    "UserRole",
    # Value Objects
    "UserStatus",
    "Username",
]
