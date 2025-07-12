"""FLEXT AUTH Domain Layer - Pure business logic.

Using flext-core base classes and modern Python 3.13 patterns.
Zero code duplication with single source of truth.
"""

from flext_auth.domain.entities import Permission
from flext_auth.domain.entities import Role
from flext_auth.domain.entities import Session
from flext_auth.domain.entities import User
from flext_auth.domain.value_objects import HashedPassword
from flext_auth.domain.value_objects import RefreshToken
from flext_auth.domain.value_objects import SessionToken
from flext_auth.domain.value_objects import UserEmail
from flext_auth.domain.value_objects import Username
from flext_auth.domain.value_objects import UserRole
from flext_auth.domain.value_objects import UserStatus

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
