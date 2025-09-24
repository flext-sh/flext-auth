"""FLEXT Auth Typings - Type definitions for authentication domain.

This module contains all type definitions, TypedDicts, TypeVars, and type aliases
used throughout the authentication domain, following flext-core standardization.
"""

from datetime import datetime
from typing import NotRequired, TypedDict

from flext_core import FlextTypes


class FlextAuthTypes(FlextTypes):
    """FLEXT Auth Types - Authentication domain type definitions unified class.

    Contains all type definitions used in the authentication domain,
    extending flext-core types without wrappers or aliases.
    """

    # TypedDict definitions for API responses and data structures
    class UserDict(TypedDict):
        """Type definition for user data in authentication responses."""

        id: str
        username: str
        email: str
        full_name: str | None
        is_active: bool
        roles: list[str]
        created_at: datetime
        updated_at: datetime
        last_login: datetime | None

    class SessionDict(TypedDict):
        """Type definition for session data in authentication responses."""

        id: str
        user_id: str
        session_token: str
        expires_at: datetime
        created_at: datetime
        last_accessed_at: datetime
        is_active: bool
        ip_address: str | None
        user_agent: str | None

    class AuthenticationResponseDict(TypedDict):
        """Type definition for authentication response."""

        user: "FlextAuthTypes.UserDict"
        session: "FlextAuthTypes.SessionDict"
        jwt_token: NotRequired[str]  # Optional JWT token
        tokens: NotRequired[dict[str, str | int]]  # Optional tokens dict
        authenticated: bool
        success: bool

    # Type aliases for common patterns
    TokenDict = dict[str, str | datetime]

    # Extend flext-core types for authentication domain
    UserId = FlextTypes.Identifiers.Id
    SessionId = FlextTypes.Identifiers.Id
    TokenId = FlextTypes.Identifiers.Id
    RoleId = FlextTypes.Identifiers.Id


__all__ = [
    "FlextAuthTypes",
]
