"""FLEXT Auth Types - Domain-specific authentication type definitions.

This module provides authentication-specific type definitions extending FlextCore.Types.
Follows FLEXT standards:
- Domain-specific complex types only
- No simple aliases to primitive types
- Python 3.13+ syntax
- Extends FlextCore.Types properly

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import datetime
from typing import NotRequired, TypedDict

from flext_core import FlextCore

from flext_auth.constants import FlextAuthConstants

# =============================================================================
# AUTH-SPECIFIC TYPE VARIABLES - Domain-specific TypeVars for authentication operations
# =============================================================================


# Authentication domain TypeVars
class FlextAuthTypes:
    """Authentication-specific type definitions for authentication domain.

    Domain-specific type system for authentication/authorization operations.
    Contains ONLY complex authentication-specific types, no simple aliases.
    Uses Python 3.13+ type syntax and patterns.
    Extends FlextCore.Types for proper inheritance following FLEXT unified patterns.
    """

    # =========================================================================
    # AUTHENTICATION DOMAIN TYPES - Complex authentication types
    # =========================================================================

    class Authentication:
        """Authentication domain complex types."""

        type AuthConfiguration = dict[
            str, str | int | float | bool | FlextCore.Types.Dict | None
        ]
        type AuthCredentials = dict[
            str, str | dict[str, str | int | float | bool | None]
        ]
        type FlextAuthProvider = dict[
            str,
            str
            | int
            | float
            | bool
            | FlextCore.Types.StringList
            | FlextCore.Types.Dict
            | None,
        ]
        type AuthenticationFlow = list[dict[str, str | bool | FlextCore.Types.Dict]]
        type AuthValidation = dict[
            str, bool | str | FlextCore.Types.StringList | FlextCore.Types.Dict
        ]
        type LoginAttempt = dict[str, str | datetime | int | bool]

    # =========================================================================
    # USER MANAGEMENT TYPES - Complex user entity types
    # =========================================================================

    class UserManagement:
        """User management complex types."""

        type UserProfile = dict[
            str, str | int | float | bool | datetime | FlextCore.Types.Dict | None
        ]
        type UserCreation = dict[
            str,
            str
            | bool
            | FlextCore.Types.StringList
            | dict[str, str | int | float | bool | None],
        ]
        type UserUpdate = dict[str, str | int | float | bool | datetime | None]
        type UserPreferences = dict[
            str, str | int | float | bool | FlextCore.Types.Dict | None
        ]
        type AccountStatus = dict[str, bool | datetime | int | str]
        type UserActivity = dict[str, datetime | str | int | FlextCore.Types.Dict]

    # =========================================================================
    # SESSION MANAGEMENT TYPES - Complex session handling types
    # =========================================================================

    class SessionManagement:
        """Session management complex types."""

        type SessionConfiguration = dict[
            str, int | bool | str | dict[str, str | int | float | bool | None]
        ]
        type SessionData = dict[
            str, str | int | float | bool | datetime | FlextCore.Types.Dict | None
        ]
        type SessionStorage = dict[str, str | int | float | bool | datetime | None]
        type SessionLifecycle = dict[str, datetime | bool | int]
        type SessionValidation = dict[str, bool | datetime | str | FlextCore.Types.Dict]
        type ConcurrentSessions = list[
            dict[str, str | int | float | bool | datetime | None]
        ]

    # =========================================================================
    # TOKEN MANAGEMENT TYPES - Complex token handling types
    # =========================================================================

    class TokenManagement:
        """Token management complex types."""

        type TokenConfiguration = dict[
            str, int | str | bool | dict[str, str | int | float | bool | None]
        ]
        type TokenPayload = dict[
            str, str | int | float | bool | datetime | FlextCore.Types.StringList | None
        ]

        # More specific token payload type for JWT tokens
        class JwtTokenPayload(TypedDict):
            """Specific type for JWT token payload with known fields."""

            user_id: str
            username: NotRequired[str]
            exp: int
            iat: int
            type: str
            valid: bool

        type TokenValidation = dict[str, bool | datetime | str | FlextCore.Types.Dict]
        type RefreshToken = dict[str, str | datetime | bool | FlextCore.Types.Dict]
        type AccessToken = dict[str, str | datetime | int | FlextCore.Types.StringList]
        type TokenRevocation = dict[str, datetime | str | bool]

    # =========================================================================
    # AUTHORIZATION TYPES - Complex authorization and RBAC types
    # =========================================================================

    class Authorization:
        """Authorization and RBAC complex types."""

        type RoleDefinition = dict[
            str,
            str
            | FlextCore.Types.StringList
            | dict[str, str | int | float | bool | None],
        ]
        type PermissionSet = dict[
            str, bool | FlextCore.Types.StringList | FlextCore.Types.Dict
        ]
        type AccessPolicy = dict[
            str, str | int | float | bool | list[FlextCore.Types.Dict] | None
        ]
        type AuthorityMapping = dict[
            str, FlextCore.Types.StringList | dict[str, str | int | float | bool | None]
        ]
        type ResourceAccess = dict[
            str,
            bool
            | FlextCore.Types.StringList
            | dict[str, str | int | float | bool | None],
        ]
        type PolicyValidation = dict[
            str, bool | str | FlextCore.Types.StringList | FlextCore.Types.Dict
        ]

    # =========================================================================
    # SECURITY TYPES - Complex security and password types
    # =========================================================================

    class Security:
        """Security and password complex types."""

        type PasswordPolicy = dict[
            str, int | bool | FlextCore.Types.StringList | FlextCore.Types.Dict
        ]
        type PasswordValidation = dict[str, bool | str | FlextCore.Types.StringList]
        type SecurityConfiguration = dict[
            str, str | int | float | bool | FlextCore.Types.Dict | None
        ]
        type ThreatDetection = dict[
            str, bool | int | FlextCore.Types.StringList | dict[str, datetime]
        ]
        type AuditLog = dict[
            str, datetime | str | dict[str, str | int | float | bool | None]
        ]
        type SecurityEvent = dict[
            str, str | datetime | dict[str, str | int | float | bool | None]
        ]

    # =========================================================================
    # AUTHENTICATION RESPONSE TYPES - Complex response structures
    # =========================================================================

    # TypedDict definitions for structured responses
    class UserDict(TypedDict):
        """Type definition for user data in authentication responses."""

        id: str
        username: str
        email: str
        full_name: str | None
        is_active: bool
        roles: FlextCore.Types.StringList
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

        user: FlextAuthTypes.UserDict
        session: FlextAuthTypes.SessionDict
        jwt_token: str  # JWT token
        tokens: NotRequired[dict[str, str | int]]  # Optional tokens dict
        authenticated: bool
        success: bool

    # =========================================================================
    # MANAGER TYPES - Type definitions for manager data structures
    # =========================================================================

    class Managers:
        """Manager-specific type definitions."""

        type UserData = FlextCore.Types.Dict
        type SessionData = FlextCore.Types.Dict
        type LogEntry = FlextCore.Types.Dict
        type AttemptData = list[datetime]

    # =========================================================================
    # AUTH PROJECT TYPES - Domain-specific project types extending FlextCore.Types
    # =========================================================================

    class Project:
        """Auth-specific project types.

        Provides authentication/authorization-specific project types.
        Follows domain separation principle: Auth domain owns auth-specific types.
        """

        # Auth-specific project types - imported from constants for centralization
        type ProjectType = FlextAuthConstants.Literals.ProjectType

        # Auth-specific project configurations
        type AuthProjectConfig = dict[str, str | int | float | bool | object | None]
        type IdentityConfig = dict[str, str | int | bool | FlextCore.Types.StringList]
        type SecurityConfig = dict[str, bool | str | FlextCore.Types.Dict]
        type SessionConfig = dict[str, str | int | float | bool | object | None]


# =============================================================================
# PUBLIC API EXPORTS - Auth TypeVars and types
# =============================================================================

__all__: FlextCore.Types.StringList = [
    "FlextAuthTypes",
]
