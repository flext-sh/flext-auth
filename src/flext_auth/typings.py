"""FLEXT Auth Types - Domain-specific authentication type definitions.

This module provides authentication-specific type definitions extending FlextTypes.
Follows FLEXT standards:
- Domain-specific complex types only
- No simple aliases to primitive types
- Python 3.13+ syntax
- Extends FlextTypes properly

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, NotRequired, TypedDict

from flext_core import FlextTypes

# =============================================================================
# AUTH-SPECIFIC TYPE VARIABLES - Domain-specific TypeVars for authentication operations
# =============================================================================


# Authentication domain TypeVars
class FlextAuthTypes(FlextTypes):
    """Authentication-specific type definitions for authentication domain.

    Domain-specific type system for authentication/authorization operations.
    Contains ONLY complex authentication-specific types, no simple aliases.
    Uses Python 3.13+ type syntax and patterns.
    Extends FlextTypes for proper inheritance following FLEXT unified patterns.
    """

    # =========================================================================
    # AUTHENTICATION DOMAIN TYPES - Complex authentication types
    # =========================================================================

    class Authentication:
        """Authentication domain complex types."""

        type AuthConfiguration = dict[
            str, str | int | float | bool | FlextTypes.Dict | None
        ]
        type AuthCredentials = dict[
            str, str | dict[str, str | int | float | bool | None]
        ]
        type FlextAuthProvider = dict[
            str,
            str | int | float | bool | FlextTypes.StringList | FlextTypes.Dict | None,
        ]
        type AuthenticationFlow = list[dict[str, str | bool | FlextTypes.Dict]]
        type AuthValidation = dict[
            str, bool | str | FlextTypes.StringList | FlextTypes.Dict
        ]
        type LoginAttempt = dict[str, str | datetime | int | bool]

    # =========================================================================
    # USER MANAGEMENT TYPES - Complex user entity types
    # =========================================================================

    class UserManagement:
        """User management complex types."""

        type UserProfile = dict[
            str, str | int | float | bool | datetime | FlextTypes.Dict | None
        ]
        type UserCreation = dict[
            str,
            str
            | bool
            | FlextTypes.StringList
            | dict[str, str | int | float | bool | None],
        ]
        type UserUpdate = dict[str, str | int | float | bool | datetime | None]
        type UserPreferences = dict[
            str, str | int | float | bool | FlextTypes.Dict | None
        ]
        type AccountStatus = dict[str, bool | datetime | int | str]
        type UserActivity = dict[str, datetime | str | int | FlextTypes.Dict]

    # =========================================================================
    # SESSION MANAGEMENT TYPES - Complex session handling types
    # =========================================================================

    class SessionManagement:
        """Session management complex types."""

        type SessionConfiguration = dict[
            str, int | bool | str | dict[str, str | int | float | bool | None]
        ]
        type SessionData = dict[
            str, str | int | float | bool | datetime | FlextTypes.Dict | None
        ]
        type SessionStorage = dict[str, str | int | float | bool | datetime | None]
        type SessionLifecycle = dict[str, datetime | bool | int]
        type SessionValidation = dict[str, bool | datetime | str | FlextTypes.Dict]
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
            str, str | int | float | bool | datetime | FlextTypes.StringList | None
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

        type TokenValidation = dict[str, bool | datetime | str | FlextTypes.Dict]
        type RefreshToken = dict[str, str | datetime | bool | FlextTypes.Dict]
        type AccessToken = dict[str, str | datetime | int | FlextTypes.StringList]
        type TokenRevocation = dict[str, datetime | str | bool]

    # =========================================================================
    # AUTHORIZATION TYPES - Complex authorization and RBAC types
    # =========================================================================

    class Authorization:
        """Authorization and RBAC complex types."""

        type RoleDefinition = dict[
            str,
            str | FlextTypes.StringList | dict[str, str | int | float | bool | None],
        ]
        type PermissionSet = dict[str, bool | FlextTypes.StringList | FlextTypes.Dict]
        type AccessPolicy = dict[
            str, str | int | float | bool | list[FlextTypes.Dict] | None
        ]
        type AuthorityMapping = dict[
            str, FlextTypes.StringList | dict[str, str | int | float | bool | None]
        ]
        type ResourceAccess = dict[
            str,
            bool | FlextTypes.StringList | dict[str, str | int | float | bool | None],
        ]
        type PolicyValidation = dict[
            str, bool | str | FlextTypes.StringList | FlextTypes.Dict
        ]

    # =========================================================================
    # SECURITY TYPES - Complex security and password types
    # =========================================================================

    class Security:
        """Security and password complex types."""

        type PasswordPolicy = dict[
            str, int | bool | FlextTypes.StringList | FlextTypes.Dict
        ]
        type PasswordValidation = dict[str, bool | str | FlextTypes.StringList]
        type SecurityConfiguration = dict[
            str, str | int | float | bool | FlextTypes.Dict | None
        ]
        type ThreatDetection = dict[
            str, bool | int | FlextTypes.StringList | dict[str, datetime]
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
        roles: FlextTypes.StringList
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

        type UserData = dict[str, object]
        type SessionData = dict[str, object]
        type LogEntry = dict[str, object]
        type AttemptData = list[datetime]

    # =========================================================================
    # AUTH PROJECT TYPES - Domain-specific project types extending FlextTypes
    # =========================================================================

    class Project:
        """Auth-specific project types.

        Provides authentication/authorization-specific project types.
        Follows domain separation principle: Auth domain owns auth-specific types.
        """

        # Auth-specific project types
        type ProjectType = Literal[
            # Generic types
            "library",
            "application",
            "service",
            # Auth-specific types
            "auth-service",
            "identity-provider",
            "sso-service",
            "oauth-provider",
            "auth-gateway",
            "session-manager",
            "jwt-service",
            "rbac-system",
            "auth-api",
            "identity-api",
            "credential-manager",
            "security-service",
        ]

        # Auth-specific project configurations
        type AuthProjectConfig = dict[str, str | int | float | bool | object | None]
        type IdentityConfig = dict[str, str | int | bool | FlextTypes.StringList]
        type SecurityConfig = dict[str, bool | str | FlextTypes.Dict]
        type SessionConfig = dict[str, str | int | float | bool | object | None]


# =============================================================================
# PUBLIC API EXPORTS - Auth TypeVars and types
# =============================================================================

__all__: FlextTypes.StringList = [
    "FlextTypes",
]
