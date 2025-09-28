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

# =============================================================================
# AUTH-SPECIFIC TYPE VARIABLES - Domain-specific TypeVars for authentication operations
# =============================================================================


# Authentication domain TypeVars
class FlextAuthTypes:
    """Authentication-specific type definitions for authentication domain.

    Domain-specific type system for authentication/authorization operations.
    Contains ONLY complex authentication-specific types, no simple aliases.
    Uses Python 3.13+ type syntax and patterns.
    Does not inherit from FlextTypes to avoid naming conflicts with nested classes.
    """

    # =========================================================================
    # AUTHENTICATION DOMAIN TYPES - Complex authentication types
    # =========================================================================

    class Authentication:
        """Authentication domain complex types."""

        type AuthConfiguration = dict[
            str, str | int | float | bool | dict[str, object] | None
        ]
        type AuthCredentials = dict[
            str, str | dict[str, str | int | float | bool | None]
        ]
        type AuthProvider = dict[
            str, str | int | float | bool | list[str] | dict[str, object] | None
        ]
        type AuthenticationFlow = list[dict[str, str | bool | dict[str, object]]]
        type AuthValidation = dict[str, bool | str | list[str] | dict[str, object]]
        type LoginAttempt = dict[str, str | datetime | int | bool]

    # =========================================================================
    # USER MANAGEMENT TYPES - Complex user entity types
    # =========================================================================

    class UserManagement:
        """User management complex types."""

        type UserProfile = dict[
            str, str | int | float | bool | datetime | dict[str, object] | None
        ]
        type UserCreation = dict[
            str, str | bool | list[str] | dict[str, str | int | float | bool | None]
        ]
        type UserUpdate = dict[str, str | int | float | bool | datetime | None]
        type UserPreferences = dict[
            str, str | int | float | bool | dict[str, object] | None
        ]
        type AccountStatus = dict[str, bool | datetime | int | str]
        type UserActivity = dict[str, datetime | str | int | dict[str, object]]

    # =========================================================================
    # SESSION MANAGEMENT TYPES - Complex session handling types
    # =========================================================================

    class SessionManagement:
        """Session management complex types."""

        type SessionConfiguration = dict[
            str, int | bool | str | dict[str, str | int | float | bool | None]
        ]
        type SessionData = dict[
            str, str | int | float | bool | datetime | dict[str, object] | None
        ]
        type SessionStorage = dict[str, str | int | float | bool | datetime | None]
        type SessionLifecycle = dict[str, datetime | bool | int]
        type SessionValidation = dict[str, bool | datetime | str | dict[str, object]]
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
            str, str | int | float | bool | datetime | list[str] | None
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

        type TokenValidation = dict[str, bool | datetime | str | dict[str, object]]
        type RefreshToken = dict[str, str | datetime | bool | dict[str, object]]
        type AccessToken = dict[str, str | datetime | int | list[str]]
        type TokenRevocation = dict[str, datetime | str | bool]

    # =========================================================================
    # AUTHORIZATION TYPES - Complex authorization and RBAC types
    # =========================================================================

    class Authorization:
        """Authorization and RBAC complex types."""

        type RoleDefinition = dict[
            str, str | list[str] | dict[str, str | int | float | bool | None]
        ]
        type PermissionSet = dict[str, bool | list[str] | dict[str, object]]
        type AccessPolicy = dict[
            str, str | int | float | bool | list[dict[str, object]] | None
        ]
        type AuthorityMapping = dict[
            str, list[str] | dict[str, str | int | float | bool | None]
        ]
        type ResourceAccess = dict[
            str, bool | list[str] | dict[str, str | int | float | bool | None]
        ]
        type PolicyValidation = dict[str, bool | str | list[str] | dict[str, object]]

    # =========================================================================
    # SECURITY TYPES - Complex security and password types
    # =========================================================================

    class Security:
        """Security and password complex types."""

        type PasswordPolicy = dict[str, int | bool | list[str] | dict[str, object]]
        type PasswordValidation = dict[str, bool | str | list[str]]
        type SecurityConfiguration = dict[
            str, str | int | float | bool | dict[str, object] | None
        ]
        type ThreatDetection = dict[str, bool | int | list[str] | dict[str, datetime]]
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

        user: FlextAuthTypes.UserDict
        session: FlextAuthTypes.SessionDict
        jwt_token: str  # JWT token
        tokens: NotRequired[dict[str, str | int]]  # Optional tokens dict
        authenticated: bool
        success: bool

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
        type IdentityConfig = dict[str, str | int | bool | list[str]]
        type SecurityConfig = dict[str, bool | str | dict[str, object]]
        type SessionConfig = dict[str, str | int | float | bool | object | None]


# =============================================================================
# PUBLIC API EXPORTS - Auth TypeVars and types
# =============================================================================

__all__: list[str] = [
    "FlextAuthTypes",
]
