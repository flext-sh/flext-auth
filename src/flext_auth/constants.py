"""FlextAuth constants - Pure constants using StrEnum + Pydantic 2 patterns.

FLEXT-AUTH domain constants with FlextCore integration. Uses advanced Python 3.13+ features:
- StrEnum for type-safe enumerations with Pydantic 2 validation
- PEP 695 type aliases for strict Literal types
- Nested classes for logical grouping (TokenTypes, ProviderTypes, etc.)
- Collections.abc for immutable validation sets

NOTE: Validation/TypeGuard methods are in utilities.py, not here.
Constants classes contain ONLY pure constant definitions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Set as AbstractSet
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal

from flext_core import FlextConstants

# ═══════════════════════════════════════════════════════════════════════════
# STRENUM + PYDANTIC 2: DEFINITIVE PATTERN FOR FLEXT-AUTH
# ═══════════════════════════════════════════════════════════════════════════

# FUNDAMENTAL PRINCIPLE: StrEnum + Pydantic 2 = Automatic Validation!
# - No need to create separate Literal for validation
# - No need to create frozenset for validation
# - No need to create AfterValidator
# - Pydantic automatically validates against StrEnum

# SUBSETS: Use Literal[TokenTypes.ACCESS, TokenTypes.REFRESH] to accept only SOME values.
# This references the enum member, does not duplicate strings!


class FlextAuthConstants(FlextConstants):
    """FlextAuth domain constants extending FlextConstants.

    Architecture: Layer 1 (Domain Constants - Extends Core)
    =========================================================
    Provides domain-specific constants for authentication using advanced patterns:
    - StrEnum for type-safe enumerations with automatic Pydantic validation
    - PEP 695 type aliases for strict Literal unions
    - Nested classes for logical grouping (TokenTypes, ProviderTypes, etc.)
    - TypeIs/TypeGuard methods for advanced type narrowing
    - Collections.abc for immutable validation sets

    Integration with p:
    This class provides the constant registry that FlextAuthProtocols depend on.
    Structural typing ensures protocol compliance without explicit inheritance.

    Architecture:
    - All Auth constants are organized in the .Auth namespace
    - Direct access via FlextAuthConstants.Auth.*
    - No aliases - use namespaces directly following FLEXT architecture patterns

    Usage Patterns:
    # Direct access (recommended)
    >>> from flext_auth.constants import FlextAuthConstants as AuthConst
    >>> token_type = AuthConst.Auth.TokenTypes.ACCESS
    >>> provider = AuthConst.Auth.ProviderTypes.JWT

    # Type-safe validation
    >>> AuthConst.Auth.TokenTypes.is_valid_token_type("access")  # True
    >>> AuthConst.Auth.ProviderTypes.is_jwt_provider("jwt")  # True

    # Literal types for Pydantic models
    >>> token: AuthConst.Auth.TokenTypeLiteral  # Type-safe: "access" | "refresh" | ...
    """

    # =========================================================================
    # NAMESPACE: .Auth - All Auth domain constants
    # =========================================================================

    class Auth:
        """Auth domain constants namespace.

        All Auth-specific constants are organized here for better namespace
        organization and to enable composition with other domain constants.
        """

        # ═══════════════════════════════════════════════════════════════════
        # STRENUM: Single declaration needed for automatic validation
        # ═══════════════════════════════════════════════════════════════════

        class TokenTypes(StrEnum):
            """Token type enumeration - automatic Pydantic validation.

            PYDANTIC MODELS:
                model_config = ConfigDict(use_enum_values=True)
                token_type: FlextAuthConstants.Auth.TokenTypes

            Result:
                - Accepts "access", "refresh", etc. or TokenTypes.ACCESS
                - Serializes as string
                - Automatically validates (rejects invalid values)

            DRY Pattern:
                StrEnum is the single source of truth. Use TokenTypes.ACCESS.value
                or TokenTypes.ACCESS directly - no base strings needed.
            """

            ACCESS = "access"
            REFRESH = "refresh"
            API = "api"
            BEARER = "bearer"

        class ProviderTypes(StrEnum):
            """Provider type enumeration - automatic Pydantic validation.

            DRY Pattern:
                StrEnum is the single source of truth. Use ProviderTypes.JWT.value
                or ProviderTypes.JWT directly - no base strings needed.
            """

            BASIC = "basic"
            JWT = "jwt"
            OAUTH2 = "oauth2"
            SAML = "saml"
            LDAP = "ldap"
            CERTIFICATE = "certificate"
            KERBEROS = "kerberos"
            APIKEY = "apikey"

        class RoleTypes(StrEnum):
            """Role type enumeration - automatic Pydantic validation.

            DRY Pattern:
                StrEnum is the single source of truth. Use RoleTypes.ADMIN.value
                or RoleTypes.ADMIN directly - no base strings needed.
            """

            ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
            USER = "user"
            MODERATOR = "moderator"
            GUEST = "guest"

        class PermissionTypes(StrEnum):
            """Permission type enumeration - automatic Pydantic validation.

            DRY Pattern:
                StrEnum is the single source of truth. Use PermissionTypes.READ.value
                or PermissionTypes.READ directly - no base strings needed.
            """

            READ = "read"
            WRITE = "write"
            DELETE = "delete"
            ADMIN = "REDACTED_LDAP_BIND_PASSWORD"

        class Algorithms(StrEnum):
            """Algorithm type enumeration.

            DRY Pattern:
                StrEnum is the single source of truth. Use Algorithms.HS256.value
                or Algorithms.HS256 directly - no base strings needed.
            """

            HS256 = "HS256"
            RS256 = "RS256"
            ES256 = "ES256"

        # ═══════════════════════════════════════════════════════════════════
        # SUBSETS: Literal referencing StrEnum members
        # ═══════════════════════════════════════════════════════════════════
        # Use to accept only SOME enum values in methods
        # This does not duplicate strings - references the enum member!

        type AccessTokens = Literal[TokenTypes.ACCESS, TokenTypes.BEARER]
        """Access token types for operations."""
        type RefreshTokens = Literal[TokenTypes.REFRESH]
        """Refresh token types."""
        type BearerTokens = Literal[TokenTypes.BEARER, TokenTypes.ACCESS]
        """Bearer token types."""
        type AdminRoles = Literal[RoleTypes.ADMIN]
        """Admin role types."""
        type UserRoles = Literal[RoleTypes.USER, RoleTypes.MODERATOR, RoleTypes.GUEST]
        """User role types."""
        type WritePermissions = Literal[PermissionTypes.WRITE, PermissionTypes.DELETE]
        """Write permission types."""
        type AdminPermissions = Literal[PermissionTypes.ADMIN]
        """Admin permission types."""

        # ═══════════════════════════════════════════════════════════════════
        # IMMUTABLE COLLECTIONS: frozenset for O(1) validation
        # ═══════════════════════════════════════════════════════════════════

        VALID_TOKEN_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in TokenTypes.__members__.values()
        )
        """Immutable set of all valid token types for O(1) validation."""

        VALID_PROVIDER_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in ProviderTypes.__members__.values()
        )
        """Immutable set of all valid provider types."""

        VALID_ROLE_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in RoleTypes.__members__.values()
        )
        """Immutable set of all valid role types."""

        VALID_PERMISSION_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in PermissionTypes.__members__.values()
        )
        """Immutable set of all valid permission types."""

        ACCESS_TOKEN_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in [TokenTypes.ACCESS, TokenTypes.BEARER]
        )
        """Access token types for validation."""

        USER_ROLE_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value
            for member in [RoleTypes.USER, RoleTypes.MODERATOR, RoleTypes.GUEST]
        )
        """User role types for validation."""

        WRITE_PERMISSION_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in [PermissionTypes.WRITE, PermissionTypes.DELETE]
        )
        """Write permission types for validation."""

        # ═══════════════════════════════════════════════════════════════════
        # CONFIGURATION CONSTANTS: Default values and limits
        # ═══════════════════════════════════════════════════════════════════

        DEFAULT_TIMEOUT: Final[float] = 30.0
        """Default request timeout in seconds."""

        DEFAULT_MAX_RETRIES: Final[int] = 3
        """Default maximum retry attempts."""

        DEFAULT_JWT_EXPIRY_MINUTES: Final[int] = 1440  # 24 hours
        """Default JWT token expiry in minutes."""

        DEFAULT_SESSION_EXPIRY_MINUTES: Final[int] = 1440  # 24 hours
        """Default session expiry in minutes."""

        DEFAULT_MAX_SESSIONS_PER_USER: Final[int] = 5
        """Default maximum sessions per user."""

        DEFAULT_HASH_ROUNDS: Final[int] = 12
        """Default bcrypt hash rounds."""

        DEFAULT_JWT_ALGORITHM: Final[str] = "HS256"
        """Default JWT algorithm."""

        MAX_USERNAME_LENGTH: Final[int] = 255
        """Maximum username length."""

        MAX_EMAIL_LENGTH: Final[int] = 254
        """Maximum email length."""

        MIN_PASSWORD_LENGTH: Final[int] = 8
        """Minimum password length."""

        MAX_PASSWORD_LENGTH: Final[int] = 128
        """Maximum password length."""

        MAX_TOKEN_LENGTH: Final[int] = 4096
        """Maximum token length."""

        MAX_SECRET_KEY_LENGTH: Final[int] = 4096
        """Maximum secret key length."""

        # JWT Configuration
        DEFAULT_ISSUER: Final[str] = "flext-auth"
        """Default JWT issuer."""
        DEFAULT_AUDIENCE: Final[str] = "flext-auth-users"
        """Default JWT audience."""

        # Hash Configuration
        HASH_ROUNDS_DEFAULT: Final[int] = 12
        """Default hash rounds."""
        HASH_ROUNDS_MIN: Final[int] = 4
        """Minimum hash rounds."""
        HASH_ROUNDS_MAX: Final[int] = 31
        """Maximum hash rounds."""

        # Credential Configuration
        CREDENTIAL_MIN_LENGTH: Final[int] = 8
        """Minimum credential length."""
        CREDENTIAL_MAX_LENGTH: Final[int] = 128
        """Maximum credential length."""

        # Security Policies
        MAX_ATTEMPTS_DEFAULT: Final[int] = 5
        """Default max authentication attempts."""
        LOCKOUT_DURATION_MINUTES: Final[int] = 30
        """Lockout duration in minutes."""

        # Session Configuration
        SESSION_EXPIRY_DEFAULT_MINUTES: Final[int] = 1440  # 24 hours
        """Default session expiry in minutes."""
        SESSION_EXPIRY_MAX_MINUTES: Final[int] = 43200  # 30 days
        """Maximum session expiry in minutes."""
        MAX_SESSIONS_DEFAULT: Final[int] = 5
        """Default max sessions per user."""

        # Performance & Rate Limiting
        PERFORMANCE_THRESHOLD_MS: Final[float] = 1000.0
        """Performance warning threshold in milliseconds."""
        MAX_REQUESTS_PER_MINUTE: Final[int] = 60
        """Max requests per minute."""
        MAX_REQUESTS_PER_HOUR: Final[int] = 3600
        """Max requests per hour."""

        # Secret Validation
        SECRET_MIN_LENGTH: Final[int] = 32
        """Minimum secret key length."""

        # ═══════════════════════════════════════════════════════════════════
        # VALIDATION LIMITS: Immutable mappings for validation
        # ═══════════════════════════════════════════════════════════════════

        VALIDATION_LIMITS: Final[Mapping[str, int | float]] = MappingProxyType({
            "MAX_USERNAME_LENGTH": MAX_USERNAME_LENGTH,
            "MAX_EMAIL_LENGTH": MAX_EMAIL_LENGTH,
            "MIN_PASSWORD_LENGTH": MIN_PASSWORD_LENGTH,
            "MAX_PASSWORD_LENGTH": MAX_PASSWORD_LENGTH,
            "MAX_TOKEN_LENGTH": MAX_TOKEN_LENGTH,
            "MAX_SECRET_KEY_LENGTH": MAX_SECRET_KEY_LENGTH,
            "DEFAULT_TIMEOUT": DEFAULT_TIMEOUT,
        })
        """Validation limits mapping."""

        # ═══════════════════════════════════════════════════════════════════
        # RESPONSE TEMPLATES: Immutable mappings
        # ═══════════════════════════════════════════════════════════════════

        SUCCESS_AUTH_RESPONSE: Final[Mapping[str, str | None]] = MappingProxyType({
            "status": "success",
            "message": "Authentication successful",
            "token_type": None,
        })
        """Template for successful authentication responses."""

        ERROR_AUTH_RESPONSE: Final[Mapping[str, str | None]] = MappingProxyType({
            "status": "error",
            "message": None,
            "error_code": None,
        })
        """Template for authentication error responses."""

        # ═══════════════════════════════════════════════════════════════════
        # LITERAL TYPES: PEP 695 strict type aliases (Python 3.13+)
        # ═══════════════════════════════════════════════════════════════════
        # All Literal types reference StrEnum members - NO string duplication!

        type TokenTypeLiteral = Literal[
            TokenTypes.ACCESS,
            TokenTypes.REFRESH,
            TokenTypes.API,
            TokenTypes.BEARER,
        ]
        """Token type literal - references TokenTypes StrEnum members."""

        type ProviderTypeLiteral = Literal[
            ProviderTypes.BASIC,
            ProviderTypes.JWT,
            ProviderTypes.OAUTH2,
            ProviderTypes.SAML,
            ProviderTypes.LDAP,
            ProviderTypes.CERTIFICATE,
            ProviderTypes.KERBEROS,
            ProviderTypes.APIKEY,
        ]
        """Provider type literal - references ProviderTypes StrEnum members."""

        type RoleTypeLiteral = Literal[
            RoleTypes.ADMIN,
            RoleTypes.USER,
            RoleTypes.MODERATOR,
            RoleTypes.GUEST,
        ]
        """Role type literal - matches RoleTypes StrEnum values exactly."""

        type PermissionTypeLiteral = Literal[
            PermissionTypes.READ,
            PermissionTypes.WRITE,
            PermissionTypes.DELETE,
            PermissionTypes.ADMIN,
        ]
        """Permission type literal - matches PermissionTypes StrEnum values exactly."""

        type AlgorithmLiteral = Literal[
            Algorithms.HS256,
            Algorithms.RS256,
            Algorithms.ES256,
        ]
        """Algorithm literal - matches Algorithms StrEnum values exactly."""

        # ═══════════════════════════════════════════════════════════════════
        # JWT CONSTANTS: Nested class for JWT-specific constants
        # ═══════════════════════════════════════════════════════════════════

        class Jwt:
            """JWT-specific constants for token generation and validation."""

            DEFAULT_ALGORITHM: Final[str] = "HS256"
            """Default JWT algorithm."""
            DEFAULT_EXPIRY_MINUTES: Final[int] = 30
            """Default JWT expiry in minutes."""
            MAX_EXPIRY_MINUTES: Final[int] = 1440
            """Maximum JWT expiry in minutes."""
            ISSUER_CLAIM: Final[str] = "flext-auth"
            """Default JWT issuer claim."""
            AUDIENCE_CLAIM: Final[str] = "flext-users"
            """Default JWT audience claim."""
            MIN_SECRET_KEY_LENGTH: Final[int] = 32
            """Minimum secret key length for JWT."""
            DEFAULT_TOKEN_TYPE: Final[str] = "Bearer"
            """Default token type for Authorization header."""

        # ═══════════════════════════════════════════════════════════════════
        # CREDENTIALS CONSTANTS: Nested class for credential validation
        # ═══════════════════════════════════════════════════════════════════

        class Credentials:
            """Credential validation constants."""

            class Username:
                """Username validation constants."""

                MIN_LENGTH: Final[int] = 3
                """Minimum username length."""
                MAX_LENGTH: Final[int] = 50
                """Maximum username length."""

            class Password:
                """Password validation constants."""

                MIN_LENGTH: Final[int] = 8
                """Minimum password length."""
                MAX_LENGTH: Final[int] = 128
                """Maximum password length."""
                MIN_SCORE: Final[int] = 3
                """Minimum password strength score."""
                MIN_BCRYPT_HASH_LENGTH: Final[int] = 60
                """Minimum bcrypt hash length."""
                BCRYPT_ROUNDS: Final[int] = 12
                """Default bcrypt rounds."""

        # ═══════════════════════════════════════════════════════════════════
        # SESSION CONSTANTS: Nested class for session management
        # ═══════════════════════════════════════════════════════════════════

    class Session:
        """Session management constants."""

        DEFAULT_EXPIRY_MINUTES: Final[int] = 120
        """Default session expiry in minutes."""
        MAX_EXPIRY_MINUTES: Final[int] = 1440
        """Maximum session expiry in minutes."""
        MAX_SESSIONS_PER_USER: Final[int] = 5
        """Maximum sessions per user."""
        MIN_TOKEN_LENGTH: Final[int] = 32
        """Minimum session token length."""

        # ═══════════════════════════════════════════════════════════════════
        # AUTH SECURITY CONSTANTS: Nested class for security policies
        # ═══════════════════════════════════════════════════════════════════

    class AuthSecurity:
        """Authentication security constants."""

        MAX_LOGIN_ATTEMPTS: Final[int] = 5
        """Maximum login attempts before lockout."""
        LOCKOUT_DURATION_MINUTES: Final[int] = 15
        """Lockout duration in minutes."""
        MAX_REQUESTS_PER_MINUTE: Final[int] = 60
        """Maximum requests per minute."""
        MAX_REQUESTS_PER_HOUR: Final[int] = 1000
        """Maximum requests per hour."""

        # ═══════════════════════════════════════════════════════════════════
        # ERROR CODES CONSTANTS: Nested class for error codes
        # ═══════════════════════════════════════════════════════════════════

    class ErrorCodes:
        """Authentication error codes."""

        INVALID_CREDENTIALS: Final[str] = "INVALID_CREDENTIALS"
        """Invalid credentials error code."""
        ACCOUNT_LOCKED: Final[str] = "ACCOUNT_LOCKED"
        """Account locked error code."""
        ACCOUNT_DISABLED: Final[str] = "ACCOUNT_DISABLED"
        """Account disabled error code."""
        TOKEN_EXPIRED: Final[str] = "TOKEN_EXPIRED"
        """Token expired error code."""
        INVALID_TOKEN: Final[str] = "INVALID_TOKEN"
        """Invalid token error code."""

        # ═══════════════════════════════════════════════════════════════════
        # MODEL VALIDATION CONSTANTS: For Pydantic field constraints
        # ═══════════════════════════════════════════════════════════════════

    class ModelValidation:
        """Constants for Pydantic model field validation."""

        # Password hashing
        BCRYPT_ROUNDS: Final[int] = 12
        """Bcrypt rounds for password hashing."""

        # Token configuration
        DEFAULT_TOKEN_EXPIRY_MINUTES: Final[int] = 60
        """Default token expiry in minutes."""

        # Role validation
        MAX_ROLE_NAME_LENGTH: Final[int] = 50
        """Maximum length for role names."""
        MAX_ROLE_DESCRIPTION_LENGTH: Final[int] = 500
        """Maximum length for role descriptions."""

        # Permission validation
        MAX_PERMISSION_NAME_LENGTH: Final[int] = 100
        """Maximum length for permission names."""
        MAX_PERMISSION_DESCRIPTION_LENGTH: Final[int] = 500
        """Maximum length for permission descriptions."""

        # ═══════════════════════════════════════════════════════════════════
        # INHERITED CONSTANTS: Access parent constants directly
        # ═══════════════════════════════════════════════════════════════════
        # All constants from FlextConstants are accessible via inheritance.
        # Use FlextConstants.Cqrs.Status, FlextConstants.Errors.*, etc. directly.
        # Use Auth.PermissionTypes and Auth.RoleTypes StrEnums directly.
        # No need for explicit Inherited class - inheritance provides access.


c = FlextAuthConstants  # Runtime alias (not TypeAlias to avoid PYI042)

__all__ = ["FlextAuthConstants", "c"]
