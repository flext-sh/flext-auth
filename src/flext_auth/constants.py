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
from enum import StrEnum, unique
from types import MappingProxyType
from typing import Final

from flext_api import FlextApiConstants


class FlextAuthConstants(FlextApiConstants):
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
    >>> from flext_auth import FlextAuthConstants as AuthConst
    >>> token_type = AuthConst.Auth.TokenTypes.ACCESS
    >>> provider = AuthConst.Auth.ProviderTypes.JWT

    # Type-safe validation
    >>> AuthConst.Auth.TokenTypes.is_valid_token_type("access")  # True
    >>> AuthConst.Auth.ProviderTypes.is_jwt_provider("jwt")  # True

    # Literal types for Pydantic models
    >>> token: AuthConst.Auth.TokenTypeLiteral  # Type-safe: "access" | "refresh" | ...
    """

    class Auth:
        """Auth domain constants namespace.

        All Auth-specific constants are organized here for better namespace
        organization and to enable composition with other domain constants.
        """

        @unique
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

        @unique
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

        @unique
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

        @unique
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

        @unique
        class Algorithms(StrEnum):
            """Algorithm type enumeration.

            DRY Pattern:
                StrEnum is the single source of truth. Use Algorithms.HS256.value
                or Algorithms.HS256 directly - no base strings needed.
            """

            HS256 = "HS256"
            RS256 = "RS256"
            ES256 = "ES256"

        VALID_TOKEN_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in TokenTypes.__members__.values()
        )
        "Immutable set of all valid token types for O(1) validation."
        VALID_PROVIDER_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in ProviderTypes.__members__.values()
        )
        "Immutable set of all valid provider types."
        VALID_ROLE_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in RoleTypes.__members__.values()
        )
        "Immutable set of all valid role types."
        VALID_PERMISSION_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in PermissionTypes.__members__.values()
        )
        "Immutable set of all valid permission types."
        ACCESS_TOKEN_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in [TokenTypes.ACCESS, TokenTypes.BEARER]
        )
        "Access token types for validation."
        USER_ROLE_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value
            for member in [RoleTypes.USER, RoleTypes.MODERATOR, RoleTypes.GUEST]
        )
        "User role types for validation."
        WRITE_PERMISSION_TYPES: Final[AbstractSet[str]] = frozenset(
            member.value for member in [PermissionTypes.WRITE, PermissionTypes.DELETE]
        )
        "Write permission types for validation."
        DEFAULT_TIMEOUT: Final[float] = float(FlextApiConstants.Network.DEFAULT_TIMEOUT)
        "Default request timeout in seconds."
        DEFAULT_MAX_RETRIES: Final[int] = FlextApiConstants.DEFAULT_MAX_RETRY_ATTEMPTS
        "Default maximum retry attempts."
        DEFAULT_JWT_EXPIRY_MINUTES: Final[int] = 1440
        "Default JWT token expiry in minutes."
        DEFAULT_SESSION_EXPIRY_MINUTES: Final[int] = 1440
        "Default session expiry in minutes."
        DEFAULT_MAX_SESSIONS_PER_USER: Final[int] = 5
        "Default maximum sessions per user."
        DEFAULT_HASH_ROUNDS: Final[int] = 12
        "Default bcrypt hash rounds."
        DEFAULT_JWT_ALGORITHM: Final[str] = "HS256"
        "Default JWT algorithm."
        MAX_USERNAME_LENGTH: Final[int] = 255
        "Maximum username length."
        MAX_EMAIL_LENGTH: Final[int] = 254
        "Maximum email length."
        MIN_PASSWORD_LENGTH: Final[int] = 8
        "Minimum password length."
        MAX_PASSWORD_LENGTH: Final[int] = 128
        "Maximum password length."
        MAX_TOKEN_LENGTH: Final[int] = 4096
        "Maximum token length."
        MAX_SECRET_KEY_LENGTH: Final[int] = 4096
        "Maximum secret key length."
        DEFAULT_ISSUER: Final[str] = "flext-auth"
        "Default JWT issuer."
        DEFAULT_AUDIENCE: Final[str] = "flext-auth-users"
        "Default JWT audience."
        HASH_ROUNDS_DEFAULT: Final[int] = 12
        "Default hash rounds."
        HASH_ROUNDS_MIN: Final[int] = 4
        "Minimum hash rounds."
        HASH_ROUNDS_MAX: Final[int] = 31
        "Maximum hash rounds."
        CREDENTIAL_MIN_LENGTH: Final[int] = 8
        "Minimum credential length."
        CREDENTIAL_MAX_LENGTH: Final[int] = 128
        "Maximum credential length."
        MAX_ATTEMPTS_DEFAULT: Final[int] = 5
        "Default max authentication attempts."
        LOCKOUT_DURATION_MINUTES: Final[int] = 30
        "Lockout duration in minutes."
        SESSION_EXPIRY_DEFAULT_MINUTES: Final[int] = 1440
        "Default session expiry in minutes."
        SESSION_EXPIRY_MAX_MINUTES: Final[int] = 43200
        "Maximum session expiry in minutes."
        MAX_SESSIONS_DEFAULT: Final[int] = 5
        "Default max sessions per user."
        PERFORMANCE_THRESHOLD_MS: Final[float] = 1000.0
        "Performance warning threshold in milliseconds."
        MAX_REQUESTS_PER_MINUTE: Final[int] = 60
        "Max requests per minute."
        MAX_REQUESTS_PER_HOUR: Final[int] = 3600
        "Max requests per hour."
        SECRET_MIN_LENGTH: Final[int] = 32
        "Minimum secret key length."
        VALIDATION_LIMITS: Final[Mapping[str, int | float]] = MappingProxyType({
            "MAX_USERNAME_LENGTH": MAX_USERNAME_LENGTH,
            "MAX_EMAIL_LENGTH": MAX_EMAIL_LENGTH,
            "MIN_PASSWORD_LENGTH": MIN_PASSWORD_LENGTH,
            "MAX_PASSWORD_LENGTH": MAX_PASSWORD_LENGTH,
            "MAX_TOKEN_LENGTH": MAX_TOKEN_LENGTH,
            "MAX_SECRET_KEY_LENGTH": MAX_SECRET_KEY_LENGTH,
            "DEFAULT_TIMEOUT": DEFAULT_TIMEOUT,
        })
        "Validation limits mapping."
        SUCCESS_AUTH_RESPONSE: Final[Mapping[str, str | None]] = MappingProxyType({
            "status": "success",
            "message": "Authentication successful",
            "token_type": None,
        })
        "Template for successful authentication responses."
        ERROR_AUTH_RESPONSE: Final[Mapping[str, str | None]] = MappingProxyType({
            "status": "error",
            "message": None,
            "error_code": None,
        })
        "Template for authentication error responses."

        class Jwt:
            """JWT-specific constants for token generation and validation."""

            DEFAULT_ALGORITHM: Final[str] = "HS256"
            "Default JWT algorithm."
            DEFAULT_EXPIRY_MINUTES: Final[int] = 30
            "Default JWT expiry in minutes."
            MAX_EXPIRY_MINUTES: Final[int] = 1440
            "Maximum JWT expiry in minutes."
            ISSUER_CLAIM: Final[str] = "flext-auth"
            "Default JWT issuer claim."
            AUDIENCE_CLAIM: Final[str] = "flext-users"
            "Default JWT audience claim."
            MIN_SECRET_KEY_LENGTH: Final[int] = 32
            "Minimum secret key length for JWT."
            DEFAULT_TOKEN_TYPE: Final[str] = "Bearer"
            "Default token type for Authorization header."

        class OAuth2:
            """OAuth2-specific constants for token exchange and flows."""

            SCOPE_DEFAULT: Final[str] = "openid profile email"
            "Default OAuth2 scope."
            FLOWS: Final[AbstractSet[str]] = frozenset([
                "authorization_code",
                "client_credentials",
                "implicit",
            ])
            "Supported OAuth2 flows."
            FLOW_DEFAULT: Final[str] = "authorization_code"
            "Default OAuth2 flow."
            USE_PKCE_DEFAULT: Final[bool] = True
            "Whether to use PKCE by default."
            TOKEN_ENDPOINT_AUTH_METHODS: Final[AbstractSet[str]] = frozenset([
                "client_secret_basic",
                "client_secret_post",
                "none",
            ])
            "Supported token endpoint authentication methods."
            TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT: Final[str] = "client_secret_basic"
            "Default token endpoint authentication method."

        class Credentials:
            """Credential validation constants."""

            class Username:
                """Username validation constants."""

                MIN_LENGTH: Final[int] = 3
                "Minimum username length."
                MAX_LENGTH: Final[int] = 50
                "Maximum username length."

            class Password:
                """Password validation constants."""

                MIN_LENGTH: Final[int] = 8
                "Minimum password length."
                MAX_LENGTH: Final[int] = 128
                "Maximum password length."
                MIN_SCORE: Final[int] = 3
                "Minimum password strength score."
                MIN_BCRYPT_HASH_LENGTH: Final[int] = 60
                "Minimum bcrypt hash length."
                BCRYPT_ROUNDS: Final[int] = 12
                "Default bcrypt rounds."

        class Session:
            """Session management constants."""

            DEFAULT_EXPIRY_MINUTES: Final[int] = 120
            "Default session expiry in minutes."
            MAX_EXPIRY_MINUTES: Final[int] = 1440
            "Maximum session expiry in minutes."
            MAX_SESSIONS_PER_USER: Final[int] = 5
            "Maximum sessions per user."
            MIN_TOKEN_LENGTH: Final[int] = 32
            "Minimum session token length."

        class AuthSecurity:
            """Authentication security constants."""

            MAX_LOGIN_ATTEMPTS: Final[int] = 5
            "Maximum login attempts before lockout."
            LOCKOUT_DURATION_MINUTES: Final[int] = 15
            "Lockout duration in minutes."
            MAX_REQUESTS_PER_MINUTE: Final[int] = 60
            "Maximum requests per minute."
            MAX_REQUESTS_PER_HOUR: Final[int] = 1000
            "Maximum requests per hour."

        class ErrorCodes:
            """Authentication error codes."""

            INVALID_CREDENTIALS: Final[str] = "INVALID_CREDENTIALS"
            "Invalid credentials error code."
            ACCOUNT_LOCKED: Final[str] = "ACCOUNT_LOCKED"
            "Account locked error code."
            ACCOUNT_DISABLED: Final[str] = "ACCOUNT_DISABLED"
            "Account disabled error code."
            TOKEN_EXPIRED: Final[str] = "TOKEN_EXPIRED"
            "Token expired error code."
            INVALID_TOKEN: Final[str] = "INVALID_TOKEN"
            "Invalid token error code."

        class Validation:
            """Validation constraints for Pydantic field definitions."""

            SHORT_NAME_MAX: Final[int] = 64
            "Maximum length for short names (provider keys, capabilities)."
            LONG_NAME_MAX: Final[int] = 255
            "Maximum length for long names (usernames, descriptions)."

        class ModelValidation:
            """Constants for Pydantic model field validation."""

            BCRYPT_ROUNDS: Final[int] = 12
            "Bcrypt rounds for password hashing."
            DEFAULT_TOKEN_EXPIRY_MINUTES: Final[int] = 60
            "Default token expiry in minutes."
            MAX_ROLE_NAME_LENGTH: Final[int] = 50
            "Maximum length for role names."
            MAX_ROLE_DESCRIPTION_LENGTH: Final[int] = 500
            "Maximum length for role descriptions."
            MAX_PERMISSION_NAME_LENGTH: Final[int] = 100
            "Maximum length for permission names."
            MAX_PERMISSION_DESCRIPTION_LENGTH: Final[int] = 500
            "Maximum length for permission descriptions."

    @unique
    class AuthMethod(StrEnum):
        """Auth method enumeration."""

        BASIC = "basic"
        JWT = "jwt"
        OAUTH2 = "oauth2"
        APIKEY = "apikey"

    @unique
    class AuthStatus(StrEnum):
        """Auth status enumeration."""

        AUTHENTICATED = "authenticated"
        UNAUTHENTICATED = "unauthenticated"
        EXPIRED = "expired"
        INVALID = "invalid"

    @unique
    class UserStatus(StrEnum):
        """User status enumeration."""

        ACTIVE = "active"
        INACTIVE = "inactive"
        LOCKED = "locked"
        PENDING = "pending"

    @unique
    class UserAction(StrEnum):
        """User action enumeration."""

        CREATE = "create"
        UPDATE = "update"
        DELETE = "delete"
        ACTIVATE = "activate"
        DEACTIVATE = "deactivate"

    @unique
    class SessionStatus(StrEnum):
        """Session status enumeration."""

        ACTIVE = "active"
        EXPIRED = "expired"
        REVOKED = "revoked"

    @unique
    class SessionAction(StrEnum):
        """Session action enumeration."""

        CREATE = "create"
        EXTEND = "extend"
        REVOKE = "revoke"
        VALIDATE = "validate"

    @unique
    class TokenType(StrEnum):
        """Token type enumeration."""

        ACCESS = "access"
        REFRESH = "refresh"
        API = "api"
        BEARER = "bearer"

    @unique
    class TokenStatus(StrEnum):
        """Token status enumeration."""

        VALID = "valid"
        EXPIRED = "expired"
        REVOKED = "revoked"
        INVALID = "invalid"

    @unique
    class Permission(StrEnum):
        """Permission enumeration."""

        READ = "read"
        WRITE = "write"
        DELETE = "delete"
        REDACTED_LDAP_BIND_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD"

    @unique
    class Role(StrEnum):
        """Role enumeration."""

        USER = "user"
        MODERATOR = "moderator"
        REDACTED_LDAP_BIND_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD"
        GUEST = "guest"

    @unique
    class SecurityEvent(StrEnum):
        """Security event enumeration."""

        LOGIN_SUCCESS = "login_success"
        LOGIN_FAILURE = "login_failure"
        TOKEN_CREATED = "token_created"
        TOKEN_REVOKED = "token_revoked"

    @unique
    class ThreatLevel(StrEnum):
        """Threat level enumeration."""

        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    @unique
    class ProjectType(StrEnum):
        """Project type enumeration."""

        FLEXT_AUTH = "flext-auth"
        FLEXT_CORE = "flext-core"
        FLEXT_API = "flext-api"

    @unique
    class AccessTokens(StrEnum):
        """Access tokens enumeration."""

        ACCESS = "access"
        BEARER = "bearer"

    @unique
    class BearerTokens(StrEnum):
        """Bearer tokens enumeration."""

        BEARER = "bearer"
        ACCESS = "access"

    @unique
    class UserRoles(StrEnum):
        """User roles enumeration."""

        USER = "user"
        MODERATOR = "moderator"
        GUEST = "guest"

    @unique
    class WritePermissions(StrEnum):
        """Write permissions enumeration."""

        WRITE = "write"
        DELETE = "delete"

    @unique
    class TokenTypeLiteral(StrEnum):
        """Token type literal enumeration."""

        ACCESS = "access"
        REFRESH = "refresh"
        API = "api"
        BEARER = "bearer"

    @unique
    class ProviderTypeLiteral(StrEnum):
        """Provider type literal enumeration."""

        BASIC = "basic"
        JWT = "jwt"
        OAUTH2 = "oauth2"
        SAML = "saml"
        LDAP = "ldap"
        CERTIFICATE = "certificate"
        KERBEROS = "kerberos"
        APIKEY = "apikey"

    @unique
    class RoleTypeLiteral(StrEnum):
        """Role type literal enumeration."""

        REDACTED_LDAP_BIND_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD"
        USER = "user"
        MODERATOR = "moderator"
        GUEST = "guest"

    @unique
    class PermissionTypeLiteral(StrEnum):
        """Permission type literal enumeration."""

        READ = "read"
        WRITE = "write"
        DELETE = "delete"
        REDACTED_LDAP_BIND_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD"

    @unique
    class AlgorithmLiteral(StrEnum):
        """Algorithm literal enumeration."""

        HS256 = "HS256"
        RS256 = "RS256"
        ES256 = "ES256"


c = FlextAuthConstants
__all__ = ["FlextAuthConstants", "c"]
