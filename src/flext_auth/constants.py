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

from collections.abc import (
    Mapping,
    Set as AbstractSet,
)
from enum import StrEnum, unique
from types import MappingProxyType
from typing import ClassVar, Final

from flext_api import c

from flext_auth import t


class FlextAuthConstants(c):
    """FlextAuth domain constants extending c via MRO.

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
    >>> from flext_auth import AuthConst
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

        DEFAULT_ADMIN_USERNAME: ClassVar[str] = "admin"
        DEFAULT_ADMIN_EMAIL: ClassVar[str] = "admin@localhost"

        @unique
        class TokenTypes(StrEnum):
            """Token type enumeration - automatic Pydantic validation.

            PYDANTIC MODELS:
                model_config: ClassVar[m.ConfigDict] = ConfigDict(use_enum_values=True)
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

        # ===== Regex Patterns for Validation =====
        PATTERN_EMAIL: Final[str] = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        "Standard email address validation pattern."

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
        KEY_SUBJECT: Final[str] = "sub"
        "Subject claim key."
        KEY_IDENTITY_ID: Final[str] = "identity_id"
        "Identity identifier claim key."
        KEY_USER_ID: Final[str] = "user_id"
        "User identifier payload key."
        KEY_USERNAME: Final[str] = "username"
        "Username claim key."
        KEY_NAME: Final[str] = "name"
        "Display-name claim key."
        KEY_PREFERRED_USERNAME: Final[str] = "preferred_username"
        "Preferred username claim key."
        KEY_CONTACT: Final[str] = "contact"
        "Contact claim key."
        KEY_EMAIL: Final[str] = "email"
        "Email claim key."
        KEY_ROLES: Final[str] = "roles"
        "Roles claim key."
        KEY_SCOPE: Final[str] = "scope"
        "OAuth scope claim key."
        KEY_CONTACT_DOMAIN: Final[str] = "contact_domain"
        "Local contact-domain override key for identity claim normalization."
        TOKEN_IDENTITY_KEYS: Final[tuple[str, ...]] = (
            KEY_SUBJECT,
            KEY_IDENTITY_ID,
            KEY_USER_ID,
            KEY_USERNAME,
        )
        "Identity claim keys in priority order."
        TOKEN_NAME_KEYS: Final[tuple[str, ...]] = (
            KEY_NAME,
            KEY_PREFERRED_USERNAME,
            KEY_USERNAME,
        )
        "Display-name claim keys in priority order."
        TOKEN_CONTACT_KEYS: Final[tuple[str, ...]] = (KEY_CONTACT, KEY_EMAIL)
        "Contact claim keys in priority order."
        TOKEN_IDENTITY_PASSTHROUGH_FIELDS: Final[tuple[str, ...]] = (
            "credential_hash",
            "failed_attempts",
            "full_name",
            "is_active",
            "last_access",
            "locked_until",
            "permissions",
            "session_id",
            "token",
        )
        "AuthIdentity fields preserved when normalizing external token claims."
        DEFAULT_OAUTH_CONTACT_DOMAIN: Final[str] = "oauth.local"
        "Fallback local contact domain for OAuth identities."
        DEFAULT_KERBEROS_CONTACT_DOMAIN: Final[str] = "kerberos.local"
        "Fallback local contact domain for Kerberos identities."
        DEFAULT_KERBEROS_USERNAME: Final[str] = "kerberos-user"
        "Fallback principal name for Kerberos ticket data without a principal."
        SCOPE_SEPARATOR: Final[str] = " "
        "OAuth scope separator."
        DEFAULT_TIMEOUT: Final[float] = float(c.DEFAULT_TIMEOUT_SECONDS)
        "Default request timeout in seconds."
        DEFAULT_MAX_RETRIES: Final[int] = 3
        "Default maximum retry attempts."
        DEFAULT_JWT_EXPIRY_MINUTES: Final[int] = 1440
        "Default JWT token expiry in minutes."
        DEFAULT_SESSION_EXPIRY_MINUTES: Final[int] = 1440
        "Default session expiry in minutes."
        DEFAULT_MAX_SESSIONS_PER_USER: Final[int] = 5
        "Default maximum sessions per user."
        DEFAULT_HASH_ROUNDS: Final[int] = 12
        "Default bcrypt hash rounds."
        DEFAULT_JWT_ALGORITHM: Final[str] = Algorithms.HS256
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
        SECRET_MIN_LENGTH: Final[int] = 32
        "Minimum secret key length."
        VALIDATION_LIMITS: Final[Mapping[str, t.Numeric]] = MappingProxyType({
            "MAX_USERNAME_LENGTH": MAX_USERNAME_LENGTH,
            "MAX_EMAIL_LENGTH": MAX_EMAIL_LENGTH,
            "MIN_PASSWORD_LENGTH": MIN_PASSWORD_LENGTH,
            "MAX_PASSWORD_LENGTH": MAX_PASSWORD_LENGTH,
            "MAX_TOKEN_LENGTH": MAX_TOKEN_LENGTH,
            "MAX_SECRET_KEY_LENGTH": MAX_SECRET_KEY_LENGTH,
            "DEFAULT_TIMEOUT": DEFAULT_TIMEOUT,
        })
        "Validation limits mapping."
        SUCCESS_AUTH_RESPONSE: Final[t.OptionalStrMapping] = MappingProxyType({
            "status": c.Status.SUCCESS.value,
            "message": "Authentication successful",
            "token_type": None,
        })
        "Template for successful authentication responses."

        # ===== JWT Constants =====
        JWT_DEFAULT_ALGORITHM: Final[str] = Algorithms.HS256
        "Default JWT algorithm."
        JWT_DEFAULT_EXPIRY_MINUTES: Final[int] = 30
        "Default JWT expiry in minutes."
        JWT_MAX_EXPIRY_MINUTES: Final[int] = 1440
        "Maximum JWT expiry in minutes."
        JWT_ISSUER_CLAIM: Final[str] = "flext-auth"
        "Default JWT issuer claim."
        JWT_AUDIENCE_CLAIM: Final[str] = "flext-users"
        "Default JWT audience claim."
        JWT_MIN_SECRET_KEY_LENGTH: Final[int] = 32
        "Minimum secret key length for JWT."
        JWT_DEFAULT_TOKEN_TYPE: Final[str] = "Bearer"
        "Default token type for Authorization header."

        # ===== OAuth2 Constants =====
        OAUTH2_SCOPE_DEFAULT: Final[str] = "openid profile email"
        "Default OAuth2 scope."
        OAUTH2_FLOWS: Final[AbstractSet[str]] = frozenset([
            "authorization_code",
            "client_credentials",
            "implicit",
        ])
        "Supported OAuth2 flows."
        OAUTH2_FLOW_DEFAULT: Final[str] = "authorization_code"
        "Default OAuth2 flow."
        OAUTH2_USE_PKCE_DEFAULT: Final[bool] = True
        "Whether to use PKCE by default."
        OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS: Final[AbstractSet[str]] = frozenset([
            "client_secret_basic",
            "client_secret_post",
            "none",
        ])
        "Supported token endpoint authentication methods."
        OAUTH2_TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT: Final[str] = "client_secret_basic"
        "Default token endpoint authentication method."

        # ===== Credentials Constants =====
        CREDENTIALS_USERNAME_MIN_LENGTH: Final[int] = 3
        "Minimum username length."
        CREDENTIALS_USERNAME_MAX_LENGTH: Final[int] = 50
        "Maximum username length."
        CREDENTIALS_PASSWORD_MIN_LENGTH: Final[int] = 8
        "Minimum password length."
        CREDENTIALS_PASSWORD_MAX_LENGTH: Final[int] = 128
        "Maximum password length."
        CREDENTIALS_PASSWORD_MIN_SCORE: Final[int] = 3
        "Minimum password strength score."
        CREDENTIALS_PASSWORD_MIN_BCRYPT_HASH_LENGTH: Final[int] = 60
        "Minimum bcrypt hash length."
        CREDENTIALS_PASSWORD_BCRYPT_ROUNDS: Final[int] = 12
        "Default bcrypt rounds."

        # ===== Session Constants =====
        SESSION_DEFAULT_EXPIRY_MINUTES: Final[int] = 120
        "Default session expiry in minutes."
        SESSION_MAX_EXPIRY_MINUTES: Final[int] = 1440
        "Maximum session expiry in minutes."
        SESSION_MAX_SESSIONS_PER_USER: Final[int] = 5
        "Maximum sessions per user."
        SESSION_MIN_TOKEN_LENGTH: Final[int] = 32
        "Minimum session token length."

        # ===== Security Constants =====
        SECURITY_MAX_LOGIN_ATTEMPTS: Final[int] = 5
        "Maximum login attempts before lockout."
        SECURITY_LOCKOUT_DURATION_MINUTES: Final[int] = 15
        "Lockout duration in minutes."
        SECURITY_MAX_REQUESTS_PER_MINUTE: Final[int] = 60
        "Maximum requests per minute."
        SECURITY_MAX_REQUESTS_PER_HOUR: Final[int] = 1000
        "Maximum requests per hour."

        # ===== Error Codes =====
        ERROR_INVALID_CREDENTIALS: Final[str] = "INVALID_CREDENTIALS"
        "Invalid credentials error code."
        ERROR_ACCOUNT_LOCKED: Final[str] = "ACCOUNT_LOCKED"
        "Account locked error code."
        ERROR_ACCOUNT_DISABLED: Final[str] = "ACCOUNT_DISABLED"
        "Account disabled error code."
        ERROR_TOKEN_EXPIRED: Final[str] = "TOKEN_EXPIRED"
        "Token expired error code."
        ERROR_INVALID_TOKEN: Final[str] = "INVALID_TOKEN"
        "Invalid token error code."

        # ===== Validation Constants =====
        VALIDATION_SHORT_NAME_MAX: Final[int] = 64
        "Maximum length for short names (provider keys, capabilities)."

        # ===== Model Validation Constants =====
        VALIDATION_BCRYPT_ROUNDS: Final[int] = 12
        "Bcrypt rounds for password hashing."
        VALIDATION_DEFAULT_TOKEN_EXPIRY_MINUTES: Final[int] = 60
        "Default token expiry in minutes."
        VALIDATION_MAX_ROLE_NAME_LENGTH: Final[int] = 50
        "Maximum length for role names."
        VALIDATION_MAX_ROLE_DESCRIPTION_LENGTH: Final[int] = 500
        "Maximum length for role descriptions."
        VALIDATION_MAX_PERMISSION_NAME_LENGTH: Final[int] = 100
        "Maximum length for permission names."
        VALIDATION_MAX_PERMISSION_DESCRIPTION_LENGTH: Final[int] = 500
        "Maximum length for permission descriptions."


c = FlextAuthConstants

__all__: t.MutableSequenceOf[str] = ["FlextAuthConstants", "c"]
