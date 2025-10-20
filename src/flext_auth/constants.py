"""FLEXT Auth Constants - Authentication domain constants following standardization plan.

**Standardization Compliance:**
- ✅ Layer 0 purity: Only constants, no functions or behavior
- ✅ Direct FlextConstants inheritance: Clean dependency chain
- ✅ Composition pattern: CoreErrors, CoreNetwork, etc. for easy access
- ✅ Final[Type] declarations: Immutable type-safe constants
- ✅ Type aliases: Literal types for strict typing

**Domain Coverage:**
- Token types, algorithms, providers, roles, permissions
- Security policies, cryptography defaults, validation constraints
- Session management, rate limiting, authentication protocols
- OAuth2, SAML, JWT, and multi-provider support

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from flext_core import FlextConstants

# =============================================================================
# STRING ENUMS - Type-safe string literals for authentication domain
# =============================================================================


class TokenType(StrEnum):
    """Token type enumeration - runtime type-safe token types."""

    ACCESS = "access"
    REFRESH = "refresh"
    API = "api"
    BEARER = "bearer"


class ProviderType(StrEnum):
    """Provider type enumeration - runtime type-safe provider types."""

    BASIC = "basic"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    SAML = "saml"
    LDAP = "ldap"
    CERTIFICATE = "certificate"
    KERBEROS = "kerberos"
    APIKEY = "apikey"


class RoleType(StrEnum):
    """Role type enumeration - runtime type-safe role types."""

    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    USER = "user"
    MODERATOR = "moderator"
    GUEST = "guest"


class PermissionType(StrEnum):
    """Permission type enumeration - runtime type-safe permission types."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"


class FlextAuthConstants(FlextConstants):
    """Authentication domain constants with composition patterns.

    **Usage Examples:**

    1. Token Management:
        >>> from flext_auth.constants import FlextAuthConstants as AuthConst
        >>> token_type = AuthConst.TOKEN_TYPE_ACCESS
        >>> algorithm = AuthConst.ALGORITHM_DEFAULT
        >>> expiry = AuthConst.EXPIRY_DEFAULT_MINUTES

    2. Security Configuration:
        >>> rounds = AuthConst.HASH_ROUNDS_DEFAULT
        >>> attempts = AuthConst.MAX_ATTEMPTS_DEFAULT
        >>> lockout = AuthConst.LOCKOUT_DURATION_MINUTES

    3. Role and Permission Management:
        >>> roles = AuthConst.VALID_ROLES
        >>> permissions = AuthConst.ADMIN_PERMISSIONS
        >>> default_role = AuthConst.DEFAULT_ROLES[0]

    4. Core Composition Access:
        >>> error = AuthConst.CoreErrors.AUTHENTICATION_ERROR
        >>> timeout = AuthConst.CoreNetwork.DEFAULT_TIMEOUT

    5. Type-Safe Literals:
        >>> token_types: AuthConst.TokenType = "access"
        >>> provider: AuthConst.ProviderType = "jwt"
    """

    # =========================================================================
    # COMPOSITION REFERENCES (Standardization Pattern)
    # =========================================================================

    # Core composition - reference core constants for easy access
    CoreErrors = FlextConstants.Errors
    CoreNetwork = FlextConstants.Network
    CoreSecurity = FlextConstants.Security
    CorePlatform = FlextConstants.Platform
    CoreValidation = FlextConstants.Validation

    # =========================================================================
    # GENERIC TYPE ALIASES - DOMAIN AGNOSTIC
    # =========================================================================

    TokenType = Literal["access", "refresh", "api", "bearer"]
    ProviderType = Literal[
        "basic", "jwt", "oauth2", "saml", "ldap", "certificate", "kerberos", "apikey"
    ]
    ProjectType = Literal[
        "library",
        "application",
        "service",
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

    # =========================================================================
    # IMMUTABLE CONSTANTS - NO CONFIGURATION (USE CONFIG.PY FOR SETTINGS)
    # =========================================================================

    # Token Types & Prefixes
    TOKEN_TYPES: Final[tuple[str, ...]] = ("access", "refresh", "api", "bearer")
    TOKEN_TYPE_ACCESS: Final[str] = "access"
    TOKEN_TYPE_BEARER: Final[str] = "bearer"
    TOKEN_TYPE_API: Final[str] = "api"
    TOKEN_PREFIX_BEARER: Final[str] = "Bearer"

    # Algorithms Supported
    ALLOWED_ALGORITHMS: Final[list[str]] = ["HS256", "RS256", "ES256"]

    # Permission & Role Constants
    PERMISSION_READ: Final[str] = "read"
    PERMISSION_WRITE: Final[str] = "write"
    PERMISSION_DELETE: Final[str] = "delete"
    PERMISSION_ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
    ROLE_ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
    ROLE_USER: Final[str] = "user"
    ROLE_MODERATOR: Final[str] = "moderator"
    ROLE_GUEST: Final[str] = "guest"
    DEFAULT_ROLES: Final[list[str]] = ["user"]
    VALID_ROLES: Final[list[str]] = ["REDACTED_LDAP_BIND_PASSWORD", "user", "moderator", "guest"]
    BASIC_PERMISSIONS: Final[list[str]] = ["read", "write"]
    ADMIN_PERMISSIONS: Final[list[str]] = ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]

    # Weak Credentials (Security Pattern)
    WEAK_CREDENTIALS: Final[list[str]] = [
        "123",
        "abc",
        "password",
        "12345678",
        "aaaaaaaa",
    ]

    # Platform & Network (from flext-core)
    PLATFORM_FLEXT_API_PORT: Final[int] = FlextConstants.Platform.FLEXT_API_PORT
    PLATFORM_DEFAULT_HOST: Final[str] = FlextConstants.Platform.DEFAULT_HOST
    PLATFORM_LOOPBACK_IP: Final[str] = "127.0.0.1"
    NETWORK_MIN_PORT: Final[int] = FlextConstants.Network.MIN_PORT
    NETWORK_MAX_PORT: Final[int] = FlextConstants.Network.MAX_PORT
    NETWORK_DEFAULT_TIMEOUT: Final[int] = FlextConstants.Network.DEFAULT_TIMEOUT

    # =========================================================================
    # VALIDATION CONSTRAINTS - All magic values for input validation
    # =========================================================================

    # Secret/credential length constraints
    SECRET_MIN_LENGTH: Final[int] = 16
    CREDENTIAL_MIN_LENGTH: Final[int] = 8
    CREDENTIAL_MAX_LENGTH: Final[int] = 128
    IDENTITY_MIN_LENGTH: Final[int] = 1
    IDENTITY_MAX_LENGTH: Final[int] = 255

    # =========================================================================
    # TOKEN & SESSION DEFAULTS - Expiry and timing
    # =========================================================================

    EXPIRY_DEFAULT_MINUTES: Final[int] = 1440  # 24 hours
    EXPIRY_MAX_MINUTES: Final[int] = 43200  # 30 days
    SESSION_EXPIRY_DEFAULT_MINUTES: Final[int] = 1440  # 24 hours
    SESSION_EXPIRY_MAX_MINUTES: Final[int] = 43200  # 30 days

    # =========================================================================
    # CRYPTOGRAPHY DEFAULTS - Hash rounds and algorithms
    # =========================================================================

    HASH_ROUNDS_DEFAULT: Final[int] = 12
    HASH_ROUNDS_MIN: Final[int] = 10
    HASH_ROUNDS_MAX: Final[int] = 15
    ALGORITHM_DEFAULT: Final[str] = "HS256"

    # =========================================================================
    # SECURITY POLICIES - Authentication attempt and lockout
    # =========================================================================

    MAX_ATTEMPTS_DEFAULT: Final[int] = 5
    LOCKOUT_DURATION_MINUTES: Final[int] = 15
    MAX_SESSIONS_DEFAULT: Final[int] = 5

    # =========================================================================
    # RATE LIMITING & PERFORMANCE - Request limits and thresholds
    # =========================================================================

    MAX_REQUESTS_PER_MINUTE: Final[int] = 60
    MAX_REQUESTS_PER_HOUR: Final[int] = 1000
    PERFORMANCE_THRESHOLD_MS: Final[float] = 100.0

    # =========================================================================
    # DEFAULT ISSUER & AUDIENCE - Token claim defaults
    # =========================================================================

    DEFAULT_TOKEN_TYPE: Final[str] = "access"
    DEFAULT_ISSUER: Final[str] = "flext-auth"
    DEFAULT_AUDIENCE: Final[str] = "flext-users"

    # =========================================================================
    # PROTOCOL CONSTANTS - GENERIC PROTOCOL SUPPORT
    # =========================================================================

    OAUTH2_CLIENT_SECRET_POST: Final[str] = "client_secret_post"
    OAUTH2_CLIENT_SECRET_BASIC: Final[str] = "client_secret_basic"
    SAML_NS_ASSERTION: Final[str] = "urn:oasis:names:tc:SAML:2.0:assertion"
    SAML_NS_PROTOCOL: Final[str] = "urn:oasis:names:tc:SAML:2.0:protocol"
    SAML_NS_SIGNATURE: Final[str] = "http://www.w3.org/2000/09/xmldsig#"

    # =========================================================================
    # CREDENTIALS CONSTANTS
    # =========================================================================

    class Credentials(FlextConstants.Validation):
        """Credential validation and security constants."""

        MIN_LENGTH: Final[int] = 8
        MAX_LENGTH: Final[int] = 128

    # =========================================================================
    # SESSION CONSTANTS
    # =========================================================================

    class Session(FlextConstants.Validation):
        """Session management constants."""

        EXPIRY_DEFAULT_MINUTES: Final[int] = 1440  # 24 hours
        EXPIRY_MAX_MINUTES: Final[int] = 43200  # 30 days

    # =========================================================================
    # ERROR CODES
    # =========================================================================

    class ErrorCodes(FlextConstants.Errors):
        """Authentication-specific error codes extending core errors."""

        AUTHORIZATION_ERROR: Final[str] = "AUTHORIZATION_ERROR"
        TOKEN_ERROR: Final[str] = "TOKEN_ERROR"
        SESSION_ERROR: Final[str] = "SESSION_ERROR"
        CREDENTIAL_ERROR: Final[str] = "CREDENTIAL_ERROR"

    # =========================================================================
    # JWT CONSTANTS
    # =========================================================================

    class Jwt:
        """JWT token constants."""

        ALGORITHM_DEFAULT: Final[str] = "HS256"
        EXPIRY_DEFAULT_MINUTES: Final[int] = 1440  # 24 hours
        EXPIRY_MAX_MINUTES: Final[int] = 43200  # 30 days

    # =========================================================================
    # AUTH SECURITY CONSTANTS
    # =========================================================================

    class AuthSecurity:
        """Authentication security constants."""

        HASH_ROUNDS_DEFAULT: Final[int] = 12
        HASH_ROUNDS_MIN: Final[int] = 10
        HASH_ROUNDS_MAX: Final[int] = 15
        MAX_ATTEMPTS_DEFAULT: Final[int] = 5
        LOCKOUT_DURATION_MINUTES: Final[int] = 15

    # =========================================================================
    # ROLES CONSTANTS
    # =========================================================================

    class Roles:
        """User role constants."""

        ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
        USER: Final[str] = "user"
        MODERATOR: Final[str] = "moderator"
        GUEST: Final[str] = "guest"
        VALID_ROLES: Final[list[str]] = ["REDACTED_LDAP_BIND_PASSWORD", "user", "moderator", "guest"]
        DEFAULT_ROLES: Final[list[str]] = ["user"]

    # =========================================================================
    # PERMISSIONS CONSTANTS
    # =========================================================================

    class Permissions:
        """User permission constants."""

        READ: Final[str] = "read"
        WRITE: Final[str] = "write"
        DELETE: Final[str] = "delete"
        ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
        BASIC_PERMISSIONS: Final[list[str]] = ["read", "write"]
        ADMIN_PERMISSIONS: Final[list[str]] = ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]


__all__ = ["FlextAuthConstants"]
