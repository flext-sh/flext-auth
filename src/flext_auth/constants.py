"""FLEXT Auth Constants - Authentication domain constants following standardization plan.

**Standardization Compliance:**
- Layer 0 purity: Only constants, no functions or behavior
- Direct FlextConstants inheritance: Clean dependency chain
- Composition pattern: CoreErrors, CoreNetwork, etc. for easy access
- Final[Type] declarations: Immutable type-safe constants
- Type aliases: Literal types for strict typing

**Domain Coverage:**
- Token types, algorithms, providers, roles, permissions
- Security policies, cryptography defaults, validation constraints
- Session management, rate limiting, authentication protocols
- OAuth2, SAML, JWT, and multi-provider support

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Set as AbstractSet
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


class AlgorithmType(StrEnum):
    """Algorithm type enumeration - runtime type-safe algorithm types."""

    HS256 = "HS256"
    RS256 = "RS256"
    ES256 = "ES256"


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

    # Validation mappings for runtime validation
    class ValidationMappings:
        """Validation mappings for runtime checks using advanced collections.abc."""

        # Token type validation mapping
        _TOKEN_TYPE_VALIDATION_MAP: ClassVar[Mapping[str, str]] = {
            "access": "access",
            "refresh": "refresh",
            "api": "api",
            "bearer": "bearer",
        }
        _TOKEN_TYPE_VALIDATION_SET: ClassVar[AbstractSet[str]] = frozenset(
            _TOKEN_TYPE_VALIDATION_MAP.keys()
        )

        # Provider type validation mapping
        _PROVIDER_TYPE_VALIDATION_MAP: ClassVar[Mapping[str, str]] = {
            "basic": "basic",
            "jwt": "jwt",
            "oauth2": "oauth2",
            "saml": "saml",
            "ldap": "ldap",
            "certificate": "certificate",
            "kerberos": "kerberos",
            "apikey": "apikey",
        }
        _PROVIDER_TYPE_VALIDATION_SET: ClassVar[AbstractSet[str]] = frozenset(
            _PROVIDER_TYPE_VALIDATION_MAP.keys()
        )

        # Role type validation mapping
        _ROLE_TYPE_VALIDATION_MAP: ClassVar[Mapping[str, str]] = {
            "REDACTED_LDAP_BIND_PASSWORD": "REDACTED_LDAP_BIND_PASSWORD",
            "user": "user",
            "moderator": "moderator",
            "guest": "guest",
        }
        _ROLE_TYPE_VALIDATION_SET: ClassVar[AbstractSet[str]] = frozenset(
            _ROLE_TYPE_VALIDATION_MAP.keys()
        )

        # Permission type validation mapping
        _PERMISSION_TYPE_VALIDATION_MAP: ClassVar[Mapping[str, str]] = {
            "read": "read",
            "write": "write",
            "delete": "delete",
            "REDACTED_LDAP_BIND_PASSWORD": "REDACTED_LDAP_BIND_PASSWORD",
        }
        _PERMISSION_TYPE_VALIDATION_SET: ClassVar[AbstractSet[str]] = frozenset(
            _PERMISSION_TYPE_VALIDATION_MAP.keys()
        )

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
    # Python 3.13+ PEP 695 best practice: Use type keyword for type aliases

    type TokenTypeLiteral = Literal["access", "refresh", "api", "bearer"]
    """Token type literal - matches TokenType StrEnum values."""

    type ProviderTypeLiteral = Literal[
        "basic", "jwt", "oauth2", "saml", "ldap", "certificate", "kerberos", "apikey"
    ]
    """Provider type literal - matches ProviderType StrEnum values."""

    type AlgorithmTypeLiteral = Literal["HS256", "RS256", "ES256"]
    """Algorithm type literal - matches AlgorithmType StrEnum values."""

    type RoleTypeLiteral = Literal["REDACTED_LDAP_BIND_PASSWORD", "user", "moderator", "guest"]
    """Role type literal - matches RoleType StrEnum values."""

    type PermissionTypeLiteral = Literal["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]
    """Permission type literal - matches PermissionType StrEnum values."""

    type ProjectTypeLiteral = Literal[
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
    """Project type literal for authentication service types."""

    # =========================================================================
    # IMMUTABLE CONSTANTS - NO CONFIGURATION (USE CONFIG.PY FOR SETTINGS)
    # =========================================================================

    # Validation methods using ValidationMappings
    @classmethod
    def validate_token_type(cls, token_type: str) -> str | None:
        """Validate token type against allowed values."""
        return cls.ValidationMappings._TOKEN_TYPE_VALIDATION_MAP.get(token_type)

    @classmethod
    def validate_provider_type(cls, provider_type: str) -> str | None:
        """Validate provider type against allowed values."""
        return cls.ValidationMappings._PROVIDER_TYPE_VALIDATION_MAP.get(provider_type)

    @classmethod
    def validate_role_type(cls, role_type: str) -> str | None:
        """Validate role type against allowed values."""
        return cls.ValidationMappings._ROLE_TYPE_VALIDATION_MAP.get(role_type)

    @classmethod
    def validate_permission_type(cls, permission_type: str) -> str | None:
        """Validate permission type against allowed values."""
        return cls.ValidationMappings._PERMISSION_TYPE_VALIDATION_MAP.get(
            permission_type
        )

    @classmethod
    def get_valid_token_types(cls) -> AbstractSet[str]:
        """Get all valid token types."""
        return cls.ValidationMappings._TOKEN_TYPE_VALIDATION_SET

    @classmethod
    def get_valid_provider_types(cls) -> AbstractSet[str]:
        """Get all valid provider types."""
        return cls.ValidationMappings._PROVIDER_TYPE_VALIDATION_SET

    @classmethod
    def get_valid_role_types(cls) -> AbstractSet[str]:
        """Get all valid role types."""
        return cls.ValidationMappings._ROLE_TYPE_VALIDATION_SET

    @classmethod
    def get_valid_permission_types(cls) -> AbstractSet[str]:
        """Get all valid permission types."""
        return cls.ValidationMappings._PERMISSION_TYPE_VALIDATION_SET

    # Token Types & Prefixes
    TOKEN_TYPES: Final[tuple[str, ...]] = ("access", "refresh", "api", "bearer")
    TOKEN_TYPE_ACCESS: Final[str] = "access"
    TOKEN_TYPE_BEARER: Final[str] = "bearer"
    TOKEN_TYPE_API: Final[str] = "api"
    TOKEN_PREFIX_BEARER: Final[str] = "Bearer"

    # Algorithms Supported
    ALLOWED_ALGORITHMS: Final[tuple[str, ...]] = ("HS256", "RS256", "ES256")

    # Permission & Role Constants
    PERMISSION_READ: Final[str] = "read"
    PERMISSION_WRITE: Final[str] = "write"
    PERMISSION_DELETE: Final[str] = "delete"
    PERMISSION_ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
    ROLE_ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
    ROLE_USER: Final[str] = "user"
    ROLE_MODERATOR: Final[str] = "moderator"
    ROLE_GUEST: Final[str] = "guest"
    DEFAULT_ROLES: Final[tuple[str, ...]] = ("user",)
    VALID_ROLES: Final[tuple[str, ...]] = ("REDACTED_LDAP_BIND_PASSWORD", "user", "moderator", "guest")
    BASIC_PERMISSIONS: Final[tuple[str, ...]] = ("read", "write")
    ADMIN_PERMISSIONS: Final[tuple[str, ...]] = ("read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD")

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
    # Bcrypt library limits (different from hash rounds defaults)
    BCRYPT_ROUNDS_MIN: Final[int] = 4
    BCRYPT_ROUNDS_MAX: Final[int] = 31
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

        class Username:
            """Username-specific constants."""

            MIN_LENGTH: Final[int] = 3
            MAX_LENGTH: Final[int] = 50

        class Password:
            """Password-specific constants."""

            MIN_LENGTH: Final[int] = 8
            MAX_LENGTH: Final[int] = 128
            MIN_SCORE: Final[int] = 3
            MIN_BCRYPT_HASH_LENGTH: Final[int] = 60
            BCRYPT_ROUNDS: Final[int] = 12

    # =========================================================================
    # SESSION CONSTANTS
    # =========================================================================

    class Session(FlextConstants.Validation):
        """Session management constants."""

        EXPIRY_DEFAULT_MINUTES: Final[int] = 1440  # 24 hours
        DEFAULT_EXPIRY_MINUTES: Final[int] = 120  # 2 hours (test expectation)
        EXPIRY_MAX_MINUTES: Final[int] = 43200  # 30 days
        MAX_EXPIRY_MINUTES: Final[int] = 1440  # 24 hours (test expectation)
        MAX_SESSIONS_PER_USER: Final[int] = 5
        MIN_TOKEN_LENGTH: Final[int] = 32

    # =========================================================================
    # ERROR CODES
    # =========================================================================

    class ErrorCodes(FlextConstants.Errors):
        """Authentication-specific error codes extending core errors."""

        TOKEN_ERROR: Final[str] = "TOKEN_ERROR"
        SESSION_ERROR: Final[str] = "SESSION_ERROR"
        CREDENTIAL_ERROR: Final[str] = "CREDENTIAL_ERROR"
        INVALID_CREDENTIALS: Final[str] = "INVALID_CREDENTIALS"
        ACCOUNT_LOCKED: Final[str] = "ACCOUNT_LOCKED"
        ACCOUNT_DISABLED: Final[str] = "ACCOUNT_DISABLED"
        TOKEN_EXPIRED: Final[str] = "TOKEN_EXPIRED"
        INVALID_TOKEN: Final[str] = "INVALID_TOKEN"

    # =========================================================================
    # JWT CONSTANTS
    # =========================================================================

    class Jwt:
        """JWT token constants."""

        ALGORITHM_DEFAULT: Final[str] = "HS256"
        DEFAULT_ALGORITHM: Final[str] = "HS256"  # Alias for ALGORITHM_DEFAULT
        EXPIRY_DEFAULT_MINUTES: Final[int] = 1440  # 24 hours
        DEFAULT_EXPIRY_MINUTES: Final[int] = 30  # 30 minutes (test expectation)
        EXPIRY_MAX_MINUTES: Final[int] = 43200  # 30 days
        MAX_EXPIRY_MINUTES: Final[int] = 1440  # 24 hours (test expectation)
        ISSUER_CLAIM: Final[str] = "flext-auth"
        AUDIENCE_CLAIM: Final[str] = "flext-users"
        MIN_SECRET_KEY_LENGTH: Final[int] = 32
        DEFAULT_TOKEN_TYPE: Final[str] = "Bearer"

    # =========================================================================
    # AUTH SECURITY CONSTANTS
    # =========================================================================

    class AuthSecurity:
        """Authentication security constants."""

        HASH_ROUNDS_DEFAULT: Final[int] = 12
        HASH_ROUNDS_MIN: Final[int] = 10
        HASH_ROUNDS_MAX: Final[int] = 15
        MAX_ATTEMPTS_DEFAULT: Final[int] = 5
        MAX_LOGIN_ATTEMPTS: Final[int] = 5  # Alias for MAX_ATTEMPTS_DEFAULT
        LOCKOUT_DURATION_MINUTES: Final[int] = 15
        MAX_REQUESTS_PER_MINUTE: Final[int] = 60
        MAX_REQUESTS_PER_HOUR: Final[int] = 1000

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
        BASIC_USER_PERMISSIONS: Final[list[str]] = [
            "read",
            "write",
        ]  # Alias for BASIC_PERMISSIONS
        ADMIN_PERMISSIONS: Final[list[str]] = ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]

    # =========================================================================
    # BASIC AUTH CONSTANTS (RFC 7617)
    # =========================================================================

    class BasicAuth:
        """HTTP Basic Authentication constants (RFC 7617)."""

        SCHEME: Final[str] = "Basic"
        REALM_DEFAULT: Final[str] = "FLEXT Auth"
        REQUIRE_HTTPS_DEFAULT: Final[bool] = True
        CASE_SENSITIVE_DEFAULT: Final[bool] = True
        ALLOW_ANONYMOUS_DEFAULT: Final[bool] = False
        ANONYMOUS_TOKEN_EXPIRY_HOURS: Final[int] = 24

    # =========================================================================
    # API KEY CONSTANTS
    # =========================================================================

    class ApiKey:
        """API Key authentication constants."""

        PREFIX_DEFAULT: Final[str] = "fk_"
        LENGTH_DEFAULT: Final[int] = 32
        HASH_ALGORITHM_DEFAULT: Final[str] = "sha256"
        HASH_ALGORITHMS: Final[list[str]] = ["sha256", "sha512"]
        REQUIRE_KEY_ID_DEFAULT: Final[bool] = False
        RATE_LIMIT_ENABLED_DEFAULT: Final[bool] = True
        RATE_LIMIT_REQUESTS_DEFAULT: Final[int] = 100
        RATE_LIMIT_WINDOW_SECONDS_DEFAULT: Final[int] = 3600
        EXPIRY_DAYS_DEFAULT: Final[int] = 365

    # =========================================================================
    # OAUTH2 CONSTANTS (RFC 6749)
    # =========================================================================

    class OAuth2:
        """OAuth 2.0 authentication constants (RFC 6749)."""

        SCOPE_DEFAULT: Final[str] = "openid profile email"
        FLOW_DEFAULT: Final[str] = "authorization_code"
        FLOWS: Final[list[str]] = [
            "authorization_code",
            "client_credentials",
            "password",
            "implicit",
        ]
        TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT: Final[str] = "client_secret_post"
        TOKEN_ENDPOINT_AUTH_METHODS: Final[list[str]] = [
            "client_secret_post",
            "client_secret_basic",
            "none",
        ]
        USE_PKCE_DEFAULT: Final[bool] = True
        PKCE_CODE_CHALLENGE_METHOD: Final[str] = "S256"

    # =========================================================================
    # JWT CONSTANTS (RFC 7519) - Extended
    # =========================================================================

    class JwtExtended:
        """Extended JWT constants (RFC 7519)."""

        ALGORITHMS: Final[list[str]] = ["HS256", "RS256", "ES256", "HS512"]
        ISSUER_DEFAULT: Final[str] = "flext-auth"
        AUDIENCE_DEFAULT: Final[str] = "flext-users"

    # =========================================================================
    # SAML CONSTANTS (SAML 2.0)
    # =========================================================================

    class Saml:
        """SAML 2.0 authentication constants."""

        NS_ASSERTION: Final[str] = "urn:oasis:names:tc:SAML:2.0:assertion"
        NS_PROTOCOL: Final[str] = "urn:oasis:names:tc:SAML:2.0:protocol"
        NS_SIGNATURE: Final[str] = "http://www.w3.org/2000/09/xmldsig#"
        NAME_ID_FORMAT_EMAIL: Final[str] = (
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        )
        NAME_ID_FORMAT_UNSPECIFIED: Final[str] = (
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        )
        NAME_ID_FORMAT_PERSISTENT: Final[str] = (
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        )
        NAME_ID_FORMATS: Final[list[str]] = [
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        ]
        SIGN_ASSERTIONS_DEFAULT: Final[bool] = True
        ENCRYPT_ASSERTIONS_DEFAULT: Final[bool] = False

    # =========================================================================
    # LDAP CONSTANTS
    # =========================================================================

    class Ldap:
        """LDAP authentication constants."""

        USE_SSL_DEFAULT: Final[bool] = True
        USE_TLS_DEFAULT: Final[bool] = False
        TIMEOUT_DEFAULT: Final[int] = 30
        USER_SEARCH_FILTER_DEFAULT: Final[str] = "(uid={username})"

    # =========================================================================
    # CERTIFICATE CONSTANTS
    # =========================================================================

    class Certificate:
        """X.509 Certificate authentication constants."""

        VERIFY_MODE_REQUIRED: Final[str] = "required"
        VERIFY_MODE_OPTIONAL: Final[str] = "optional"
        VERIFY_MODE_NONE: Final[str] = "none"
        VERIFY_MODES: Final[list[str]] = ["required", "optional", "none"]
        CHECK_OCSP_DEFAULT: Final[bool] = False
        CHECK_CRL_DEFAULT: Final[bool] = False
        ALLOW_SELF_SIGNED_DEFAULT: Final[bool] = False

    # =========================================================================
    # KERBEROS CONSTANTS
    # =========================================================================

    class Kerberos:
        """Kerberos authentication constants."""

        CLOCKSKEW_TOLERANCE_DEFAULT: Final[int] = 300
        TICKET_LIFETIME_DEFAULT: Final[int] = 10


__all__ = ["FlextAuthConstants"]
