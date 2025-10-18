"""FLEXT Auth Constants - Generic authentication constants with minimal domain coupling.

Uses Python 3.13+ syntax, type aliases, and consolidated patterns for maximum
genericity and maintainability. Single flat structure with no domain assumptions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, Final, Literal

from flext_core import FlextConstants


class FlextAuthConstants(FlextConstants):
    """Generic authentication constants with flat structure and type aliases.

    Python 3.13+ features, minimal line count through consolidation.
    Domain-agnostic constants for any authentication system.
    """

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
    # GENERIC SECURITY CONSTANTS - NO DOMAIN ASSUMPTIONS
    # =========================================================================

    # Core Security - Generic
    SECRET_KEY_DEFAULT: Final[str] = "your-secret-key-change-in-production"  # nosec B105
    SECRET_MIN_LENGTH: Final[int] = 32
    ALGORITHM_DEFAULT: Final[str] = "HS256"
    ALLOWED_ALGORITHMS: ClassVar[list[str]] = ["HS256", "RS256", "ES256"]

    # Token Configuration - Generic
    EXPIRY_MINUTES_DEFAULT: Final[int] = 60
    EXPIRY_MAX_MINUTES: Final[int] = 43200
    TOKEN_TYPES: ClassVar[tuple[str, ...]] = ("access", "refresh", "api", "bearer")
    TOKEN_TYPE_ACCESS: Final[str] = "access"
    TOKEN_TYPE_BEARER: Final[str] = "bearer"
    TOKEN_TYPE_API: Final[str] = "api"
    TOKEN_PREFIX_BEARER: Final[str] = "Bearer"

    # Identity Configuration - Generic
    IDENTITY_MIN_LENGTH: Final[int] = 3
    IDENTITY_MAX_LENGTH: Final[int] = 50
    CREDENTIAL_MIN_LENGTH: Final[int] = 8
    CREDENTIAL_MAX_LENGTH: Final[int] = 128
    CREDENTIAL_MIN_SCORE: Final[int] = 3
    HASH_ROUNDS_DEFAULT: Final[int] = 12
    HASH_ROUNDS_MIN: Final[int] = 8
    HASH_ROUNDS_MAX: Final[int] = 16
    HASH_MIN_LENGTH: Final[int] = 60
    WEAK_CREDENTIALS: ClassVar[list[str]] = [
        "123",
        "abc",
        "password",
        "12345678",
        "aaaaaaaa",
    ]

    # Session Management - Generic
    SESSION_EXPIRY_MINUTES_DEFAULT: Final[int] = 60
    SESSION_EXPIRY_MAX_MINUTES: Final[int] = 10080
    MAX_SESSIONS_PER_IDENTITY: Final[int] = 5
    CLEANUP_INTERVAL_MINUTES: Final[int] = 60
    EXTEND_MINUTES: Final[int] = 30
    MIN_TOKEN_LENGTH: Final[int] = 32
    DEFAULT_EXTEND_HOURS: Final[int] = 24

    # Security Policies - Generic
    MAX_ATTEMPTS_DEFAULT: Final[int] = 5
    LOCKOUT_DURATION_MINUTES: Final[int] = 30
    MAX_REQUESTS_PER_MINUTE: Final[int] = 100
    MAX_REQUESTS_PER_HOUR: Final[int] = 1000
    RATE_LIMIT_MAX_ATTEMPTS: Final[int] = 10
    RATE_LIMIT_WINDOW_MINUTES: Final[int] = 15

    # Audit & Logging - Generic
    ENABLE_AUDIT_LOGGING: Final[bool] = True
    LOG_ATTEMPTS: Final[bool] = True
    LOG_FAILURES: Final[bool] = True
    LOG_SUCCESS: Final[bool] = False
    LOG_CREATION: Final[bool] = True
    LOG_VALIDATION: Final[bool] = False
    LOG_DELETION: Final[bool] = True
    LOG_CHANGES: Final[bool] = True
    TRACK_PERFORMANCE: Final[bool] = True
    PERFORMANCE_WARNING_THRESHOLD: Final[float] = 1000.0
    PERFORMANCE_CRITICAL_THRESHOLD: Final[float] = 3000.0
    INCLUDE_IDENTITY_ID: Final[bool] = True
    INCLUDE_SESSION_ID: Final[bool] = True
    INCLUDE_IP_ADDRESS: Final[bool] = True
    INCLUDE_USER_AGENT: Final[bool] = False
    INCLUDE_REQUEST_ID: Final[bool] = True
    MASK_CREDENTIALS: Final[bool] = True
    MASK_TOKENS: Final[bool] = True
    MASK_SESSION_IDS: Final[bool] = True
    LOG_VALIDATION_ERRORS: Final[bool] = True
    LOG_AUTHENTICATION_ERRORS: Final[bool] = True
    LOG_AUTHORIZATION_ERRORS: Final[bool] = True
    LOG_TOKEN_EXPIRY: Final[bool] = True
    LOG_SESSION_TIMEOUT: Final[bool] = True
    AUDIT_LOG_LEVEL: Final[str] = "INFO"
    AUDIT_LOG_FILE: Final[str] = "flext_auth_audit.log"

    # Authorization - Generic
    PERMISSION_READ: Final[str] = "read"
    PERMISSION_WRITE: Final[str] = "write"
    PERMISSION_DELETE: Final[str] = "delete"
    PERMISSION_ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
    BASIC_PERMISSIONS: ClassVar[list[str]] = ["read", "write"]
    ADMIN_PERMISSIONS: ClassVar[list[str]] = ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]

    # Roles - Generic
    ROLE_ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
    ROLE_USER: Final[str] = "user"
    ROLE_MODERATOR: Final[str] = "moderator"
    ROLE_GUEST: Final[str] = "guest"
    DEFAULT_ROLES: ClassVar[list[str]] = ["user"]
    VALID_ROLES: ClassVar[list[str]] = ["REDACTED_LDAP_BIND_PASSWORD", "user", "moderator", "guest"]

    # Platform Constants - Inherited from flext-core
    PLATFORM_FLEXT_API_PORT: Final[int] = FlextConstants.Platform.FLEXT_API_PORT
    PLATFORM_DEFAULT_HOST: Final[str] = FlextConstants.Platform.DEFAULT_HOST
    PLATFORM_LOOPBACK_IP: Final[str] = "127.0.0.1"
    PLATFORM_HTTP_STATUS_OK: Final[int] = 200

    # Network Constants - Inherited from flext-core
    NETWORK_MIN_PORT: Final[int] = FlextConstants.Network.MIN_PORT
    NETWORK_MAX_PORT: Final[int] = FlextConstants.Network.MAX_PORT
    NETWORK_TOTAL_TIMEOUT: Final[int] = 300
    NETWORK_DEFAULT_TIMEOUT: Final[int] = FlextConstants.Network.DEFAULT_TIMEOUT

    # Generic Defaults - No Domain Assumptions
    DEFAULT_TOKEN_LENGTH: Final[int] = 32
    DEFAULT_SESSION_EXTEND_HOURS: Final[int] = 24
    DEFAULT_TIMEOUT: Final[float] = 30.0
    DEFAULT_MAX_RETRIES: Final[int] = 3
    DEMO_USERS_COUNT: Final[int] = 10
    DEFAULT_JWT_PARTS_COUNT: Final[int] = 3
    DEFAULT_BASE64_PADDING_SIZE: Final[int] = 4
    DEFAULT_ADMIN_CREDENTIAL: Final[str] = "***MUST_BE_SET_IN_PRODUCTION***"
    DEFAULT_MOCK_PREFIX: Final[str] = "user_"
    DEFAULT_MOCK_DOMAIN: Final[str] = "@example.com"
    DEFAULT_VALIDATED_ID: Final[str] = "validated_user"
    DEFAULT_VALIDATED_NAME: Final[str] = "validated_user"
    DEFAULT_VALIDATED_EMAIL: Final[str] = "validated@example.com"
    DEFAULT_PROVIDER: Final[str] = "jwt"
    DEFAULT_ACTIVE: Final[bool] = True
    DEFAULT_FAILED_ATTEMPTS: Final[int] = 0
    DEFAULT_REVOKED: Final[bool] = False
    ENABLE_RATE_LIMITING: Final[bool] = True
    REQUIRE_COMPLEXITY: Final[bool] = True
    ENABLE_VERIFICATION: Final[bool] = False
    ENABLE_HISTORY: Final[bool] = False

    # =========================================================================
    # PROTOCOL CONSTANTS - GENERIC PROTOCOL SUPPORT
    # =========================================================================

    OAUTH2_CLIENT_SECRET_POST: Final[str] = "client_secret_post"
    OAUTH2_CLIENT_SECRET_BASIC: Final[str] = "client_secret_basic"
    SAML_NS_ASSERTION: Final[str] = "urn:oasis:names:tc:SAML:2.0:assertion"
    SAML_NS_PROTOCOL: Final[str] = "urn:oasis:names:tc:SAML:2.0:protocol"
    SAML_NS_SIGNATURE: Final[str] = "http://www.w3.org/2000/09/xmldsig#"


__all__ = ["FlextAuthConstants"]
