"""FLEXT Auth Constants - Authentication-specific constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import ClassVar, Final, Literal

from flext_core import FlextConstants, FlextTypes


class FlextAuthConstants(FlextConstants):
    """Authentication-specific constants following FLEXT unified pattern with nested domains.

    Inherits from FlextConstants for universal constants, defines only
    auth-specific constants using nested namespace classes.
    """

    # Default credentials (inherited from FlextConstants where possible)

    class Jwt:
        """JWT Token management constants."""

        DEFAULT_ALGORITHM: Final[str] = "HS256"
        DEFAULT_EXPIRY_MINUTES: Final[int] = 60  # 1 hour default
        MAX_EXPIRY_MINUTES: Final[int] = 43200  # 30 days maximum
        ISSUER_CLAIM: Final[str] = "iss"
        AUDIENCE_CLAIM: Final[str] = "aud"
        SECRET_KEY: Final[str] = "your-secret-key-change-in-production"  # nosec B105
        ALLOWED_ALGORITHMS: ClassVar[FlextTypes.StringList] = [
            "HS256",
            "RS256",
            "ES256",
        ]
        DEFAULT_TOKEN_TYPE: Final[str] = "access"
        DEFAULT_ACCESS_TOKEN_TYPE: Final[str] = "access"
        API_TOKEN_TYPE: Final[str] = "api"
        BASIC_TOKEN_TYPE: Final[str] = "basic"
        BEARER_TOKEN_TYPE: Final[str] = "bearer"
        BEARER_PREFIX: Final[str] = "Bearer"
        MIN_SECRET_KEY_LENGTH: Final[int] = 32

    class Credentials:
        """User credential validation constants."""

        class Username:
            """Username validation rules."""

            MIN_LENGTH: Final[int] = 3
            MAX_LENGTH: Final[int] = 50

        class Password:
            """Password validation and security constants."""

            MIN_LENGTH: Final[int] = 8
            MAX_LENGTH: Final[int] = 128
            MIN_SCORE: Final[int] = 3
            MIN_BCRYPT_HASH_LENGTH: Final[int] = 60
            BCRYPT_ROUNDS: Final[int] = 12
            MIN_BCRYPT_ROUNDS: Final[int] = 8
            MAX_BCRYPT_ROUNDS: Final[int] = 16
            WEAK_PASSWORDS: ClassVar[FlextTypes.StringList] = [
                "123",
                "abc",
                "password",
                "12345678",
                "aaaaaaaa",
            ]

    class Session:
        """Session management constants."""

        DEFAULT_EXPIRY_MINUTES: Final[int] = 60
        MAX_EXPIRY_MINUTES: Final[int] = 10080  # 7 days
        MAX_SESSIONS_PER_USER: Final[int] = 5
        CLEANUP_INTERVAL_MINUTES: Final[int] = 60
        EXTEND_MINUTES: Final[int] = 30
        MIN_TOKEN_LENGTH: Final[int] = 32
        DEFAULT_EXTEND_HOURS: Final[int] = 24

    class AuthSecurity:
        """Authentication-specific security enforcement constants."""

        MAX_LOGIN_ATTEMPTS: Final[int] = 5
        LOCKOUT_DURATION_MINUTES: Final[int] = 30
        MAX_REQUESTS_PER_MINUTE: Final[int] = 100
        MAX_REQUESTS_PER_HOUR: Final[int] = 1000
        # Rate limiting defaults
        RATE_LIMIT_MAX_ATTEMPTS: Final[int] = 10
        RATE_LIMIT_WINDOW_MINUTES: Final[int] = 15

    class Oidc:
        """OIDC provider constants."""

        DEFAULT_ID_TOKEN_SIGNING_ALGORITHM: Final[str] = "RS256"

    class ApiKey:
        """API Key provider constants."""

        DEFAULT_KEY_LENGTH: Final[int] = 32
        DEFAULT_HASH_ALGORITHM: Final[str] = "sha256"
        DEFAULT_REQUIRE_KEY_ID: Final[bool] = False
        DEFAULT_KEY_STORAGE: Final[str] = "memory"
        DEFAULT_RATE_LIMIT_ENABLED: Final[bool] = False
        DEFAULT_RATE_LIMIT_REQUESTS: Final[int] = 1000
        DEFAULT_RATE_LIMIT_WINDOW_SECONDS: Final[int] = 3600

    class ErrorCodes:
        """Authentication error codes."""

        INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
        ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
        ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
        TOKEN_EXPIRED = "TOKEN_EXPIRED"  # nosec B105
        INVALID_TOKEN = "INVALID_TOKEN"  # nosec B105
        USERNAME_TAKEN = "USERNAME_TAKEN"
        EMAIL_TAKEN = "EMAIL_TAKEN"
        SESSION_NOT_FOUND = "SESSION_NOT_FOUND"

    class AuthLogging:
        """Authentication-specific audit and security logging configuration."""

        class Audit:
            """Audit logging controls."""

            ENABLE_AUDIT_LOGGING = True
            LOG_AUTH_ATTEMPTS = True
            LOG_AUTH_FAILURES = True
            LOG_AUTH_SUCCESS = False  # Privacy consideration
            LOG_TOKEN_CREATION = True
            LOG_TOKEN_VALIDATION = False  # Privacy consideration
            LOG_USER_CREATION = True
            LOG_USER_DELETION = True
            LOG_PERMISSION_CHANGES = True

        class Performance:
            """Performance monitoring configuration."""

            TRACK_AUTH_PERFORMANCE = True
            THRESHOLD_WARNING = 1000.0  # milliseconds
            THRESHOLD_CRITICAL = 3000.0  # milliseconds

        class Context:
            """Context information logging."""

            INCLUDE_USER_ID = True
            INCLUDE_SESSION_ID = True
            INCLUDE_IP_ADDRESS = True
            INCLUDE_USER_AGENT = False  # Privacy consideration
            INCLUDE_REQUEST_ID = True

        class Security:
            """Security-focused logging controls."""

            MASK_PASSWORDS = True
            MASK_TOKENS = True
            MASK_SESSION_IDS = True
            LOG_VALIDATION_ERRORS = True
            LOG_AUTHENTICATION_ERRORS = True
            LOG_AUTHORIZATION_ERRORS = True
            LOG_TOKEN_EXPIRY = True
            LOG_SESSION_TIMEOUT = True

        class Files:
            """Log file configuration."""

            AUDIT_LOG_LEVEL = "INFO"
            AUDIT_LOG_FILE = "flext_auth_audit.log"

    class Permissions:
        """Permission constants for role-based access control."""

        # Basic permissions
        READ = "read"
        WRITE = "write"
        DELETE = "delete"
        ADMIN = "REDACTED_LDAP_BIND_PASSWORD"

        # Permission sets
        BASIC_USER_PERMISSIONS: ClassVar[FlextTypes.StringList] = [READ, WRITE]
        ADMIN_PERMISSIONS: ClassVar[FlextTypes.StringList] = [
            READ,
            WRITE,
            DELETE,
            ADMIN,
        ]

    class Roles:
        """Role constants for role-based access control."""

        # Standard roles
        ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
        USER = "user"
        MODERATOR = "moderator"
        GUEST = "guest"

        # Role sets
        DEFAULT_ROLES: ClassVar[FlextTypes.StringList] = [USER]
        VALID_ROLES: ClassVar[FlextTypes.StringList] = [
            ADMIN,
            USER,
            MODERATOR,
            GUEST,
        ]

    class AuthPlatform:
        """Platform defaults for authentication services."""

        FLEXT_API_PORT: Final[int] = FlextConstants.Platform.FLEXT_API_PORT
        DEFAULT_HOST: Final[str] = FlextConstants.Platform.DEFAULT_HOST
        LOOPBACK_IP: Final[str] = FlextConstants.Platform.LOOPBACK_IP
        HTTP_STATUS_OK: Final[int] = FlextConstants.Http.HTTP_OK

    class AuthNetwork:
        """Network defaults for authentication services."""

        MIN_PORT: Final[int] = FlextConstants.Network.MIN_PORT
        MAX_PORT: Final[int] = FlextConstants.Network.MAX_PORT
        TOTAL_TIMEOUT: Final[int] = FlextConstants.Network.TOTAL_TIMEOUT
        DEFAULT_TIMEOUT: Final[int] = FlextConstants.Network.DEFAULT_TIMEOUT

    class AuthDefaults:
        """Default values for various operations."""

        DEFAULT_TOKEN_LENGTH: Final[int] = 32
        DEFAULT_SESSION_EXTEND_HOURS: Final[int] = 24  # For protocols
        DEMO_USERS_COUNT: Final[int] = 3
        # Transport defaults
        DEFAULT_TIMEOUT: Final[float] = 30.0
        MAX_RETRIES: Final[int] = 3
        # OIDC defaults
        JWT_PARTS_COUNT: Final[int] = 3
        BASE64_PADDING_SIZE: Final[int] = 4
        # Admin defaults
        DEFAULT_ADMIN_PASSWORD: Final[str] = "***MUST_BE_SET_IN_PRODUCTION***"
        # Mock/test data defaults
        MOCK_USER_PREFIX: Final[str] = "user_"
        MOCK_EMAIL_DOMAIN: Final[str] = "@example.com"
        MOCK_VALIDATED_USER_ID: Final[str] = "validated_user"
        MOCK_VALIDATED_USERNAME: Final[str] = "validated_user"
        MOCK_VALIDATED_EMAIL: Final[str] = "validated@example.com"
        # Provider defaults
        DEFAULT_PROVIDER: Final[str] = "jwt"
        # User model defaults
        DEFAULT_USER_ACTIVE: Final[bool] = True
        DEFAULT_USER_ROLES: ClassVar[FlextTypes.StringList] = ["user"]
        DEFAULT_FAILED_LOGIN_ATTEMPTS: Final[int] = 0
        # Session model defaults
        DEFAULT_SESSION_ACTIVE: Final[bool] = True
        # Token model defaults
        DEFAULT_TOKEN_REVOKED: Final[bool] = False
        # Config defaults
        DEFAULT_ENABLE_RATE_LIMITING: Final[bool] = True
        DEFAULT_REQUIRE_PASSWORD_COMPLEXITY: Final[bool] = True
        DEFAULT_ENABLE_EMAIL_VERIFICATION: Final[bool] = False
        DEFAULT_ENABLE_PASSWORD_HISTORY: Final[bool] = False

    class Literals:
        """Literal types for type safety - CRITICAL VIOLATION to define elsewhere."""

        # Project types for auth domain
        PROJECT_TYPES: ClassVar[tuple[str, ...]] = (
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
        )
        type ProjectType = Literal[
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

        # Token types
        TOKEN_TYPES: ClassVar[tuple[str, ...]] = (
            "access",
            "refresh",
            "api",
            "bearer",
        )
        type TokenType = Literal[
            "access",
            "refresh",
            "api",
            "bearer",
        ]

        # Provider types
        PROVIDER_TYPES: ClassVar[tuple[str, ...]] = (
            "basic",
            "jwt",
            "oauth2",
            "saml",
            "ldap",
            "certificate",
            "kerberos",
            "apikey",
        )
        type ProviderType = Literal[
            "basic",
            "jwt",
            "oauth2",
            "saml",
            "ldap",
            "certificate",
            "kerberos",
            "apikey",
        ]

    class OAuth2:
        """OAuth2 authentication constants."""

        CLIENT_SECRET_POST = "client_secret_post"
        CLIENT_SECRET_BASIC = "client_secret_basic"

    class SAML:
        """SAML 2.0 authentication constants."""

        NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
        NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
        NS_DS = "http://www.w3.org/2000/09/xmldsig#"


__all__ = ["FlextAuthConstants"]
