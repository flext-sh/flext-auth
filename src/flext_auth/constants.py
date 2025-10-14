"""FLEXT Auth Constants - Authentication-specific constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import ClassVar, Literal

from flext_core import FlextCore


class FlextAuthConstants(FlextCore.Constants):
    """Authentication-specific constants following FLEXT unified pattern with nested domains.

    Inherits from FlextCore.Constants for universal constants, defines only
    auth-specific constants using nested namespace classes.
    """

    # Default credentials (inherited from FlextCore.Constants where possible)

    class Jwt:
        """JWT Token management constants."""

        DEFAULT_ALGORITHM = FlextCore.Constants.Security.JWT_DEFAULT_ALGORITHM
        DEFAULT_EXPIRY_MINUTES = FlextCore.Constants.Security.JWT_DEFAULT_EXPIRY_MINUTES
        MAX_EXPIRY_MINUTES = FlextCore.Constants.Security.JWT_MAX_EXPIRY_MINUTES
        ISSUER_CLAIM = FlextCore.Constants.Security.JWT_ISSUER_CLAIM
        AUDIENCE_CLAIM = FlextCore.Constants.Security.JWT_AUDIENCE_CLAIM
        SECRET_KEY = FlextCore.Constants.Security.DEFAULT_JWT_SECRET  # nosec B105
        ALLOWED_ALGORITHMS: ClassVar[FlextCore.Types.StringList] = list(
            FlextCore.Constants.Security.JWT_ALLOWED_ALGORITHMS
        )
        DEFAULT_TOKEN_TYPE = FlextCore.Constants.Security.JWT_DEFAULT_TOKEN_TYPE
        DEFAULT_ACCESS_TOKEN_TYPE = (
            FlextCore.Constants.Security.JWT_DEFAULT_ACCESS_TOKEN_TYPE
        )
        API_TOKEN_TYPE = FlextCore.Constants.Security.JWT_API_TOKEN_TYPE
        BASIC_TOKEN_TYPE = FlextCore.Constants.Security.JWT_BASIC_TOKEN_TYPE
        BEARER_TOKEN_TYPE = "bearer"
        BEARER_PREFIX = FlextCore.Constants.Security.JWT_BEARER_PREFIX
        MIN_SECRET_KEY_LENGTH = FlextCore.Constants.Security.JWT_MIN_SECRET_KEY_LENGTH

    class Credentials:
        """User credential validation constants."""

        class Username:
            """Username validation rules."""

            MIN_LENGTH = FlextCore.Constants.Security.CREDENTIAL_USERNAME_MIN_LENGTH
            MAX_LENGTH = FlextCore.Constants.Security.CREDENTIAL_USERNAME_MAX_LENGTH

        class Password:
            """Password validation and security constants."""

            MIN_LENGTH = FlextCore.Constants.Security.CREDENTIAL_PASSWORD_MIN_LENGTH
            MAX_LENGTH = FlextCore.Constants.Security.CREDENTIAL_PASSWORD_MAX_LENGTH
            MIN_SCORE = FlextCore.Constants.Security.CREDENTIAL_PASSWORD_MIN_SCORE
            MIN_BCRYPT_HASH_LENGTH = (
                FlextCore.Constants.Security.CREDENTIAL_MIN_BCRYPT_HASH_LENGTH
            )
            BCRYPT_ROUNDS = FlextCore.Constants.Security.CREDENTIAL_BCRYPT_ROUNDS
            MIN_BCRYPT_ROUNDS = (
                FlextCore.Constants.Security.CREDENTIAL_MIN_BCRYPT_ROUNDS
            )
            MAX_BCRYPT_ROUNDS = (
                FlextCore.Constants.Security.CREDENTIAL_MAX_BCRYPT_ROUNDS
            )
            WEAK_PASSWORDS: ClassVar[FlextCore.Types.StringList] = [
                "123",
                "abc",
                "password",
                "12345678",
                "aaaaaaaa",
            ]

    class Session:
        """Session management constants."""

        DEFAULT_EXPIRY_MINUTES = (
            FlextCore.Constants.Security.SESSION_DEFAULT_EXPIRY_MINUTES
        )
        MAX_EXPIRY_MINUTES = FlextCore.Constants.Security.SESSION_MAX_EXPIRY_MINUTES
        MAX_SESSIONS_PER_USER = (
            FlextCore.Constants.Security.SESSION_MAX_SESSIONS_PER_USER
        )
        CLEANUP_INTERVAL_MINUTES = (
            FlextCore.Constants.Security.SESSION_CLEANUP_INTERVAL_MINUTES
        )
        EXTEND_MINUTES = FlextCore.Constants.Security.SESSION_EXTEND_MINUTES
        MIN_TOKEN_LENGTH = FlextCore.Constants.Security.SESSION_MIN_TOKEN_LENGTH
        DEFAULT_EXTEND_HOURS = FlextCore.Constants.Security.SESSION_DEFAULT_EXTEND_HOURS

    class AuthSecurity:
        """Authentication-specific security enforcement constants."""

        MAX_LOGIN_ATTEMPTS = FlextCore.Constants.Security.AUTH_MAX_LOGIN_ATTEMPTS
        LOCKOUT_DURATION_MINUTES = (
            FlextCore.Constants.Security.AUTH_LOCKOUT_DURATION_MINUTES
        )
        MAX_REQUESTS_PER_MINUTE = (
            FlextCore.Constants.Security.AUTH_MAX_REQUESTS_PER_MINUTE
        )
        MAX_REQUESTS_PER_HOUR = FlextCore.Constants.Security.AUTH_MAX_REQUESTS_PER_HOUR
        # Rate limiting defaults
        RATE_LIMIT_MAX_ATTEMPTS = (
            FlextCore.Constants.Security.AUTH_RATE_LIMIT_MAX_ATTEMPTS
        )
        RATE_LIMIT_WINDOW_MINUTES = (
            FlextCore.Constants.Security.AUTH_RATE_LIMIT_WINDOW_MINUTES
        )

    class Oidc:
        """OIDC provider constants."""

        DEFAULT_ID_TOKEN_SIGNING_ALGORITHM = (
            FlextCore.Constants.Security.OIDC_DEFAULT_ID_TOKEN_SIGNING_ALGORITHM
        )

    class ApiKey:
        """API Key provider constants."""

        DEFAULT_KEY_LENGTH = 32
        DEFAULT_HASH_ALGORITHM = "sha256"
        DEFAULT_REQUIRE_KEY_ID = False
        DEFAULT_KEY_STORAGE = "memory"
        DEFAULT_RATE_LIMIT_ENABLED = False
        DEFAULT_RATE_LIMIT_REQUESTS = 1000
        DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 3600

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
        BASIC_USER_PERMISSIONS: ClassVar[FlextCore.Types.StringList] = [READ, WRITE]
        ADMIN_PERMISSIONS: ClassVar[FlextCore.Types.StringList] = [
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
        DEFAULT_ROLES: ClassVar[FlextCore.Types.StringList] = [USER]
        VALID_ROLES: ClassVar[FlextCore.Types.StringList] = [
            ADMIN,
            USER,
            MODERATOR,
            GUEST,
        ]

    class AuthPlatform:
        """Platform defaults for authentication services."""

        FLEXT_API_PORT = 8000
        DEFAULT_HOST = "localhost"
        LOOPBACK_IP = "127.0.0.1"
        HTTP_STATUS_OK = 200

    class AuthNetwork:
        """Network defaults for authentication services."""

        MIN_PORT = 1
        MAX_PORT = 65535
        TOTAL_TIMEOUT = 60
        DEFAULT_TIMEOUT = 30

    class AuthDefaults:
        """Default values for various operations."""

        DEFAULT_TOKEN_LENGTH = 32
        DEFAULT_SESSION_EXTEND_HOURS = 24  # For protocols
        DEMO_USERS_COUNT = 3
        # Transport defaults
        DEFAULT_TIMEOUT = 30.0
        MAX_RETRIES = 3
        # OIDC defaults
        JWT_PARTS_COUNT = 3
        BASE64_PADDING_SIZE = 4
        # Admin defaults
        DEFAULT_ADMIN_PASSWORD = "***MUST_BE_SET_IN_PRODUCTION***"
        # Mock/test data defaults
        MOCK_USER_PREFIX = "user_"
        MOCK_EMAIL_DOMAIN = "@example.com"
        MOCK_VALIDATED_USER_ID = "validated_user"
        MOCK_VALIDATED_USERNAME = "validated_user"
        MOCK_VALIDATED_EMAIL = "validated@example.com"
        # Provider defaults
        DEFAULT_PROVIDER = "jwt"
        # User model defaults
        DEFAULT_USER_ACTIVE = True
        DEFAULT_USER_ROLES: ClassVar[FlextCore.Types.StringList] = ["user"]
        DEFAULT_FAILED_LOGIN_ATTEMPTS = 0
        # Session model defaults
        DEFAULT_SESSION_ACTIVE = True
        # Token model defaults
        DEFAULT_TOKEN_REVOKED = False
        # Config defaults
        DEFAULT_ENABLE_RATE_LIMITING = True
        DEFAULT_REQUIRE_PASSWORD_COMPLEXITY = True
        DEFAULT_ENABLE_EMAIL_VERIFICATION = False
        DEFAULT_ENABLE_PASSWORD_HISTORY = False

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
