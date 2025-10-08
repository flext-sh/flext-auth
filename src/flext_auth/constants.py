"""FLEXT Auth Constants - Authentication-specific constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import FlextConstants, FlextTypes


class FlextAuthConstants(FlextConstants):
    """Authentication-specific constants following FLEXT unified pattern with nested domains.

    Inherits from FlextConstants for universal constants, defines only
    auth-specific constants using nested namespace classes.
    """

    # Default credentials
    DEFAULT_ADMIN_PASSWORD = "AdminPassword123!"  # nosec B105 - Default REDACTED_LDAP_BIND_PASSWORD password for testing

    class Jwt:
        """JWT Token management constants."""

        DEFAULT_ALGORITHM = FlextConstants.Security.JWT_DEFAULT_ALGORITHM
        DEFAULT_EXPIRY_MINUTES = FlextConstants.Security.JWT_DEFAULT_EXPIRY_MINUTES
        MAX_EXPIRY_MINUTES = FlextConstants.Security.JWT_MAX_EXPIRY_MINUTES
        ISSUER_CLAIM = FlextConstants.Security.JWT_ISSUER_CLAIM
        AUDIENCE_CLAIM = FlextConstants.Security.JWT_AUDIENCE_CLAIM
        SECRET_KEY = FlextConstants.Security.DEFAULT_JWT_SECRET  # nosec B105
        ALLOWED_ALGORITHMS: ClassVar[FlextTypes.StringList] = list(
            FlextConstants.Security.JWT_ALLOWED_ALGORITHMS
        )
        DEFAULT_TOKEN_TYPE = FlextConstants.Security.JWT_DEFAULT_TOKEN_TYPE
        DEFAULT_ACCESS_TOKEN_TYPE = (
            FlextConstants.Security.JWT_DEFAULT_ACCESS_TOKEN_TYPE
        )
        API_TOKEN_TYPE = FlextConstants.Security.JWT_API_TOKEN_TYPE
        BASIC_TOKEN_TYPE = FlextConstants.Security.JWT_BASIC_TOKEN_TYPE
        BEARER_PREFIX = FlextConstants.Security.JWT_BEARER_PREFIX
        MIN_SECRET_KEY_LENGTH = FlextConstants.Security.JWT_MIN_SECRET_KEY_LENGTH

    class Credentials:
        """User credential validation constants."""

        class Username:
            """Username validation rules."""

            MIN_LENGTH = FlextConstants.Security.CREDENTIAL_USERNAME_MIN_LENGTH
            MAX_LENGTH = FlextConstants.Security.CREDENTIAL_USERNAME_MAX_LENGTH

        class Password:
            """Password validation and security constants."""

            MIN_LENGTH = FlextConstants.Security.CREDENTIAL_PASSWORD_MIN_LENGTH
            MAX_LENGTH = FlextConstants.Security.CREDENTIAL_PASSWORD_MAX_LENGTH
            MIN_SCORE = FlextConstants.Security.CREDENTIAL_PASSWORD_MIN_SCORE
            MIN_BCRYPT_HASH_LENGTH = (
                FlextConstants.Security.CREDENTIAL_MIN_BCRYPT_HASH_LENGTH
            )
            BCRYPT_ROUNDS = FlextConstants.Security.CREDENTIAL_BCRYPT_ROUNDS
            MIN_BCRYPT_ROUNDS = FlextConstants.Security.CREDENTIAL_MIN_BCRYPT_ROUNDS
            MAX_BCRYPT_ROUNDS = FlextConstants.Security.CREDENTIAL_MAX_BCRYPT_ROUNDS
            WEAK_PASSWORDS: ClassVar[FlextTypes.StringList] = [
                "123",
                "abc",
                "password",
                "12345678",
                "aaaaaaaa",
            ]

    class Session:
        """Session management constants."""

        DEFAULT_EXPIRY_MINUTES = FlextConstants.Security.SESSION_DEFAULT_EXPIRY_MINUTES
        MAX_EXPIRY_MINUTES = FlextConstants.Security.SESSION_MAX_EXPIRY_MINUTES
        MAX_SESSIONS_PER_USER = FlextConstants.Security.SESSION_MAX_SESSIONS_PER_USER
        CLEANUP_INTERVAL_MINUTES = (
            FlextConstants.Security.SESSION_CLEANUP_INTERVAL_MINUTES
        )
        EXTEND_MINUTES = FlextConstants.Security.SESSION_EXTEND_MINUTES
        MIN_TOKEN_LENGTH = FlextConstants.Security.SESSION_MIN_TOKEN_LENGTH
        DEFAULT_EXTEND_HOURS = FlextConstants.Security.SESSION_DEFAULT_EXTEND_HOURS

    class AuthSecurity:
        """Authentication-specific security enforcement constants."""

        MAX_LOGIN_ATTEMPTS = FlextConstants.Security.AUTH_MAX_LOGIN_ATTEMPTS
        LOCKOUT_DURATION_MINUTES = FlextConstants.Security.AUTH_LOCKOUT_DURATION_MINUTES
        MAX_REQUESTS_PER_MINUTE = FlextConstants.Security.AUTH_MAX_REQUESTS_PER_MINUTE
        MAX_REQUESTS_PER_HOUR = FlextConstants.Security.AUTH_MAX_REQUESTS_PER_HOUR
        # Rate limiting defaults
        RATE_LIMIT_MAX_ATTEMPTS = FlextConstants.Security.AUTH_RATE_LIMIT_MAX_ATTEMPTS
        RATE_LIMIT_WINDOW_MINUTES = (
            FlextConstants.Security.AUTH_RATE_LIMIT_WINDOW_MINUTES
        )

    class Oidc:
        """OIDC provider constants."""

        DEFAULT_ID_TOKEN_SIGNING_ALGORITHM = (
            FlextConstants.Security.OIDC_DEFAULT_ID_TOKEN_SIGNING_ALGORITHM
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
        VALID_ROLES: ClassVar[FlextTypes.StringList] = [ADMIN, USER, MODERATOR, GUEST]

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

    class Defaults:
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
        DEFAULT_ADMIN_PASSWORD = "AdminPassword123!"  # nosec B105 - Default REDACTED_LDAP_BIND_PASSWORD password for testing

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
