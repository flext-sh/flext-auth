"""FLEXT Auth Constants - Authentication-specific constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import FlextConstants


class FlextAuthConstants(FlextConstants):
    """Authentication-specific constants following FLEXT unified pattern with nested domains."""

    class Jwt:
        """JWT Token management constants."""

        DEFAULT_ALGORITHM = "HS256"
        DEFAULT_EXPIRY_MINUTES = 30
        MAX_EXPIRY_MINUTES = 1440  # 24 hours
        ISSUER_CLAIM = "flext-auth"
        AUDIENCE_CLAIM = "flext-users"
        SECRET_KEY = "your-super-secure-jwt-secret-key-change-in-production"  # nosec B105
        ALLOWED_ALGORITHMS: ClassVar[list[str]] = [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
        ]
        DEFAULT_TOKEN_TYPE = "access"
        MIN_SECRET_KEY_LENGTH = 32

    class Credentials:
        """User credential validation constants."""

        class Username:
            """Username validation rules."""

            MIN_LENGTH = 3
            MAX_LENGTH = 50

        class Password:
            """Password validation and security constants."""

            MIN_LENGTH = 8
            MAX_LENGTH = 128
            MIN_SCORE = 3  # Require at least 3 of: upper, lower, digit, special
            MIN_BCRYPT_HASH_LENGTH = 60
            BCRYPT_ROUNDS = 12
            MIN_BCRYPT_ROUNDS = 10
            MAX_BCRYPT_ROUNDS = 15

    class Session:
        """Session management constants."""

        DEFAULT_EXPIRY_MINUTES = 120  # 2 hours
        MAX_EXPIRY_MINUTES = 1440  # 24 hours
        MAX_SESSIONS_PER_USER = 5
        CLEANUP_INTERVAL_MINUTES = 30
        EXTEND_MINUTES = 30
        MIN_TOKEN_LENGTH = 32

    class Security:
        """Security enforcement constants."""

        MAX_LOGIN_ATTEMPTS = 5
        LOCKOUT_DURATION_MINUTES = 30
        MAX_REQUESTS_PER_MINUTE = 60
        MAX_REQUESTS_PER_HOUR = 1000

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

    class Logging:
        """Audit and security logging configuration."""

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


__all__ = ["FlextAuthConstants"]
