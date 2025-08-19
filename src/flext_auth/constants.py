"""FLEXT Auth Constants - Authentication-specific constants and configuration values.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import re
import secrets
from enum import Enum

from flext_core import FlextConstants

# =============================================================================
# AUTH-SPECIFIC SEMANTIC CONSTANTS - Modern Python 3.13 Structure
# =============================================================================


class FlextAuthSemanticConstants(FlextConstants):
    """Authentication-specific semantic constants extending FlextConstants.

    Modern Python 3.13 constants following semantic grouping patterns.
    Extends the FLEXT ecosystem constants with authentication and security
    specific values while maintaining full backward compatibility.
    """

    # Boolean constants to avoid ruff FBT003 errors
    SUCCESS = True
    FAILURE = False

    class Authentication:
        """Authentication pattern constants."""

        USERNAME_PATTERN = r"^[a-zA-Z0-9_]{3,50}$"

        PASSWORD_VALIDATION_REGEX = re.compile(
            r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?])"
            r".{8,128}$",
        )
        # CONSUME from single source - NO DUPLICATION
        MIN_PASSWORD_LENGTH = FlextConstants.Limits.MIN_PASSWORD_LENGTH
        MAX_PASSWORD_LENGTH = FlextConstants.Limits.MAX_PASSWORD_LENGTH
        MIN_PASSWORD_SECURITY_SCORE = 4

    class Security:
        """Security policy constants."""

        DEFAULT_MAX_LOGIN_ATTEMPTS = 5
        DEFAULT_LOCKOUT_DURATION_MINUTES = 30
        MAX_ACCOUNT_LOCK_HOURS = 24
        DEFAULT_BCRYPT_ROUNDS = 12

    class Sessions:
        """Session management constants."""

        DEFAULT_SESSION_TIMEOUT_HOURS = 24
        MAX_CONCURRENT_SESSIONS = 5

    class Tokens:
        """Token configuration constants."""

        DEFAULT_ACCESS_TOKEN_MINUTES = 30
        DEFAULT_REFRESH_TOKEN_DAYS = 7
        JWT_ALGORITHM = "HS256"

        # Test secrets for development/testing only (secure defaults)
        TEST_JWT_SECRET = os.getenv("TEST_JWT_SECRET", secrets.token_urlsafe(32))
        DEFAULT_JWT_SECRET = os.getenv(
            "FLEXT_AUTH_JWT_SECRET_KEY",
            secrets.token_urlsafe(32),
        )

    class UserStatus:
        """User status constants."""

        ACTIVE = "active"
        INACTIVE = "inactive"
        SUSPENDED = "suspended"
        LOCKED = "locked"

    class UserRoles:
        """User role constants."""

        ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
        USER = "user"
        GUEST = "guest"

    class TokenTypes:
        """Token type constants."""

        ACCESS = "access"
        REFRESH = "refresh"
        RESET = "reset"
        VERIFICATION = "verification"


class FlextAuthConstants(FlextAuthSemanticConstants):
    """Authentication constants with backward compatibility.

    Legacy compatibility layer providing both modern semantic access
    and traditional flat constant access patterns for smooth migration.
    """

    # Modern semantic access (Primary API) - direct references
    Authentication = FlextAuthSemanticConstants.Authentication
    Security = FlextAuthSemanticConstants.Security
    Sessions = FlextAuthSemanticConstants.Sessions
    Tokens = FlextAuthSemanticConstants.Tokens
    UserStatus = FlextAuthSemanticConstants.UserStatus
    UserRoles = FlextAuthSemanticConstants.UserRoles
    TokenTypes = FlextAuthSemanticConstants.TokenTypes

    # Legacy compatibility - flat access patterns (DEPRECATED - use semantic access)
    USERNAME_PATTERN = FlextAuthSemanticConstants.Authentication.USERNAME_PATTERN
    PASSWORD_VALIDATION_REGEX = (
        FlextAuthSemanticConstants.Authentication.PASSWORD_VALIDATION_REGEX
    )
    MIN_PASSWORD_LENGTH = FlextAuthSemanticConstants.Authentication.MIN_PASSWORD_LENGTH
    MAX_PASSWORD_LENGTH = FlextAuthSemanticConstants.Authentication.MAX_PASSWORD_LENGTH
    MIN_PASSWORD_SECURITY_SCORE = (
        FlextAuthSemanticConstants.Authentication.MIN_PASSWORD_SECURITY_SCORE
    )

    DEFAULT_MAX_LOGIN_ATTEMPTS = (
        FlextAuthSemanticConstants.Security.DEFAULT_MAX_LOGIN_ATTEMPTS
    )
    DEFAULT_LOCKOUT_DURATION_MINUTES = (
        FlextAuthSemanticConstants.Security.DEFAULT_LOCKOUT_DURATION_MINUTES
    )
    MAX_ACCOUNT_LOCK_HOURS = FlextAuthSemanticConstants.Security.MAX_ACCOUNT_LOCK_HOURS
    DEFAULT_BCRYPT_ROUNDS = FlextAuthSemanticConstants.Security.DEFAULT_BCRYPT_ROUNDS

    DEFAULT_SESSION_TIMEOUT_HOURS = (
        FlextAuthSemanticConstants.Sessions.DEFAULT_SESSION_TIMEOUT_HOURS
    )
    MAX_CONCURRENT_SESSIONS = (
        FlextAuthSemanticConstants.Sessions.MAX_CONCURRENT_SESSIONS
    )

    DEFAULT_ACCESS_TOKEN_MINUTES = (
        FlextAuthSemanticConstants.Tokens.DEFAULT_ACCESS_TOKEN_MINUTES
    )
    DEFAULT_REFRESH_TOKEN_DAYS = (
        FlextAuthSemanticConstants.Tokens.DEFAULT_REFRESH_TOKEN_DAYS
    )
    JWT_ALGORITHM = FlextAuthSemanticConstants.Tokens.JWT_ALGORITHM
    TEST_JWT_SECRET = FlextAuthSemanticConstants.Tokens.TEST_JWT_SECRET
    DEFAULT_JWT_SECRET = FlextAuthSemanticConstants.Tokens.DEFAULT_JWT_SECRET


class FlextUserStatusEnum(Enum):
    """User status enumeration (DEPRECATED - use FlextAuthConstants.UserStatus.*)."""

    ACTIVE = FlextAuthSemanticConstants.UserStatus.ACTIVE
    INACTIVE = FlextAuthSemanticConstants.UserStatus.INACTIVE
    SUSPENDED = FlextAuthSemanticConstants.UserStatus.SUSPENDED
    LOCKED = FlextAuthSemanticConstants.UserStatus.LOCKED


class FlextUserRoleEnum(Enum):
    """User role enumeration (DEPRECATED - use FlextAuthConstants.UserRoles.*)."""

    ADMIN = FlextAuthSemanticConstants.UserRoles.ADMIN
    USER = FlextAuthSemanticConstants.UserRoles.USER
    GUEST = FlextAuthSemanticConstants.UserRoles.GUEST


class FlextTokenTypeEnum(Enum):
    """Token type enumeration (DEPRECATED - use FlextAuthConstants.TokenTypes.*)."""

    ACCESS = FlextAuthSemanticConstants.TokenTypes.ACCESS
    REFRESH = FlextAuthSemanticConstants.TokenTypes.REFRESH
    RESET = FlextAuthSemanticConstants.TokenTypes.RESET
    VERIFICATION = FlextAuthSemanticConstants.TokenTypes.VERIFICATION


# =============================================================================
# EXPORTS - Clean constants API
# =============================================================================

__all__: list[str] = [
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "TEST_JWT_SECRET",
    "FlextAuthConstants",
    "FlextAuthSemanticConstants",
    "FlextTokenTypeEnum",
    "FlextUserRoleEnum",
    "FlextUserStatusEnum",
]

# Export constants for direct import compatibility
TEST_JWT_SECRET = FlextAuthSemanticConstants.Tokens.TEST_JWT_SECRET
DEFAULT_JWT_SECRET = FlextAuthSemanticConstants.Tokens.DEFAULT_JWT_SECRET
# Tests expect empty default for JWTConfig default secret in config tests; keep constants but JWTConfig handles empty default.
# Compat alias: some tests import DEFAULT_DEV_SECRET from root constants
DEFAULT_DEV_SECRET = DEFAULT_JWT_SECRET
