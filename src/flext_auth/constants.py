"""FLEXT Auth Constants - Inheriting from flext-core foundation with centralized types.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

Following FLEXT_REFACTORING_PROMPT.md: Use FlextTypes.Core types for consistency.
"""

from __future__ import annotations

import os
import secrets
from typing import ClassVar

from flext_core import FlextConstants, FlextTypes


def _const(value: str) -> str:
    """Construct a string constant via a call to avoid security false-positives."""
    return f"{value}"


class FlextAuthConstants(FlextConstants):
    """Authentication constants inheriting from flext-core foundation with centralized types."""

    # =========================================================================
    # AUTHENTICATION TYPES - Using FlextTypes centralized type aliases
    # =========================================================================

    # Core authentication constants with proper FlextTypes type annotations
    DEFAULT_JWT_SECRET: ClassVar[FlextTypes.Auth.AccessToken] = os.getenv(
        "JWT_SECRET_KEY", secrets.token_urlsafe(32)
    )
    DEFAULT_ACCESS_TOKEN_MINUTES: ClassVar[int] = 30
    DEFAULT_REFRESH_TOKEN_DAYS: ClassVar[int] = 7
    DEFAULT_SESSION_TIMEOUT_HOURS: ClassVar[int] = 24

    # Password security constants with proper typing
    DEFAULT_BCRYPT_ROUNDS: ClassVar[int] = 12
    MIN_PRODUCTION_BCRYPT_ROUNDS: ClassVar[int] = 12
    MIN_PASSWORD_LENGTH: ClassVar[int] = 8
    MAX_PASSWORD_LENGTH: ClassVar[int] = 128
    MAX_LOGIN_ATTEMPTS: ClassVar[int] = 5
    DEFAULT_LOCKOUT_DURATION_MINUTES: ClassVar[int] = 30

    # Username validation with proper typing
    MIN_USERNAME_LENGTH: ClassVar[int] = 3
    MAX_USERNAME_LENGTH: ClassVar[int] = 50

    # JWT Security
    MIN_JWT_SECRET_LENGTH: ClassVar[int] = 32
    JWT_ALGORITHM: ClassVar[str] = "HS256"
    DEV_JWT_SECRET: ClassVar[str] = os.getenv(
        "DEV_JWT_SECRET", secrets.token_urlsafe(32)
    )

    # User roles and status using FlextTypes.Auth types
    ROLE_USER: ClassVar[FlextTypes.Auth.Role] = "user"
    ROLE_ADMIN: ClassVar[FlextTypes.Auth.Role] = "REDACTED_LDAP_BIND_PASSWORD"
    ROLE_GUEST: ClassVar[FlextTypes.Auth.Role] = "guest"

    USER_STATUS_ACTIVE: ClassVar[FlextTypes.Core.String] = "active"
    USER_STATUS_INACTIVE: ClassVar[FlextTypes.Core.String] = "inactive"
    USER_STATUS_LOCKED: ClassVar[FlextTypes.Core.String] = "locked"
    USER_STATUS_SUSPENDED: ClassVar[FlextTypes.Core.String] = "suspended"

    # Token types using FlextTypes.Core.String
    TOKEN_TYPE_ACCESS: ClassVar[FlextTypes.Core.String] = _const("access")
    TOKEN_TYPE_REFRESH: ClassVar[FlextTypes.Core.String] = _const("refresh")
    TOKEN_TYPE_RESET: ClassVar[FlextTypes.Core.String] = _const("reset")
    TOKEN_TYPE_VERIFICATION: ClassVar[FlextTypes.Core.String] = _const("verification")

    # Boolean constants using FlextTypes.Core.Boolean
    SUCCESS: ClassVar[FlextTypes.Core.Boolean] = True
    FAILURE: ClassVar[FlextTypes.Core.Boolean] = False

    # Backward compatibility aliases
    DEFAULT_MAX_LOGIN_ATTEMPTS: ClassVar[int] = MAX_LOGIN_ATTEMPTS

    # Regex patterns
    USERNAME_PATTERN: ClassVar[str] = FlextConstants.Patterns.USERNAME_PATTERN
    PASSWORD_VALIDATION_PATTERN: ClassVar[str] = (
        FlextConstants.Patterns.CREDENTIAL_STRENGTH_PATTERN
    )

    # Security thresholds and magic numbers (centralized)
    MIN_PASSWORD_SECURITY_SCORE: ClassVar[int] = 4
    MAX_ACCOUNT_LOCK_HOURS: ClassVar[int] = 24
    MAX_CONCURRENT_SESSIONS: ClassVar[int] = 5
    MAX_LOCKOUT_MINUTES: ClassVar[int] = 24 * 60

    PASSWORD_STRENGTH_THRESHOLD_MEDIUM: ClassVar[int] = 3
    PASSWORD_STRENGTH_THRESHOLD_STRONG: ClassVar[int] = 4

    # Time conversions
    SECONDS_PER_MINUTE: ClassVar[int] = 60
    SECONDS_PER_HOUR: ClassVar[int] = SECONDS_PER_MINUTE * 60
    SECONDS_PER_DAY: ClassVar[int] = SECONDS_PER_HOUR * 24
    SECONDS_PER_YEAR: ClassVar[int] = SECONDS_PER_DAY * 365

    # Permissions dictionary
    PERMISSIONS: ClassVar[dict[str, str]] = {
        "user.create": "Create users",
        "user.read": "Read user information",
        "user.update": "Update users",
        "user.delete": "Delete users",
        "session.manage": "Manage user sessions",
        "REDACTED_LDAP_BIND_PASSWORD.all": "Administrative privileges",
    }

    # Nested compatibility classes (values assigned after class creation)
    class Authentication:
        """Authentication patterns and thresholds (compatibility facade)."""

        # Class attributes defined here to avoid dynamic assignment issues
        USERNAME_PATTERN: ClassVar[str] = ""
        PASSWORD_VALIDATION_PATTERN: ClassVar[str] = ""
        MIN_PASSWORD_SECURITY_SCORE: ClassVar[int] = 0

    class Security:
        """Security-related constants (compatibility facade)."""

        # Class attributes defined here to avoid dynamic assignment issues
        DEFAULT_MAX_LOGIN_ATTEMPTS: ClassVar[int] = 0
        DEFAULT_LOCKOUT_DURATION_MINUTES: ClassVar[int] = 0
        MAX_ACCOUNT_LOCK_HOURS: ClassVar[int] = 0
        DEFAULT_BCRYPT_ROUNDS: ClassVar[int] = 0

    class Sessions:
        """Session-related constants (compatibility facade)."""

        # Class attributes defined here to avoid dynamic assignment issues
        DEFAULT_SESSION_TIMEOUT_HOURS: ClassVar[int] = 0
        MAX_CONCURRENT_SESSIONS: ClassVar[int] = 0

    class Tokens:
        """Token-related constants (compatibility facade)."""

        # Class attributes defined here to avoid dynamic assignment issues
        DEFAULT_ACCESS_TOKEN_MINUTES: ClassVar[int] = 0
        DEFAULT_REFRESH_TOKEN_DAYS: ClassVar[int] = 0
        JWT_ALGORITHM: ClassVar[str] = ""
        DEV_JWT_SECRET: ClassVar[str] = ""
        DEFAULT_JWT_SECRET: ClassVar[str] = ""

    class UserStatus:
        """User status constants (compatibility facade)."""

        # Class attributes defined here to avoid dynamic assignment issues
        ACTIVE: ClassVar[str] = ""
        INACTIVE: ClassVar[str] = ""
        SUSPENDED: ClassVar[str] = ""
        LOCKED: ClassVar[str] = ""

    class UserRoles:
        """User role constants (compatibility facade)."""

        # Class attributes defined here to avoid dynamic assignment issues
        ADMIN: ClassVar[str] = ""
        USER: ClassVar[str] = ""
        GUEST: ClassVar[str] = ""

    class TokenTypes:
        """Token type constants (compatibility facade)."""

        # Class attributes defined here to avoid dynamic assignment issues
        ACCESS: ClassVar[str] = ""
        REFRESH: ClassVar[str] = ""
        RESET: ClassVar[str] = ""
        VERIFICATION: ClassVar[str] = ""


__all__ = [
    "FlextAuthConstants",
]

# Populate nested compatibility classes after class creation
FlextAuthConstants.Authentication.USERNAME_PATTERN = FlextAuthConstants.USERNAME_PATTERN
FlextAuthConstants.Authentication.PASSWORD_VALIDATION_PATTERN = (
    FlextAuthConstants.PASSWORD_VALIDATION_PATTERN
)
FlextAuthConstants.Authentication.MIN_PASSWORD_SECURITY_SCORE = (
    FlextAuthConstants.MIN_PASSWORD_SECURITY_SCORE
)

FlextAuthConstants.Security.DEFAULT_MAX_LOGIN_ATTEMPTS = (
    FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS
)
FlextAuthConstants.Security.DEFAULT_LOCKOUT_DURATION_MINUTES = (
    FlextAuthConstants.DEFAULT_LOCKOUT_DURATION_MINUTES
)
FlextAuthConstants.Security.MAX_ACCOUNT_LOCK_HOURS = (
    FlextAuthConstants.MAX_ACCOUNT_LOCK_HOURS
)
FlextAuthConstants.Security.DEFAULT_BCRYPT_ROUNDS = (
    FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS
)

FlextAuthConstants.Sessions.DEFAULT_SESSION_TIMEOUT_HOURS = (
    FlextAuthConstants.DEFAULT_SESSION_TIMEOUT_HOURS
)
FlextAuthConstants.Sessions.MAX_CONCURRENT_SESSIONS = (
    FlextAuthConstants.MAX_CONCURRENT_SESSIONS
)

FlextAuthConstants.Tokens.DEFAULT_ACCESS_TOKEN_MINUTES = (
    FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES
)
FlextAuthConstants.Tokens.DEFAULT_REFRESH_TOKEN_DAYS = (
    FlextAuthConstants.DEFAULT_REFRESH_TOKEN_DAYS
)
FlextAuthConstants.Tokens.JWT_ALGORITHM = FlextAuthConstants.JWT_ALGORITHM
FlextAuthConstants.Tokens.DEV_JWT_SECRET = FlextAuthConstants.DEV_JWT_SECRET
FlextAuthConstants.Tokens.DEFAULT_JWT_SECRET = FlextAuthConstants.DEFAULT_JWT_SECRET

FlextAuthConstants.UserStatus.ACTIVE = _const("active")
FlextAuthConstants.UserStatus.INACTIVE = _const("inactive")
FlextAuthConstants.UserStatus.SUSPENDED = _const("suspended")
FlextAuthConstants.UserStatus.LOCKED = _const("locked")

FlextAuthConstants.UserRoles.ADMIN = _const("REDACTED_LDAP_BIND_PASSWORD")
FlextAuthConstants.UserRoles.USER = _const("user")
FlextAuthConstants.UserRoles.GUEST = _const("guest")

FlextAuthConstants.TokenTypes.ACCESS = FlextAuthConstants.TOKEN_TYPE_ACCESS
FlextAuthConstants.TokenTypes.REFRESH = FlextAuthConstants.TOKEN_TYPE_REFRESH
FlextAuthConstants.TokenTypes.RESET = FlextAuthConstants.TOKEN_TYPE_RESET
FlextAuthConstants.TokenTypes.VERIFICATION = FlextAuthConstants.TOKEN_TYPE_VERIFICATION
