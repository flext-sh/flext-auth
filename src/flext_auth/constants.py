"""FLEXT Auth Constants - SINGLE CONSOLIDATED CLASS following FLEXT patterns.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

FLEXT REFACTORING: Consolidated ALL constant definitions into single FlextAuthConstants class
following FLEXT architectural standards. All constants available as class attributes.
"""

from __future__ import annotations

import os
import re
import secrets
from typing import ClassVar

from flext_core import FlextConstants

# =============================================================================
# SINGLE CONSOLIDATED CLASS - FLEXT ARCHITECTURAL PATTERN
# =============================================================================


class FlextAuthConstants(FlextConstants):
    """Single consolidated class containing ALL authentication constants.

    FLEXT REFACTORING: Consolidates ALL constant definitions into one class following
    FLEXT architectural standards. All constants available as class attributes
    for organization while maintaining single entry point.

    Usage:
        # Direct access to constants
        max_attempts = FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS
        secret = FlextAuthConstants.DEFAULT_JWT_SECRET
        pattern = FlextAuthConstants.USERNAME_PATTERN
    """

    # =============================================================================
    # BOOLEAN CONSTANTS - Semantic constants to avoid ruff FBT003 errors
    # =============================================================================

    SUCCESS: ClassVar[bool] = True
    FAILURE: ClassVar[bool] = False

    # =============================================================================
    # AUTHENTICATION CONSTANTS - User authentication patterns and validation
    # =============================================================================

    USERNAME_PATTERN: ClassVar[str] = r"^[a-zA-Z0-9_]{3,50}$"

    PASSWORD_VALIDATION_REGEX: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]).{8,128}$",
    )

    # CONSUME from flext-core single source - NO DUPLICATION
    MIN_PASSWORD_SECURITY_SCORE: ClassVar[int] = 4

    # =============================================================================
    # SECURITY CONSTANTS - Security policy and protection settings
    # =============================================================================

    DEFAULT_MAX_LOGIN_ATTEMPTS: ClassVar[int] = 5
    DEFAULT_LOCKOUT_DURATION_MINUTES: ClassVar[int] = 30
    MAX_ACCOUNT_LOCK_HOURS: ClassVar[int] = 24
    DEFAULT_BCRYPT_ROUNDS: ClassVar[int] = 12

    # =============================================================================
    # SESSION CONSTANTS - Session management settings
    # =============================================================================

    DEFAULT_SESSION_TIMEOUT_HOURS: ClassVar[int] = FlextConstants.Auth.DEFAULT_SESSION_TIMEOUT // 3600  # Convert seconds to hours
    MAX_CONCURRENT_SESSIONS: ClassVar[int] = FlextConstants.Auth.MAX_SESSIONS_PER_USER

    # =============================================================================
    # TOKEN CONSTANTS - JWT and token configuration
    # =============================================================================

    DEFAULT_ACCESS_TOKEN_MINUTES: ClassVar[int] = FlextConstants.Auth.DEFAULT_TOKEN_EXPIRY // 60  # Convert seconds to minutes
    DEFAULT_REFRESH_TOKEN_DAYS: ClassVar[int] = FlextConstants.Auth.MAX_TOKEN_EXPIRY // 86400  # Convert seconds to days
    JWT_ALGORITHM: ClassVar[str] = "HS256"  # noqa: S105

    # Secure secret generation with environment variable support
    DEV_JWT_SECRET: ClassVar[str] = os.getenv(
        "DEV_JWT_SECRET", secrets.token_urlsafe(32)
    )
    DEFAULT_JWT_SECRET: ClassVar[str] = os.getenv(
        "FLEXT_AUTH_JWT_SECRET_KEY",
        secrets.token_urlsafe(32),
    )

    # =============================================================================
    # USER STATUS CONSTANTS - User account status values
    # =============================================================================

    USER_STATUS_ACTIVE: ClassVar[str] = "active"
    USER_STATUS_INACTIVE: ClassVar[str] = "inactive"
    USER_STATUS_SUSPENDED: ClassVar[str] = "suspended"
    USER_STATUS_LOCKED: ClassVar[str] = "locked"

    # =============================================================================
    # USER ROLE CONSTANTS - User role definitions
    # =============================================================================

    ROLE_ADMIN: ClassVar[str] = "REDACTED_LDAP_BIND_PASSWORD"
    ROLE_USER: ClassVar[str] = "user"
    ROLE_GUEST: ClassVar[str] = "guest"

    # =============================================================================
    # TOKEN TYPE CONSTANTS - Token type definitions
    # =============================================================================

    TOKEN_TYPE_ACCESS: ClassVar[str] = "access"  # noqa: S105
    TOKEN_TYPE_REFRESH: ClassVar[str] = "refresh"  # noqa: S105
    TOKEN_TYPE_RESET: ClassVar[str] = "reset"  # noqa: S105
    TOKEN_TYPE_VERIFICATION: ClassVar[str] = "verification"  # noqa: S105

    # =============================================================================
    # BACKWARD COMPATIBILITY - Legacy nested class access patterns
    # =============================================================================

    class Authentication:
        """Backward compatibility nested class for Authentication constants."""

        USERNAME_PATTERN = r"^[a-zA-Z0-9_]{3,50}$"
        PASSWORD_VALIDATION_REGEX = re.compile(
            r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]).{8,128}$",
        )
        MIN_PASSWORD_SECURITY_SCORE = 4

    class Security:
        """Backward compatibility nested class for Security constants."""

        DEFAULT_MAX_LOGIN_ATTEMPTS = 5
        DEFAULT_LOCKOUT_DURATION_MINUTES = 30
        MAX_ACCOUNT_LOCK_HOURS = 24
        DEFAULT_BCRYPT_ROUNDS = 12

    class Sessions:
        """Backward compatibility nested class for Sessions constants."""

        DEFAULT_SESSION_TIMEOUT_HOURS = 24
        MAX_CONCURRENT_SESSIONS = 5

    class Tokens:
        """Backward compatibility nested class for Tokens constants."""

        DEFAULT_ACCESS_TOKEN_MINUTES = 30
        DEFAULT_REFRESH_TOKEN_DAYS = 7
        JWT_ALGORITHM = "HS256"  # noqa: S105
        DEV_JWT_SECRET = os.getenv("DEV_JWT_SECRET", secrets.token_urlsafe(32))
        DEFAULT_JWT_SECRET = os.getenv(
            "FLEXT_AUTH_JWT_SECRET_KEY", secrets.token_urlsafe(32)
        )

    class UserStatus:
        """Backward compatibility nested class for UserStatus constants."""

        ACTIVE = "active"
        INACTIVE = "inactive"
        SUSPENDED = "suspended"
        LOCKED = "locked"

    class UserRoles:
        """Backward compatibility nested class for UserRoles constants."""

        ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
        USER = "user"
        GUEST = "guest"

    class TokenTypes:
        """Backward compatibility nested class for TokenTypes constants."""

        ACCESS = "access"  # noqa: S105
        REFRESH = "refresh"  # noqa: S105
        RESET = "reset"  # noqa: S105
        VERIFICATION = "verification"  # noqa: S105

    MIN_PASSWORD_LENGTH: int = FlextConstants.Validation.MIN_PASSWORD_LENGTH
    MAX_PASSWORD_LENGTH: int = FlextConstants.Validation.MAX_PASSWORD_LENGTH


# =============================================================================
# BACKWARD COMPATIBILITY - Legacy class and constant exports
# =============================================================================

# Create backward compatibility aliases for legacy imports
FlextAuthSemanticConstants = FlextAuthConstants

# Legacy constant exports at module level for direct import compatibility
DEV_JWT_SECRET = FlextAuthConstants.DEV_JWT_SECRET
DEFAULT_JWT_SECRET = FlextAuthConstants.DEFAULT_JWT_SECRET
DEFAULT_DEV_SECRET = DEFAULT_JWT_SECRET


# =============================================================================
# EXPORTS - Clean constants API
# =============================================================================

__all__: list[str] = [
    # Legacy constant exports for backward compatibility
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "DEV_JWT_SECRET",
    # CONSOLIDATED CLASS - FLEXT Pattern (main export)
    "FlextAuthConstants",
    # Legacy class exports for backward compatibility
    "FlextAuthSemanticConstants",
]
