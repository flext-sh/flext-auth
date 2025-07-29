"""Authentication constants using flext-core patterns.

Simplified constants eliminating duplication and leveraging flext-core
constants patterns directly.
"""

from __future__ import annotations

from enum import Enum

# Use flext-core constants directly
from flext_core import FlextConstants

# =============================================================================
# AUTHENTICATION CONSTANTS - Extending flext-core efficiently
# =============================================================================


class FlextAuthConstants(FlextConstants):
    """Authentication constants extending flext-core patterns."""

    # Authentication patterns
    USERNAME_PATTERN = r"^[a-zA-Z0-9_]{3,50}$"

    # Password validation regex - requires mixed case, digits, special chars
    # This is a validation regex, not a hardcoded password
    PASSWORD_VALIDATION_REGEX = (
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?])"  # noqa: S105
        r".{8,128}$"
    )

    # Password constraints
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    MIN_PASSWORD_SECURITY_SCORE = 4

    # Account security
    DEFAULT_MAX_LOGIN_ATTEMPTS = 5
    DEFAULT_LOCKOUT_DURATION_MINUTES = 30
    MAX_ACCOUNT_LOCK_HOURS = 24

    # Session defaults
    DEFAULT_SESSION_TIMEOUT_HOURS = 24
    MAX_CONCURRENT_SESSIONS = 5

    # Token defaults
    DEFAULT_ACCESS_TOKEN_MINUTES = 30
    DEFAULT_REFRESH_TOKEN_DAYS = 7


class FlextUserStatusEnum(Enum):
    """User status enumeration."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    LOCKED = "locked"


class FlextUserRoleEnum(Enum):
    """User role enumeration."""

    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    USER = "user"
    GUEST = "guest"


class FlextTokenTypeEnum(Enum):
    """Token type enumeration."""

    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"
    VERIFICATION = "verification"


# =============================================================================
# EXPORTS - Clean constants API
# =============================================================================

__all__ = [
    "FlextAuthConstants",
    "FlextTokenTypeEnum",
    "FlextUserRoleEnum",
    "FlextUserStatusEnum",
]
