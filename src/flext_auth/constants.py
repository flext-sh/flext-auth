"""FLEXT Auth Constants - Authentication-specific constants and configuration values.

This module provides authentication-related constants following flext-core patterns
for consistency across the ecosystem. It extends base constants with authentication-
specific values while eliminating duplication through inheritance.

Architecture:
    - Constants Layer: Centralized configuration values
    - Inheritance: Extends flext-core constants for consistency
    - Type Safety: Enum-based constants for type safety
    - Security-First: Secure defaults for production environments

Constant Categories:
    - Authentication: Login and password validation patterns
    - Security: Account lockout and security policies
    - Session: Session management and timeouts
    - Token: JWT and token configuration
    - Validation: Input validation patterns and limits

TODO (Based on docs/TODO.md):
    - [ ] MEDIUM: Add environment-specific constants (Issue #8)
    - [ ] LOW: Add constants for rate limiting (Issue #11)
    - [ ] LOW: Add constants for audit logging (Issue #11)

Current Project Status:
    ✅ Authentication constants fully documented with security-first approach
    ✅ Type-safe enum patterns documented and implemented
    ✅ Configuration inheritance from flext-core documented
    🔄 Implementation focus: Environment-specific constants and rate limiting

Design Patterns:
    - Inheritance: Extends flext-core constants
    - Enumeration: Type-safe constant definitions
    - Namespace: Organized constant grouping
    - Configuration: Environment-specific values

Security Constants:
    All security-related constants follow enterprise best practices:
    - Password complexity requirements
    - Account lockout policies
    - Session timeout policies
    - Token expiration settings

Example Usage:
    >>> from flext_auth.constants import FlextAuthConstants
    >>>
    >>> # Use authentication-specific constants
    >>> min_length = FlextAuthConstants.MIN_PASSWORD_LENGTH
    >>> max_attempts = FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS
    >>> pattern = FlextAuthConstants.USERNAME_PATTERN

Environment Considerations:
    Constants are designed for different environments:
    - Development: Relaxed for easier testing
    - Staging: Production-like for realistic testing
    - Production: Strict security for enterprise deployment

Integration Points:
    - FlextConfig: Configuration validation
    - Security Policies: Enforcement of security rules
    - Validation: Input validation patterns
    - Monitoring: Default thresholds for alerts

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import Enum

# Use flext-core constants directly
from flext_core import FlextConstants

# DRY: Test secrets centralized to eliminate duplication
TEST_JWT_SECRET = "test-secret-key"  # noqa: S105
DEFAULT_JWT_SECRET = "default-secret"  # noqa: S105

# =============================================================================
# AUTHENTICATION CONSTANTS - Extending flext-core efficiently
# =============================================================================


class FlextAuthConstants(FlextConstants):
    """Authentication constants extending flext-core platform constants."""

    # Authentication patterns (extend core patterns)
    USERNAME_PATTERN = r"^[a-zA-Z0-9_]{3,50}$"

    # Password validation regex - requires mixed case, digits, special chars
    # This is a validation regex, not a hardcoded password
    PASSWORD_VALIDATION_REGEX = (
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?])"  # noqa: S105
        r".{8,128}$"
    )

    # Password constraints (hardcoded as auth-specific)
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    MIN_PASSWORD_SECURITY_SCORE = 4

    # Account security (hardcoded as auth-specific)
    DEFAULT_MAX_LOGIN_ATTEMPTS = 5
    DEFAULT_LOCKOUT_DURATION_MINUTES = 30
    MAX_ACCOUNT_LOCK_HOURS = 24

    # Session defaults
    DEFAULT_SESSION_TIMEOUT_HOURS = 24
    MAX_CONCURRENT_SESSIONS = 5

    # Token defaults (hardcoded as auth-specific)
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
