"""FLEXT Auth Constants - Authentication-specific constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import FlextConstants


class FlextAuthConstants(FlextConstants):
    """Authentication-specific constants following flext-core patterns."""

    # JWT Configuration
    JWT_DEFAULT_ALGORITHM = "HS256"
    JWT_DEFAULT_EXPIRY_MINUTES = 30
    JWT_MAX_EXPIRY_MINUTES = 1440  # 24 hours
    JWT_ISSUER_CLAIM = "flext-auth"
    JWT_AUDIENCE_CLAIM = "flext-users"
    JWT_SECRET_KEY = "your-super-secure-jwt-secret-key-change-in-production"  # nosec B105
    JWT_ALLOWED_ALGORITHMS: ClassVar[list[str]] = [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
    ]
    JWT_DEFAULT_TOKEN_TYPE = "access"
    MIN_SECRET_KEY_LENGTH = 32

    # Username Configuration
    MIN_USERNAME_LENGTH = 3
    MAX_USERNAME_LENGTH = 50

    # Password Configuration
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    MIN_PASSWORD_SCORE = 3  # Require at least 3 of: upper, lower, digit, special
    MIN_BCRYPT_HASH_LENGTH = 60
    BCRYPT_ROUNDS = 12
    MIN_BCRYPT_ROUNDS = 10
    MAX_BCRYPT_ROUNDS = 15

    # Session Configuration
    DEFAULT_SESSION_EXPIRY_MINUTES = 120  # 2 hours
    MAX_SESSION_EXPIRY_MINUTES = 1440  # 24 hours
    MAX_SESSIONS_PER_USER = 5
    SESSION_CLEANUP_INTERVAL_MINUTES = 30
    SESSION_EXTEND_MINUTES = 30
    MIN_TOKEN_LENGTH = 32

    # Security Configuration
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    MAX_REQUESTS_PER_MINUTE = 60
    MAX_REQUESTS_PER_HOUR = 1000

    # Error Codes
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"  # nosec B105
    INVALID_TOKEN = "INVALID_TOKEN"  # nosec B105
    USERNAME_TAKEN = "USERNAME_TAKEN"
    EMAIL_TAKEN = "EMAIL_TAKEN"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"


# Export constants for easy access
__all__ = ["FlextAuthConstants"]
