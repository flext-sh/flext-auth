"""FLEXT Auth Utilities - Consolidated helper functions and utilities.

This module consolidates authentication utilities and helper functions following
PEP8 strict naming patterns. It provides common utility functions for the
FLEXT authentication ecosystem.

Consolidated from:
    - helpers.py: Helper functions for authentication operations
    - utils.py: General utility functions

Architecture:
    - Utility Layer: Common functions and helpers
    - Pure Functions: Side-effect free utilities where possible
    - Railway-Oriented: FlextResult[T] for type-safe operations

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import secrets
import string
from datetime import UTC, datetime, timedelta

from flext_core import FlextResult

# =============================================================================
# STRING UTILITIES
# =============================================================================


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure random password with mixed characters."""
    length = max(length, 8)

    # Character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-="

    # Ensure at least one character from each set
    password_chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]

    # Fill remaining length with random characters
    all_chars = uppercase + lowercase + digits + symbols
    password_chars.extend(secrets.choice(all_chars) for _ in range(length - 4))

    # Shuffle the password
    password_list = list(password_chars)
    for i in range(len(password_list)):
        j = secrets.randbelow(len(password_list))
        password_list[i], password_list[j] = password_list[j], password_list[i]

    return "".join(password_list)


def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """Mask sensitive data showing only first few characters."""
    if len(data) <= visible_chars:
        return "*" * len(data)
    return data[:visible_chars] + "*" * (len(data) - visible_chars)


# =============================================================================
# TIME UTILITIES
# =============================================================================


def get_utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(UTC)


def is_expired(expires_at: datetime) -> bool:
    """Check if datetime is in the past."""
    return get_utc_now() >= expires_at


def add_minutes_to_now(minutes: int) -> datetime:
    """Add minutes to current UTC time."""
    return get_utc_now() + timedelta(minutes=minutes)


def add_hours_to_now(hours: int) -> datetime:
    """Add hours to current UTC time."""
    return get_utc_now() + timedelta(hours=hours)


# =============================================================================
# VALIDATION UTILITIES
# =============================================================================


def is_valid_email_format(email: str) -> bool:
    """Validate basic email format."""
    return "@" in email and "." in email.rsplit("@", maxsplit=1)[-1]


def is_strong_password(password: str) -> bool:
    """Check if password meets basic strength requirements."""
    min_password_length = 8
    if len(password) < min_password_length:
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in "!@#$%^&*()_+-=" for c in password)

    return has_upper and has_lower and has_digit and has_symbol


def sanitize_input(input_str: str) -> str:
    """Sanitize input string by trimming whitespace."""
    return input_str.strip()


# =============================================================================
# CONVERSION UTILITIES
# =============================================================================


def safe_str(value: object) -> str:
    """Safely convert value to string."""
    if value is None:
        return ""
    return str(value)


def safe_int(value: object, default: int = 0) -> int:
    """Safely convert value to integer."""
    try:
        return int(str(value)) if value is not None else default
    except (ValueError, TypeError):
        return default


def safe_bool(value: object, *, default: bool = False) -> bool:
    """Safely convert value to boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"true", "1", "yes", "on"}
    return bool(value) if value is not None else default


# =============================================================================
# DICTIONARY UTILITIES
# =============================================================================


def extract_dict_value(data: dict[str, object], key: str, default: object = None) -> object:
    """Safely extract value from dictionary."""
    return data.get(key, default)


def filter_sensitive_data(data: dict[str, object]) -> dict[str, object]:
    """Filter out sensitive data from dictionary."""
    sensitive_keys = {"password", "secret", "token", "key", "hash"}

    filtered: dict[str, object] = {}
    for key, value in data.items():
        if key.lower() in sensitive_keys:
            filtered[key] = "[REDACTED]"
        else:
            filtered[key] = value

    return filtered


# =============================================================================
# ERROR HANDLING UTILITIES
# =============================================================================


def create_error_result(message: str, error_code: str = "AUTH_ERROR") -> FlextResult[None]:
    """Create a standardized error result."""
    return FlextResult.fail(f"[{error_code}] {message}")


def handle_exception(e: Exception, operation: str = "operation") -> FlextResult[None]:
    """Handle exception and return standardized error result."""
    return FlextResult.fail(f"Failed to {operation}: {e}")


# =============================================================================
# EXPORTS - Clean utilities API
# =============================================================================

__all__: list[str] = [
    "add_hours_to_now",
    "add_minutes_to_now",
    # Error handling utilities
    "create_error_result",
    # Dictionary utilities
    "extract_dict_value",
    "filter_sensitive_data",
    "generate_secure_password",
    # String utilities
    "generate_secure_token",
    # Time utilities
    "get_utc_now",
    "handle_exception",
    "is_expired",
    "is_strong_password",
    # Validation utilities
    "is_valid_email_format",
    "mask_sensitive_data",
    "safe_bool",
    "safe_int",
    # Conversion utilities
    "safe_str",
    "sanitize_input",
]
