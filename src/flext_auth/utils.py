"""FLEXT Auth Utils - Single FlextAuthUtils class following Flext[Area][Module] pattern.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module implements the Flext[Area][Module] pattern with a single FlextAuthUtils
class that consolidates ALL authentication utility functionality. It follows FLEXT
architectural standards by providing all utility methods within a single class.

"""

from __future__ import annotations

import secrets
import string
from datetime import UTC, datetime, timedelta

from flext_core import FlextResult

from .typings import FlextAuthValidationResultType


class FlextAuthUtils:
    """Single authentication utilities class following Flext[Area][Module] pattern.

    This class consolidates ALL authentication utility functionality that was previously
    scattered across multiple utility classes. Following FLEXT architectural standards,
    all utility methods are now available through a single class interface.

    All methods are static since they are utilities that don't require instance state.
    This maintains compatibility with existing usage patterns while providing a unified
    interface following the Flext[Area][Module] architectural pattern.

    Example:
        Token generation:

        >>> token = FlextAuthUtils.generate_secure_token(32)
        >>> api_key = FlextAuthUtils.generate_api_key("auth", 24)

        Password utilities:

        >>> password = FlextAuthUtils.generate_secure_password(16)
        >>> is_strong = FlextAuthUtils.is_strong_password(password)
        >>> validation = FlextAuthUtils.validate_password_strength(password)

        Time operations:

        >>> now = FlextAuthUtils.get_utc_now()
        >>> future = FlextAuthUtils.add_minutes_to_now(30)

        Data utilities:

        >>> masked = FlextAuthUtils.mask_sensitive_data("secret123", 2)
        >>> filtered = FlextAuthUtils.filter_sensitive_data({"password": "secret"})

    """

    # =============================================================================
    # CONSTANTS - Centralized constants for all utility methods
    # =============================================================================

    MIN_PASSWORD_LENGTH = 8
    DEFAULT_TOKEN_LENGTH = 32
    DEFAULT_PASSWORD_LENGTH = 16
    DEFAULT_VISIBLE_CHARS = 4

    # =============================================================================
    # TOKEN UTILITIES - Methods from FlextAuthTokenUtils
    # =============================================================================

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a cryptographically secure random token."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_api_key(prefix: str = "fa", length: int = 32) -> str:
        """Generate API key with prefix."""
        token = secrets.token_urlsafe(length)
        return f"{prefix}_{token}"

    # =============================================================================
    # PASSWORD UTILITIES - Methods from FlextAuthPasswordUtils
    # =============================================================================

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate a secure random password with mixed characters."""
        length = max(length, FlextAuthUtils.MIN_PASSWORD_LENGTH)

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

    @staticmethod
    def is_strong_password(password: str) -> bool:
        """Check if password meets basic strength requirements."""
        if len(password) < FlextAuthUtils.MIN_PASSWORD_LENGTH:
            return False

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in "!@#$%^&*()_+-=" for c in password)

        return has_upper and has_lower and has_digit and has_symbol

    @staticmethod
    def validate_password_strength(password: str) -> FlextAuthValidationResultType:
        """Validate password strength and return detailed result."""
        errors: list[str] = []
        score = 0

        if len(password) < FlextAuthUtils.MIN_PASSWORD_LENGTH:
            errors.append("Password must be at least 8 characters long")
        else:
            score += 1

        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        else:
            score += 1

        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        else:
            score += 1

        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        else:
            score += 1

        if not any(c in "!@#$%^&*()_+-=" for c in password):
            errors.append("Password must contain at least one special character")
        else:
            score += 1

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": [],
            "score": score,
        }

    # =============================================================================
    # DATA UTILITIES - Methods from FlextAuthDataUtils
    # =============================================================================

    @staticmethod
    def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
        """Mask sensitive data showing only first few characters."""
        if len(data) <= visible_chars:
            return "*" * len(data)
        return data[:visible_chars] + "*" * (len(data) - visible_chars)

    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize input string by trimming whitespace."""
        return input_str.strip()

    # =============================================================================
    # TIME UTILITIES - Methods from FlextAuthTimeUtils
    # =============================================================================

    @staticmethod
    def get_utc_now() -> datetime:
        """Get current UTC datetime."""
        return datetime.now(UTC)

    @staticmethod
    def is_expired(expires_at: datetime) -> bool:
        """Check if datetime is in the past."""
        return FlextAuthUtils.get_utc_now() >= expires_at

    @staticmethod
    def add_minutes_to_now(minutes: int) -> datetime:
        """Add minutes to current UTC time."""
        return FlextAuthUtils.get_utc_now() + timedelta(minutes=minutes)

    @staticmethod
    def add_hours_to_now(hours: int) -> datetime:
        """Add hours to current UTC time."""
        return FlextAuthUtils.get_utc_now() + timedelta(hours=hours)

    @staticmethod
    def add_days_to_now(days: int) -> datetime:
        """Add days to current UTC time."""
        return FlextAuthUtils.get_utc_now() + timedelta(days=days)

    # =============================================================================
    # VALIDATION UTILITIES - Methods from FlextAuthValidationUtils
    # =============================================================================

    @staticmethod
    def is_valid_email_format(email: str) -> bool:
        """Validate basic email format."""
        return "@" in email and "." in email.rsplit("@", maxsplit=1)[-1]

    # =============================================================================
    # CONVERSION UTILITIES - Methods from FlextAuthConversionUtils
    # =============================================================================

    @staticmethod
    def safe_str(value: object) -> str:
        """Safely convert value to string."""
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def safe_int(value: object, default: int = 0) -> int:
        """Safely convert value to integer."""
        try:
            return int(str(value)) if value is not None else default
        except (ValueError, TypeError):
            return default

    @staticmethod
    def safe_bool(value: object, *, default: bool = False) -> bool:
        """Safely convert value to boolean."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"true", "1", "yes", "on"}
        return bool(value) if value is not None else default

    # =============================================================================
    # DICTIONARY UTILITIES - Methods from FlextAuthDictUtils
    # =============================================================================

    @staticmethod
    def extract_dict_value(
        data: dict[str, object],
        key: str,
        default: object = None,
    ) -> object:
        """Safely extract value from dictionary."""
        return data.get(key, default)

    @staticmethod
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
    # ERROR UTILITIES - Methods from FlextAuthErrorUtils
    # =============================================================================

    @staticmethod
    def create_error_result(
        message: str,
        error_code: str = "AUTH_ERROR",
    ) -> FlextResult[None]:
        """Create a standardized error result."""
        return FlextResult[None].fail(f"[{error_code}] {message}")

    @staticmethod
    def handle_exception(
        e: Exception,
        operation: str = "operation",
    ) -> FlextResult[None]:
        """Handle exception and return standardized error result."""
        return FlextResult[None].fail(f"Failed to {operation}: {e}")


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Legacy function aliases to class methods
# =============================================================================

# Legacy functions that delegate to FlextAuthUtils methods for backward compatibility
def generate_secure_password(length: int = 16) -> str:
    """Generate secure password - delegates to FlextAuthUtils (legacy function)."""
    return FlextAuthUtils.generate_secure_password(length)


def generate_secure_token(length: int = 32) -> str:
    """Generate secure token - delegates to FlextAuthUtils (legacy function)."""
    return FlextAuthUtils.generate_secure_token(length)


def get_utc_now() -> datetime:
    """Get UTC now - delegates to FlextAuthUtils (legacy function)."""
    return FlextAuthUtils.get_utc_now()


def is_strong_password(password: str) -> bool:
    """Check password strength - delegates to FlextAuthUtils (legacy function)."""
    return FlextAuthUtils.is_strong_password(password)


def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """Mask sensitive data - delegates to FlextAuthUtils (legacy function)."""
    return FlextAuthUtils.mask_sensitive_data(data, visible_chars)


# Legacy class aliases for backward compatibility
# All methods are now available through FlextAuthUtils, but these aliases maintain compatibility
FlextAuthTokenUtils = FlextAuthUtils  # All token methods available through FlextAuthUtils
FlextAuthPasswordUtils = FlextAuthUtils  # All password methods available through FlextAuthUtils
FlextAuthDataUtils = FlextAuthUtils  # All data methods available through FlextAuthUtils
FlextAuthTimeUtils = FlextAuthUtils  # All time methods available through FlextAuthUtils
FlextAuthValidationUtils = FlextAuthUtils  # All validation methods available through FlextAuthUtils
FlextAuthConversionUtils = FlextAuthUtils  # All conversion methods available through FlextAuthUtils
FlextAuthDictUtils = FlextAuthUtils  # All dict methods available through FlextAuthUtils
FlextAuthErrorUtils = FlextAuthUtils  # All error methods available through FlextAuthUtils

# =============================================================================
# EXPORTS - Single class with legacy compatibility aliases
# =============================================================================

__all__ = [
    "FlextAuthConversionUtils",  # → FlextAuthUtils (all conversion methods)
    "FlextAuthDataUtils",       # → FlextAuthUtils (all data methods)
    "FlextAuthDictUtils",       # → FlextAuthUtils (all dict methods)
    "FlextAuthErrorUtils",      # → FlextAuthUtils (all error methods)
    "FlextAuthPasswordUtils",   # → FlextAuthUtils (all password methods)
    "FlextAuthTimeUtils",       # → FlextAuthUtils (all time methods)
    # =============================================================================
    # LEGACY COMPATIBILITY ALIASES - Backward compatibility class aliases
    # =============================================================================
    "FlextAuthTokenUtils",      # → FlextAuthUtils (all token methods)
    "FlextAuthUtils",  # 🎯 MAIN CLASS: Single class following Flext[Area][Module] pattern
    "FlextAuthValidationUtils",  # → FlextAuthUtils (all validation methods)
    # =============================================================================
    # LEGACY COMPATIBILITY FUNCTIONS - Backward compatibility function aliases
    # =============================================================================
    "generate_secure_password",  # → FlextAuthUtils.generate_secure_password()
    "generate_secure_token",    # → FlextAuthUtils.generate_secure_token()
    "get_utc_now",              # → FlextAuthUtils.get_utc_now()
    "is_strong_password",       # → FlextAuthUtils.is_strong_password()
    "mask_sensitive_data",      # → FlextAuthUtils.mask_sensitive_data()
]
