"""Authentication validation using flext-core patterns.

Simplified validation eliminating duplication and leveraging flext-core's
validation patterns directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Use flext-core validation directly
from flext_core import FlextResult, FlextValidators

from flext_auth.constants import FlextAuthConstants

if TYPE_CHECKING:
    from flext_auth.auth_types import TEmail, TPassword, TUsername

# =============================================================================
# AUTHENTICATION VALIDATORS - Using flext-core directly
# =============================================================================


class FlextAuthValidators:
    """Authentication validators using flext-core patterns."""

    @staticmethod
    def validate_username(username: TUsername) -> FlextResult[None]:
        """Validate username using flext-core validators."""
        if not FlextValidators.is_non_empty_string(username):
            return FlextResult.fail("Username cannot be empty")

        if not FlextValidators.has_min_length(username, 3):
            return FlextResult.fail("Username must be at least 3 characters")

        if not FlextValidators.has_max_length(username, 50):
            return FlextResult.fail("Username cannot exceed 50 characters")

        if not FlextValidators.matches_pattern(
            username,
            FlextAuthConstants.USERNAME_PATTERN,
        ):
            return FlextResult.fail("Username contains invalid characters")

        return FlextResult.ok(None)

    @staticmethod
    def validate_email(email: TEmail) -> FlextResult[None]:
        """Validate email using flext-core validators."""
        if not FlextValidators.is_email(email):
            return FlextResult.fail("Invalid email format")
        return FlextResult.ok(None)

    @staticmethod
    def validate_password(password: TPassword) -> FlextResult[None]:
        """Validate password using flext-core validators."""
        if not FlextValidators.is_non_empty_string(password):
            return FlextResult.fail("Password cannot be empty")

        if not FlextValidators.has_min_length(
            password,
            FlextAuthConstants.MIN_PASSWORD_LENGTH,
        ):
            return FlextResult.fail(
                f"Password must be at least "
                f"{FlextAuthConstants.MIN_PASSWORD_LENGTH} characters",
            )

        if not FlextValidators.has_max_length(
            password,
            FlextAuthConstants.MAX_PASSWORD_LENGTH,
        ):
            return FlextResult.fail(
                f"Password cannot exceed "
                f"{FlextAuthConstants.MAX_PASSWORD_LENGTH} characters",
            )

        if not FlextValidators.matches_pattern(
            password,
            FlextAuthConstants.PASSWORD_VALIDATION_REGEX,
        ):
            return FlextResult.fail(
                "Password must contain uppercase, lowercase, digit and "
                "special character",
            )

        return FlextResult.ok(None)

    @staticmethod
    def validate_user_id(user_id: str) -> FlextResult[None]:
        """Validate user ID using flext-core validators."""
        if not FlextValidators.is_non_empty_string(user_id):
            return FlextResult.fail("User ID cannot be empty")
        return FlextResult.ok(None)


# =============================================================================
# EXPORTS - Clean validation API
# =============================================================================

__all__ = [
    "FlextAuthValidators",
]
