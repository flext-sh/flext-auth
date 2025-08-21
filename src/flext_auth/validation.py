"""FLEXT Auth Validation - Input validation and business rule enforcement.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_core import FlextResult
from flext_core.validation import FlextValidators

from flext_auth.auth_types import TEmail, TPassword, TUsername
from flext_auth.constants import FlextAuthConstants

# =============================================================================
# VALIDATION CONSTANTS
# =============================================================================

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50

# =============================================================================
# AUTHENTICATION VALIDATORS - Using flext-core directly
# =============================================================================


class FlextAuthValidators:
    """Authentication validators using flext-core patterns."""

    @staticmethod
    def validate_username(username: TUsername) -> FlextResult[None]:
        """Validate username using flext-core validators."""
        if not FlextValidators.is_non_empty_string(username):
            return FlextResult[None].fail("Username cannot be empty")

        if len(username) < MIN_USERNAME_LENGTH:
            return FlextResult[None].fail(
                f"Username must be at least {MIN_USERNAME_LENGTH} characters",
            )

        if len(username) > MAX_USERNAME_LENGTH:
            return FlextResult[None].fail(
                f"Username cannot exceed {MAX_USERNAME_LENGTH} characters",
            )

        if not re.match(FlextAuthConstants.Authentication.USERNAME_PATTERN, username):
            return FlextResult[None].fail("Username contains invalid characters")

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_email(email: TEmail) -> FlextResult[None]:
        """Validate email using flext-core validators."""
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, email):
            return FlextResult[None].fail("Invalid email format")
        return FlextResult[None].ok(None)

    @staticmethod
    def validate_password(password: TPassword) -> FlextResult[None]:
        """Validate password using flext-core validators."""
        if not FlextValidators.is_non_empty_string(password):
            return FlextResult[None].fail("Password cannot be empty")

        if len(password) < FlextAuthConstants.Authentication.MIN_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password must be at least {FlextAuthConstants.Authentication.MIN_PASSWORD_LENGTH} characters",
            )

        if len(password) > FlextAuthConstants.Authentication.MAX_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password cannot exceed {FlextAuthConstants.Authentication.MAX_PASSWORD_LENGTH} characters",
            )

        if not FlextAuthConstants.Authentication.PASSWORD_VALIDATION_REGEX.match(
            password
        ):
            return FlextResult[None].fail(
                "Password must contain uppercase, lowercase, digit and special character",
            )

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_user_id(user_id: str) -> FlextResult[None]:
        """Validate user ID using flext-core validators."""
        if not FlextValidators.is_non_empty_string(user_id):
            return FlextResult[None].fail("User ID cannot be empty")
        return FlextResult[None].ok(None)


# =============================================================================
# EXPORTS - Clean validation API
# =============================================================================

__all__: list[str] = [
    "FlextAuthValidators",
]
