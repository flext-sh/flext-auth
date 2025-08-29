"""FLEXT Auth Validation - Input validation and business rule enforcement.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_core import FlextConstants, FlextResult, FlextValidation

from flext_auth.constants import FlextAuthConstants

# =============================================================================
# VALIDATION CONSTANTS
# =============================================================================

# FlextConstants already imported above in main imports
MIN_USERNAME_LENGTH = FlextConstants.Auth.MIN_USERNAME_LENGTH
MAX_USERNAME_LENGTH = FlextConstants.Auth.MAX_USERNAME_LENGTH
MIN_PASSWORD_LENGTH = FlextConstants.Auth.MIN_PASSWORD_LENGTH
MAX_PASSWORD_LENGTH = FlextConstants.Auth.MAX_PASSWORD_LENGTH

# =============================================================================
# AUTHENTICATION VALIDATORS - Using flext-core directly
# =============================================================================


class FlextAuthValidators:
    """Authentication validators using flext-core patterns."""

    @staticmethod
    def validate_username(username: str) -> FlextResult[None]:
        """Validate username using flext-core validators."""
        if not FlextValidation.validate_non_empty_string_func(username):
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
    def validate_email(email: str) -> FlextResult[None]:
        """Validate email using flext-core validators."""
        if not re.match(FlextConstants.Patterns.EMAIL_PATTERN, email):
            return FlextResult[None].fail("Invalid email format")
        return FlextResult[None].ok(None)

    @staticmethod
    def validate_password(password: str) -> FlextResult[None]:
        """Validate password using flext-core validators."""
        if not FlextValidation.validate_non_empty_string_func(password):
            return FlextResult[None].fail("Password cannot be empty")

        if len(password) < MIN_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password must be at least {MIN_PASSWORD_LENGTH} characters",
            )

        if len(password) > MAX_PASSWORD_LENGTH:
            return FlextResult[None].fail(
                f"Password cannot exceed {MAX_PASSWORD_LENGTH} characters",
            )

        if not FlextAuthConstants.Authentication.PASSWORD_VALIDATION_REGEX.match(
            password,
        ):
            return FlextResult[None].fail(
                "Password must contain uppercase, lowercase, digit and special character",
            )

        return FlextResult[None].ok(None)

    @staticmethod
    def validate_user_id(user_id: str) -> FlextResult[None]:
        """Validate user ID using flext-core validators."""
        if not FlextValidation.validate_non_empty_string_func(user_id):
            return FlextResult[None].fail("User ID cannot be empty")
        return FlextResult[None].ok(None)


# =============================================================================
# EXPORTS - Clean validation API
# =============================================================================

__all__: list[str] = [
    "FlextAuthValidators",
]
