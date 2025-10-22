"""FLEXT Auth Mixins - Validation utilities for models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_core import FlextMixins, FlextResult

from flext_auth.constants import FlextAuthConstants

# Constants for validation
MAX_USERNAME_LENGTH = 255


class FlextAuthMixins(FlextMixins):
    """Auth mixins class with validation utilities extending flext-core mixins."""

    class ValidationMixin(FlextMixins):
        """Validation utilities for Auth domain."""

        @staticmethod
        def validate_password_strength(password: str) -> FlextResult[str]:
            """Validate password strength.

            Args:
            password: Password string to validate

            Returns:
            FlextResult[str]: Success with validated password or failure

            """
            if not password:
                return FlextResult[str].fail("Password cannot be empty")

            if len(password) < FlextAuthConstants.CREDENTIAL_MIN_LENGTH:
                return FlextResult[str].fail(
                    f"Password must be at least {FlextAuthConstants.CREDENTIAL_MIN_LENGTH} characters"
                )

            if len(password) > FlextAuthConstants.CREDENTIAL_MAX_LENGTH:
                return FlextResult[str].fail(
                    f"Password must be no more than {128} characters"
                )

            # Check for password complexity
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

            if not (has_upper and has_lower and has_digit and has_special):
                return FlextResult[str].fail(
                    "Password must contain at least one uppercase letter, lowercase letter, digit, and special character"
                )

            return FlextResult[str].ok(password)

        @staticmethod
        def validate_username_format(username: str) -> FlextResult[str]:
            """Validate username format.

            Args:
            username: Username string to validate

            Returns:
            FlextResult[str]: Success with validated username or failure

            """
            if not username or not username.strip():
                return FlextResult[str].fail("Username cannot be empty")

            username = username.strip()

            if len(username) < 1:
                return FlextResult[str].fail(
                    f"Username must be at least {1} characters"
                )

            if len(username) > MAX_USERNAME_LENGTH:
                return FlextResult[str].fail(
                    f"Username must be no more than {MAX_USERNAME_LENGTH} characters"
                )  # MAX_USERNAME_LENGTH = 255

            # Check for valid characters
            if not re.match(r"^[a-zA-Z0-9_-]+$", username):
                return FlextResult[str].fail(
                    "Username can only contain letters, numbers, underscores, and hyphens"
                )

            return FlextResult[str].ok(username)


__all__ = ["FlextAuthMixins"]
