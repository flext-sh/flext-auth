"""FLEXT Auth Mixins - Validation utilities for models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_core import r, x

from flext_auth.constants import FlextAuthConstants

# Constants for validation
MAX_USERNAME_LENGTH = 255


class FlextAuthMixins(x):
    """Auth mixins class with validation utilities extending flext-core mixins."""

    class ValidationMixin(x):
        """Validation utilities for Auth domain."""

        @staticmethod
        def validate_password_strength(password: str) -> r[str]:
            """Validate password strength.

            Args:
            password: Password string to validate

            Returns:
            r[str]: Success with validated password or failure

            """
            if not password:
                return r[str].fail("Password cannot be empty")

            if len(password) < FlextAuthConstants.CREDENTIAL_MIN_LENGTH:
                return r[str].fail(
                    f"Password must be at least {FlextAuthConstants.CREDENTIAL_MIN_LENGTH} characters"
                )

            if len(password) > FlextAuthConstants.CREDENTIAL_MAX_LENGTH:
                return r[str].fail(
                    f"Password must be no more than {128} characters"
                )

            # Check for password complexity
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

            if not (has_upper and has_lower and has_digit and has_special):
                return r[str].fail(
                    "Password must contain at least one uppercase letter, lowercase letter, digit, and special character"
                )

            return r[str].ok(password)

        @staticmethod
        def validate_username_format(username: str) -> r[str]:
            """Validate username format.

            Args:
            username: Username string to validate

            Returns:
            r[str]: Success with validated username or failure

            """
            if not username or not username.strip():
                return r[str].fail("Username cannot be empty")

            username = username.strip()

            if len(username) < 1:
                return r[str].fail(
                    f"Username must be at least {1} characters"
                )

            if len(username) > MAX_USERNAME_LENGTH:
                return r[str].fail(
                    f"Username must be no more than {MAX_USERNAME_LENGTH} characters"
                )  # MAX_USERNAME_LENGTH = 255

            # Check for valid characters
            if not re.match(r"^[a-zA-Z0-9_-]+$", username):
                return r[str].fail(
                    "Username can only contain letters, numbers, underscores, and hyphens"
                )

            return r[str].ok(username)


__all__ = ["FlextAuthMixins"]
