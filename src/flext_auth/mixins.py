"""FLEXT Auth Mixins - Validation utilities for models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_core import FlextCore

from flext_auth.constants import FlextAuthConstants


class FlextAuthMixins(FlextCore.Mixins):
    """Auth mixins class with validation utilities extending flext-core mixins."""

    class ValidationMixin(FlextCore.Mixins):
        """Validation utilities for Auth domain."""

        @staticmethod
        def validate_email_format(email: str) -> FlextCore.Result[str]:
            """Validate email format using flext-core validation.

            Args:
                email: Email string to validate

            Returns:
                FlextCore.Result[str]: Success with validated email or failure

            """
            # Use flext-core validation instead of custom regex
            return FlextCore.Utilities.Validation.validate_email(email)

        @staticmethod
        def validate_password_strength(password: str) -> FlextCore.Result[str]:
            """Validate password strength.

            Args:
                password: Password string to validate

            Returns:
                FlextCore.Result[str]: Success with validated password or failure

            """
            if not password:
                return FlextCore.Result[str].fail("Password cannot be empty")

            if len(password) < FlextAuthConstants.Credentials.Password.MIN_LENGTH:
                return FlextCore.Result[str].fail(
                    f"Password must be at least {FlextAuthConstants.Credentials.Password.MIN_LENGTH} characters"
                )

            if len(password) > FlextAuthConstants.Credentials.Password.MAX_LENGTH:
                return FlextCore.Result[str].fail(
                    f"Password must be no more than {FlextAuthConstants.Credentials.Password.MAX_LENGTH} characters"
                )

            # Check for password complexity
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

            if not (has_upper and has_lower and has_digit and has_special):
                return FlextCore.Result[str].fail(
                    "Password must contain at least one uppercase letter, lowercase letter, digit, and special character"
                )

            return FlextCore.Result[str].ok(password)

        @staticmethod
        def validate_username_format(username: str) -> FlextCore.Result[str]:
            """Validate username format.

            Args:
                username: Username string to validate

            Returns:
                FlextCore.Result[str]: Success with validated username or failure

            """
            if not username or not username.strip():
                return FlextCore.Result[str].fail("Username cannot be empty")

            username = username.strip()

            if len(username) < FlextAuthConstants.Credentials.Username.MIN_LENGTH:
                return FlextCore.Result[str].fail(
                    f"Username must be at least {FlextAuthConstants.Credentials.Username.MIN_LENGTH} characters"
                )

            if len(username) > FlextAuthConstants.Credentials.Username.MAX_LENGTH:
                return FlextCore.Result[str].fail(
                    f"Username must be no more than {FlextAuthConstants.Credentials.Username.MAX_LENGTH} characters"
                )

            # Check for valid characters
            if not re.match(r"^[a-zA-Z0-9_-]+$", username):
                return FlextCore.Result[str].fail(
                    "Username can only contain letters, numbers, underscores, and hyphens"
                )

            return FlextCore.Result[str].ok(username)


__all__ = ["FlextAuthMixins"]
