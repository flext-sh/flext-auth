"""FLEXT Auth Mixins - Single unified class following FLEXT standards.

Common validation and factory patterns for Auth operations.
Single FlextAuthMixins class with nested mixin subclasses following FLEXT pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable

from flext_auth.constants import FlextAuthConstants
from flext_core import FlextMixins, FlextResult, T


class FlextAuthMixins(FlextMixins):
    """Single unified Auth mixins class following FLEXT standards.

    Contains all mixin subclasses for Auth domain operations.
    Follows FLEXT pattern: one class per module with nested subclasses.
    """

    # =========================================================================
    # VALIDATION MIXIN - Common validation utilities
    # =========================================================================

    class ValidationMixin:
        """Mixin providing common validation utilities for Auth classes.

        Contains reusable validation methods to eliminate duplication
        across Auth models and config classes.
        """

        @staticmethod
        def validate_not_empty(field_name: str, field_value: str) -> FlextResult[None]:
            """Validate that a field is not empty or whitespace.

            Args:
                field_name: Name of the field for error messages
                field_value: String value to validate

            Returns:
                FlextResult[None]: Success or failure result

            """
            if not field_value or not field_value.strip():
                return FlextResult[None].fail(f"{field_name} cannot be empty")
            return FlextResult[None].ok(None)

        @staticmethod
        def validate_email_format(email: str) -> FlextResult[str]:
            """Validate email format using regex.

            Args:
                email: Email string to validate

            Returns:
                FlextResult[str]: Success with validated email or failure result

            """
            if not email or not email.strip():
                return FlextResult[str].fail("Email cannot be empty")

            email = email.strip()
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, email):
                return FlextResult[str].fail("Invalid email format")

            return FlextResult[str].ok(email)

        @staticmethod
        def validate_password_strength(password: str) -> FlextResult[str]:
            """Validate password strength requirements.

            Args:
                password: Password string to validate

            Returns:
                FlextResult[str]: Success with validated password or failure result

            """
            if not password:
                return FlextResult[str].fail("Password cannot be empty")

            if len(password) < FlextAuthConstants.MIN_PASSWORD_LENGTH:
                return FlextResult[str].fail(
                    f"Password must be at least {FlextAuthConstants.MIN_PASSWORD_LENGTH} characters"
                )

            if len(password) > FlextAuthConstants.MAX_PASSWORD_LENGTH:
                return FlextResult[str].fail(
                    f"Password must be no more than {FlextAuthConstants.MAX_PASSWORD_LENGTH} characters"
                )

            # Check for at least one uppercase, lowercase, digit, and special character
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
                FlextResult[str]: Success with validated username or failure result

            """
            if not username or not username.strip():
                return FlextResult[str].fail("Username cannot be empty")

            username = username.strip()

            if len(username) < FlextAuthConstants.MIN_USERNAME_LENGTH:
                return FlextResult[str].fail(
                    f"Username must be at least {FlextAuthConstants.MIN_USERNAME_LENGTH} characters"
                )

            if len(username) > FlextAuthConstants.MAX_USERNAME_LENGTH:
                return FlextResult[str].fail(
                    f"Username must be no more than {FlextAuthConstants.MAX_USERNAME_LENGTH} characters"
                )

            # Check for valid characters (alphanumeric, underscore, hyphen)
            if not re.match(r"^[a-zA-Z0-9_-]+$", username):
                return FlextResult[str].fail(
                    "Username can only contain letters, numbers, underscores, and hyphens"
                )

            return FlextResult[str].ok(username)

        @staticmethod
        def validate_token_format(token: str) -> FlextResult[str]:
            """Validate token format.

            Args:
                token: Token string to validate

            Returns:
                FlextResult[str]: Success with validated token or failure result

            """
            if not token or not token.strip():
                return FlextResult[str].fail("Token cannot be empty")

            token = token.strip()

            if len(token) < FlextAuthConstants.MIN_TOKEN_LENGTH:
                return FlextResult[str].fail(
                    f"Token must be at least {FlextAuthConstants.MIN_TOKEN_LENGTH} characters"
                )

            return FlextResult[str].ok(token)

        @staticmethod
        def validate_role_format(role: str) -> FlextResult[str]:
            """Validate role format.

            Args:
                role: Role string to validate

            Returns:
                FlextResult[str]: Success with validated role or failure result

            """
            if not role or not role.strip():
                return FlextResult[str].fail("Role cannot be empty")

            role = role.strip()

            valid_roles = ["REDACTED_LDAP_BIND_PASSWORD", "user", "moderator", "guest"]
            if role not in valid_roles:
                return FlextResult[str].fail(
                    f"Invalid role. Valid roles: {valid_roles}"
                )

            return FlextResult[str].ok(role)

    # =========================================================================
    # FACTORY MIXIN - Common factory patterns
    # =========================================================================

    class FactoryMixin:
        """Mixin providing common factory patterns for Auth classes.

        Contains reusable factory methods and FlextResult creation patterns.
        """

        @staticmethod
        def create_with_validation(
            validation_func: Callable[[], T],
            error_context: str = "validation",
        ) -> FlextResult[T]:
            """Generic factory method with validation.

            Args:
                validation_func: Function that creates and validates the instance
                error_context: Context string for error messages

            Returns:
                FlextResult[T]: Success or failure result

            """
            try:
                instance = validation_func()
                return FlextResult[T].ok(instance)
            except ValueError as e:
                return FlextResult[T].fail(str(e))
            except Exception as e:
                return FlextResult[T].fail(f"{error_context} error: {e}")

        @staticmethod
        def create_flext_result_ok(data: T) -> FlextResult[T]:
            """Create successful FlextResult.

            Args:
                data: Data to wrap in success result

            Returns:
                FlextResult[T]: Success result

            """
            return FlextResult[T].ok(data)

        @staticmethod
        def create_flext_result_fail(
            error: str,
        ) -> FlextResult[object]:
            """Create failed FlextResult.

            Args:
                error: Error message

            Returns:
                FlextResult[object]: Failure result

            """
            return FlextResult[object].fail(error)

    # =========================================================================
    # BUSINESS RULES MIXIN - Common business rule validation patterns
    # =========================================================================

    class BusinessRulesMixin:
        """Mixin providing common business rule validation patterns for Auth classes.

        Contains reusable business rule validation methods.
        """

        @staticmethod
        def validate_user_creation_consistency(
            username: str, email: str, password: str, roles: list[str]
        ) -> FlextResult[None]:
            """Validate user creation business rules.

            Args:
                username: Username to validate
                email: Email to validate
                password: Password to validate
                roles: List of roles to validate

            Returns:
                FlextResult[None]: Validation result

            """
            # Validate username
            username_result = FlextAuthMixins.ValidationMixin.validate_username_format(
                username
            )
            if username_result.is_failure:
                return FlextResult[None].fail(
                    username_result.error or "Username validation failed"
                )

            # Validate email
            email_result = FlextAuthMixins.ValidationMixin.validate_email_format(email)
            if email_result.is_failure:
                return FlextResult[None].fail(
                    email_result.error or "Email validation failed"
                )

            # Validate password
            password_result = (
                FlextAuthMixins.ValidationMixin.validate_password_strength(password)
            )
            if password_result.is_failure:
                return FlextResult[None].fail(
                    password_result.error or "Password validation failed"
                )

            # Validate roles
            for role in roles:
                role_result = FlextAuthMixins.ValidationMixin.validate_role_format(role)
                if role_result.is_failure:
                    return FlextResult[None].fail(
                        role_result.error or f"Role validation failed for: {role}"
                    )

            return FlextResult[None].ok(None)

        @staticmethod
        def validate_authentication_consistency(
            username: str, password: str
        ) -> FlextResult[None]:
            """Validate authentication business rules.

            Args:
                username: Username to validate
                password: Password to validate

            Returns:
                FlextResult[None]: Validation result

            """
            # Validate username format
            username_result = FlextAuthMixins.ValidationMixin.validate_username_format(
                username
            )
            if username_result.is_failure:
                return FlextResult[None].fail(
                    username_result.error or "Username validation failed"
                )

            # Validate password is not empty
            if not password:
                return FlextResult[None].fail("Password cannot be empty")

            return FlextResult[None].ok(None)

        @staticmethod
        def validate_token_consistency(
            token: str, user_id: str | None = None
        ) -> FlextResult[None]:
            """Validate token business rules.

            Args:
                token: Token to validate
                user_id: Optional user ID to validate

            Returns:
                FlextResult[None]: Validation result

            """
            # Validate token format
            token_result = FlextAuthMixins.ValidationMixin.validate_token_format(token)
            if token_result.is_failure:
                return FlextResult[None].fail(
                    token_result.error or "Token validation failed"
                )

            # Validate user ID if provided
            if user_id is not None:
                user_id_result = FlextAuthMixins.ValidationMixin.validate_not_empty(
                    "User ID", user_id
                )
                if user_id_result.is_failure:
                    return FlextResult[None].fail(
                        user_id_result.error or "User ID validation failed"
                    )

            return FlextResult[None].ok(None)


# Aliases for nested mixins to match import expectations
FlextAuthValidationMixin = FlextAuthMixins.ValidationMixin
FlextAuthFactoryMixin = FlextAuthMixins.FactoryMixin
FlextAuthBusinessRulesMixin = FlextAuthMixins.BusinessRulesMixin

__all__ = [
    "FlextAuthBusinessRulesMixin",
    "FlextAuthFactoryMixin",
    "FlextAuthMixins",
    "FlextAuthValidationMixin",
]
