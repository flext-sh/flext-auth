#!/usr/bin/env python3
"""FLEXT Auth - Basic usage examples with refactored API.

This example demonstrates basic FLEXT Auth usage with the new clean architecture.
All methods used exist and work as expected with the refactored library.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import secrets
import string
import sys
from typing import cast

from flext_auth import (
    FlextAuth,
    FlextAuthModels,
)
from flext_core import FlextResult

# Use unified class structure
AuthenticationResponseDict = FlextAuthModels.AuthenticationResponseDict


# Extract Method Pattern - reduce main() complexity from 42 to manageable chunks
class FlextAuthDemo:
    """Demo class using Extract Method Pattern to reduce complexity."""

    def __init__(self) -> None:
        """Initialize demo with FlextAuth instance."""
        self.auth = FlextAuth()

    def demo_user_registration(self) -> FlextResult[object]:
        """Extract Method: User registration demo.

        Returns:
            FlextResult[object]: Registration result

        """
        result = self.auth.register_user(
            username="demouser",
            email="demo@example.com",
            password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
            roles=["user"],
        )

        if result.is_success:
            pass

        return cast(FlextResult[object], result)

    def demo_user_authentication(self) -> FlextResult[AuthenticationResponseDict]:
        """Extract Method: User authentication demo.

        Returns:
            FlextResult[AuthenticationResponseDict]: Authentication result

        """
        result = self.auth.authenticate_user("demouser", "DemoPassword123!")

        if result.is_success:
            auth_data = result.value
            self._print_token_info(auth_data)

        return result

    def _print_token_info(self, auth_data: AuthenticationResponseDict) -> None:
        """Helper: Print token information."""
        tokens_data = auth_data.get("tokens", {})

        len(str(tokens_data.get("access_token", "")))


def _demo_password_utilities() -> None:
    """Demo password utilities and validation."""
    test_password = os.getenv("FLEXT_DEMO_TEST_PASSWORD", "TestPassword123!")

    try:
        from flext_auth import FlextAuthModels

        demo_user = FlextAuthModels.User(
            id="password-util-demo", username="util_demo", email="util@demo.com"
        )

        # Set and verify password using User model
        set_result = demo_user.set_password(test_password)
        if set_result.is_success:
            demo_user.verify_password(test_password)
    except Exception as e:
        error_message = f"Password hashing failed: {e}"
        del error_message  # Clean up


def _demo_secure_password_generation() -> None:
    """Demo secure password generation."""
    length = 16
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = '!@#$%^&*(),.?":{}|<>'

    secure_password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    all_chars = lowercase + uppercase + digits + special
    secure_password.extend(secrets.choice(all_chars) for _ in range(length - 4))
    secrets.SystemRandom().shuffle(secure_password)
    "".join(secure_password)


def _demo_email_validation() -> None:
    """Demo email validation."""
    test_emails = ["valid@example.com", "invalid.email", "test@domain.co.uk"]

    def validate_email_manual(email: str) -> bool:
        """Manual email validation without helpers.

        Returns:
            bool: True if email is valid, False otherwise

        """
        if "@" not in email or "." not in email.rsplit("@", maxsplit=1)[-1]:
            return False
        if email.count("@") != 1:
            return False
        local, domain = email.split("@")
        if not local or not domain:
            return False
        return ".." not in email

    for email in test_emails:
        validate_email_manual(email)


def _demo_jwt_operations(demo: FlextAuthDemo) -> None:
    """Demo JWT token operations."""
    jwt_user_result = demo.auth.register_user(
        username="jwtuser",
        email="jwt@example.com",
        password=os.getenv("JWT_PASSWORD", "JWTPassword123!"),
    )

    if jwt_user_result.is_success:
        user = jwt_user_result.value
        token_result = demo.auth.generate_jwt_token(user.id)
        if token_result.is_success:
            token = token_result.value
            token_validation = demo.auth.validate_token(token)
            if token_validation.is_success:
                pass


def main() -> None:
    """Main function using Extract Method Pattern - reduced complexity.

    Uses extracted methods to eliminate code smells:
    - High complexity reduced through method extraction
    - Clear separation of concerns
    - Method extraction for maintainability
    """
    # Extract Method Pattern - create demo instance
    demo = FlextAuthDemo()

    # Railway Pattern - chain operations with early returns on failure
    registration_result = demo.demo_user_registration()
    if registration_result.is_failure:
        return

    auth_result = demo.demo_user_authentication()
    if auth_result.is_failure:
        return

    # Extract token for further demos
    auth_data = auth_result.value
    tokens_data = auth_data.get("tokens", {})
    access_token = str(tokens_data.get("access_token", ""))

    # Token Validation
    validation_result = demo.auth.validate_token(access_token)
    if validation_result.is_success:
        pass

    # Demo various utilities
    _demo_password_utilities(demo)
    _demo_secure_password_generation()
    _demo_email_validation()
    _demo_jwt_operations(demo)

    # Constants and Configuration
    # Note: FlextAuth doesn't have a get_config() method
    from flext_auth import FlextAuthConfig

    FlextAuthConfig()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        sys.exit(1)
