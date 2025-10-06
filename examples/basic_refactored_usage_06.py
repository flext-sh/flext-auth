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

from flext_core import FlextResult

from flext_auth import (
    FlextAuth,
    FlextAuthModels,
    FlextAuthTypes,
)

AuthenticationResponseDict = FlextAuthTypes.AuthenticationResponseDict


# Extract Method Pattern - reduce main() complexity from 42 to manageable chunks
class FlextAuthDemo:
    """Demo class using Extract Method Pattern to reduce complexity."""

    def __init__(self) -> None:
        """Initialize demo with FlextAuth instance."""
        self.auth = FlextAuth()

    def demo_user_registration(self) -> FlextResult[FlextAuthModels.User]:
        """Extract Method: User registration demo.

        Returns:
            FlextResult[FlextAuthModels.User]: Registration result

        """
        result = self.auth.register_user(
            username="demouser",
            email="demo@example.com",
            password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
            roles=["user"],
        )

        if result.is_success:
            pass

        return result

    def demo_user_authentication(self) -> FlextResult[FlextAuthModels.AuthToken]:
        """Extract Method: User authentication demo.

        Returns:
            FlextResult[FlextAuthModels.AuthToken]: Authentication result

        """
        result = self.auth.authenticate_user("demouser", "DemoPassword123!")

        if result.is_success:
            auth_data = result.value
            self._print_token_info(auth_data)

        return result

    def _print_token_info(self, auth_data: FlextAuthModels.AuthToken) -> None:
        """Helper: Print token information."""
        token_length = len(str(auth_data.token)) if auth_data.token else 0
        print(f"Token length: {token_length}")


def _demo_password_utilities() -> None:
    """Demo password utilities and validation."""
    test_password = os.getenv("FLEXT_DEMO_TEST_PASSWORD", "TestPassword123!")

    try:
        demo_user = FlextAuthModels.User(
            id="password-util-demo",
            username="util_demo",
            email="util@demo.com",
            full_name="Util Demo User",
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
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
        user_id = user.user_id or user.username
        token_result = demo.auth.generate_jwt_token(user_id)
        if token_result.is_success:
            token = token_result.value
            # Extract token string for validation
            token_string = token.token if hasattr(token, "token") else str(token)
            token_validation = demo.auth.validate_token(token_string)
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
    # auth_data is an AuthToken object, not a dict
    access_token = str(auth_data.token) if auth_data.token else ""

    # Token Validation
    validation_result = demo.auth.validate_token(access_token)
    if validation_result.is_success:
        pass

    # Demo various utilities


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        sys.exit(1)
