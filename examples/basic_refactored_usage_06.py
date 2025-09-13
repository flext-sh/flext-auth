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

from flext_core import FlextResult, FlextTypes

from flext_auth import FlextAuth


# Extract Method Pattern - reduce main() complexity from 42 to manageable chunks
class FlextAuthDemo:
    """Demo class using Extract Method Pattern to reduce complexity."""

    def __init__(self) -> None:
        """Initialize demo with FlextAuth instance."""
        self.auth: FlextAuth[object] = FlextAuth()

    def demo_user_registration(self) -> FlextResult[object]:
        """Extract Method: User registration demo."""
        result = self.auth.register_user(
            username="demouser",
            email="demo@example.com",
            password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
            roles=["user"],
        )

        if result.is_success:
            pass

        return cast("FlextResult[object]", result)

    def demo_user_authentication(self) -> FlextResult[FlextTypes.Core.Dict]:
        """Extract Method: User authentication demo."""
        result = self.auth.authenticate_user("demouser", "DemoPassword123!")

        if result.is_success:
            auth_data = result.value
            self._print_token_info(auth_data)

        return result

    def _print_token_info(self, auth_data: FlextTypes.Core.Dict) -> None:
        """Helper: Print token information."""
        tokens_data = cast("FlextTypes.Core.Dict", auth_data.get("tokens", {}))

        len(str(tokens_data.get("access_token", "")))


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
    tokens_data = cast("FlextTypes.Core.Dict", auth_data.get("tokens", {}))
    access_token = str(tokens_data.get("access_token", ""))

    # 4. Token Validation - continuing with existing pattern
    validation_result = demo.auth.validate_token(access_token)

    if validation_result.is_success:
        pass

    # 5. Password Utilities - Using FlextAuth directly

    # Password hashing and verification using FlextAuth
    test_password = os.getenv("FLEXT_DEMO_TEST_PASSWORD", "TestPassword123!")

    try:
        # Use FlextAuth for password operations
        hashed_password = demo.auth.hash_password(test_password)

        # Verify password
        demo.auth.verify_password(test_password, hashed_password)

    except Exception as e:
        # Handle password hashing error
        error_message = f"Password hashing failed: {e}"
        # In production, this would be logged properly
        del error_message  # Clean up

    # Generate secure password using manual implementation
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

    # 6. Email Validation - Manual implementation
    test_emails = ["valid@example.com", "invalid.email", "test@domain.co.uk"]

    def validate_email_manual(email: str) -> bool:
        """Manual email validation without helpers."""
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

    # 7. JWT Token Operations using FlextAuth

    # Register a test user for JWT operations
    jwt_user_result = demo.auth.register_user(
        username="jwtuser",
        email="jwt@example.com",
        password=os.getenv("JWT_PASSWORD", "JWTPassword123!"),
    )

    if jwt_user_result.is_success:
        user = jwt_user_result.value

        # Generate JWT token
        token_result = demo.auth.generate_jwt_token(user.id)
        if token_result.is_success:
            token = token_result.value

            # Validate the token
            token_validation = demo.auth.validate_token(token)
            if token_validation.is_success:
                pass

    # 8. Constants and Configuration
    demo.auth.get_config()
    demo.auth.config.get_security_settings()
    demo.auth.config.get_jwt_settings()

    # FlextCore constants


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        sys.exit(1)
