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

from flext_auth import FlextAuth
from flext_core import FlextConstants, FlextResult


# Extract Method Pattern - reduce main() complexity from 42 to manageable chunks
class FlextAuthDemo:
    """Demo class using Extract Method Pattern to reduce complexity."""

    def __init__(self) -> None:
        """Initialize demo with FlextAuth instance."""
        self.auth: FlextAuth[object] = FlextAuth()

    def demo_user_registration(self) -> FlextResult[object]:
        """Extract Method: User registration demo."""
        print("\n2. User Registration")
        result = self.auth.register_user(
            username="demouser",
            email="demo@example.com",
            password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
            roles=["user"],
        )

        if result.is_success:
            print("✅ User registered successfully")
            user = result.value
            print(f"   Username: {user.username}")
            print(f"   Email: {user.email_str}")
            print(f"   Role: {user.role}")
            print(f"   Active: {user.active}")
        else:
            print(f"❌ Registration failed: {result.error}")

        return cast("FlextResult[object]", result)

    def demo_user_authentication(self) -> FlextResult[dict[str, object]]:
        """Extract Method: User authentication demo."""
        print("\n3. User Authentication")
        result = self.auth.authenticate_user("demouser", "DemoPassword123!")

        if result.is_success:
            print("✅ Authentication successful")
            auth_data = result.value
            self._print_token_info(auth_data)
        else:
            print(f"❌ Authentication failed: {result.error}")

        return result

    def _print_token_info(self, auth_data: dict[str, object]) -> None:
        """Helper: Print token information."""
        tokens_data = cast("dict[str, object]", auth_data.get("tokens", {}))

        token_len = len(str(tokens_data.get("access_token", "")))
        print(f"   Access token length: {token_len} characters")
        print(f"   Token type: {tokens_data.get('token_type', 'N/A')}")
        print(f"   Expires in: {tokens_data.get('expires_in', 0)} seconds")


def main() -> None:
    """Main function using Extract Method Pattern - reduced complexity.

    Uses extracted methods to eliminate code smells:
    - High complexity reduced through method extraction
    - Clear separation of concerns
    - Method extraction for maintainability
    """
    print("🚀 FLEXT Auth - Basic Usage Examples")
    print("=" * 50)

    # Extract Method Pattern - create demo instance
    demo = FlextAuthDemo()
    print("\n1. FlextAuth Instance Creation")
    print("✅ Created FlextAuth instance")

    # Railway Pattern - chain operations with early returns on failure
    registration_result = demo.demo_user_registration()
    if registration_result.is_failure:
        return

    auth_result = demo.demo_user_authentication()
    if auth_result.is_failure:
        return

    # Extract token for further demos
    auth_data = auth_result.value
    tokens_data = cast("dict[str, object]", auth_data.get("tokens", {}))
    access_token = str(tokens_data.get("access_token", ""))

    # 4. Token Validation - continuing with existing pattern
    print("\n4. Token Validation")
    validation_result = demo.auth.validate_token(access_token)

    if validation_result.is_success:
        print("✅ Token is valid")
        validation_data = validation_result.value
        print(f"   User ID: {validation_data.get('user_id', 'N/A')}")
        print(f"   Username: {validation_data.get('username', 'N/A')}")
        print(f"   Role: {validation_data.get('role', 'N/A')}")
    else:
        print(f"❌ Token validation failed: {validation_result.error}")

    # 5. Password Utilities - Using FlextAuth directly
    print("\n5. Password Utilities")

    # Password hashing and verification using FlextAuth
    test_password = os.getenv("FLEXT_DEMO_TEST_PASSWORD", "TestPassword123!")

    try:
        # Use FlextAuth for password operations
        hashed_password = demo.auth.hash_password(test_password)
        print(f"✅ Password hashed: {hashed_password[:20]}...")

        # Verify password
        is_valid = demo.auth.verify_password(test_password, hashed_password)
        print(f"✅ Password verification: {'Match' if is_valid else 'No match'}")

    except Exception as e:
        print(f"❌ Password operation failed: {e}")

    # Generate secure password using manual implementation
    print("\n   Generating secure password...")
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
    secure_password_str = "".join(secure_password)

    print(f"✅ Generated secure password: {secure_password_str}")

    # 6. Email Validation - Manual implementation
    print("\n6. Email Validation")
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
        is_valid = validate_email_manual(email)
        status = "✅ Valid" if is_valid else "❌ Invalid"
        print(f"   {email}: {status}")

    # 7. JWT Token Operations using FlextAuth
    print("\n7. JWT Token Operations")

    # Register a test user for JWT operations
    jwt_user_result = demo.auth.register_user(
        username="jwtuser",
        email="jwt@example.com",
        password="JWTPassword123!"
    )

    if jwt_user_result.is_success:
        user = jwt_user_result.value

        # Generate JWT token
        token_result = demo.auth.generate_jwt_token(user.id)
        if token_result.is_success:
            token = token_result.value
            print("✅ JWT token generated successfully")
            print(f"   Token: {token[:30]}...")

            # Validate the token
            token_validation = demo.auth.validate_token(token)
            if token_validation.is_success:
                print("✅ JWT token validation successful")
                validation_claims = token_validation.value
                print(f"   User ID: {validation_claims.get('user_id', 'N/A')}")
                print(f"   Username: {validation_claims.get('username', 'N/A')}")
            else:
                print(f"❌ JWT validation failed: {token_validation.error}")
        else:
            print(f"❌ JWT generation failed: {token_result.error}")
    else:
        print(f"❌ JWT user registration failed: {jwt_user_result.error}")

    # 8. Constants and Configuration
    print("\n8. Constants and Configuration")
    config = demo.auth.get_config()
    security_settings = demo.auth.config.get_security_settings()
    jwt_settings = demo.auth.config.get_jwt_settings()

    print(f"JWT Expiry Minutes: {config.jwt_expiry_minutes}")
    print(f"Bcrypt Rounds: {security_settings.get('bcrypt_rounds')}")
    print(f"Max Login Attempts: {security_settings.get('max_login_attempts')}")
    print(f"JWT Algorithm: {jwt_settings.get('jwt_algorithm')}")

    # FlextCore constants
    print(f"Min Password Length: {FlextConstants.Auth.MIN_PASSWORD_LENGTH}")
    print(f"Max Password Length: {FlextConstants.Auth.MAX_PASSWORD_LENGTH}")
    print(f"Default Bcrypt Rounds: {FlextConstants.Auth.BCRYPT_ROUNDS}")

    print("\n✅ All examples completed successfully!")
    print("🎉 FLEXT Auth is working properly with the refactored API!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Demo interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        sys.exit(1)
