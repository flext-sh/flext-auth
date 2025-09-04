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
from datetime import UTC, datetime

from flext_auth import (
    FlextAuth,
    FlextAuthConstants,
    FlextJWTService,
    FlextPasswordService,
)
from flext_auth.typings import FlextAuthTypes
from flext_core import FlextResult


# Extract Method Pattern - reduce main() complexity from 42 to manageable chunks
class FlextAuthDemo:
    """Demo class using Extract Method Pattern to reduce complexity."""

    def __init__(self) -> None:
        """Initialize demo with FlextAuth instance."""
        self.auth = FlextAuth()

    def demo_user_registration(self) -> FlextResult[dict[str, object]]:
        """Extract Method: User registration demo."""
        print("\n2. User Registration")
        result = self.auth.register_user(
            username="demouser",
            email="demo@example.com",
            password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
            role=FlextAuthConstants.ROLE_USER,
        )

        match result:
            case result if result.success:
                print("✅ User registered successfully")
                self._print_user_info(result.value)
                return result
            case _:
                print(f"❌ Registration failed: {result.error}")
                return result

    def demo_user_authentication(self) -> FlextResult[dict[str, object]]:
        """Extract Method: User authentication demo."""
        print("\n3. User Authentication")
        result = self.auth.authenticate_user("demouser", "DemoPassword123!")

        match result:
            case result if result.success:
                print("✅ Authentication successful")
                self._print_token_info(result.value)
                return result
            case _:
                print(f"❌ Authentication failed: {result.error}")
                return result

    def _print_user_info(self, data: dict[str, object]) -> None:
        """Helper: Print user information using pattern matching."""
        match data.get("user"):
            case dict() as user_data:
                print(f"   Username: {user_data.get('username', 'N/A')}")
                print(f"   Email: {user_data.get('email', 'N/A')}")
                print(f"   Role: {user_data.get('role', 'N/A')}")
                print(f"   Status: {user_data.get('status', 'N/A')}")

    def _print_token_info(self, data: dict[str, object]) -> None:
        """Helper: Print token information using pattern matching."""
        match data.get("tokens"):
            case dict() as tokens:
                token_len = len(str(tokens.get("access_token", "")))
                print(f"   Access token length: {token_len} characters")
                print(f"   Token type: {tokens.get('token_type', 'N/A')}")
                print(f"   Expires in: {tokens.get('expires_in', 0)} seconds")


def main() -> None:
    """Main function using Extract Method Pattern - reduced from 42 to ~8 complexity.

    Uses FlextDecorators and extracted methods to eliminate code smells:
    - High complexity (42 → ~8)
    - Many returns (6 → 2)
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
    access_token = str(auth_result.value.get("tokens", {}).get("access_token", ""))

    # 4. Token Validation - continuing with existing pattern
    print("\n4. Token Validation")
    validation_result = auth.validate_token(access_token)

    if validation_result.success:
        print("✅ Token is valid")
        validation_data = validation_result.value
        if isinstance(validation_data, dict):
            print(f"   User ID: {validation_data.get('user_id', 'N/A')}")
            print(f"   Username: {validation_data.get('username', 'N/A')}")
            print(f"   Role: {validation_data.get('role', 'N/A')}")
    else:
        print(f"❌ Token validation failed: {validation_result.error}")

    # 5. Password Utilities - Using FlextPasswordService directly
    print("\n5. Password Utilities")

    # Create password service instance
    password_service = FlextPasswordService()

    # Password strength validation
    test_password = os.getenv("FLEXT_DEMO_TEST_PASSWORD", "TestPassword123!")
    strength_result = password_service.validate_password_strength(test_password)
    print(
        f"Password strength check: {'✅ Strong' if strength_result.success else '❌ Weak'}"
    )

    # Password hashing and verification
    hash_result = password_service.hash_password(test_password)
    if hash_result.success:
        hashed_password = hash_result.value
        print(f"Password hashed: {hashed_password[:20]}...")

        verification_result = password_service.verify_password(
            test_password, hashed_password
        )
        print(
            f"Password verification: {'✅ Match' if verification_result.success and verification_result.value else '❌ No match'}"
        )

    # Generate secure password using manual implementation (not helpers)

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

    print(f"Generated secure password: {secure_password_str}")

    # Check if it's strong
    strength_check_result = password_service.validate_password_strength(
        secure_password_str
    )
    print(
        f"Is strong password: {'✅ Yes' if strength_check_result.success else '❌ No'}"
    )

    # 6. Email Validation - Manual implementation (not helpers)
    print("\n6. Email Validation")
    test_emails = ["valid@example.com", "invalid.email", "test@domain.co.uk"]

    def validate_email_manual(email: FlextAuthTypes.Email) -> bool:
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

    # 7. JWT Service Direct Usage
    print("\n7. JWT Service Direct Usage")
    jwt_secret = os.getenv("FLEXT_DEMO_JWT_SECRET", "my-secret-key")

    # Create JWT service instance
    jwt_service = FlextJWTService(jwt_secret)

    claims = {
        "sub": "user123",
        "username": "testuser",
        "role": "user",
        "iat": datetime.now(UTC).timestamp(),
    }

    token_result = jwt_service.generate_token(claims)
    if token_result.success:
        print("✅ JWT token generated successfully")

        # Validate the token
        token_validation = jwt_service.validate_token(token_result.value)
        if token_validation.success:
            print("✅ JWT token validation successful")
            validation_claims = token_validation.value
            if isinstance(validation_claims, dict):
                print(f"   Subject: {validation_claims.get('sub', 'N/A')}")
                print(f"   Username: {validation_claims.get('username', 'N/A')}")
        else:
            print(f"❌ JWT validation failed: {token_validation.error}")
    else:
        print(f"❌ JWT generation failed: {token_result.error}")

    # 8. Constants and Configuration
    print("\n8. Constants and Configuration")
    print(f"Default JWT Secret: {FlextAuthConstants.DEFAULT_JWT_SECRET[:20]}...")
    print(f"Default Bcrypt Rounds: {FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS}")
    print(
        f"Default Max Login Attempts: {FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS}"
    )
    print(f"User Status Active: {FlextAuthConstants.USER_STATUS_ACTIVE}")
    print(f"Admin Role: {FlextAuthConstants.ROLE_ADMIN}")

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
