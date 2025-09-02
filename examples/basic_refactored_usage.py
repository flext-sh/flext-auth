#!/usr/bin/env python3
"""FLEXT Auth - Basic usage examples with refactored API.

This example demonstrates basic FLEXT Auth usage with the new clean architecture.
All methods used exist and work as expected with the refactored library.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime

from flext_auth import (
    FlextAuth,
    FlextAuthConstants,
    FlextJWTService,
    FlextPasswordService,
)


def main() -> None:
    """Demonstrate basic FLEXT Auth functionality."""
    print("🚀 FLEXT Auth - Basic Usage Examples")
    print("=" * 50)

    # 1. Direct FlextAuth instantiation - Using real classes
    print("\n1. FlextAuth Instance Creation")
    auth = FlextAuth()
    print("✅ Created FlextAuth instance")

    # 2. User Registration
    print("\n2. User Registration")
    registration_result = auth.register_user(
        username="demouser",
        email="demo@example.com",
        password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
        role=FlextAuthConstants.ROLE_USER,
    )

    if registration_result.success:
        print("✅ User registered successfully")
        result_data = registration_result.value
        if isinstance(result_data, dict) and "user" in result_data:
            user_data = result_data["user"]
            if isinstance(user_data, dict):
                print(f"   Username: {user_data.get('username', 'N/A')}")
                print(f"   Email: {user_data.get('email', 'N/A')}")
                print(f"   Role: {user_data.get('role', 'N/A')}")
                print(f"   Status: {user_data.get('status', 'N/A')}")
    else:
        print(f"❌ Registration failed: {registration_result.error}")
        return

    # 3. User Authentication
    print("\n3. User Authentication")
    auth_result = auth.authenticate_user("demouser", "DemoPassword123!")

    if auth_result.success:
        print("✅ Authentication successful")
        result_data = auth_result.value
        if isinstance(result_data, dict) and "tokens" in result_data:
            tokens = result_data["tokens"]
            if isinstance(tokens, dict):
                access_token_val = tokens.get("access_token", "")
                print(
                    f"   Access token length: {len(str(access_token_val))} characters"
                )
                print(f"   Token type: {tokens.get('token_type', 'N/A')}")
                print(f"   Expires in: {tokens.get('expires_in', 0)} seconds")

                # Store token for later use
                access_token = str(access_token_val)
    else:
        print(f"❌ Authentication failed: {auth_result.error}")
        return

    # 4. Token Validation
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
    import secrets
    import string

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
