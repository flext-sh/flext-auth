#!/usr/bin/env python3
"""Basic Authentication Example.

Demonstrates the core flext-auth functionality:
- User registration and authentication
- JWT token generation and validation
- Password hashing and verification

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os

from flext_auth import FlextAuth, flext_auth_quick_start


def main() -> None:
    """Run basic authentication example."""
    # 1. Password Hashing Example using FlextAuth directly
    password = os.getenv("FLEXT_DEMO_PASSWORD", "SecurePassword123!")
    auth: FlextAuth[object] = FlextAuth()

    try:
        hashed = auth.hash_password(password)
        print(f"Password hashed successfully: {len(hashed)} chars")

        # Verify password
        is_valid = auth.verify_password(password, hashed)
        print(f"Password verification: {is_valid}")
    except Exception as e:
        print(f"Password operations failed: {e}")

    # 2. JWT Token Example using FlextAuth
    # Register user first
    user_result = auth.register_user(
        username="tokenuser",
        email="token@example.com",
        password="TokenPassword123!"
    )

    if user_result.is_success:
        user = user_result.value

        # Generate JWT token
        token_result = auth.generate_jwt_token(user.id)
        if token_result.is_success:
            token = token_result.value
            print(f"JWT token generated: {token[:30]}...")

            # Validate token
            validation_result = auth.validate_token(token)
            if validation_result.is_success:
                payload = validation_result.value
                print(f"JWT token valid for user: {payload.get('username', 'Unknown')}")
            else:
                print(f"Token validation failed: {validation_result.error}")
        else:
            print(f"Token generation failed: {token_result.error}")
    else:
        print(f"User registration failed: {user_result.error}")

    # 3. Quick Start Example
    flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    print("Quick start FlextAuth instance created")

    # 4. FlextAuth Class Example with proper error handling
    demo_auth: FlextAuth[object] = FlextAuth()

    # Register user
    user_reg_result = demo_auth.register_user(
        username="demouser",
        email="demo@example.com",
        password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
    )

    if user_reg_result.is_success:
        print(f"User registered: {user_reg_result.value.username}")

        # Try to authenticate
        auth_result = demo_auth.authenticate_user(
            "demouser", os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!")
        )

        if auth_result.is_success:
            print("Authentication successful with FlextAuth instance")
            auth_data = auth_result.value
            session_id = auth_data.get("session_id")
            jwt_token = auth_data.get("jwt_token")
            print(f"Session ID: {session_id}")
            print(f"JWT Token: {str(jwt_token)[:20]}...")
        else:
            print(f"Authentication failed: {auth_result.error}")
    else:
        print(f"User registration failed: {user_reg_result.error}")


if __name__ == "__main__":
    main()
