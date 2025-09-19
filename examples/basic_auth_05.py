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
    auth: FlextAuth = FlextAuth()

    try:
        hashed = auth.hash_password(password)

        # Verify password
        auth.verify_password(password, hashed)
    except Exception as e:
        # Handle password verification error
        error_message = f"Password verification failed: {e}"
        # In production, this would be logged properly
        del error_message  # Clean up

    # 2. JWT Token Example using FlextAuth
    # Register user first
    user_result = auth.register_user(
        username="tokenuser",
        email="token@example.com",
        password=os.getenv("TOKEN_PASSWORD", "TokenPassword123!"),
    )

    if user_result.is_success:
        user = user_result.value

        # Generate JWT token
        token_result = auth.generate_jwt_token(user.id)
        if token_result.is_success:
            token = token_result.value

            # Validate token
            validation_result = auth.validate_token(token)
            if validation_result.is_success:
                pass

    # 3. Quick Start Example
    flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

    # 4. FlextAuth Class Example with proper error handling
    demo_auth: FlextAuth = FlextAuth()

    # Register user
    user_reg_result = demo_auth.register_user(
        username="demouser",
        email="demo@example.com",
        password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
    )

    if user_reg_result.is_success:
        # Try to authenticate
        auth_result = demo_auth.authenticate_user(
            "demouser",
            os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
        )

        if auth_result.is_success:
            auth_data = auth_result.value
            auth_data.get("session_id")
            auth_data.get("jwt_token")


if __name__ == "__main__":
    main()
