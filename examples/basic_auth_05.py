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

from flext_auth import FlextAuth, FlextAuthModels
from flext_auth.config import FlextAuthConfig


def main() -> None:
    """Demonstrate basic authentication functionality."""
    # 1. Password Hashing Example using User model
    # For demo purposes, we'll use a default password
    password = "SecurePassword123!"  # In production, this would come from secure config

    # Create a user with password
    user_creation_result = FlextAuthModels.User.create(
        username="demouser",
        email="demo@example.com",
        password=password,
    )

    if user_creation_result.is_failure:
        print(f"Failed to create user: {user_creation_result.error}")
        return

    user = user_creation_result.value

    # Demonstrate password operations
    print("=== Password Operations Demo ===")

    # Set password (this will hash it)
    set_result = user.set_password(password)
    if set_result.is_success:
        print("✓ Password set successfully")

        # Verify password
        verify_result = user.verify_password(password)
        if verify_result.is_success and verify_result.value:
            print("✓ Password verification successful")
        else:
            print("✗ Password verification failed")
    else:
        print(f"✗ Failed to set password: {set_result.error}")

    # 2. JWT Token Example
    print("\n=== JWT Token Demo ===")

    # Create authentication service
    auth_service = FlextAuth(
        config=FlextAuthConfig(
            jwt_auth_secret="demo-jwt-secret-key-for-examples-only-not-secure",  # nosec
            jwt_expiry_minutes=30,
            bcrypt_rounds=4,  # Fast for demo
        )
    )

    # Create user for token demo
    token_user_creation = FlextAuthModels.User.create(
        username="tokendemo",
        email="token@example.com",
        password="TokenPassword123!",  # Demo password for example
    )

    if token_user_creation.is_failure:
        print(f"Failed to create token demo user: {token_user_creation.error}")
        return

    # Authenticate user to get token
    auth_result = auth_service.authenticate_user("tokendemo", "TokenPassword123!")
    if auth_result.is_failure:
        print(f"Authentication failed: {auth_result.error}")
        return

    token = auth_result.value
    print(f"✓ Authentication successful, token: {token.token[:20]}...")

    # Validate token
    validation_result = auth_service.validate_token(token.token)
    if validation_result.is_success:
        print("✓ Token validation successful")
    else:
        print(f"✗ Token validation failed: {validation_result.error}")

    # Refresh token
    refresh_result = auth_service.refresh_token(token.token)
    if refresh_result.is_success:
        new_token = refresh_result.value
        print(f"✓ Token refresh successful, new token: {new_token.token[:20]}...")
    else:
        print(f"✗ Token refresh failed: {refresh_result.error}")

    # 3. User Management Example
    print("\n=== User Management Demo ===")

    # Create multiple users
    users_data = [
        (
            "user1",
            "user1@example.com",
            os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
        ),
        (
            "user2",
            "user2@example.com",
            os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
        ),
        (
            "REDACTED_LDAP_BIND_PASSWORD",
            "REDACTED_LDAP_BIND_PASSWORD@example.com",
            os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
        ),
    ]

    created_users = []
    for username, email, pwd in users_data:
        user_result = FlextAuthModels.User.create(
            username=username, email=email, password=pwd
        )
        if user_result.is_success:
            created_users.append(user_result.value)
            print(f"✓ Created user: {username}")
        else:
            print(f"✗ Failed to create user {username}: {user_result.error}")

    # Demonstrate user lookup
    lookup_result = FlextAuthModels.User.get_by_username("user1")
    if lookup_result.is_success:
        found_user = lookup_result.value
        print(f"✓ Found user by username: {found_user.username} ({found_user.email})")
    else:
        print(f"✗ User lookup failed: {lookup_result.error}")

    print("\n=== Demo Complete ===")
    print("This example demonstrates:")
    print("- Password hashing and verification")
    print("- JWT token creation, validation, and refresh")
    print("- User creation and lookup")
    print("- Basic authentication service usage")


if __name__ == "__main__":
    main()
