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

from flext_core import FlextContainer

from flext_auth import FlextAuth, FlextAuthModels
from flext_auth.config import FlextAuthConfig


def main() -> None:
    """Demonstrate basic authentication functionality."""
    # 1. User Creation Example
    # Create a user (password operations are handled by the auth service)
    user_creation_result = FlextAuthModels.User(
        username="demouser",
        email="demo@example.com",
    )

    if user_creation_result.is_failure:
        print(f"Failed to create user: {user_creation_result.error}")
        return

    user = user_creation_result.value
    print(f"✓ Created user: {user.username}")

    # 2. JWT Token Example
    print("\n=== JWT Token Demo ===")

    # Configure authentication service through FlextContainer
    container = FlextContainer.get_global()
    config = FlextAuthConfig.create(
        jwt_auth_secret="demo-jwt-secret-key-for-examples-only-not-secure",
        jwt_expiry_minutes=30,
        bcrypt_rounds=4,  # Fast for demo
    )
    container.register("config", config)

    # Create authentication service
    auth_service = FlextAuth()

    # Create user for token demo
    token_user_creation = FlextAuthModels.User(
        username="tokendemo",
        email="token@example.com",
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

    # Token refresh is handled internally by the authentication provider
    # when tokens expire, re-authentication is required

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
    for username, email, _pwd in users_data:
        user_result = FlextAuthModels.User(username=username, email=email)
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
