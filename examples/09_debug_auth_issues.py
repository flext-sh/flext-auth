#!/usr/bin/env python3
"""Debug Authentication Issues.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import FlextAuth


def debug_password_operations() -> None:
    """Debug password hashing using FlextAuth."""
    password = "TestPassword123!"

    # Use FlextAuth directly
    auth: FlextAuth[object] = FlextAuth()

    # Test password hashing
    try:
        hashed = auth.hash_password(password)
        print(f"Password hashed successfully: {len(hashed)} chars")

        # Test verification
        is_valid = auth.verify_password(password, hashed)
        print(f"Password verification: {is_valid}")

        # Test with wrong password
        is_invalid = auth.verify_password("WrongPassword", hashed)
        print(f"Wrong password verification: {is_invalid}")

    except Exception as e:
        print(f"Password operation failed: {e}")


def debug_jwt_operations() -> None:
    """Debug JWT token operations using FlextAuth."""
    # Use FlextAuth directly
    auth: FlextAuth[object] = FlextAuth()

    # Register a test user first
    user_result = auth.register_user(
        username="testuser",
        email="test@example.com",
        password="TestPassword123!"
    )

    if user_result.is_failure:
        print(f"User registration failed: {user_result.error}")
        return

    user = user_result.value
    print(f"User registered: {user.username}")

    # Test JWT token generation
    token_result = auth.generate_jwt_token(user.id)
    if token_result.is_failure:
        print(f"Token generation failed: {token_result.error}")
        return

    token = token_result.value
    print(f"Generated token: {token[:50]}...")

    # Test token validation
    validate_result = auth.validate_token(token)
    if validate_result.is_success:
        payload = validate_result.value
        print(f"Token validation successful: user_id={payload.get('user_id')}")
    else:
        print(f"Token validation failed: {validate_result.error}")

    # Test with Bearer prefix
    bearer_token = f"Bearer {token}"
    bearer_result = auth.validate_token(bearer_token)
    if bearer_result.is_success:
        print("Bearer token validation successful")
    else:
        print(f"Bearer token validation failed: {bearer_result.error}")


def debug_authentication_workflow() -> None:
    """Debug complete authentication workflow."""
    auth: FlextAuth[object] = FlextAuth()

    # Register user
    reg_result = auth.register_user(
        username="debuguser",
        email="debug@example.com",
        password="DebugPassword123!",
        roles=["REDACTED_LDAP_BIND_PASSWORD"]
    )

    if reg_result.is_failure:
        print(f"Registration failed: {reg_result.error}")
        return

    print("User registered successfully")

    # Authenticate user
    auth_result = auth.authenticate_user("debuguser", "DebugPassword123!")

    if auth_result.is_success:
        auth_data = auth_result.value
        print("Authentication successful")
        print(f"Session ID: {auth_data.get('session_id')}")
        print(f"JWT Token: {str(auth_data.get('jwt_token', ''))[:30]}...")
    else:
        print(f"Authentication failed: {auth_result.error}")


def main() -> None:
    """Run debug diagnostics."""
    print("=== Password Operations Debug ===")
    debug_password_operations()

    print("\n=== JWT Operations Debug ===")
    debug_jwt_operations()

    print("\n=== Authentication Workflow Debug ===")
    debug_authentication_workflow()


if __name__ == "__main__":
    main()
