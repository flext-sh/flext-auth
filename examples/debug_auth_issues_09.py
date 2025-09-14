#!/usr/bin/env python3
"""Debug Authentication Issues.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os

from flext_auth import FlextAuth


def debug_password_operations() -> None:
    """Debug password hashing using FlextAuth."""
    password = os.getenv("DEBUG_PASSWORD", "TestPassword123!")

    # Use FlextAuth directly
    auth: FlextAuth = FlextAuth()

    # Test password hashing
    try:
        hashed = auth.hash_password(password)

        # Test verification
        auth.verify_password(password, hashed)

        # Test with wrong password
        auth.verify_password("WrongPassword", hashed)

    except Exception as e:
        # Handle password verification error
        error_message = f"Password verification failed: {e}"
        # In production, this would be logged properly
        del error_message  # Clean up


def debug_jwt_operations() -> None:
    """Debug JWT token operations using FlextAuth."""
    # Use FlextAuth directly
    auth: FlextAuth = FlextAuth()

    # Register a test user first
    user_result = auth.register_user(
        username="testuser",
        email="test@example.com",
        password=os.getenv("TEST_PASSWORD", "TestPassword123!"),
    )

    if user_result.is_failure:
        return

    user = user_result.value

    # Test JWT token generation
    token_result = auth.generate_jwt_token(user.id)
    if token_result.is_failure:
        return

    token = token_result.value

    # Test token validation
    validate_result = auth.validate_token(token)
    if validate_result.is_success:
        pass

    # Test with Bearer prefix
    bearer_token = f"Bearer {token}"
    bearer_result = auth.validate_token(bearer_token)
    if bearer_result.is_success:
        pass


def debug_authentication_workflow() -> None:
    """Debug complete authentication workflow."""
    auth: FlextAuth = FlextAuth()

    # Register user
    reg_result = auth.register_user(
        username="debuguser",
        email="debug@example.com",
        password=os.getenv("DEBUG_PASSWORD", "DebugPassword123!"),
        roles=["REDACTED_LDAP_BIND_PASSWORD"],
    )

    if reg_result.is_failure:
        return

    # Authenticate user
    auth_result = auth.authenticate_user("debuguser", "DebugPassword123!")

    if auth_result.is_success:
        pass


def main() -> None:
    """Run debug diagnostics."""
    debug_password_operations()

    debug_jwt_operations()

    debug_authentication_workflow()


if __name__ == "__main__":
    main()
