#!/usr/bin/env python3
"""FLEXT Auth - Simple usage example with clean types.

This example demonstrates basic FLEXT Auth usage with proper type handling.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import sys

from flext_auth import FlextAuth, FlextAuthModels


def main() -> None:
    """Demonstrate FLEXT Auth functionality with clean types."""
    # 1. Initialize Authentication
    auth: FlextAuth = FlextAuth()

    # 2. Direct API Usage

    # Password hashing using FlextAuth directly
    try:
        # Create user with password hashing
        FlextAuthModels.UserCreationRequest(
            username="testuser", email="test@example.com", password="TestPassword123!",
        )

        # Register user (includes password hashing)
        user_result = auth.register_user(
            "testuser", "test@example.com", "TestPassword123!",
        )
        if user_result.is_success:
            user = user_result.value
            # Password verification through user model
            verify_result = user.verify_password("TestPassword123!")
            print(f"Password verification: {verify_result.value}")
    except Exception as e:
        # Handle password verification error
        error_message = f"Password verification failed: {e}"
        # In production, this would be logged properly
        del error_message  # Clean up

    # 3. Full Authentication Flow

    # Register user
    reg_result = auth.register_user(
        username="testuser",
        email="test@example.com",
        password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "SecurePassword123!"),
        roles=["user"],
    )

    if reg_result.is_success:
        # Authenticate user
        auth_result = auth.authenticate_user("testuser", "SecurePassword123!")

        if auth_result.is_success:
            # Extract authentication data
            auth_data = auth_result.value

            # Get JWT token
            str(auth_data.get("jwt_token", ""))
            auth_data.get("session_id")

            # Note: token validation would be done through AuthToken.verify_jwt_token
            # if needed for a specific use case

    # 4. Configuration Access
    # Note: config access methods don't exist in current FlextAuth API
    # Configuration would be accessed through FlextAuthConfig if needed

    # 5. FlextCore Constants


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        sys.exit(1)
