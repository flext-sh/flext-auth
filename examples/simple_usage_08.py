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
    auth: FlextAuth = FlextAuth()
    try:
        test_password = "SecureDemoPassword123!"
        FlextAuthModels.Auth.AuthIdentityRequest(
            name="testuser", contact="test@example.com", credential=test_password
        )
        user_result = auth.register_user("testuser", "test@example.com", test_password)
        if user_result.is_success:
            pass
    except Exception as e:
        error_message = f"Password verification failed: {e}"
        del error_message
    reg_result = auth.register_user(
        username="testuser",
        email="test@example.com",
        password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "SecurePassword123!"),
        roles=["user"],
    )
    if reg_result.is_success:
        auth_result = auth.authenticate_user("testuser", "SecurePassword123!")
        if auth_result.is_success:
            auth_data = auth_result.value
            _ = str(auth_data.token)
            _ = auth_data.session_id


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        sys.exit(1)
