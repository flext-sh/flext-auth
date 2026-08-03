"""FLEXT Auth - Simple usage example with clean types.

This example demonstrates basic FLEXT Auth usage with proper type handling.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os

from flext_auth import FlextAuth, FlextAuthModels


class FlextAuthSimpleUsageExample:
    """Single owner for the simple usage example."""

    @staticmethod
    def main() -> None:
        """Demonstrate FLEXT Auth functionality with clean types."""
        auth: FlextAuth = FlextAuth()
        try:
            test_password = os.getenv(
                "FLEXT_DEMO_USER_PASSWORD", "SecureDemoPassword123!"
            )
            FlextAuthModels.Auth.AuthIdentityRequest(
                name="testuser", contact="test@example.com", credential=test_password
            )
            auth.register_user("testuser", "test@example.com", test_password)
        except Exception as error:
            error_message = f"Password verification failed: {error}"
            del error_message
        reg_result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "SecurePassword123!"),
            roles=["user"],
        )
        if reg_result.success:
            auth_result = auth.authenticate_user("testuser", "SecurePassword123!")
            if auth_result.success:
                auth_data = auth_result.value
                _ = auth_data.token
                _ = auth_data.session_id


if __name__ == "__main__":
    try:
        FlextAuthSimpleUsageExample.main()
    except KeyboardInterrupt:
        raise SystemExit(0) from None
    except (RuntimeError, ValueError, OSError):
        raise SystemExit(1) from None
