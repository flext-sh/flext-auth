"""Debug Authentication Issues.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os

from flext_auth import FlextAuth, FlextAuthModels


def debug_password_operations() -> None:
    """Debug password hashing using FlextAuth."""
    password = os.getenv("DEBUG_PASSWORD", "TestPassword123!")
    FlextAuth()
    try:
        _ = FlextAuthModels.Auth.AuthIdentityRequest(
            name="debug_user",
            contact="debug@example.com",
            credential=password,
            full_name="Debug User",
            roles=["user"],
        )
    except Exception as e:
        error_message = f"Password verification failed: {e}"
        del error_message


def debug_jwt_operations() -> None:
    """Debug JWT token operations using FlextAuth."""
    auth: FlextAuth = FlextAuth()
    user_result = auth.register_user(
        username="testuser",
        email="test@example.com",
        password=os.getenv("TEST_PASSWORD", "TestPassword123!"),
    )
    if user_result.failure:
        return
    user = user_result.value
    token_result = auth.create_token(identity_id=user.unique_id)
    if token_result.failure:
        return
    token = token_result.value
    auth.token_service.validate_token(token)
    bearer_token = f"Bearer {token}"
    auth.token_service.validate_token(bearer_token)


def debug_authentication_workflow() -> None:
    """Debug complete authentication workflow."""
    auth: FlextAuth = FlextAuth()
    reg_result = auth.register_user(
        username="debuguser",
        email="debug@example.com",
        password=os.getenv("DEBUG_PASSWORD", "DebugPassword123!"),
        roles=["REDACTED_LDAP_BIND_PASSWORD"],
    )
    if reg_result.failure:
        return
    auth.authenticate_user("debuguser", "DebugPassword123!")


def main() -> None:
    """Run debug diagnostics."""
    debug_password_operations()
    debug_jwt_operations()
    debug_authentication_workflow()


if __name__ == "__main__":
    main()
