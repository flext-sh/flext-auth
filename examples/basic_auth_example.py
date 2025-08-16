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

from flext_auth import (
    FlextAuth,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_jwt,
)


def main() -> None:
    """Run basic authentication example."""  # 1. Password Hashing Example
    password = "SecurePassword123!"  # noqa: S105 - Example password for documentation
    flext_auth_hash_password(password)

    # 2. JWT Token Example
    payload = {"user_id": "user123", "username": "testuser", "role": "REDACTED_LDAP_BIND_PASSWORD"}

    token_result = flext_auth_generate_jwt(payload)
    if token_result.success and token_result.data:
        token = token_result.data

        # Validate token
        validation = flext_auth_validate_jwt(token)
        if validation.success and validation.data:
            pass

    # 3. Quick Start Example
    setup_result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    if setup_result.success:
        pass

    # 4. FlextAuth Class Example
    auth = FlextAuth()

    # Register user
    user_result = auth.register_user(
        username="demouser",
        email="demo@example.com",
        password="DemoPassword123!",  # noqa: S106 - Example password for documentation
    )

    if isinstance(user_result, dict) and "error" not in user_result:
        # Try to authenticate
        auth_result = auth.authenticate_user("demouser", "DemoPassword123!")
        if isinstance(auth_result, dict) and "error" not in auth_result:
            pass


if __name__ == "__main__":
    main()
