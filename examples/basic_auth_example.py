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
    """Run basic authentication example."""
    # 1. Password Hashing Example
    password = "SecurePassword123!"
    flext_auth_hash_password(password)

    # 2. JWT Token Example
    payload: dict[str, object] = {
        "user_id": "user123",
        "username": "testuser",
        "role": "REDACTED_LDAP_BIND_PASSWORD",
    }

    # flext_auth_generate_jwt returns a string directly
    token = flext_auth_generate_jwt(payload)

    # Validate token - flext_auth_validate_jwt returns dict[str, object]
    validation = flext_auth_validate_jwt(token)
    if validation.get("valid", False):
        pass

    # 3. Quick Start Example - returns FlextResult[object]
    setup_result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    if setup_result.success and setup_result.value:
        # Store the auth service for potential future use
        _auth_service = setup_result.value

    # 4. FlextAuth Class Example
    auth = FlextAuth()

    # Register user
    user_result = auth.register_user(
        username="demouser",
        email="demo@example.com",
        password="DemoPassword123!",
    )

    if "error" not in user_result:
        # Try to authenticate
        auth_result = auth.authenticate_user("demouser", "DemoPassword123!")
        if "error" not in auth_result:
            pass


if __name__ == "__main__":
    main()
