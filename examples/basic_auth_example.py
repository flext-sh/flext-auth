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
    flext_auth_verify_password,
)


def main() -> None:
    """Run basic authentication example."""
    print("🔐 FLEXT Authentication Basic Example")
    print("=" * 50)

    # 1. Password Hashing Example
    print("\n1. Password Hashing:")
    password = "SecurePassword123!"
    hashed = flext_auth_hash_password(password)
    print(f"Original: {password}")
    print(f"Hashed: {hashed[:20]}...")
    print(f"Verification: {flext_auth_verify_password(password, hashed)}")

    # 2. JWT Token Example
    print("\n2. JWT Token Generation:")
    payload = {"user_id": "user123", "username": "testuser", "role": "REDACTED_LDAP_BIND_PASSWORD"}

    token_result = flext_auth_generate_jwt(payload)
    if token_result.is_success and token_result.data:
        token = token_result.data
        print(f"Generated Token: {token[:50]}...")

        # Validate token
        validation = flext_auth_validate_jwt(token)
        if validation.is_success and validation.data:
            decoded = validation.data
            print(f"Decoded payload: {decoded}")

    # 3. Quick Start Example
    print("\n3. Quick Start Authentication Service:")
    setup_result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    if setup_result.is_success:
        print("✅ Auth service created successfully")
        auth_service = setup_result.data
        print(f"Service type: {type(auth_service).__name__}")

    # 4. FlextAuth Class Example
    print("\n4. FlextAuth Class Usage:")
    auth = FlextAuth()

    # Register user
    user_result = auth.register_user(
        username="demouser", email="demo@example.com", password="DemoPassword123!"
    )

    if isinstance(user_result, dict) and "error" not in user_result:
        print(f"✅ User registered: {user_result['username']}")
        print(f"   Email: {user_result['email']}")
        print(f"   Role: {user_result['role']}")

        # Try to authenticate
        auth_result = auth.authenticate_user("demouser", "DemoPassword123!")
        if isinstance(auth_result, dict) and "error" not in auth_result:
            print("✅ Authentication successful!")
        else:
            print(
                f"❌ Authentication failed: {auth_result.get('error', 'Unknown error')}"
            )
    else:
        print(f"❌ Registration failed: {user_result.get('error', 'Unknown error')}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Example failed: {e}")
        raise
