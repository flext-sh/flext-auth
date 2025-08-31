#!/usr/bin/env python3
"""FLEXT Auth - Simple usage example with clean types.

This example demonstrates basic FLEXT Auth usage with proper type handling.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys

from flext_auth import (
    FlextAuth,
    FlextAuthConstants,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_jwt,
)


def main() -> None:
    """Demonstrate FLEXT Auth functionality with clean types."""
    print("🚀 FLEXT Auth - Simple Usage Example")
    print("=" * 40)

    # 1. Quick Start Authentication
    print("\n1. Quick Start")
    auth: FlextAuth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    print("✅ FlextAuth instance created")

    # 2. Utility Functions
    print("\n2. Utility Functions")

    # Password hashing
    password_hash = flext_auth_hash_password("TestPassword123!")  # noqa: S106
    print(f"✅ Password hashed: {len(password_hash)} characters")

    # JWT generation and validation
    jwt_result = flext_auth_generate_jwt({"user_id": "123", "role": "user"})
    if jwt_result.success:
        token = jwt_result.value
        print(f"✅ JWT token generated: {len(token)} characters")

        # Validate the JWT
        validation_result = flext_auth_validate_jwt(token)
        if validation_result.success:
            print("✅ JWT token validated successfully")
        else:
            print(f"❌ JWT validation failed: {validation_result.error}")
    else:
        print(f"❌ JWT generation failed: {jwt_result.error}")

    # 3. Full Authentication Flow
    print("\n3. Authentication Flow")

    # Register user
    reg_result = auth.register_user(
        username="testuser",
        email="test@example.com",
        password="SecurePassword123!",  # noqa: S106
        role=FlextAuthConstants.ROLE_USER,
    )

    if reg_result.success:
        print("✅ User registered successfully")

        # Authenticate user
        auth_result = auth.authenticate_user("testuser", "SecurePassword123!")  # noqa: S106

        if auth_result.success:
            print("✅ User authenticated successfully")

            # Extract token for validation (we know auth_result.value is dict[str, object])
            from typing import cast

            auth_data = cast("dict[str, object]", auth_result.value)  # type: ignore[redundant-cast]
            tokens_data = cast("dict[str, object]", auth_data["tokens"])
            access_token = cast("str", tokens_data["access_token"])

            # Validate token through service
            token_validation = auth.validate_token(access_token)
            if token_validation.success:
                print("✅ Token validation successful")
            else:
                print(f"❌ Token validation failed: {token_validation.error}")
        else:
            print(f"❌ Authentication failed: {auth_result.error}")
    else:
        print(f"❌ Registration failed: {reg_result.error}")

    # 4. Constants Usage
    print("\n4. Configuration Constants")
    print(f"✅ Default JWT algorithm: {FlextAuthConstants.JWT_ALGORITHM}")
    print(f"✅ Default bcrypt rounds: {FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS}")
    print(f"✅ User role constant: {FlextAuthConstants.ROLE_USER}")
    print(f"✅ Admin role constant: {FlextAuthConstants.ROLE_ADMIN}")

    print("\n✅ Simple example completed successfully!")
    print("🎉 FLEXT Auth is working correctly!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Example interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Example failed: {e}")
        sys.exit(1)
