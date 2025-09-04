#!/usr/bin/env python3
"""FLEXT Auth - Simple usage example with clean types.

This example demonstrates basic FLEXT Auth usage with proper type handling.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import sys
from typing import cast

from flext_auth import FlextAuth, flext_auth_quick_start
from flext_core import FlextConstants


def main() -> None:
    """Demonstrate FLEXT Auth functionality with clean types."""
    print("🚀 FLEXT Auth - Simple Usage Example")
    print("=" * 40)

    # 1. Quick Start Authentication
    print("\n1. Quick Start")
    auth: FlextAuth[object] = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    print("✅ FlextAuth instance created")

    # 2. Direct API Usage
    print("\n2. Direct API Usage")

    # Password hashing using FlextAuth directly
    try:
        password_hash = auth.hash_password("TestPassword123!")
        print(f"✅ Password hashed: {len(password_hash)} characters")

        # Password verification
        is_valid = auth.verify_password("TestPassword123!", password_hash)
        print(f"✅ Password verification: {is_valid}")
    except Exception as e:
        print(f"❌ Password operation failed: {e}")

    # 3. Full Authentication Flow
    print("\n3. Authentication Flow")

    # Register user
    reg_result = auth.register_user(
        username="testuser",
        email="test@example.com",
        password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "SecurePassword123!"),
        roles=["user"],
    )

    if reg_result.is_success:
        print("✅ User registered successfully")
        user = reg_result.value
        print(f"   Username: {user.username}")
        print(f"   Email: {user.email_str}")
        print(f"   Role: {user.role}")

        # Authenticate user
        auth_result = auth.authenticate_user("testuser", "SecurePassword123!")

        if auth_result.is_success:
            print("✅ User authenticated successfully")

            # Extract authentication data
            auth_data = auth_result.value

            # Get JWT token
            jwt_token_str = str(auth_data.get("jwt_token", ""))
            session_id = auth_data.get("session_id")

            print(f"   Session ID: {session_id}")
            print(f"   JWT Token: {jwt_token_str[:30]}...")

            # Validate token through service
            token_validation = auth.validate_token(jwt_token_str)
            if token_validation.is_success:
                payload = token_validation.value
                print("✅ Token validation successful")
                print(f"   User ID from token: {payload.get('user_id')}")
            else:
                print(f"❌ Token validation failed: {token_validation.error}")
        else:
            print(f"❌ Authentication failed: {auth_result.error}")
    else:
        print(f"❌ Registration failed: {reg_result.error}")

    # 4. Configuration Access
    print("\n4. Configuration Access")
    config = auth.get_config()
    security_settings = auth.config.get_security_settings()
    jwt_settings = auth.config.get_jwt_settings()

    print(f"✅ JWT Expiry: {config.jwt_expiry_minutes} minutes")
    print(f"✅ Bcrypt rounds: {security_settings.get('bcrypt_rounds')}")
    print(f"✅ JWT Algorithm: {jwt_settings.get('jwt_algorithm')}")
    print(f"✅ Max login attempts: {security_settings.get('max_login_attempts')}")

    # 5. FlextCore Constants
    print("\n5. FlextCore Constants Usage")
    print(f"✅ Min password length: {FlextConstants.Auth.MIN_PASSWORD_LENGTH}")
    print(f"✅ JWT default expiry: {FlextConstants.Auth.JWT_DEFAULT_EXPIRY_MINUTES}")
    print(f"✅ Default bcrypt rounds: {FlextConstants.Auth.BCRYPT_ROUNDS}")
    print(f"✅ Max login attempts: {FlextConstants.Auth.MAX_LOGIN_ATTEMPTS}")

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
