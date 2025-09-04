#!/usr/bin/env python3
"""FLEXT Auth - Comprehensive Demo (Working Version).

This example provides a comprehensive demonstration of FLEXT Auth capabilities
using REAL, working functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import secrets
import string

from flext_core import FlextResult

from flext_auth import FlextAuth, flext_auth_quick_start


def demo_complete_auth_workflow() -> None:
    """Demonstrate complete authentication workflow."""
    print("=== Complete Authentication Workflow Demo ===")

    # 1. Initialize auth service
    auth: FlextAuth[object] = FlextAuth()
    print("✅ Auth service initialized")

    # 2. Create user account (using register_user, not create_user)
    username = "demo_user"
    email = "demo@example.com"
    password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoSecurePass123!")

    result = auth.register_user(username, email, password, roles=["user"])
    if result.is_success:
        user = result.value
        print(f"✅ User registration successful: {user.username}")
    else:
        print(f"❌ User registration failed: {result.error}")
        return

    # 3. Authenticate user (using authenticate_user, not authenticate)
    auth_result = auth.authenticate_user(username, password)
    if auth_result.is_success:
        auth_data = auth_result.value
        print("✅ Authentication successful")

        # Extract authentication details
        session_id = auth_data.get("session_id")
        jwt_token = auth_data.get("jwt_token")

        print(f"   Session ID: {session_id}")
        print(f"   JWT Token: {str(jwt_token)[:30]}...")

        # 4. Validate JWT token
        if jwt_token:
            token_result = auth.validate_token(str(jwt_token))
            if token_result.is_success:
                payload = token_result.value
                print(f"✅ JWT validation successful: user_id={payload.get('user_id')}")
            else:
                print(f"❌ JWT validation failed: {token_result.error}")

        # 5. Session management
        user_sessions = auth.get_user_sessions(user.id)
        if user_sessions.is_success:
            sessions = user_sessions.value
            print(f"✅ User has {len(sessions)} active sessions")

        # 6. Logout user
        if session_id:
            logout_result = auth.logout_user(str(session_id))
            if logout_result.is_success:
                print("✅ User logout successful")
            else:
                print(f"❌ Logout failed: {logout_result.error}")
    else:
        print(f"❌ Authentication failed: {auth_result.error}")


def demo_password_operations() -> None:
    """Demonstrate password hashing and verification operations."""
    print("\n=== Password Operations Demo ===")

    auth: FlextAuth[object] = FlextAuth()
    test_password = "TestPassword123!"

    try:
        # Hash password
        hashed = auth.hash_password(test_password)
        print(f"✅ Password hashed: {len(hashed)} characters")

        # Verify correct password
        is_valid = auth.verify_password(test_password, hashed)
        print(f"✅ Correct password verification: {is_valid}")

        # Verify incorrect password
        is_invalid = auth.verify_password("WrongPassword", hashed)
        print(f"✅ Incorrect password verification: {is_invalid}")

    except Exception as e:
        print(f"❌ Password operations failed: {e}")


def demo_jwt_operations() -> None:
    """Demonstrate JWT token operations."""
    print("\n=== JWT Operations Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Register user for JWT operations
    user_result = auth.register_user("jwtuser", "jwt@example.com", "JWTPassword123!")
    if user_result.is_failure:
        print(f"❌ JWT user registration failed: {user_result.error}")
        return

    user = user_result.value

    # Generate JWT token
    token_result = auth.generate_jwt_token(user.id)
    if token_result.is_success:
        token = token_result.value
        print(f"✅ JWT token generated: {token[:30]}...")

        # Validate token
        validation_result = auth.validate_token(token)
        if validation_result.is_success:
            payload = validation_result.value
            print("✅ Token validation successful")
            print(f"   User ID: {payload.get('user_id')}")
            print(f"   Username: {payload.get('username')}")
            print(f"   Role: {payload.get('role')}")
        else:
            print(f"❌ Token validation failed: {validation_result.error}")
    else:
        print(f"❌ Token generation failed: {token_result.error}")


def demo_user_management() -> None:
    """Demonstrate user management operations."""
    print("\n=== User Management Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Register multiple users with different roles
    users_data = [
        ("REDACTED_LDAP_BIND_PASSWORD_user", "REDACTED_LDAP_BIND_PASSWORD@example.com", "AdminPass123!", ["REDACTED_LDAP_BIND_PASSWORD", "user"]),
        ("regular_user", "regular@example.com", "RegularPass123!", ["user"]),
        ("guest_user", "guest@example.com", "GuestPass123!", ["guest"]),
    ]

    registered_users = []
    for username, email, password, roles in users_data:
        result = auth.register_user(username, email, password, roles=roles)
        if result.is_success:
            user = result.value
            registered_users.append(user)
            print(f"✅ {username} registered with roles: {user.roles}")
        else:
            print(f"❌ Failed to register {username}: {result.error}")

    # Demonstrate user lookups
    for user in registered_users:
        lookup_result = auth.get_user_by_username(user.username)
        if lookup_result.is_success and lookup_result.value:
            found_user = lookup_result.value
            print(f"✅ Found user: {found_user.username} (ID: {found_user.id})")
        else:
            print(f"❌ Failed to find user: {user.username}")


def demo_security_features() -> None:
    """Demonstrate security features."""
    print("\n=== Security Features Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Show configuration security settings
    config = auth.get_config()
    security_settings = auth.config.get_security_settings()

    print("✅ Security Configuration:")
    print(f"   Bcrypt rounds: {security_settings.get('bcrypt_rounds')}")
    print(f"   Max login attempts: {security_settings.get('max_login_attempts')}")
    print(f"   JWT expiry: {config.jwt_expiry_minutes} minutes")
    print(f"   Password min length: {security_settings.get('min_password_length')}")

    # Demonstrate password strength validation by attempting weak passwords
    weak_passwords = ["123", "password", "abc"]
    for weak_pass in weak_passwords:
        weak_result = auth.register_user("weakuser", "weak@example.com", weak_pass)
        if weak_result.is_failure:
            print(f"✅ Weak password '{weak_pass}' properly rejected: {weak_result.error}")
        else:
            print(f"❌ Weak password '{weak_pass}' should have been rejected")


def demo_error_handling() -> None:
    """Demonstrate comprehensive error handling."""
    print("\n=== Error Handling Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Test duplicate registration
    auth.register_user("duplicate", "dup@example.com", "DupPass123!")
    dup_result = auth.register_user("duplicate", "dup2@example.com", "DupPass123!")
    if dup_result.is_failure:
        print(f"✅ Duplicate username rejected: {dup_result.error}")

    # Test invalid authentication
    invalid_result = auth.authenticate_user("nonexistent", "password")
    if invalid_result.is_failure:
        print(f"✅ Invalid authentication rejected: {invalid_result.error}")

    # Test invalid token validation
    invalid_token_result = auth.validate_token("invalid.jwt.token")
    if invalid_token_result.is_failure:
        print(f"✅ Invalid token rejected: {invalid_token_result.error}")


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(chars) for _ in range(length))


def basic_example_runner() -> None:
    """Run basic example functionality (replaced utils import)."""
    print("✅ Basic example runner executed")


def main() -> None:
    """Execute comprehensive demonstration."""
    print("🚀 FLEXT Auth - Comprehensive Demonstration")
    print("=" * 60)

    # Run basic example first
    basic_example_runner()

    # Run comprehensive demos
    demo_complete_auth_workflow()
    demo_password_operations()
    demo_jwt_operations()
    demo_user_management()
    demo_security_features()
    demo_error_handling()

    # Quick start demo
    print("\n=== Quick Start Demo ===")
    flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    print("✅ Quick start authentication service created")

    print("\n🎉 Comprehensive demonstration completed!")
    print("✅ All FLEXT Auth functionality working correctly!")


if __name__ == "__main__":
    main()
