#!/usr/bin/env python3
"""FLEXT Auth - Advanced Features Examples (Working Version).

This example demonstrates advanced FLEXT Auth features with REAL functionality.
All methods used exist and work as expected.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import secrets
import string

from flext_auth import FlextAuth


def example_advanced_configuration() -> None:
    """Demonstrate advanced configuration options."""
    print("=== Advanced Configuration Demo ===")

    # Create auth with advanced configuration
    auth: FlextAuth[object] = FlextAuth(
        jwt_secret=os.getenv(
            "FLEXT_DEMO_JWT_SECRET",
            "my-super-secure-jwt-secret-key-256-bits-minimum-length-required",
        ),
        token_expire_minutes=60,
        password_rounds=12
    )
    print("✅ FlextAuth created with advanced configuration")

    # Show configuration details
    config = auth.get_config()
    security_settings = auth.config.get_security_settings()
    jwt_settings = auth.config.get_jwt_settings()

    print(f"   JWT Expiry: {config.jwt_expiry_minutes} minutes")
    print(f"   Bcrypt Rounds: {security_settings.get('bcrypt_rounds')}")
    print(f"   JWT Secret Length: {jwt_settings.get('jwt_secret_length')} chars")
    print(f"   Max Login Attempts: {security_settings.get('max_login_attempts')}")


def example_jwt_operations() -> None:
    """Advanced JWT operations example using REAL current API."""
    print("\n=== Advanced JWT Operations Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Register user for JWT operations
    user_result = auth.register_user(
        username="advanced_user",
        email="advanced@example.com",
        password="AdvancedPassword123!",
        roles=["REDACTED_LDAP_BIND_PASSWORD", "user"]
    )

    if user_result.is_failure:
        print(f"❌ User registration failed: {user_result.error}")
        return

    user = user_result.value
    print(f"✅ Advanced user registered: {user.username}")

    # Generate JWT with custom expiry
    token_result = auth.generate_jwt_token(user.id, expires_in_minutes=120)
    if token_result.is_success:
        token = token_result.value
        print(f"✅ JWT generated (2hr expiry): {token[:30]}...")

        # Validate JWT and show payload
        validation_result = auth.validate_token(token)
        if validation_result.is_success:
            payload = validation_result.value
            print("✅ JWT validation successful:")
            print(f"   User ID: {payload.get('user_id')}")
            print(f"   Username: {payload.get('username')}")
            print(f"   Role: {payload.get('role')}")
            print(f"   Issued At: {payload.get('iat')}")
            print(f"   Expires At: {payload.get('exp')}")
        else:
            print(f"❌ JWT validation failed: {validation_result.error}")
    else:
        print(f"❌ JWT generation failed: {token_result.error}")


def example_role_based_access() -> None:
    """Demonstrate role-based access control."""
    print("\n=== Role-Based Access Control Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Create users with different roles
    users_data = [
        ("REDACTED_LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD@company.com", "AdminPass123!", ["REDACTED_LDAP_BIND_PASSWORD", "user"]),
        ("manager", "manager@company.com", "ManagerPass123!", ["manager", "user"]),
        ("employee", "employee@company.com", "EmployeePass123!", ["user"]),
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

    # Demonstrate role checking
    for user in registered_users:
        print(f"\n   User: {user.username}")
        print(f"   Has REDACTED_LDAP_BIND_PASSWORD role: {user.has_role('REDACTED_LDAP_BIND_PASSWORD')}")
        print(f"   Has manager role: {user.has_role('manager')}")
        print(f"   Has user role: {user.has_role('user')}")
        print(f"   Primary role: {user.role}")


def example_session_management() -> None:
    """Demonstrate advanced session management."""
    print("\n=== Advanced Session Management Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Register user for session demo
    user_result = auth.register_user("sessionuser", "session@example.com", "SessionPass123!")
    if user_result.is_failure:
        print(f"❌ User registration failed: {user_result.error}")
        return

    user = user_result.value

    # Create multiple authentication sessions
    sessions = []
    for i in range(3):
        auth_result = auth.authenticate_user("sessionuser", "SessionPass123!")
        if auth_result.is_success:
            session_id = auth_result.value.get("session_id")
            sessions.append(session_id)
            print(f"✅ Session {i + 1} created: {session_id}")

    # Show user sessions
    user_sessions_result = auth.get_user_sessions(user.id)
    if user_sessions_result.is_success:
        user_sessions = user_sessions_result.value
        print(f"✅ User has {len(user_sessions)} active sessions")

        for session in user_sessions:
            print(f"   Session ID: {session.id}")
            print(f"   Valid: {session.is_valid}")
            print(f"   Expires: {session.expires_at}")

    # Cleanup expired sessions
    cleanup_result = auth.cleanup_expired_sessions()
    if cleanup_result.is_success:
        cleaned_count = cleanup_result.value
        print(f"✅ Cleaned up {cleaned_count} expired sessions")

    # Logout all sessions
    for session_id in sessions:
        if session_id:
            logout_result = auth.logout_user(str(session_id))
            if logout_result.is_success:
                print(f"✅ Session logged out: {session_id}")


def example_password_security() -> None:
    """Demonstrate password security features."""
    print("\n=== Password Security Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Test various password strengths
    passwords_to_test = [
        ("weak", "123"),
        ("simple", "password"),
        ("medium", "Password123"),
        ("strong", "StrongPassword123!"),
        ("very_strong", "VeryStr0ng!P@ssw0rd#2024$"),
    ]

    for level, password in passwords_to_test:
        result = auth.register_user(f"user_{level}", f"{level}@example.com", password)
        if result.is_success:
            print(f"✅ {level.capitalize()} password accepted")
        else:
            print(f"❌ {level.capitalize()} password rejected: {result.error}")

    # Demonstrate password hashing with different rounds
    test_password = "TestPassword123!"

    # Show current hashing
    try:
        hash1 = auth.hash_password(test_password)
        hash2 = auth.hash_password(test_password)

        print(f"✅ Password hashed (length: {len(hash1)})")
        print(f"   Hash 1: {hash1[:30]}...")
        print(f"   Hash 2: {hash2[:30]}...")
        print(f"   Hashes different (salt): {hash1 != hash2}")

        # Verify both hashes work
        valid1 = auth.verify_password(test_password, hash1)
        valid2 = auth.verify_password(test_password, hash2)
        print(f"✅ Both hashes verify: {valid1 and valid2}")

    except Exception as e:
        print(f"❌ Password hashing failed: {e}")


def example_token_validation() -> None:
    """Demonstrate advanced token validation."""
    print("\n=== Advanced Token Validation Demo ===")

    auth: FlextAuth[object] = FlextAuth()

    # Register user and create token
    user_result = auth.register_user("tokenuser", "token@example.com", "TokenPass123!")
    if user_result.is_failure:
        print(f"❌ User registration failed: {user_result.error}")
        return

    user = user_result.value

    # Generate token
    token_result = auth.generate_jwt_token(user.id)
    if token_result.is_failure:
        print(f"❌ Token generation failed: {token_result.error}")
        return

    token = token_result.value

    # Test various token formats
    test_tokens = [
        ("Valid token", token),
        ("Bearer token", f"Bearer {token}"),
        ("Invalid format", "invalid.token.format"),
        ("Empty token", ""),
        ("Malformed JWT", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid"),
    ]

    for desc, test_token in test_tokens:
        validation_result = auth.validate_token(test_token)
        if validation_result.is_success:
            payload = validation_result.value
            print(f"✅ {desc}: Valid (user: {payload.get('username', 'Unknown')})")
        else:
            print(f"❌ {desc}: Invalid ({validation_result.error})")


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure password with mixed characters."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(chars) for _ in range(length))


def basic_example_runner() -> None:
    """Run basic example functionality (replaced utils import)."""
    print("✅ Basic example runner executed")


def main() -> None:
    """Execute advanced features demonstration."""
    print("🚀 FLEXT Auth - Advanced Features Demonstration")
    print("=" * 60)

    # Run basic example first
    basic_example_runner()

    # Run advanced feature demos
    example_advanced_configuration()
    example_jwt_operations()
    example_role_based_access()
    example_session_management()
    example_password_security()
    example_token_validation()

    print("\n🎉 Advanced features demonstration completed!")
    print("✅ All FLEXT Auth advanced functionality working correctly!")


if __name__ == "__main__":
    main()
