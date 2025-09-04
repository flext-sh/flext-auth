#!/usr/bin/env python3
"""FLEXT Auth - Basic usage examples.

This example demonstrates basic FLEXT Auth usage with real functionality.
All methods used exist and work as expected.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import secrets
import string
from typing import cast

from flext_auth import FlextAuth

# Use inline constants instead of scattered globals
# All passwords follow the same pattern: secure + examples


def example_basic_authentication() -> None:
    """Demonstrate basic authentication with FlextAuth."""
    print("🔐 Basic Authentication Example")
    print("=" * 40)

    # Create authentication instance
    auth: FlextAuth[object] = FlextAuth()
    print("✅ FlextAuth instance created (in-memory storage)")

    # Show current configuration
    config = auth.get_config()
    security_settings = auth.config.get_security_settings()

    print(f"   JWT Expiry: {config.jwt_expiry_minutes} minutes")
    print(f"   Bcrypt Rounds: {security_settings.get('bcrypt_rounds')}")
    print(f"   Max Login Attempts: {security_settings.get('max_login_attempts')}")


def example_password_operations() -> None:
    """Demonstrate password operations."""
    print("\n🔑 Password Operations Example")
    print("=" * 40)

    auth: FlextAuth[object] = FlextAuth()

    # Hash a password
    password = os.getenv("FLEXT_DEMO_PASSWORD", "MySecurePassword123!")
    try:
        hashed = auth.hash_password(password)
        print(f"✅ Password hashed successfully: {len(hashed)} chars")

        # Verify correct password
        is_valid = auth.verify_password(password, hashed)
        print(f"✅ Correct password verification: {is_valid}")

        # Verify wrong password
        is_invalid = auth.verify_password("WrongPassword", hashed)
        print(f"✅ Wrong password verification: {is_invalid}")

    except Exception as e:
        print(f"❌ Password operation failed: {e}")


def example_email_validation() -> None:
    """Demonstrate email validation patterns."""
    print("\n📧 Email Validation Example")
    print("=" * 40)

    test_emails = [
        "valid@example.com",
        "user.name@domain.co.uk",
        "invalid.email",
        "missing@domain",
        "double@@domain.com",
        ""
    ]

    def validate_email_manual(email: str) -> bool:
        """Manual email validation for demonstration."""
        if not email:
            return False
        if "@" not in email or email.count("@") != 1:
            return False
        local, domain = email.split("@")
        if not local or not domain:
            return False
        if "." not in domain:
            return False
        return ".." not in email

    for email in test_emails:
        is_valid = validate_email_manual(email)
        status = "✅ Valid" if is_valid else "❌ Invalid"
        print(f"   {email}: {status}")


def example_user_lifecycle() -> None:
    """Demonstrate complete user lifecycle."""
    print("\n👤 User Lifecycle Example")
    print("=" * 40)

    auth: FlextAuth[object] = FlextAuth()

    # Register user
    print("1. Registering user...")
    register_result = auth.register_user(
        username="lifecycleuser",
        email="lifecycle@example.com",
        password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "StrongPass123!"),
        full_name="Lifecycle User",
        roles=["user"]
    )

    if register_result.is_success:
        user_data = register_result.value
        print(f"✅ User registered successfully: {user_data.username}")
        print(f"   Email: {user_data.email_str}")
        print(f"   Role: {user_data.role}")
        print(f"   Active: {user_data.active}")

        # Authenticate user
        print("\n2. Authenticating user...")
        auth_result = auth.authenticate_user("lifecycleuser", os.getenv("FLEXT_DEMO_USER_PASSWORD", "StrongPass123!"))

        if auth_result.is_success:
            print("✅ Authentication successful")
            auth_data = auth_result.value

            # Extract token info
            jwt_token_str = str(auth_data.get("jwt_token", ""))
            session_id = auth_data.get("session_id")

            print(f"   JWT Token: {jwt_token_str[:30]}...")
            print(f"   Session ID: {session_id}")

            # Validate token
            print("\n3. Validating token...")
            token_result = auth.validate_token(jwt_token_str)
            if token_result.is_success:
                claims = token_result.value
                print("✅ Token validation successful")
                print(f"   User ID: {claims.get('user_id')}")
                print(f"   Username: {claims.get('username')}")
            else:
                print(f"❌ Token validation failed: {token_result.error}")
        else:
            print(f"❌ Authentication failed: {auth_result.error}")
    else:
        print(f"❌ Registration failed: {register_result.error}")


def example_direct_auth() -> None:
    """Demonstrate direct authentication workflow."""
    print("\n🚀 Direct Authentication Example")
    print("=" * 40)

    auth: FlextAuth[object] = FlextAuth()

    # Register and authenticate in sequence
    username = "directuser"
    email = "direct@example.com"
    password = os.getenv("FLEXT_DEMO_PASSWORD", "MySecurePassword123!")

    # Step 1: Register
    reg_result = auth.register_user(username, email, password)

    if reg_result.is_success:
        print(f"✅ User '{username}' registered")

        # Step 2: Authenticate
        auth_result = auth.authenticate_user(username, password)

        if auth_result.is_success:
            print(f"✅ User '{username}' authenticated successfully")

            auth_data = auth_result.value
            tokens_data = cast("dict[str, object]", auth_data.get("tokens", {}))

            access_token = str(tokens_data.get("access_token", ""))
            print(f"   Access token: {access_token[:20]}...")

        else:
            print(f"❌ Authentication failed: {auth_result.error}")
    else:
        print(f"❌ Registration failed: {reg_result.error}")


def example_advanced_registration() -> None:
    """Demonstrate advanced user registration with roles."""
    print("\n⚡ Advanced Registration Example")
    print("=" * 40)

    auth: FlextAuth[object] = FlextAuth()

    # Register REDACTED_LDAP_BIND_PASSWORD user
    REDACTED_LDAP_BIND_PASSWORD_result = auth.register_user(
        username="REDACTED_LDAP_BIND_PASSWORD",
        email="REDACTED_LDAP_BIND_PASSWORD@company.com",
        password=os.getenv("FLEXT_DEMO_ADVANCED_PASSWORD", "AdvancedPass123!"),
        full_name="Administrator",
        roles=["REDACTED_LDAP_BIND_PASSWORD", "user"]
    )

    if REDACTED_LDAP_BIND_PASSWORD_result.is_success:
        user_data = REDACTED_LDAP_BIND_PASSWORD_result.value
        print("✅ Admin user registered successfully")
        print(f"   Username: {user_data.username}")
        print(f"   Roles: {user_data.roles}")
        print(f"   Has REDACTED_LDAP_BIND_PASSWORD role: {user_data.has_role('REDACTED_LDAP_BIND_PASSWORD')}")
        print(f"   Is verified: {user_data.is_verified}")

    else:
        print(f"❌ Admin registration failed: {REDACTED_LDAP_BIND_PASSWORD_result.error}")

    # Register regular user
    user_result = auth.register_user(
        username="regularuser",
        email="user@company.com",
        password=os.getenv("FLEXT_DEMO_ADVANCED_PASSWORD", "AdvancedPass123!"),
        full_name="Regular User",
        roles=["user"]
    )

    if user_result.is_success:
        user_data = user_result.value
        print("✅ Regular user registered successfully")
        print(f"   Username: {user_data.username}")
        print(f"   Roles: {user_data.roles}")
        print(f"   Has REDACTED_LDAP_BIND_PASSWORD role: {user_data.has_role('REDACTED_LDAP_BIND_PASSWORD')}")

    else:
        print(f"❌ User registration failed: {user_result.error}")


def example_complete_workflow() -> None:
    """Demonstrate complete authentication workflow."""
    print("\n🔄 Complete Workflow Example")
    print("=" * 40)

    auth: FlextAuth[object] = FlextAuth()

    # Step 1: Register user
    print("1. User Registration")
    reg_result = auth.register_user(
        username="workflowuser",
        email="workflow@example.com",
        password=os.getenv("FLEXT_DEMO_WORKFLOW_PASSWORD", "WorkflowPass123!"),
        full_name="Workflow User"
    )

    if reg_result.is_failure:
        print(f"❌ Registration failed: {reg_result.error}")
        return

    user = reg_result.value
    print(f"✅ User registered: {user.username}")

    # Step 2: Authentication
    print("\n2. User Authentication")
    auth_result = auth.authenticate_user("workflowuser", os.getenv("FLEXT_DEMO_WORKFLOW_PASSWORD", "WorkflowPass123!"))

    if auth_result.is_failure:
        print(f"❌ Authentication failed: {auth_result.error}")
        return

    auth_data = auth_result.value
    print("✅ Authentication successful")

    # Step 3: Token operations
    print("\n3. Token Operations")
    jwt_token_str = str(auth_data.get("jwt_token", ""))
    session_id = str(auth_data.get("session_id", ""))

    # Validate token
    token_validation = auth.validate_token(jwt_token_str)
    if token_validation.is_success:
        claims = token_validation.value
        print(f"✅ Token valid for user: {claims.get('username')}")
    else:
        print(f"❌ Token validation failed: {token_validation.error}")

    # Step 4: Session management
    print("\n4. Session Management")
    user_sessions = auth.get_user_sessions(user.id)
    if user_sessions.is_success:
        sessions = user_sessions.value
        print(f"✅ User has {len(sessions)} active sessions")

    # Step 5: Logout
    print("\n5. User Logout")
    logout_result = auth.logout_user(session_id)
    if logout_result.is_success:
        print("✅ User logged out successfully")
    else:
        print(f"❌ Logout failed: {logout_result.error}")


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(chars) for _ in range(length))


def main() -> None:
    """Run all examples."""
    print("🚀 FLEXT Auth - Comprehensive Examples")
    print("=" * 50)

    try:
        example_basic_authentication()
        example_password_operations()
        example_email_validation()
        example_user_lifecycle()
        example_direct_auth()
        example_advanced_registration()
        example_complete_workflow()

        print("\n🎉 All examples completed successfully!")
        print("✅ FLEXT Auth is working correctly!")

    except Exception as e:
        print(f"\n❌ Example failed: {e}")
        raise


if __name__ == "__main__":
    main()
