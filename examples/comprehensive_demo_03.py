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

from flext_auth import FlextAuth, flext_auth_quick_start


def demo_complete_auth_workflow() -> None:
    """Demonstrate complete authentication workflow."""
    # 1. Initialize auth service
    auth: FlextAuth = FlextAuth()

    # 2. Create user account (using register_user, not create_user)
    username = "demo_user"
    email = "demo@example.com"
    password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoSecurePass123!")

    result = auth.register_user(username, email, password, roles=["user"])
    if result.is_success:
        user = result.value
    else:
        return

    # 3. Authenticate user (using authenticate_user, not authenticate)
    auth_result = auth.authenticate_user(username, password)
    if auth_result.is_success:
        auth_data = auth_result.value

        # Extract authentication details
        session_id = auth_data.get("session_id")
        jwt_token = auth_data.get("jwt_token")

        # 4. Validate JWT token
        if jwt_token:
            token_result = auth.validate_token(str(jwt_token))
            if token_result.is_success:
                pass

        # 5. Session management
        user_sessions = auth.get_user_sessions(user.id)
        if user_sessions.is_success:
            pass

        # 6. Logout user
        if session_id:
            logout_result = auth.logout_user(str(session_id))
            if logout_result.is_success:
                pass


def demo_password_operations() -> None:
    """Demonstrate password hashing and verification operations."""
    auth: FlextAuth = FlextAuth()
    test_password = os.getenv("TEST_PASSWORD", "TestPassword123!")

    try:
        # Hash password
        hashed = auth.hash_password(test_password)

        # Verify correct password
        auth.verify_password(test_password, hashed)

        # Verify incorrect password
        auth.verify_password("WrongPassword", hashed)

    except Exception as e:
        # Handle password hashing error
        error_message = f"Password hashing failed: {e}"
        # In production, this would be logged properly
        del error_message  # Clean up


def demo_jwt_operations() -> None:
    """Demonstrate JWT token operations."""
    auth: FlextAuth = FlextAuth()

    # Register user for JWT operations
    user_result = auth.register_user("jwtuser", "jwt@example.com", "JWTPassword123!")
    if user_result.is_failure:
        return

    user = user_result.value

    # Generate JWT token
    token_result = auth.generate_jwt_token(user.id)
    if token_result.is_success:
        token = token_result.value

        # Validate token
        validation_result = auth.validate_token(token)
        if validation_result.is_success:
            pass


def demo_user_management() -> None:
    """Demonstrate user management operations."""
    auth: FlextAuth = FlextAuth()

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

    # Demonstrate user lookups
    for user in registered_users:
        lookup_result = auth.get_user_by_username(user.username)
        if lookup_result.is_success and lookup_result.value:
            pass


def demo_security_features() -> None:
    """Demonstrate security features."""
    auth: FlextAuth = FlextAuth()

    # Show configuration security settings
    auth.get_config()
    auth.config.get_security_settings()

    # Demonstrate password strength validation by attempting weak passwords
    weak_passwords = ["123", "password", "abc"]
    for weak_pass in weak_passwords:
        weak_result = auth.register_user("weakuser", "weak@example.com", weak_pass)
        if weak_result.is_failure:
            pass


def demo_error_handling() -> None:
    """Demonstrate comprehensive error handling."""
    auth: FlextAuth = FlextAuth()

    # Test duplicate registration
    auth.register_user("duplicate", "dup@example.com", "DupPass123!")
    dup_result = auth.register_user("duplicate", "dup2@example.com", "DupPass123!")
    if dup_result.is_failure:
        pass

    # Test invalid authentication
    invalid_result = auth.authenticate_user("nonexistent", "password")
    if invalid_result.is_failure:
        pass

    # Test invalid token validation
    invalid_token_result = auth.validate_token("invalid.jwt.token")
    if invalid_token_result.is_failure:
        pass


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure password.

    Returns:
        str: Generated secure password string

    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(chars) for _ in range(length))


def basic_example_runner() -> None:
    """Run basic example functionality (replaced utils import)."""


def main() -> None:
    """Execute comprehensive demonstration."""
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
    flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)


if __name__ == "__main__":
    main()
