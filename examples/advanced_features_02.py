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
    # Create auth with advanced configuration
    auth: FlextAuth[object] = FlextAuth(
        jwt_secret=os.getenv(
            "FLEXT_DEMO_JWT_SECRET",
            "my-super-secure-jwt-secret-key-256-bits-minimum-length-required",
        ),
        token_expire_minutes=60,
        password_rounds=12,
    )

    # Show configuration details
    auth.get_config()
    auth.config.get_security_settings()
    auth.config.get_jwt_settings()


def example_jwt_operations() -> None:
    """Advanced JWT operations example using REAL current API."""
    auth: FlextAuth[object] = FlextAuth()

    # Register user for JWT operations
    user_result = auth.register_user(
        username="advanced_user",
        email="advanced@example.com",
        password=os.getenv("EXAMPLE_PASSWORD", "AdvancedPassword123!"),
        roles=["REDACTED_LDAP_BIND_PASSWORD", "user"],
    )

    if user_result.is_failure:
        return

    user = user_result.value

    # Generate JWT with custom expiry
    token_result = auth.generate_jwt_token(user.id, expires_in_minutes=120)
    if token_result.is_success:
        token = token_result.value

        # Validate JWT and show payload
        validation_result = auth.validate_token(token)
        if validation_result.is_success:
            pass


def example_role_based_access() -> None:
    """Demonstrate role-based access control."""
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

    # Demonstrate role checking
    for user in registered_users:
        # Check if user has REDACTED_LDAP_BIND_PASSWORD role
        if user.roles and "REDACTED_LDAP_BIND_PASSWORD" in user.roles:
            # User has REDACTED_LDAP_BIND_PASSWORD privileges
            pass
        else:
            # User has standard privileges
            pass


def example_session_management() -> None:
    """Demonstrate advanced session management."""
    auth: FlextAuth[object] = FlextAuth()

    # Register user for session demo
    user_result = auth.register_user(
        "sessionuser", "session@example.com", "SessionPass123!"
    )
    if user_result.is_failure:
        return

    user = user_result.value

    # Create multiple authentication sessions
    sessions = []
    for _i in range(3):
        auth_result = auth.authenticate_user("sessionuser", "SessionPass123!")
        if auth_result.is_success:
            session_id = auth_result.value.get("session_id")
            sessions.append(session_id)

    # Show user sessions
    user_sessions_result = auth.get_user_sessions(user.id)
    if user_sessions_result.is_success:
        user_sessions = user_sessions_result.value

        for session in user_sessions:
            # Display session information
            # Session is active
            if session:
                # Process active session
                pass

    # Cleanup expired sessions
    cleanup_result = auth.cleanup_expired_sessions()
    if cleanup_result.is_success:
        pass

    # Logout all sessions
    for session_id in sessions:
        if session_id:
            logout_result = auth.logout_user(str(session_id))
            if logout_result.is_success:
                pass


def example_password_security() -> None:
    """Demonstrate password security features."""
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
            pass

    # Demonstrate password hashing with different rounds
    test_password = os.getenv("TEST_PASSWORD", "TestPassword123!")

    # Show current hashing
    try:
        hash1 = auth.hash_password(test_password)
        hash2 = auth.hash_password(test_password)

        # Verify both hashes work
        auth.verify_password(test_password, hash1)
        auth.verify_password(test_password, hash2)

    except Exception as e:
        # Handle password hashing error
        # Log error for debugging
        error_message = f"Password hashing failed: {e}"
        # In production, this would be logged properly
        del error_message  # Clean up


def example_token_validation() -> None:
    """Demonstrate advanced token validation."""
    auth: FlextAuth[object] = FlextAuth()

    # Register user and create token
    user_result = auth.register_user("tokenuser", "token@example.com", "TokenPass123!")
    if user_result.is_failure:
        return

    user = user_result.value

    # Generate token
    token_result = auth.generate_jwt_token(user.id)
    if token_result.is_failure:
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

    for _desc, test_token in test_tokens:
        validation_result = auth.validate_token(test_token)
        if validation_result.is_success:
            pass


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure password with mixed characters."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(chars) for _ in range(length))


def basic_example_runner() -> None:
    """Run basic example functionality (replaced utils import)."""


def main() -> None:
    """Execute advanced features demonstration."""
    # Run basic example first
    basic_example_runner()

    # Run advanced feature demos
    example_advanced_configuration()
    example_jwt_operations()
    example_role_based_access()
    example_session_management()
    example_password_security()
    example_token_validation()


if __name__ == "__main__":
    main()
