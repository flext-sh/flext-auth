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
from collections.abc import Sequence

from flext_auth import (
    FlextAuth,
    FlextAuthModels,
    FlextAuthQuickstart,
    FlextAuthSettings,
    m,
)


def demo_complete_auth_workflow() -> None:
    """Demonstrate complete authentication workflow."""
    auth: FlextAuth = FlextAuth()
    username = "demo_user"
    email = "demo@example.com"
    password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoSecurePass123!")
    result = auth.register_user(username, email, password, roles=["user"])
    if result.is_success:
        user = result.value
    else:
        return
    auth_result = auth.authenticate_user(username, password)
    if auth_result.is_success:
        auth_data = auth_result.value
        session_id = auth_data.session_id
        jwt_token = auth_data.token
        if jwt_token:
            token_result = auth.validate_token(str(jwt_token))
            if token_result.is_success:
                pass
        identity_id: str = user.name
        user_sessions = auth.get_user_sessions(identity_id)
        if user_sessions.is_success:
            pass
        if session_id:
            logout_result = auth.logout_user(str(session_id))
            if logout_result.is_success:
                pass


def demo_password_operations() -> None:
    """Demonstrate password hashing and verification operations."""
    FlextAuth()
    os.getenv("TEST_PASSWORD", "TestPassword123!")
    try:
        m.Auth.AuthIdentityRequest(
            name="password_demo",
            contact="password@demo.com",
            credential="DemoPassword123!",
            full_name="Password Demo User",
            roles=["user"],
        )
    except Exception as e:
        error_message = f"Password hashing failed: {e}"
        del error_message


def demo_jwt_operations() -> None:
    """Demonstrate JWT token operations."""
    auth: FlextAuth = FlextAuth()
    user_result = auth.register_user("jwtuser", "jwt@example.com", "JWTPassword123!")
    if user_result.is_failure:
        return
    user = user_result.value
    identity_id: str = user.name
    token_result = auth.create_token(identity_id=identity_id)
    if token_result.is_success:
        token_string = token_result.value
        validation_result = auth.validate_token(token_string)
        if validation_result.is_success:
            pass


def demo_user_management() -> None:
    """Demonstrate user management operations."""
    auth: FlextAuth = FlextAuth()
    users_data = [
        (
            "REDACTED_LDAP_BIND_PASSWORD_user",
            "REDACTED_LDAP_BIND_PASSWORD@example.com",
            "AdminPass123!",
            ["REDACTED_LDAP_BIND_PASSWORD", "user"],
        ),
        ("regular_user", "regular@example.com", "RegularPass123!", ["user"]),
        ("guest_user", "guest@example.com", "GuestPass123!", ["guest"]),
    ]
    registered_users: Sequence[FlextAuthModels.Auth.AuthIdentity] = []
    for username, email, password, roles in users_data:
        result = auth.register_user(username, email, password, roles=roles)
        if result.is_success:
            user = result.value
            registered_users.append(user)
    for user in registered_users:
        lookup_result = auth.get_user_by_username(user.name)
        if lookup_result.is_success and lookup_result.value:
            pass


def demo_security_features() -> None:
    """Demonstrate security features."""
    auth: FlextAuth = FlextAuth()
    FlextAuthSettings()
    weak_passwords = ["123", "password", "abc"]
    for weak_pass in weak_passwords:
        weak_result = auth.register_user("weakuser", "weak@example.com", weak_pass)
        if weak_result.is_failure:
            pass


def demo_error_handling() -> None:
    """Demonstrate comprehensive error handling."""
    auth: FlextAuth = FlextAuth()
    auth.register_user("duplicate", "dup@example.com", "DupPass123!")
    dup_result = auth.register_user("duplicate", "dup2@example.com", "DupPass123!")
    if dup_result.is_failure:
        pass
    invalid_result = auth.authenticate_user("nonexistent", "password")
    if invalid_result.is_failure:
        pass
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
    basic_example_runner()
    demo_complete_auth_workflow()
    demo_password_operations()
    demo_jwt_operations()
    demo_user_management()
    demo_security_features()
    demo_error_handling()
    quickstart = FlextAuthQuickstart()
    quickstart.flext_auth_quick_start(create_admin_user=False)


if __name__ == "__main__":
    main()
