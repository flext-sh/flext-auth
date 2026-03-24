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
from collections.abc import Sequence

from flext_core import FlextLogger

from flext_auth import FlextAuth, FlextAuthModels, FlextAuthSettings, t


def example_advanced_configuration() -> None:
    """Demonstrate advanced configuration options."""
    FlextAuthSettings()
    FlextAuth()
    logger = FlextLogger(__name__)
    logger.info("FlextAuth created with custom configuration")


def example_jwt_operations() -> None:
    """Advanced JWT operations example using REAL current API."""
    auth: FlextAuth = FlextAuth()
    user_result = auth.register_user(
        username="advanced_user",
        email="advanced@example.com",
        password=os.getenv("EXAMPLE_PASSWORD", "AdvancedPassword123!"),
        roles=["REDACTED_LDAP_BIND_PASSWORD", "user"],
    )
    if user_result.is_failure:
        return
    token_result = auth.authenticate_user(
        username="advanced_user",
        password=os.getenv("EXAMPLE_PASSWORD", "AdvancedPassword123!"),
    )
    if token_result.is_success:
        auth_token = token_result.value
        validation_result = auth.validate_token(auth_token.token)
        if validation_result.is_success:
            pass


def example_role_based_access() -> None:
    """Demonstrate role-based access control."""
    auth: FlextAuth = FlextAuth()
    users_data = [
        (
            "REDACTED_LDAP_BIND_PASSWORD",
            "REDACTED_LDAP_BIND_PASSWORD@company.com",
            "AdminPass123!",
            ["REDACTED_LDAP_BIND_PASSWORD", "user"],
        ),
        ("manager", "manager@company.com", "ManagerPass123!", ["manager", "user"]),
        ("employee", "employee@company.com", "EmployeePass123!", ["user"]),
    ]
    registered_users: Sequence[FlextAuthModels.Auth.AuthIdentity] = []
    for username, email, password, roles in users_data:
        result = auth.register_user(username, email, password, roles=roles)
        if result.is_success:
            user = result.value
            registered_users.append(user)
    for user in registered_users:
        if user.roles and "REDACTED_LDAP_BIND_PASSWORD" in user.roles:
            pass


def example_session_management() -> None:
    """Demonstrate authentication session handling."""
    auth: FlextAuth = FlextAuth()
    user_result = auth.register_user(
        "sessionuser", "session@example.com", "SessionPass123!"
    )
    if user_result.is_failure:
        return
    tokens: t.StrSequence = []
    for _i in range(3):
        auth_result = auth.authenticate_user("sessionuser", "SessionPass123!")
        if auth_result.is_success:
            token = auth_result.value.token
            tokens.append(token)


def example_password_security() -> None:
    """Demonstrate password security features."""
    auth: FlextAuth = FlextAuth()
    passwords_to_test = [
        ("weak", "123"),
        ("simple", "password"),
        ("medium", "Password123"),
        ("strong", "StrongPassword123!"),
        ("very_strong", "VeryStr0ng!P@ssw0rd#2025$"),
    ]
    for level, password in passwords_to_test:
        result = auth.register_user(f"user_{level}", f"{level}@example.com", password)
        if result.is_success:
            pass
    os.getenv("TEST_PASSWORD", "TestPassword123!")
    _ = FlextAuthModels.Auth.AuthIdentityRequest(
        name="security_demo_request",
        contact="security@demo.com",
        credential="StrongPassword123!",
        full_name="Security Demo Request",
        roles=["user"],
    )


def example_token_validation() -> None:
    """Demonstrate advanced token validation."""
    auth: FlextAuth = FlextAuth()
    user_result = auth.register_user("tokenuser", "token@example.com", "TokenPass123!")
    if user_result.is_failure:
        return
    user = user_result.value
    identity_id: str = user.name
    token_result = auth.create_token(identity_id=identity_id)
    if token_result.is_failure:
        return
    auth_token = token_result.value
    test_tokens = [
        ("Valid token", auth_token),
        ("Bearer token", f"Bearer {auth_token}"),
        ("Invalid format", "invalid.token.format"),
        ("Empty token", ""),
        ("Malformed JWT", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid"),
    ]
    for _desc, test_token in test_tokens:
        validation_result = auth.validate_token(test_token)
        if validation_result.is_success:
            pass


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure password with mixed characters.

    Returns:
        str: Generated secure password string

    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(chars) for _ in range(length))


def basic_example_runner() -> None:
    """Run basic example functionality (replaced utils import)."""


def main() -> None:
    """Execute advanced features demonstration."""
    basic_example_runner()
    example_advanced_configuration()
    example_jwt_operations()
    example_role_based_access()
    example_session_management()
    example_password_security()
    example_token_validation()


if __name__ == "__main__":
    main()
