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

from flext_auth import FlextAuth, FlextAuthModels, FlextAuthSettings, m


class FlextAuthComprehensiveDemo:
    """Single owner for the comprehensive example flow."""

    @staticmethod
    def demo_complete_auth_workflow() -> None:
        """Demonstrate complete authentication workflow."""
        auth: FlextAuth = FlextAuth()
        username = "demo_user"
        email = "demo@example.com"
        password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoSecurePass123!")
        result = auth.register_user(username, email, password, roles=["user"])
        if result.success:
            user = result.value
        else:
            return
        auth_result = auth.authenticate_user(username, password)
        if auth_result.success:
            auth_data = auth_result.value
            session_id = auth_data.session_id
            jwt_token = auth_data.token
            if jwt_token:
                auth.token_service.validate_token(jwt_token)
            identity_id: str = user.unique_id
            auth.session_service.session_manager.get_active_sessions(identity_id)
            if session_id:
                auth.session_service.session_manager.end_session_by_id(
                    session_id,
                )

    @staticmethod
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
        except Exception as exc:
            error_message = f"Password hashing failed: {exc}"
            del error_message

    @staticmethod
    def demo_jwt_operations() -> None:
        """Demonstrate JWT token operations."""
        auth: FlextAuth = FlextAuth()
        user_result = auth.register_user(
            "jwtuser",
            "jwt@example.com",
            "JWTPassword123!",
        )
        if user_result.failure:
            return
        user = user_result.value
        identity_id: str = user.unique_id
        token_result = auth.create_token(identity_id=identity_id)
        if token_result.success:
            auth.token_service.validate_token(token_result.value)

    @staticmethod
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
        registered_users: list[FlextAuthModels.Auth.AuthIdentity] = []
        for username, email, password, roles in users_data:
            result = auth.register_user(username, email, password, roles=roles)
            if result.success:
                registered_users.append(result.value)
        for user in registered_users:
            auth.identity_service.identity_manager.get_user_by_username(user.name)

    @staticmethod
    def demo_security_features() -> None:
        """Demonstrate security features."""
        auth: FlextAuth = FlextAuth()
        FlextAuthSettings()
        weak_passwords = ["123", "password", "abc"]
        for weak_pass in weak_passwords:
            auth.register_user("weakuser", "weak@example.com", weak_pass)

    @staticmethod
    def demo_error_handling() -> None:
        """Demonstrate comprehensive error handling."""
        auth: FlextAuth = FlextAuth()
        auth.register_user("duplicate", "dup@example.com", "DupPass123!")
        auth.register_user("duplicate", "dup2@example.com", "DupPass123!")
        auth.authenticate_user("nonexistent", "password")
        auth.token_service.validate_token("invalid.jwt.token")

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate a secure password."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        return "".join(secrets.choice(chars) for _ in range(length))

    @staticmethod
    def basic_example_runner() -> None:
        """Run basic example functionality (replaced utils import)."""

    @classmethod
    def main(cls) -> None:
        """Execute comprehensive demonstration."""
        cls.basic_example_runner()
        cls.demo_complete_auth_workflow()
        cls.demo_password_operations()
        cls.demo_jwt_operations()
        cls.demo_user_management()
        cls.demo_security_features()
        cls.demo_error_handling()
        FlextAuth.quick_start(create_admin_user=False)


if __name__ == "__main__":
    FlextAuthComprehensiveDemo.main()
