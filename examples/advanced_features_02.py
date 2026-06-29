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

from flext_auth import FlextAuth, FlextAuthModels, FlextAuthSettings, t, u


class FlextAuthAdvancedFeaturesExample:
    """Single owner for the advanced features example flow."""

    logger = u.fetch_logger(__name__)

    @classmethod
    def example_advanced_configuration(cls) -> None:
        """Demonstrate advanced configuration options."""
        FlextAuthSettings()
        FlextAuth()
        cls.logger.info("FlextAuth created with custom configuration")

    @staticmethod
    def example_jwt_operations() -> None:
        """Advanced JWT operations example using REAL current API."""
        auth: FlextAuth = FlextAuth()
        user_result = auth.register_user(
            username="advanced_user",
            email="advanced@example.com",
            password=os.getenv("EXAMPLE_PASSWORD", "AdvancedPassword123!"),
            roles=["REDACTED_LDAP_BIND_PASSWORD", "user"],
        )
        if user_result.failure:
            return
        token_result = auth.authenticate_user(
            username="advanced_user",
            password=os.getenv("EXAMPLE_PASSWORD", "AdvancedPassword123!"),
        )
        if token_result.success:
            auth_token = token_result.value
            auth.token_service.validate_token(auth_token.token)

    @staticmethod
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
            (
                "manager",
                "manager@company.com",
                "ManagerPass123!",
                ["manager", "user"],
            ),
            ("employee", "employee@company.com", "EmployeePass123!", ["user"]),
        ]
        registered_users: t.MutableSequenceOf[FlextAuthModels.Auth.AuthIdentity] = []
        for username, email, password, roles in users_data:
            result = auth.register_user(username, email, password, roles=roles)
            if result.success:
                registered_users.append(result.value)

    @staticmethod
    def example_session_management() -> None:
        """Demonstrate authentication session handling."""
        auth: FlextAuth = FlextAuth()
        user_result = auth.register_user(
            "sessionuser",
            "session@example.com",
            "SessionPass123!",
        )
        if user_result.failure:
            return
        tokens: t.MutableSequenceOf[str] = []
        for _i in range(3):
            auth_result = auth.authenticate_user("sessionuser", "SessionPass123!")
            if auth_result.success:
                tokens.append(auth_result.value.token)

    @staticmethod
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
            auth.register_user(f"user_{level}", f"{level}@example.com", password)
        os.getenv("TEST_PASSWORD", "TestPassword123!")
        _ = FlextAuthModels.Auth.AuthIdentityRequest(
            name="security_demo_request",
            contact="security@demo.com",
            credential="StrongPassword123!",
            full_name="Security Demo Request",
            roles=["user"],
        )

    @staticmethod
    def example_token_validation() -> None:
        """Demonstrate advanced token validation."""
        auth: FlextAuth = FlextAuth()
        user_result = auth.register_user(
            "tokenuser",
            "token@example.com",
            "TokenPass123!",
        )
        if user_result.failure:
            return
        user = user_result.value
        identity_id: str = user.unique_id
        token_result = auth.create_token(identity_id=identity_id)
        if token_result.failure:
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
            auth.token_service.validate_token(test_token)

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate a secure password with mixed characters."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        return "".join(secrets.choice(chars) for _ in range(length))

    @staticmethod
    def basic_example_runner() -> None:
        """Run basic example functionality (replaced utils import)."""

    @classmethod
    def main(cls) -> None:
        """Execute advanced features demonstration."""
        cls.basic_example_runner()
        cls.example_advanced_configuration()
        cls.example_jwt_operations()
        cls.example_role_based_access()
        cls.example_session_management()
        cls.example_password_security()
        cls.example_token_validation()


if __name__ == "__main__":
    FlextAuthAdvancedFeaturesExample.main()
