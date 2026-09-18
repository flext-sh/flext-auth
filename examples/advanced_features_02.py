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

from flext_auth import FlextAuth, FlextAuthModels, FlextAuthSettings, p, r, t, u


def _demo_credential(prefix: str) -> str:
    """Per-run demo credential; the example never embeds a reusable secret."""
    return f"{prefix}-{secrets.token_hex(6)}"


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
    def example_jwt_operations() -> p.Result[None]:
        """Advanced JWT operations example using REAL current API."""
        auth: FlextAuth = FlextAuth()
        demo_password = os.getenv("EXAMPLE_PASSWORD") or _demo_credential("jwt")
        user_result = auth.register_user(
            username="advanced_user",
            email="advanced@example.com",
            password=demo_password,
            roles=["admin", "user"],
        )
        if user_result.failure:
            return r[None].from_failure(user_result)
        auth_result = auth.authenticate_user(
            username="advanced_user",
            password=demo_password,
        )
        if auth_result.success:
            auth_token = auth_result.value
            auth.token_service.validate_token(auth_token.token)
        return r[None].ok(None)

    @staticmethod
    def example_role_based_access() -> None:
        """Demonstrate role-based access control."""
        auth: FlextAuth = FlextAuth()
        users_data = [
            (
                "admin",
                "admin@company.com",
                _demo_credential("admin"),
                ["admin", "user"],
            ),
            (
                "manager",
                "manager@company.com",
                _demo_credential("manager"),
                ["manager", "user"],
            ),
            ("employee", "employee@company.com", _demo_credential("employee"), ["user"]),
        ]
        registered_users: t.MutableSequenceOf[FlextAuthModels.Auth.AuthIdentity] = []
        for username, email, password, roles in users_data:
            result = auth.register_user(username, email, password, roles=roles)
            if result.success:
                registered_users.append(result.value)

    @staticmethod
    def example_session_management() -> p.Result[None]:
        """Demonstrate authentication session handling."""
        auth: FlextAuth = FlextAuth()
        session_password = _demo_credential("session")
        user_result = auth.register_user(
            "sessionuser", "session@example.com", session_password
        )
        if user_result.failure:
            return r[None].from_failure(user_result)
        invalid_sessions: t.MutableSequenceOf[str] = []
        for _i in range(3):
            auth_result = auth.authenticate_user("sessionuser", session_password)
            if auth_result.success:
                invalid_sessions.append(auth_result.value.token)
        return r[None].ok(None)

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
    def example_token_validation() -> p.Result[None]:
        """Demonstrate advanced token validation."""
        auth: FlextAuth = FlextAuth()
        user_result = auth.register_user(
            "tokenuser", "token@example.com", _demo_credential("token")
        )
        if user_result.failure:
            return r[None].from_failure(user_result)
        user = user_result.value
        identity_id: str = user.unique_id
        token_result = auth.create_token(identity_id=identity_id)
        if token_result.failure:
            return r[None].from_failure(token_result)
        auth_token = token_result.value
        expired_test_tokens = [
            ("Valid token", auth_token),
            ("Bearer token", f"Bearer {auth_token}"),
            ("Invalid format", "invalid.token.format"),
            ("Empty token", ""),
            ("Malformed JWT", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid"),
        ]
        for _desc, test_token in expired_test_tokens:
            auth.token_service.validate_token(test_token)
        return r[None].ok(None)

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
