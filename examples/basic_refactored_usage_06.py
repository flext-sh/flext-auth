"""FLEXT Auth - Basic usage examples with refactored API.

This example demonstrates basic FLEXT Auth usage with the new clean architecture.
All methods used exist and work as expected with the refactored library.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import secrets
import string

from flext_auth import FlextAuth, m, p
from flext_cli import u as cli_u


def _emit(message: str) -> None:
    """Emit example output through the canonical CLI facade."""
    cli_u.Cli.formatters_print(message)


class FlextAuthDemo:
    """Demo class using Extract Method Pattern to reduce complexity."""

    def __init__(self) -> None:
        """Initialize demo with FlextAuth instance."""
        super().__init__()
        self.auth = FlextAuth()

    def demo_user_authentication(self) -> p.Result[p.Auth.AuthIdentity]:
        """Extract Method: User authentication demo.

        Returns:
            r[p.AuthToken]: Authentication result

        """
        result = self.auth.authenticate_user("demouser", "DemoPassword123!")
        if result.success:
            auth_data = result.value
            self._print_token_info(auth_data)
        return result

    def demo_user_registration(self) -> p.Result[p.Auth.AuthIdentity]:
        """Extract Method: User registration demo.

        Returns:
            r[p.Identity]: Registration result

        """
        return self.auth.register_user(
            username="demouser",
            email="demo@example.com",
            password=os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!"),
            roles=["user"],
        )

    def _print_token_info(self, auth_data: p.Auth.AuthIdentity) -> None:
        """Print token information."""
        token_length = len(auth_data.token) if auth_data.token else 0
        _emit(f"Token length: {token_length}")

    def demo_password_utilities(self) -> None:
        """Demo password utilities and validation."""
        _ = os.getenv("FLEXT_DEMO_TEST_PASSWORD", "TestPassword123!")
        try:
            _ = m.Auth.AuthIdentityRequest(
                name="util_demo",
                contact="util@demo.com",
                credential="TestPassword123!",
                full_name="Util Demo User",
                roles=["user"],
            )
        except Exception as error:
            error_message = f"Password hashing failed: {error}"
            del error_message

    @staticmethod
    def demo_secure_password_generation() -> None:
        """Demo secure password generation."""
        length = 16
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = '!@#$%^&*(),.?":{}|<>'
        secure_password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special),
        ]
        all_chars = lowercase + uppercase + digits + special
        secure_password.extend(secrets.choice(all_chars) for _ in range(length - 4))
        secrets.SystemRandom().shuffle(secure_password)
        _ = "".join(secure_password)

    @staticmethod
    def demo_email_validation() -> None:
        """Demo email validation."""
        test_emails = ["valid@example.com", "invalid.email", "test@domain.co.uk"]

        def validate_email_manual(email: str) -> bool:
            """Manual email validation without helpers."""
            if "@" not in email or "." not in email.rsplit("@", maxsplit=1)[-1]:
                return False
            if email.count("@") != 1:
                return False
            local, domain = email.split("@")
            if not local or not domain:
                return False
            return ".." not in email

        for email in test_emails:
            _ = validate_email_manual(email)

    def demo_jwt_operations(self) -> None:
        """Demo JWT token operations."""
        jwt_user_result = self.auth.register_user(
            username="jwtuser",
            email="jwt@example.com",
            password=os.getenv("JWT_PASSWORD", "JWTPassword123!"),
        )
        if jwt_user_result.success:
            user = jwt_user_result.value
            identity_id: str = user.unique_id
            token_result = self.auth.create_token(identity_id=identity_id)
            if token_result.success:
                token_string = token_result.value
                self.auth.token_service.validate_token(token_string)

    @classmethod
    def main(cls) -> None:
        """Execute the refactored demo flow."""
        demo = cls()
        registration_result = demo.demo_user_registration()
        if registration_result.failure:
            return
        auth_result = demo.demo_user_authentication()
        if auth_result.failure:
            return
        auth_data = auth_result.value
        access_token = auth_data.token or ""
        demo.auth.token_service.validate_token(access_token)
        demo.demo_password_utilities()
        demo.demo_secure_password_generation()
        demo.demo_email_validation()
        demo.demo_jwt_operations()


if __name__ == "__main__":
    try:
        FlextAuthDemo.main()
    except KeyboardInterrupt:
        raise SystemExit(0) from None
    except (RuntimeError, ValueError, OSError):
        raise SystemExit(1) from None
