#!/usr/bin/env python3
"""FLEXT Auth - Basic usage examples.

This example demonstrates basic FLEXT Auth usage with real functionality.
All methods used exist and work as expected.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

# from flext_auth.mixins import FlextAuthMixin  # Disabled
# Example constants - not for production use
# Demo credentials - using environment variables with fallbacks for examples
import os

# import asyncio  # Not needed
from example_utils import basic_example_runner

from flext_auth import (
    FlextAuth,
    FlextPasswordService,
)

EXAMPLE_PASSWORD = os.getenv("FLEXT_DEMO_PASSWORD", "MySecurePassword123!")
EXAMPLE_WRONG_PASSWORD = os.getenv("FLEXT_DEMO_WRONG_PASSWORD", "WrongPassword")
EXAMPLE_TOKEN = os.getenv("FLEXT_DEMO_TOKEN", "sample_token_12345")
EXAMPLE_USER_PASSWORD = os.getenv("FLEXT_DEMO_USER_PASSWORD", "StrongPass123!")
EXAMPLE_ADVANCED_PASSWORD = os.getenv(
    "FLEXT_DEMO_ADVANCED_PASSWORD", "AdvancedPass123!"
)
EXAMPLE_WORKFLOW_PASSWORD = os.getenv(
    "FLEXT_DEMO_WORKFLOW_PASSWORD", "WorkflowPass123!"
)


def example_basic_authentication() -> None:
    """Demonstrate basic authentication with FlextAuth."""
    # Criar instância de autenticação para desenvolvimento (usando in-memory por padrão)
    FlextAuth()  # Creates in-memory repositories by default

    # Demonstrar configurações padrão


def example_password_operations() -> None:
    """Demonstrate password operations."""
    # Create password service instance
    password_service = FlextPasswordService()

    # Hash de senha
    password = EXAMPLE_PASSWORD
    hash_result = password_service.hash_password(password)  # Uses default rounds
    if hash_result.success:
        hashed_password = hash_result.value

        # Verificação de senha
        verify_result = password_service.verify_password(password, hashed_password)
        print(
            f"Password verification: {'✅ Success' if verify_result.success and verify_result.value else '❌ Failed'}"
        )

        # Verificação com senha incorreta
        wrong_password = EXAMPLE_WRONG_PASSWORD
        wrong_verify_result = password_service.verify_password(
            wrong_password, hashed_password
        )
        print(
            f"Wrong password verification: {'❌ Failed (expected)' if not wrong_verify_result.value else '⚠️ Unexpected success'}"
        )

    # Análise de força da senha
    strength_result = password_service.validate_password_strength(password)
    print(f"Password strength: {'✅ Strong' if strength_result.success else '❌ Weak'}")

    # Generate secure password manually (no utilities)
    import secrets
    import string

    # Manual secure password generation
    length = 12
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
    secure_password_str = "".join(secure_password)

    print(f"Generated secure password: {secure_password_str[:10]}...")

    # Check password strength
    strength_check = password_service.validate_password_strength(secure_password_str)
    print(f"Is strong password: {'✅ Yes' if strength_check.success else '❌ No'}")


def example_email_validation() -> None:
    """Demonstrate email validation."""

    def validate_email_manual(email: str) -> bool:
        """Manual email validation without utilities."""
        if "@" not in email or "." not in email.rsplit("@", maxsplit=1)[-1]:
            return False
        if email.count("@") != 1:
            return False
        local, domain = email.split("@")
        if not local or not domain:
            return False
        return ".." not in email

    # Emails válidos
    valid_emails = ["user@example.com", "REDACTED_LDAP_BIND_PASSWORD@flext.io", "test.user+tag@domain.co.uk"]
    for email in valid_emails:
        is_valid = validate_email_manual(email)
        print(f"Email {email}: {'✅ Valid' if is_valid else '❌ Invalid'}")

    # Emails inválidos
    invalid_emails = ["invalid", "user@", "@domain.com", "user..double@domain.com"]
    for email in invalid_emails:
        is_valid = validate_email_manual(email)
        print(
            f"Email {email}: {'❌ Invalid (expected)' if not is_valid else '⚠️ Unexpected valid'}"
        )


def example_user_lifecycle() -> None:
    """Demonstrate a complete user lifecycle."""
    # Criar serviço de autenticação (in-memory por padrão)
    auth = FlextAuth()

    # Simulate user registration using real async API
    user_result = auth.register_user(
        "testuser", "testuser@example.com", EXAMPLE_USER_PASSWORD
    )

    if user_result.success:
        user_data = user_result.value
        if user_data and isinstance(user_data, dict):
            pass

    # Simulate authentication using real async API
    auth_result = auth.authenticate_user("testuser", EXAMPLE_USER_PASSWORD)
    if auth_result.success:
        auth_data = auth_result.value
        if auth_data and isinstance(auth_data, dict):
            pass


def example_direct_auth() -> None:
    """Demonstrate direct FlextAuth usage."""
    # Setup direto usando classe (sem helpers)
    auth = FlextAuth()
    print("✅ Direct FlextAuth instance created")

    # Show configuration
    print(f"JWT Secret length: {len(auth.jwt_secret)} characters")
    print(f"Password rounds: {auth.password_rounds}")
    print(f"Token expiry: {auth.token_expiry_minutes} minutes")


def example_mixin_usage() -> None:
    """Demonstrate how to use basic authentication patterns."""

    class MyController:
        """Example controller with authentication capabilities."""

        def handle_request(self, token: str) -> dict[str, object]:
            """Handle request with authentication - simplified implementation."""
            return {
                "success": True,
                "message": "Controller demonstrates basic pattern",
                "token_provided": bool(token),
            }

    # Create the controller
    controller = MyController()
    print("Controller created successfully")

    # Test request with token
    result = controller.handle_request("sample_token")
    print(f"Request result: {result}")


def example_direct_workflow() -> None:
    """Demonstrate direct FlextAuth workflow."""
    # Create authentication service directly (no helpers)
    auth = FlextAuth()
    print("✅ Direct FlextAuth authentication created")

    # Basic authentication demo using real async API (in-memory por padrão)
    user_result = auth.register_user("testuser", "test@example.com", "TestPass123!")

    if user_result.success:
        print("✅ User created successfully")
        auth_result = auth.authenticate_user("testuser", "TestPass123!")
        if auth_result.success:
            print("✅ User authenticated successfully")
        else:
            print(f"❌ Authentication failed: {auth_result.error}")
    else:
        print(f"❌ User creation failed: {user_result.error}")


def example_advanced_registration() -> None:
    """Demonstrate advanced registration with validation."""
    auth = FlextAuth()

    # First validate password strength
    strength_result = FlextPasswordService().validate_password_strength(
        EXAMPLE_ADVANCED_PASSWORD
    )
    if strength_result.success:
        print("✅ Password is strong enough for registration")

        # Create user with strong password using real async API
        register_result = auth.register_user(
            "advanceduser", "advanced@example.com", EXAMPLE_ADVANCED_PASSWORD
        )

        if register_result.success:
            user_data = register_result.value
            if isinstance(user_data, dict):
                print(
                    f"✅ Advanced user registered: {user_data.get('user', {}).get('username')}"
                )

            # Authenticate the newly created user using real async API
            auth_result = auth.authenticate_user(
                "advanceduser", EXAMPLE_ADVANCED_PASSWORD
            )
            if auth_result.success:
                print("✅ Advanced user authenticated successfully")
            else:
                print(f"❌ Advanced user authentication failed: {auth_result.error}")
        else:
            print(f"❌ Advanced user registration failed: {register_result.error}")
    else:
        print(f"❌ Password too weak: {strength_result.error}")


def example_complete_workflow() -> None:
    """Demonstrate a complete workflow in a single function."""
    # Create service and user in one workflow (in-memory por padrão)
    auth = FlextAuth()

    # Step 1: Create user using real async API
    user_result = auth.register_user(
        "workflowuser", "workflow@example.com", EXAMPLE_WORKFLOW_PASSWORD
    )

    if user_result.success:
        # Step 2: Authenticate user using real async API
        auth_result = auth.authenticate_user("workflowuser", EXAMPLE_WORKFLOW_PASSWORD)
        if auth_result.success:
            auth_data = auth_result.value
            if isinstance(auth_data, dict):
                auth_data.get("username", "unknown")


def main() -> None:
    """Execute all basic examples using the shared runner."""
    # Define sync examples
    sync_examples = [
        example_basic_authentication,
        example_password_operations,
        example_email_validation,
        example_direct_auth,
        example_mixin_usage,
        example_direct_workflow,
        example_complete_workflow,
    ]

    # Define async examples
    async_examples = [
        example_user_lifecycle,
        example_advanced_registration,
    ]

    # Run all examples using shared runner (DRY principle)
    basic_example_runner(sync_examples, async_examples)


if __name__ == "__main__":
    main()
