#!/usr/bin/env python3
"""FLEXT Auth - Basic usage examples.

This example demonstrates basic FLEXT Auth usage with real functionality.
All methods used exist and work as expected.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Import everything from public API only - no legacy or internal imports
from flext_auth import (
    FlextAuth,
    FlextAuthMixin,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
    generate_secure_password,
    is_strong_password,
)

# Add examples directory to path for imports
examples_dir = Path(__file__).parent
sys.path.insert(0, str(examples_dir))

from example_utils import basic_example_runner  # noqa: E402

# Example constants - not for production use
# These are intentionally hardcoded for demonstration purposes only

EXAMPLE_PASSWORD = "MySecurePassword123!"  # noqa: S105 - Example password for documentation
EXAMPLE_WRONG_PASSWORD = "WrongPassword"  # noqa: S105 - Example password for documentation
EXAMPLE_TOKEN = "sample_token_12345"  # noqa: S105 - Example token for documentation
EXAMPLE_USER_PASSWORD = "StrongPass123!"  # noqa: S105 - Example password for documentation
EXAMPLE_ADVANCED_PASSWORD = "AdvancedPass123!"  # noqa: S105 - Example password for documentation
EXAMPLE_WORKFLOW_PASSWORD = "WorkflowPass123!"  # noqa: S105 - Example password for documentation


def example_basic_authentication() -> None:
    """Demonstrate basic authentication with FlextAuth."""
    # Criar instância de autenticação para desenvolvimento
    _ = (
        FlextAuth.create_for_testing_with_in_memory()
    )  # Use underscore to indicate intentionally unused variable

    # Demonstrar configurações padrão
    print("Auth service created with default config")


def example_password_operations() -> None:
    """Demonstrate password operations."""
    # Hash de senha
    password = EXAMPLE_PASSWORD
    hashed_password = flext_auth_hash_password(password)  # Uses default rounds

    # Verificação de senha
    is_valid = flext_auth_verify_password(password, hashed_password)
    print(f"Password verification (correct): {is_valid}")

    # Verificação com senha incorreta
    wrong_password = EXAMPLE_WRONG_PASSWORD
    is_invalid = flext_auth_verify_password(wrong_password, hashed_password)
    print(f"Password verification (incorrect): {is_invalid}")

    # Análise de força da senha
    strength = flext_auth_validate_password_strength(password)
    if strength.get("feedback"):
        print(f"Password strength: {strength.get('is_strong')}")

    # Generate secure password
    secure_password = generate_secure_password()
    print(f"Generated secure password: {secure_password[:8]}...")

    # Check password strength
    is_strong = is_strong_password(password)
    print(f"Is strong password: {is_strong}")


def example_email_validation() -> None:
    """Demonstrate email validation."""
    # Emails válidos
    valid_emails = ["user@example.com", "REDACTED_LDAP_BIND_PASSWORD@flext.io", "test.user+tag@domain.co.uk"]
    for email in valid_emails:
        is_valid = flext_auth_validate_email(email)
        print(f"Email {email}: {'valid' if is_valid else 'invalid'}")

    # Emails inválidos
    invalid_emails = ["invalid", "user@", "@domain.com", "user..double@domain.com"]
    for email in invalid_emails:
        is_valid = flext_auth_validate_email(email)
        print(f"Email {email}: {'valid' if is_valid else 'invalid'}")


async def example_user_lifecycle() -> None:
    """Demonstrate a complete user lifecycle."""
    # Criar serviço de autenticação
    auth = FlextAuth.create_for_testing_with_in_memory()
    print("Created FlextAuth instance")

    # Simulate user registration using real async API
    user_result = await auth.create_user(
        "testuser", "testuser@example.com", EXAMPLE_USER_PASSWORD
    )

    if user_result.success:
        print("User created successfully")
        user_data = user_result.value
        if user_data and isinstance(user_data, dict):
            print(f"Created user: {user_data.get('username', 'unknown')}")

    # Simulate authentication using real async API
    auth_result = await auth.authenticate("testuser", EXAMPLE_USER_PASSWORD)
    if auth_result.success:
        print("Authentication successful")
        auth_data = auth_result.value
        if auth_data and isinstance(auth_data, dict):
            print(f"Authenticated user: {auth_data.get('username', 'unknown')}")
    else:
        print("Authentication failed")


def example_quick_helpers() -> None:
    """Demonstrate quick helpers and utilities."""
    # Setup instantâneo
    flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

    # Headers padrão (implementação real)

    # Responses padrão (implementação real)


def example_mixin_usage() -> None:
    """Demonstrate how to use ``FlextAuthMixin``."""

    class MyController(FlextAuthMixin):
        """Example controller with authentication capabilities."""

        def handle_request(self, token: str) -> dict[str, object]:
            """Handle request with authentication - simplified implementation."""
            # Initialize auth for the controller - mixin requires auth_service
            # For demonstration, we'll show the initialization pattern

            # In real usage, you would pass an auth_service instance:
            # auth_service = get_auth_service_from_di_container()
            # init_result = self.init_auth(auth_service=auth_service)

            # For this example, we'll simulate the mixin behavior without actual auth
            init_result_success = False  # Mixin requires dependencies as documented

            return {
                "success": True,
                "message": "Controller demonstrates FlextAuth mixin pattern",
                "auth_initialized": init_result_success,
                "token_provided": bool(token),
                "note": "Mixin requires auth_service parameter for full initialization",
            }

    # Use the controller
    controller = MyController()

    # Test request with and without token
    controller.handle_request("sample_token")

    controller.handle_request("")


def example_ultra_helpers() -> None:
    """Demonstrate ultra-helpers for massive code reduction."""
    # Create authentication service with quick start helper
    auth_service = flext_auth_quick_start()
    print(f"Quick start service created: {auth_service}")

    # Basic authentication demo using real async API
    auth = FlextAuth.create_for_testing_with_in_memory()
    user_result = asyncio.run(
        auth.create_user("testuser", "test@example.com", "TestPass123!")
    )

    if user_result.success:
        print("User created via ultra helper")
        auth_result = asyncio.run(auth.authenticate("testuser", "TestPass123!"))
        if auth_result.success:
            print("Authentication successful via ultra helper")


async def example_advanced_registration() -> None:
    """Demonstrate advanced registration with validation."""
    auth = FlextAuth.create_for_testing_with_in_memory()

    # First validate password strength
    password_strength = flext_auth_validate_password_strength(EXAMPLE_ADVANCED_PASSWORD)
    if password_strength.get("is_strong"):
        print("Password meets strength requirements")

        # Create user with strong password using real async API
        register_result = await auth.create_user(
            "advanceduser", "advanced@example.com", EXAMPLE_ADVANCED_PASSWORD
        )

        if register_result.success:
            print("Advanced user registration successful")
            user_data = register_result.value
            if isinstance(user_data, dict):
                print(f"Registered user: {user_data.get('username', 'unknown')}")

            # Authenticate the newly created user using real async API
            auth_result = await auth.authenticate(
                "advanceduser", EXAMPLE_ADVANCED_PASSWORD
            )
            if auth_result.success:
                print("Advanced user authentication successful")


def example_complete_workflow() -> None:
    """Demonstrate a complete workflow in a single function."""
    # Create service and user in one workflow
    auth = FlextAuth.create_for_testing_with_in_memory()

    # Step 1: Create user using real async API
    user_result = asyncio.run(
        auth.create_user(
            "workflowuser", "workflow@example.com", EXAMPLE_WORKFLOW_PASSWORD
        )
    )

    if user_result.success:
        print("Workflow: User created")

        # Step 2: Authenticate user using real async API
        auth_result = asyncio.run(
            auth.authenticate("workflowuser", EXAMPLE_WORKFLOW_PASSWORD)
        )
        if auth_result.success:
            print("Workflow: Authentication successful")
            auth_data = auth_result.value
            if isinstance(auth_data, dict):
                username = auth_data.get("username", "unknown")
                print(f"Workflow completed for user: {username}")
        else:
            print("Workflow: Authentication failed")
    else:
        print("Workflow: User creation failed")


def main() -> None:
    """Execute all basic examples using the shared runner."""
    # Define sync examples
    sync_examples = [
        example_basic_authentication,
        example_password_operations,
        example_email_validation,
        example_quick_helpers,
        example_mixin_usage,
        example_ultra_helpers,
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
