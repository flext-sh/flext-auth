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

from example_utils import basic_example_runner

# Example constants - not for production use
# These are intentionally hardcoded for demonstration purposes only

EXAMPLE_PASSWORD = "MySecurePassword123!"
EXAMPLE_WRONG_PASSWORD = "WrongPassword"
EXAMPLE_TOKEN = "sample_token_12345"
EXAMPLE_USER_PASSWORD = "StrongPass123!"
EXAMPLE_ADVANCED_PASSWORD = "AdvancedPass123!"
EXAMPLE_WORKFLOW_PASSWORD = "WorkflowPass123!"


def example_basic_authentication() -> None:
    """Demonstrate basic authentication with FlextAuth."""
    # Criar instância de autenticação para desenvolvimento (usando in-memory por padrão)
    FlextAuth()  # Creates in-memory repositories by default

    # Demonstrar configurações padrão


def example_password_operations() -> None:
    """Demonstrate password operations."""
    # Hash de senha
    password = EXAMPLE_PASSWORD
    hashed_password = flext_auth_hash_password(password)  # Uses default rounds

    # Verificação de senha
    flext_auth_verify_password(password, hashed_password)

    # Verificação com senha incorreta
    wrong_password = EXAMPLE_WRONG_PASSWORD
    flext_auth_verify_password(wrong_password, hashed_password)

    # Análise de força da senha - use unwrap_or pattern
    flext_auth_validate_password_strength(password).unwrap_or(False)

    # Generate secure password
    generate_secure_password()

    # Check password strength
    is_strong_password(password)


def example_email_validation() -> None:
    """Demonstrate email validation."""
    # Emails válidos
    valid_emails = ["user@example.com", "REDACTED_LDAP_BIND_PASSWORD@flext.io", "test.user+tag@domain.co.uk"]
    for email in valid_emails:
        flext_auth_validate_email(email)

    # Emails inválidos
    invalid_emails = ["invalid", "user@", "@domain.com", "user..double@domain.com"]
    for email in invalid_emails:
        flext_auth_validate_email(email)


async def example_user_lifecycle() -> None:
    """Demonstrate a complete user lifecycle."""
    # Criar serviço de autenticação (in-memory por padrão)
    auth = FlextAuth()

    # Simulate user registration using real async API
    user_result = await auth.create_user(
        "testuser", "testuser@example.com", EXAMPLE_USER_PASSWORD
    )

    if user_result.success:
        user_data = user_result.value
        if user_data and isinstance(user_data, dict):
            pass

    # Simulate authentication using real async API
    auth_result = await auth.authenticate("testuser", EXAMPLE_USER_PASSWORD)
    if auth_result.success:
        auth_data = auth_result.value
        if auth_data and isinstance(auth_data, dict):
            pass


def example_quick_helpers() -> None:
    """Demonstrate quick helpers and utilities."""
    # Setup instantâneo (não precisa create_REDACTED_LDAP_BIND_PASSWORD, usa padrão)
    flext_auth_quick_start()

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
    flext_auth_quick_start()

    # Basic authentication demo using real async API (in-memory por padrão)
    auth = FlextAuth()
    user_result = asyncio.run(
        auth.create_user("testuser", "test@example.com", "TestPass123!")
    )

    if user_result.success:
        auth_result = asyncio.run(auth.authenticate("testuser", "TestPass123!"))
        if auth_result.success:
            pass


async def example_advanced_registration() -> None:
    """Demonstrate advanced registration with validation."""
    auth = FlextAuth()

    # First validate password strength - use unwrap_or pattern
    is_strong = flext_auth_validate_password_strength(
        EXAMPLE_ADVANCED_PASSWORD
    ).unwrap_or(False)
    if is_strong:
        # Create user with strong password using real async API
        register_result = await auth.create_user(
            "advanceduser", "advanced@example.com", EXAMPLE_ADVANCED_PASSWORD
        )

        if register_result.success:
            user_data = register_result.value
            if isinstance(user_data, dict):
                pass

            # Authenticate the newly created user using real async API
            auth_result = await auth.authenticate(
                "advanceduser", EXAMPLE_ADVANCED_PASSWORD
            )
            if auth_result.success:
                pass


def example_complete_workflow() -> None:
    """Demonstrate a complete workflow in a single function."""
    # Create service and user in one workflow (in-memory por padrão)
    auth = FlextAuth()

    # Step 1: Create user using real async API
    user_result = asyncio.run(
        auth.create_user(
            "workflowuser", "workflow@example.com", EXAMPLE_WORKFLOW_PASSWORD
        )
    )

    if user_result.success:
        # Step 2: Authenticate user using real async API
        auth_result = asyncio.run(
            auth.authenticate("workflowuser", EXAMPLE_WORKFLOW_PASSWORD)
        )
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
