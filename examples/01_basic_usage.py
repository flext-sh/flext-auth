#!/usr/bin/env python3
"""FLEXT Auth - Basic usage examples.

This example demonstrates basic FLEXT Auth usage with real functionality.
All methods used exist and work as expected.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from example_utils import basic_example_runner

from flext_auth import (
    FlextAuth,
    FlextAuthMixin,
    flext_auth_complete_workflow,
    flext_auth_dev,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
)
from flext_auth.config import AppConfig

# Example constants - not for production use
# These are intentionally hardcoded for demonstration purposes only

EXAMPLE_PASSWORD = "MySecurePassword123!"  # noqa: S105 - Example password for documentation
EXAMPLE_WRONG_PASSWORD = "WrongPassword"  # noqa: S105 - Example password for documentation
EXAMPLE_TOKEN = "sample_token_12345"  # noqa: S105 - Example token for documentation
EXAMPLE_USER_PASSWORD = "SecurePass123!"  # noqa: S105 - Example password for documentation
EXAMPLE_ADVANCED_PASSWORD = "AdvancedPass123!"  # noqa: S105 - Example password for documentation
EXAMPLE_WORKFLOW_PASSWORD = "WorkflowPass123!"  # noqa: S105 - Example password for documentation


def example_basic_authentication() -> None:
    """Demonstrate basic authentication with FlextAuth."""
    # Criar instância de autenticação para desenvolvimento
    flext_auth_dev()

    # Demonstrar configurações padrão

    AppConfig()


def example_password_operations() -> None:
    """Demonstrate password operations."""
    # Hash de senha
    password = EXAMPLE_PASSWORD
    hashed_password = flext_auth_hash_password(password, rounds=4)  # Fast for demo

    # Verificação de senha
    flext_auth_verify_password(password, hashed_password)

    # Verificação com senha incorreta
    wrong_password = EXAMPLE_WRONG_PASSWORD
    flext_auth_verify_password(wrong_password, hashed_password)

    # Análise de força da senha
    strength = flext_auth_validate_password_strength(password)
    if strength["feedback"]:
        pass


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
    # Criar serviço de autenticação
    auth = FlextAuth()

    # Registro de usuário
    register_result = await auth.register(
        username="testuser",
        email="testuser@example.com",
        password=EXAMPLE_USER_PASSWORD,
        role="user",
    )

    if register_result.success:
        # Login do usuário
        login_result = await auth.login("testuser", "SecurePass123!")
        if login_result.success:
            login_data = login_result.data
            access_token = login_data["tokens"]["access_token"]

            # Validação do token
            validation_result = await auth.validate(access_token)
            if validation_result.success:
                pass

            # Logout
            await auth.logout(access_token)


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
    # One-liner completo (registro + login)
    result = flext_auth_complete_workflow(
        "quickuser",
        "quick@example.com",
        "QuickPass123!",
    )
    if result.get("success", False) and "user" in result:
        user_data = result["user"]
        (
            user_data.get("username")
            if isinstance(user_data, dict)
            else getattr(user_data, "username", "N/A")
        )

    # Basic authentication demo
    auth = FlextAuth()
    user_result = auth.register_user("testuser", "test@example.com", "TestPass123!")

    if "error" not in user_result:
        auth.authenticate_user("testuser", "TestPass123!")


async def example_advanced_registration() -> None:
    """Demonstrate advanced registration with validation."""
    auth = FlextAuth()

    # Registro com validação completa
    register_result = await auth.register_validated(
        username="advanceduser",
        email="advanced@example.com",
        password=EXAMPLE_ADVANCED_PASSWORD,
        role="user",
        require_strong_password=True,
    )

    if register_result.success:
        user_data = register_result.data

        if user_data.get("password_strength"):
            user_data["password_strength"]

        # Login e validação em uma operação
        # Login e validação em uma operação
        login_validate_result = await auth.login_and_validate(
            "advanceduser",
            "AdvancedPass123!",
        )
        if login_validate_result.success:
            pass


def example_complete_workflow() -> None:
    """Demonstrate a complete workflow in a single function."""
    # Workflow completo em uma chamada
    workflow_result = flext_auth_complete_workflow(
        username="workflowuser",
        email="workflow@example.com",
        password=EXAMPLE_WORKFLOW_PASSWORD,
        role="user",
    )

    if workflow_result.get("success", False):
        if "user" in workflow_result:
            user_data = workflow_result["user"]
            (
                user_data.get("username")
                if isinstance(user_data, dict)
                else getattr(user_data, "username", "N/A")
            )
        if "token" in workflow_result:
            workflow_result["token"]
        auth_context = workflow_result.get("auth_context")
        auth_context.get("role") if isinstance(auth_context, dict) else "none"


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
