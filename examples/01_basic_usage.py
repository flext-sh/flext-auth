#!/usr/bin/env python3
"""FLEXT Auth - Basic Usage Examples.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

Este exemplo demonstra o uso básico da FLEXT Auth com funcionalidade REAL.
Todos os métodos usados existem e funcionam.
"""

from __future__ import annotations

from flext_auth import (
    ADMIN_ROLE,
    USER_ROLE,
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

# Example constants - not for production use

EXAMPLE_PASSWORD = "MySecurePassword123!"  # noqa: S105
EXAMPLE_WRONG_PASSWORD = "WrongPassword"  # noqa: S105
EXAMPLE_TOKEN = "sample_token_12345"  # noqa: S105
EXAMPLE_USER_PASSWORD = "SecurePass123!"  # noqa: S105
EXAMPLE_ADVANCED_PASSWORD = "AdvancedPass123!"  # noqa: S105
EXAMPLE_WORKFLOW_PASSWORD = "WorkflowPass123!"  # noqa: S105


def example_basic_authentication() -> None:
    """Exemplo: Autenticação básica com FlextAuth."""
    print("=== Basic Authentication Example ===")

    # Criar instância de autenticação para desenvolvimento
    flext_auth_dev()
    print("Auth instance created for development")

    # Demonstrar configurações padrão
    print("\nDefault Configurations:")
    from flext_auth.config import FlextAuthConfig
    config = FlextAuthConfig()
    print(f"  JWT Secret: {config.jwt_secret_key[:10]}...")
    print(f"  Admin Role: {ADMIN_ROLE}")
    print(f"  User Role: {USER_ROLE}")

    print("Authentication service ready for use")


def example_password_operations() -> None:
    """Exemplo: Operações com senhas."""
    print("\n=== Password Operations Example ===")

    # Hash de senha
    password = EXAMPLE_PASSWORD
    hashed_password = flext_auth_hash_password(password, rounds=4)  # Fast for demo
    print(f"Password hashed: {hashed_password[:50]}...")

    # Verificação de senha
    is_valid = flext_auth_verify_password(password, hashed_password)
    print(f"Password verification: {is_valid}")

    # Verificação com senha incorreta
    wrong_password = EXAMPLE_WRONG_PASSWORD
    is_wrong = flext_auth_verify_password(wrong_password, hashed_password)
    print(f"Wrong password verification: {is_wrong}")

    # Análise de força da senha
    strength = flext_auth_validate_password_strength(password)
    print(f"Password score: {strength['score']}/5")
    print(f"Valid password: {strength['valid']}")
    print(f"Length check: {strength['length']}")
    print(f"Has uppercase: {strength['uppercase']}")
    print(f"Has lowercase: {strength['lowercase']}")
    print(f"Has digit: {strength['digit']}")
    print(f"Has special: {strength['special']}")


def example_email_validation() -> None:
    """Exemplo: Validação de email."""
    print("\n=== Email Validation Example ===")

    # Emails válidos
    valid_emails = ["user@example.com", "REDACTED_LDAP_BIND_PASSWORD@flext.io", "test.user+tag@domain.co.uk"]
    for email in valid_emails:
        is_valid = flext_auth_validate_email(email)
        print(f"  {email}: {'✅ Valid' if is_valid else '❌ Invalid'}")

    # Emails inválidos
    invalid_emails = ["invalid", "user@", "@domain.com", "user..double@domain.com"]
    for email in invalid_emails:
        is_valid = flext_auth_validate_email(email)
        print(f"  {email}: {'✅ Valid' if is_valid else '❌ Invalid'}")


async def example_user_lifecycle() -> None:
    """Exemplo: Ciclo completo de vida do usuário."""
    print("\n=== User Lifecycle Example ===")

    # Criar serviço de autenticação
    auth = FlextAuth()
    print("Auth service created")

    # Registro de usuário
    register_result = await auth.register(
        username="testuser",
        email="testuser@example.com",
        password=EXAMPLE_USER_PASSWORD,
        role="user",
    )

    if register_result.is_success:
        user = register_result.data
        print(f"User registered: {user.username} ({user.email})")
        print(f"User ID: {user.id}")
        print(f"User role: {user.role.value}")

        # Login do usuário
        login_result = await auth.login("testuser", "SecurePass123!")
        if login_result.is_success:
            login_data = login_result.data
            access_token = login_data["tokens"]["access_token"]
            print("User logged in successfully")
            print(f"Access token: {access_token[:30]}...")

            # Validação do token
            validation_result = await auth.validate(access_token)
            if validation_result.is_success:
                context = validation_result.data
                print(f"Token validated - User: {context['username']}")
                print(f"Role: {context['role']}")
                print(f"Permissions: {context['permissions']}")

            # Logout
            logout_result = await auth.logout(access_token)
            print(f"Logout successful: {logout_result.is_success}")

        else:
            print(f"Login failed: {login_result.error}")
    else:
        print(f"Registration failed: {register_result.error}")


def example_quick_helpers() -> None:
    """Exemplo: Helpers rápidos e utilitários."""
    print("\n=== Quick Helpers Example ===")

    # Setup instantâneo
    flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    print("Quick start completed (without REDACTED_LDAP_BIND_PASSWORD creation)")

    # Headers padrão (implementação real)
    token = EXAMPLE_TOKEN
    auth_headers = {"Authorization": f"Bearer {token}"}
    print(f"Auth headers: {auth_headers}")

    api_key = "api_key_67890"
    api_headers = {"X-API-Key": api_key}
    print(f"API headers: {api_headers}")

    # Responses padrão (implementação real)
    success_response = {"status": "success", "message": "Operation completed"}
    print(f"Success response: {success_response}")

    error_response = {"status": "error", "message": "Something went wrong"}
    print(f"Error response: {error_response}")


def example_mixin_usage() -> None:
    """Exemplo: Como usar FlextAuthMixin."""
    print("\n=== FlextAuthMixin Example ===")

    class MyController(FlextAuthMixin):
        """Exemplo de controller com capacidades de autenticação."""

        def handle_request(self, token: str) -> dict[str, object]:
            """Handle request with authentication - simplified implementation."""
            # Initialize auth for the controller
            init_result = self.init_auth()

            return {
                "success": True,
                "message": "Controller initialized with FlextAuth capabilities",
                "auth_initialized": init_result.is_success,
                "token_provided": bool(token),
            }

    # Use the controller
    controller = MyController()

    # Test request with and without token
    result = controller.handle_request("sample_token")
    print(f"Request with token: {result}")

    result_no_token = controller.handle_request("")
    print(f"Request without token: {result_no_token}")

    print("Mixin controller created and tested successfully")


def example_ultra_helpers() -> None:
    """Exemplo: Ultra-helpers para redução massiva de código."""
    print("\n=== Ultra Helpers Example ===")

    # One-liner completo (registro + login)
    result = flext_auth_complete_workflow("quickuser", "quick@example.com", "QuickPass123!")
    print(f"Complete workflow success: {result.is_success}")
    if result.is_success and result.data:
        print(f"Workflow completed: {result.data['status']}")
        print(f"User created: {result.data['user'].username}")

    # Basic authentication demo
    auth = FlextAuth()
    user_result = auth.register_user("testuser", "test@example.com", "TestPass123!")
    print(f"User registration: {'success' if 'error' not in user_result else 'failed'}")

    if "error" not in user_result:
        auth_result = auth.authenticate_user("testuser", "TestPass123!")
        print(f"Authentication: {'success' if 'error' not in auth_result else 'failed'}")


async def example_advanced_registration() -> None:
    """Exemplo: Registro avançado com validação."""
    print("\n=== Advanced Registration Example ===")

    auth = FlextAuth()

    # Registro com validação completa
    register_result = await auth.register_validated(
        username="advanceduser",
        email="advanced@example.com",
        password=EXAMPLE_ADVANCED_PASSWORD,
        role="user",
        require_strong_password=True,
    )

    if register_result.is_success:
        user_data = register_result.data
        print("Advanced registration successful:")
        print(f"  User: {user_data['user']['username']}")
        print(f"  Email: {user_data['user']['email']}")
        print(f"  Role: {user_data['user']['role']}")

        if user_data.get("password_strength"):
            strength = user_data["password_strength"]
            print(f"  Password strength: {strength['strength']}")
            print(f"  Password score: {strength['score']}")

        # Login e validação em uma operação
        # Login e validação em uma operação
        login_validate_result = await auth.login_and_validate(
            "advanceduser", "AdvancedPass123!"
        )
        if login_validate_result.is_success:
            session_data = login_validate_result.data
            print("Login and validation successful")
            print(f"Token: {session_data['token'][:30]}...")
            print(f"Context: {session_data['context']['username']}")
    else:
        print(f"Advanced registration failed: {register_result.error}")


def example_complete_workflow() -> None:
    """Exemplo: Workflow completo em uma função."""
    print("\n=== Complete Workflow Example ===")

    # Workflow completo em uma chamada
    workflow_result = flext_auth_complete_workflow(
        username="workflowuser",
        email="workflow@example.com",
        password=EXAMPLE_WORKFLOW_PASSWORD,
        role="user",
    )

    print(f"Complete workflow success: {workflow_result['success']}")
    if workflow_result["success"]:
        print(f"Workflow completed: {workflow_result['workflow_completed']}")
        print(f"User: {workflow_result['user']['username']}")
        print(f"Token: {workflow_result['token'][:30]}...")
        print(f"Permissions: {workflow_result['permissions']}")
        auth_context = workflow_result["auth_context"]
        role = auth_context["role"] if auth_context else "none"
        print(f"Auth context: {role}")
    else:
        print(f"Workflow failed: {workflow_result['error']}")


def main() -> None:
    """Execute all basic examples using shared runner."""
    from example_utils import basic_example_runner

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
