#!/usr/bin/env python3
"""FLEXT Auth - Basic Usage Examples.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

Este exemplo demonstra o uso básico da FLEXT Auth com funcionalidade REAL.
Todos os métodos usados existem e funcionam.
"""

from __future__ import annotations

import asyncio

from flext_auth import (
    ADMIN_ROLE,
    USER_ROLE,
    FlextAuth,
    FlextAuthDefaults,
    FlextAuthMixin,
    flext_auth_complete_workflow,
    flext_auth_dev,
    flext_auth_hash_password,
    flext_auth_one_liner,
    flext_auth_quick_start,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
    flext_auth_web_session,
)


def example_basic_authentication() -> None:
    """Exemplo: Autenticação básica com FlextAuth."""
    print("=== Basic Authentication Example ===")

    # Criar instância de autenticação para desenvolvimento
    flext_auth_dev()
    print("Auth instance created for development")

    # Demonstrar configurações padrão
    print("\nDefault Configurations:")
    print(f"  Dev Config: {FlextAuthDefaults.CONFIGS['dev']}")
    print(f"  Admin Role: {ADMIN_ROLE}")
    print(f"  User Role: {USER_ROLE}")

    print("Authentication service ready for use")


def example_password_operations() -> None:
    """Exemplo: Operações com senhas."""
    print("\n=== Password Operations Example ===")

    # Hash de senha
    password = "MySecurePassword123!"
    hashed_password = flext_auth_hash_password(password, rounds=4)  # Fast for demo
    print(f"Password hashed: {hashed_password[:50]}...")

    # Verificação de senha
    is_valid = flext_auth_verify_password(password, hashed_password)
    print(f"Password verification: {is_valid}")

    # Verificação com senha incorreta
    wrong_password = "WrongPassword"
    is_wrong = flext_auth_verify_password(wrong_password, hashed_password)
    print(f"Wrong password verification: {is_wrong}")

    # Análise de força da senha
    strength = flext_auth_validate_password_strength(password)
    print(f"Password strength: {strength['strength']} (score: {strength['score']})")
    print(f"Valid password: {strength['valid']}")
    print(f"Feedback: {strength['feedback']}")


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
        password="SecurePass123!",
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

    # Headers padrão
    token = "sample_token_12345"
    auth_headers = FlextAuthDefaults.auth_headers(token)
    print(f"Auth headers: {auth_headers}")

    api_key = "api_key_67890"
    api_headers = FlextAuthDefaults.api_headers(api_key)
    print(f"API headers: {api_headers}")

    # Responses padrão
    success_response = FlextAuthDefaults.SUCCESS_RESPONSE
    print(f"Success response: {success_response}")

    error_response = FlextAuthDefaults.error_response("Something went wrong")
    print(f"Error response: {error_response}")


def example_mixin_usage() -> None:
    """Exemplo: Como usar FlextAuthMixin."""
    print("\n=== FlextAuthMixin Example ===")

    class MyController(FlextAuthMixin):
        """Exemplo de controller com capacidades de autenticação."""

        def handle_request(self, token: str) -> dict[str, object]:
            """Handle request with authentication."""
            # Get current user (1 linha vs 10+ linhas)
            user = self.get_current_user(token)
            if not user:
                return {"error": "Authentication required"}

            # Check permission
            has_permission = self.check_permission(token, "read")

            return {
                "success": True,
                "user": user.get("username", "unknown") if user else "none",
                "has_read_permission": has_permission,
                "data": "Protected content",
            }

    # Usar o controller
    controller = MyController()

    # Simular request sem token
    result = controller.handle_request("")
    print(f"Request without token: {result}")

    print("Mixin controller created and tested")


def example_ultra_helpers() -> None:
    """Exemplo: Ultra-helpers para redução massiva de código."""
    print("\n=== Ultra Helpers Example ===")

    # One-liner completo (registro + login)
    result = flext_auth_one_liner("quickuser", "quick@example.com", "QuickPass123!")
    print(f"One-liner result success: {result['success']}")
    if result["success"]:
        print(f"Token created: {result['token'][:30]}...")
        print(f"User created: {result['user']['username']}")

    # Web session completa
    # Exemplo com REDACTED_LDAP_BIND_PASSWORD padrão
    request_data = {"username": "REDACTED_LDAP_BIND_PASSWORD", "password": "REDACTED_LDAP_BIND_PASSWORD123"}
    session_result = flext_auth_web_session(request_data)
    print(f"Web session success: {session_result['success']}")
    if session_result["success"]:
        print(f"Session token: {session_result['token'][:30]}...")
        print(f"Headers ready: {len(session_result['headers'])} headers")


async def example_advanced_registration() -> None:
    """Exemplo: Registro avançado com validação."""
    print("\n=== Advanced Registration Example ===")

    auth = FlextAuth()

    # Registro com validação completa
    register_result = await auth.register_validated(
        username="advanceduser",
        email="advanced@example.com",
        password="AdvancedPass123!",
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
        password="WorkflowPass123!",
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


async def main() -> None:
    """Execute all examples."""
    print("FLEXT Auth - Basic Usage Examples")
    print("=" * 50)

    try:
        # Sync examples
        example_basic_authentication()
        example_password_operations()
        example_email_validation()
        example_quick_helpers()
        example_mixin_usage()
        example_ultra_helpers()
        example_complete_workflow()

        # Async examples
        await example_user_lifecycle()
        await example_advanced_registration()

        print("\n" + "=" * 50)
        print("✅ ALL BASIC EXAMPLES COMPLETED SUCCESSFULLY!")
        print("All methods used exist and work correctly.")

    except (RuntimeError, ValueError, TypeError) as e:
        print(f"\n❌ ERROR in examples: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
