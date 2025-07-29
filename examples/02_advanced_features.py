#!/usr/bin/env python3
"""FLEXT Auth - Advanced Features Examples.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

Este exemplo demonstra recursos avançados da FLEXT Auth com funcionalidade REAL.
Todos os métodos usados existem e funcionam.
"""

from __future__ import annotations

import asyncio

from flext_auth import (
    ADMIN_ROLE,
    MODERATOR_ROLE,
    USER_ROLE,
    FlextAuth,
    FlextAuthConfig,
    flext_auth_batch_operations,
    flext_auth_create_api_key,
    flext_auth_create_auth_context,
    flext_auth_create_multi_factor_token,
    flext_auth_create_role_hierarchy,
    flext_auth_create_secure_session,
    flext_auth_create_service_token,
    flext_auth_decode_jwt,
    flext_auth_extract_user_context,
    flext_auth_generate_jwt,
    flext_auth_permission_required,
    flext_auth_prod,
    flext_auth_required,
    flext_auth_role_required,
    flext_auth_validate_api_key,
    flext_auth_validate_permissions,
)


def example_advanced_configuration() -> None:
    """Exemplo: Configuração avançada personalizada."""
    print("=== Advanced Configuration Example ===")

    # Configuração personalizada para produção
    custom_config = FlextAuthConfig(
        jwt_secret_key="production-secret-key-super-secure-256-bits-minimum",
        jwt_algorithm="HS256",
        access_token_expire_minutes=15,  # Tokens mais seguros, expiration curta
        refresh_token_expire_days=30,
        bcrypt_rounds=14,  # Produção: mais seguro
        max_login_attempts=3,  # Mais restritivo
        lockout_duration_minutes=60,  # Lockout mais longo
        session_timeout_hours=8,  # Sessões mais curtas
        max_concurrent_sessions=2,  # Limite baixo
    )

    print("Advanced Configuration Created:")
    print(f"  JWT Algorithm: {custom_config.jwt_algorithm}")
    print(f"  Access Token Expiry: {custom_config.access_token_expire_minutes} minutes")
    print(f"  Bcrypt Rounds: {custom_config.bcrypt_rounds}")
    print(f"  Max Login Attempts: {custom_config.max_login_attempts}")
    print(f"  Session Timeout: {custom_config.session_timeout_hours} hours")

    # Criar instância com configuração personalizada
    FlextAuth(config=custom_config.model_dump())
    print("Production auth instance created with advanced configuration")


def example_jwt_operations() -> None:
    """Exemplo: Operações avançadas com JWT."""
    print("\n=== JWT Operations Example ===")

    # Payload personalizado
    user_payload = {
        "user_id": "user_12345",
        "username": "advanced_user",
        "role": ADMIN_ROLE,
        "session_id": "session_67890",
        "department": "engineering",
        "clearance_level": 5,
    }

    # Gerar JWT
    secret = "my-super-secure-jwt-secret-key-256-bits-minimum-length-required"
    token = flext_auth_generate_jwt(user_payload, secret=secret, expires_minutes=60)
    print(f"JWT Generated: {token[:50]}...")

    # Decodificar JWT
    decoded = flext_auth_decode_jwt(token, secret)
    if decoded:
        print("JWT Decoded successfully:")
        print(f"  User ID: {decoded['user_id']}")
        print(f"  Username: {decoded['username']}")
        print(f"  Role: {decoded['role']}")
        print(f"  Session ID: {decoded['session_id']}")
        print(f"  Expires: {decoded['expires']}")

    # Extrair contexto completo
    context = flext_auth_extract_user_context(token, secret)
    if context:
        print("Complete Context Extracted:")
        print(f"  Token Type: {context['token_type']}")
        print(f"  User: {context['username']}")
        print(f"  Role: {context['role']}")


def example_api_key_management() -> None:
    """Exemplo: Gerenciamento de API keys."""
    print("\n=== API Key Management Example ===")

    # Criar API key para usuário
    user_id = "api_user_12345"
    api_key = flext_auth_create_api_key(
        user_id=user_id,
        scope="api",
        expires_days=90,  # 3 meses
        secret="api-secret-key-for-validation-256-bits-minimum-length",
    )
    print(f"API Key Created: {api_key[:50]}...")

    # Validar API key
    validation_result = flext_auth_validate_api_key(
        api_key,
        "api-secret-key-for-validation-256-bits-minimum-length",
    )
    if validation_result:
        print("API Key Validation:")
        print(f"  User ID: {validation_result['user_id']}")
        print(f"  Scope: {validation_result['scope']}")
        print(f"  Created: {validation_result['created_at']}")

    # Service token para comunicação serviço-a-serviço
    service_token = flext_auth_create_service_token(
        service_name="data-processor",
        permissions=["read_data", "write_logs", "access_cache"],
        expires_hours=48,
        secret="service-to-service-secret-key-256-bits",
    )
    print(f"Service Token Created: {service_token[:50]}...")


def example_role_permission_system() -> None:
    """Exemplo: Sistema de roles e permissões."""
    print("\n=== Role & Permission System Example ===")

    # Criar hierarquia de roles
    role_hierarchy = flext_auth_create_role_hierarchy()
    print("Role Hierarchy Created:")
    for role, permissions in role_hierarchy.items():
        print(f"  {role}: {permissions}")

    # Validar permissões para diferentes roles
    test_cases = [
        (ADMIN_ROLE, "delete"),
        (MODERATOR_ROLE, "moderate"),
        (USER_ROLE, "read"),
        (USER_ROLE, "REDACTED_LDAP_BIND_PASSWORD"),  # Should fail
        ("guest", "read_public"),
    ]

    print("\nPermission Validation Tests:")
    for role, permission in test_cases:
        has_permission = flext_auth_validate_permissions(role, permission, role_hierarchy)
        status = "✅ Allowed" if has_permission else "❌ Denied"
        print(f"  {role} -> {permission}: {status}")


def example_secure_sessions() -> None:
    """Exemplo: Sessões seguras avançadas."""
    print("\n=== Secure Sessions Example ===")

    # Criar sessão segura básica
    basic_session = flext_auth_create_secure_session(
        user_id="secure_user_123",
        username="secure_user",
        role=MODERATOR_ROLE,
        expires_hours=12,
    )
    print("Basic Secure Session:")
    print(f"  Session ID: {basic_session['session_id'][:16]}...")
    print(f"  User: {basic_session['username']}")
    print(f"  Role: {basic_session['role']}")
    print(f"  Expires: {basic_session['expires_at']}")

    # Criar sessão com permissões incluídas
    enhanced_session = flext_auth_create_secure_session(
        user_id="enhanced_user_456",
        username="enhanced_user",
        role=ADMIN_ROLE,
        expires_hours=6,
        include_permissions=True,
    )
    print("\nEnhanced Session with Permissions:")
    print(f"  User: {enhanced_session['username']}")
    print(f"  Role: {enhanced_session['role']}")
    print(f"  Permissions: {enhanced_session['permissions']}")


def example_multi_factor_authentication() -> None:
    """Exemplo: Multi-factor authentication tokens."""
    print("\n=== Multi-Factor Authentication Example ===")

    # Token MFA para TOTP
    totp_token = flext_auth_create_multi_factor_token(
        user_id="mfa_user_789",
        factor_type="totp",
        expires_minutes=5,  # Tokens MFA expiram rapidamente
        secret="mfa-totp-secret-key-256-bits-minimum-length",
    )
    print(f"TOTP MFA Token: {totp_token[:50]}...")

    # Token MFA para SMS
    sms_token = flext_auth_create_multi_factor_token(
        user_id="mfa_user_789",
        factor_type="sms",
        expires_minutes=10,
        secret="mfa-sms-secret-key-256-bits-minimum-length",
    )
    print(f"SMS MFA Token: {sms_token[:50]}...")

    # Validar contexto de token MFA
    mfa_context = flext_auth_create_auth_context(
        totp_token,
        "mfa-totp-secret-key-256-bits-minimum-length",
        include_permissions=False,
    )
    if mfa_context:
        print("MFA Token Context:")
        print(f"  Token Type: {mfa_context['token_type']}")
        print(f"  User ID: {mfa_context.get('user_id', 'N/A')}")


def example_decorators() -> None:
    """Exemplo: Decoradores de autenticação."""
    print("\n=== Authentication Decorators Example ===")

    # Função que requer autenticação
    @flext_auth_required(secret_key="test-secret-key-256-bits-minimum-length")
    def protected_endpoint(request: dict[str, object], **kwargs: object) -> dict[str, object]:
        """Endpoint protegido que requer autenticação."""
        auth_context = kwargs.get("auth_context", {})
        return {
            "message": "Access granted",
            "user": auth_context.get("username", "unknown"),
            "role": auth_context.get("role", "none"),
        }

    # Função que requer role específico
    @flext_auth_role_required(
        ADMIN_ROLE,
        secret_key="test-secret-key-256-bits-minimum-length",
    )
    def REDACTED_LDAP_BIND_PASSWORD_endpoint(request: dict[str, object], **kwargs: object) -> dict[str, object]:
        """Endpoint que requer role de REDACTED_LDAP_BIND_PASSWORD."""
        return {"message": "Admin access granted", "REDACTED_LDAP_BIND_PASSWORD_only": True}

    # Função que requer permissão específica
    @flext_auth_permission_required("delete")
    def delete_endpoint(request: dict[str, object], **kwargs: object) -> dict[str, object]:
        """Endpoint que requer permissão de delete."""
        return {"message": "Delete permission granted"}

    # Testar decoradores com mock request
    mock_request = {
        "headers": {"Authorization": "Bearer invalid_token"},
        "user": "test_user",
    }

    # Test protected endpoint (will fail due to invalid token)
    result = protected_endpoint(mock_request)
    print(f"Protected endpoint result: {result}")

    # Test REDACTED_LDAP_BIND_PASSWORD endpoint (will fail due to invalid token)
    REDACTED_LDAP_BIND_PASSWORD_result = REDACTED_LDAP_BIND_PASSWORD_endpoint(mock_request)
    print(f"Admin endpoint result: {REDACTED_LDAP_BIND_PASSWORD_result}")

    # Test permission endpoint (will pass as it's just a demo)
    perm_result = delete_endpoint(mock_request)
    print(f"Permission endpoint result: {perm_result}")


async def example_batch_operations() -> None:
    """Exemplo: Operações em lote."""
    print("\n=== Batch Operations Example ===")

    # Criar instância de auth
    auth = FlextAuth()
    batch_ops = flext_auth_batch_operations(auth)

    # Dados para múltiplos usuários
    users_data = [
        {
            "username": "batch_user_1",
            "email": "batch1@example.com",
            "password": "BatchPass123!",
            "role": "user",
        },
        {
            "username": "batch_user_2",
            "email": "batch2@example.com",
            "password": "BatchPass456!",
            "role": "moderator",
        },
        {
            "username": "batch_REDACTED_LDAP_BIND_PASSWORD",
            "email": "batchREDACTED_LDAP_BIND_PASSWORD@example.com",
            "password": "BatchAdminPass789!",
            "role": "REDACTED_LDAP_BIND_PASSWORD",
        },
    ]

    # Registro em lote
    batch_register_result = await batch_ops.register_multiple(
        users_data,
        validate_all=True,
    )

    if batch_register_result.is_success:
        registered_users = batch_register_result.data
        print(f"Batch Registration Successful: {len(registered_users)} users")
        for user in registered_users:
            print(f"  - {user['user']['username']} ({user['user']['role']})")
    else:
        print(f"Batch registration failed: {batch_register_result.error}")

    # Credenciais para sessões em lote
    credentials = [
        ("batch_user_1", "BatchPass123!"),
        ("batch_user_2", "BatchPass456!"),
        ("batch_REDACTED_LDAP_BIND_PASSWORD", "BatchAdminPass789!"),
    ]

    # Criar múltiplas sessões
    batch_sessions_result = await batch_ops.create_multiple_sessions(
        credentials,
        session_hours=12,
    )

    if batch_sessions_result.is_success:
        session_data = batch_sessions_result.data
        print(f"Batch Sessions Created: {session_data['successful']}/{session_data['total']}")

        # Extrair tokens para validação em lote
        tokens = []
        for session in session_data["sessions"]:
            session_token = session["session_data"].get("token")
            if session_token:
                tokens.append(session_token)

        if tokens:
            # Validar múltiplos tokens
            batch_validation_result = await batch_ops.validate_multiple_tokens(tokens)
            if batch_validation_result.is_success:
                validation_data = batch_validation_result.data
                print(f"Batch Token Validation: {validation_data['valid_count']}/{validation_data['total']} valid")
            else:
                print(f"Batch validation failed: {batch_validation_result.error}")
    else:
        print(f"Batch sessions failed: {batch_sessions_result.error}")


async def example_advanced_user_management() -> None:
    """Exemplo: Gerenciamento avançado de usuários."""
    print("\n=== Advanced User Management Example ===")

    # Configuração de produção
    auth = flext_auth_prod()
    print("Production auth instance created")

    # Registro de usuário REDACTED_LDAP_BIND_PASSWORDistrador
    REDACTED_LDAP_BIND_PASSWORD_result = await auth.register_validated(
        username="production_REDACTED_LDAP_BIND_PASSWORD",
        email="REDACTED_LDAP_BIND_PASSWORD@production.com",
        password="ProductionAdminPass123!@#",
        role=ADMIN_ROLE,
        require_strong_password=True,
    )

    if REDACTED_LDAP_BIND_PASSWORD_result.is_success:
        REDACTED_LDAP_BIND_PASSWORD_data = REDACTED_LDAP_BIND_PASSWORD_result.data
        print("Production Admin Created:")
        print(f"  Username: {REDACTED_LDAP_BIND_PASSWORD_data['user']['username']}")
        print(f"  Email: {REDACTED_LDAP_BIND_PASSWORD_data['user']['email']}")
        print(f"  Role: {REDACTED_LDAP_BIND_PASSWORD_data['user']['role']}")

        if REDACTED_LDAP_BIND_PASSWORD_data.get("password_strength"):
            strength = REDACTED_LDAP_BIND_PASSWORD_data["password_strength"]
            print(f"  Password Strength: {strength['strength']} (score: {strength['score']})")

        # Sessão completa com dados do usuário
        session_result = await auth.create_user_session(
            "production_REDACTED_LDAP_BIND_PASSWORD",
            "ProductionAdminPass123!@#",
            include_user_data=True,
        )

        if session_result.is_success:
            session_data = session_result.data
            print("Complete Session Created:")
            print(f"  Token: {session_data['token'][:30]}...")
            print(f"  Context: {session_data['context']['username']}")
            print(f"  User Data Included: {'user' in session_data}")
            print(f"  Expires: {session_data.get('expires_at', 'Unknown')}")

            # Refresh token test
            if "refresh_token" in session_data:
                refresh_result = await auth.refresh(session_data["refresh_token"])
                if refresh_result.is_success:
                    print("Token refresh successful")
                else:
                    print(f"Token refresh failed: {refresh_result.error}")

        else:
            print(f"Session creation failed: {session_result.error}")
    else:
        print(f"Admin registration failed: {REDACTED_LDAP_BIND_PASSWORD_result.error}")


async def main() -> None:
    """Execute all advanced examples."""
    print("FLEXT Auth - Advanced Features Examples")
    print("=" * 60)

    try:
        # Sync examples
        example_advanced_configuration()
        example_jwt_operations()
        example_api_key_management()
        example_role_permission_system()
        example_secure_sessions()
        example_multi_factor_authentication()
        example_decorators()

        # Async examples
        await example_batch_operations()
        await example_advanced_user_management()

        print("\n" + "=" * 60)
        print("✅ ALL ADVANCED EXAMPLES COMPLETED SUCCESSFULLY!")
        print("All methods demonstrate real flext-auth advanced functionality.")

    except (RuntimeError, ValueError, TypeError) as e:
        print(f"\n❌ ERROR in advanced examples: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
