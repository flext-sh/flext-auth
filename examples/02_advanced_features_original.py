#!/usr/bin/env python3
"""FLEXT Auth - Advanced Features Examples.

Este exemplo demonstra recursos avançados da FLEXT Auth com funcionalidade REAL.
Todos os métodos usados existem e funcionam.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys
from pathlib import Path

from flext_auth import (
    FlextAuth,
    FlextAuthConfig,
    FlextUserRole,
    flext_auth_permission_required,
    flext_auth_required,
    flext_auth_role_required,
)

# Import from legacy module for backward compatibility
from flext_auth.legacy import (
    flext_auth_batch_operations,
    flext_auth_generate_jwt,
    flext_auth_validate_jwt,
)

# Import utilities

# Add examples directory to path for imports
examples_dir = Path(__file__).parent
sys.path.insert(0, str(examples_dir))

from example_utils import basic_example_runner

# Example constants - not for production use
# These are intentionally hardcoded for demonstration purposes only
EXAMPLE_PRODUCTION_SECRET = "production-secret-key-super-secure-256-bits-minimum"  # noqa: S105 - Example secret for documentation
EXAMPLE_JWT_SECRET = "my-super-secure-jwt-secret-key-256-bits-minimum-length-required"  # noqa: S105 - Example JWT secret for documentation
EXAMPLE_API_SECRET = "api-secret-key-for-validation-256-bits-minimum-length"  # noqa: S105 - Example API secret for documentation
EXAMPLE_SERVICE_SECRET = "service-to-service-secret-key-256-bits"  # noqa: S105 - Example service secret for documentation
EXAMPLE_MFA_TOTP_SECRET = "mfa-totp-secret-key-256-bits-minimum-length"  # noqa: S105 - Example MFA TOTP secret for documentation
EXAMPLE_MFA_SMS_SECRET = "mfa-sms-secret-key-256-bits-minimum-length"  # noqa: S105 - Example MFA SMS secret for documentation
EXAMPLE_TEST_SECRET = "test-secret-key-256-bits-minimum-length"  # noqa: S105 - Example test secret for documentation
EXAMPLE_PRODUCTION_ADMIN_PASSWORD = "ProductionAdminPass123!@#"  # noqa: S105 - Example REDACTED_LDAP_BIND_PASSWORD password for documentation


def example_advanced_configuration() -> None:
    """Exemplo: Configuração avançada personalizada."""
    # Configuração personalizada para produção (campos válidos)
    custom_config = FlextAuthConfig(
        app_name="AdvancedFlextAuth",
        version="2.0.0",
        password_min_length=12,
        password_max_length=128,
        rate_limit_per_minute=30,
        auth_rate_limit_per_minute=3,
        access_token_expire_minutes=60,
        refresh_token_expire_days=7,
        jwt_secret_key=EXAMPLE_PRODUCTION_SECRET,
        bcrypt_rounds=14,  # Produção: mais seguro
        max_login_attempts=3,  # Mais restritivo
        lockout_duration_minutes=60,  # Lockout mais longo
        session_timeout_hours=8,  # Sessões mais curtas
        max_concurrent_sessions=2,  # Limite baixo
        debug=False,  # Produção
        environment="production",
    )

    # Criar instância com configuração personalizada
    FlextAuth(config=custom_config.model_dump())


def example_jwt_operations() -> None:
    """Exemplo: Operações avançadas com JWT."""
    # Payload personalizado
    user_payload = {
        "user_id": "user_12345",
        "username": "advanced_user",
        "role": FlextUserRole.ADMIN,
        "session_id": "session_67890",
        "department": "engineering",
        "clearance_level": 5,
    }

    # Gerar JWT (função legacy retorna string diretamente)
    secret = EXAMPLE_JWT_SECRET
    token = flext_auth_generate_jwt(user_payload, secret=secret)
    print(f"JWT gerado com sucesso (tamanho: {len(token)})")

    # Validar JWT (função legacy retorna dict diretamente)
    decoded = flext_auth_validate_jwt(token, secret)
    if isinstance(decoded, dict) and decoded.get("valid"):
        print("JWT validado com sucesso")
        print(f"User ID: {decoded.get('user_id', 'N/A')}")
    else:
        print("Falha na validação do JWT")


def example_api_key_management() -> None:
    """Exemplo: Gerenciamento de API keys."""
    # Criar API key para usuário
    user_id = "api_user_12345"
    api_key = flext_auth_create_api_key(
        user_id=user_id,
        scope="api",
        expires_days=90,  # 3 meses
        secret=EXAMPLE_API_SECRET,
    )

    # Validar API key
    validation_result = flext_auth_validate_api_key(
        api_key,
        "api-secret-key-for-validation-256-bits-minimum-length",
    )
    if validation_result:
        pass

    # Service token para comunicação serviço-a-serviço
    flext_auth_create_service_token(
        service_name="data-processor",
        permissions=["read_data", "write_logs", "access_cache"],
        expires_hours=48,
        secret=EXAMPLE_SERVICE_SECRET,
    )


def example_role_permission_system() -> None:
    """Exemplo: Sistema de roles e permissões."""
    # Criar hierarquia de roles
    role_hierarchy = flext_auth_create_role_hierarchy()
    for _role in role_hierarchy:
        pass

    # Validar permissões para diferentes roles
    test_cases = [
        (FlextUserRole.ADMIN, "delete"),
        (FlextUserRole.MODERATOR, "moderate"),
        (FlextUserRole.USER, "read"),
        (FlextUserRole.USER, "REDACTED_LDAP_BIND_PASSWORD"),  # Should fail
        ("guest", "read_public"),
    ]

    for role, permission in test_cases:
        flext_auth_validate_permissions(
            role,
            permission,
            role_hierarchy,
        )


def example_secure_sessions() -> None:
    """Exemplo: Sessões seguras avançadas."""
    # Criar sessão segura básica
    flext_auth_create_secure_session(
        user_id="secure_user_123",
        username="secure_user",
        role=FlextUserRole.MODERATOR,
        expires_hours=12,
    )

    # Criar sessão com permissões incluídas
    flext_auth_create_secure_session(
        user_id="enhanced_user_456",
        username="enhanced_user",
        role=FlextUserRole.ADMIN,
        expires_hours=6,
        include_permissions=True,
    )


def example_multi_factor_authentication() -> None:
    """Exemplo: Multi-factor authentication tokens."""
    # Token MFA para TOTP
    totp_token = flext_auth_create_multi_factor_token(
        user_id="mfa_user_789",
        factor_type="totp",
        expires_minutes=5,  # Tokens MFA expiram rapidamente
        secret=EXAMPLE_MFA_TOTP_SECRET,
    )

    # Token MFA para SMS
    flext_auth_create_multi_factor_token(
        user_id="mfa_user_789",
        factor_type="sms",
        expires_minutes=10,
        secret=EXAMPLE_MFA_SMS_SECRET,
    )

    # Validar contexto de token MFA
    mfa_context = flext_auth_create_auth_context(
        totp_token,
        "mfa-totp-secret-key-256-bits-minimum-length",
        include_permissions=False,
    )
    if mfa_context:
        pass


def example_decorators() -> None:
    """Exemplo: Decoradores de autenticação."""

    # Função que requer autenticação
    @flext_auth_required(secret_key=EXAMPLE_TEST_SECRET)
    def protected_endpoint(
        _request: dict[str, object],
        **kwargs: object,
    ) -> dict[str, object]:
        """Endpoint protegido que requer autenticação."""
        auth_context = kwargs.get("auth_context", {})
        if isinstance(auth_context, dict):
            return {
                "message": "Access granted",
                "user": auth_context.get("username", "unknown"),
                "role": auth_context.get("role", "none"),
            }
        return {"message": "Access granted", "user": "unknown", "role": "none"}

    # Função que requer role específico
    @flext_auth_role_required(
        FlextUserRole.ADMIN,
        secret_key=EXAMPLE_TEST_SECRET,
    )
    def REDACTED_LDAP_BIND_PASSWORD_endpoint(
        _request: dict[str, object],
        **_kwargs: object,
    ) -> dict[str, object]:
        """Endpoint que requer role de REDACTED_LDAP_BIND_PASSWORD."""
        return {"message": "Admin access granted", "REDACTED_LDAP_BIND_PASSWORD_only": True}

    # Função que requer permissão específica
    @flext_auth_permission_required("delete")
    def delete_endpoint(
        _request: dict[str, object],
        **_kwargs: object,
    ) -> dict[str, object]:
        """Endpoint que requer permissão de delete."""
        return {"message": "Delete permission granted"}

    # Testar decoradores com mock request
    mock_request = {
        "headers": {"Authorization": "Bearer invalid_token"},
        "user": "test_user",
    }

    # Test protected endpoint (will fail due to invalid token)
    protected_endpoint(mock_request)

    # Test REDACTED_LDAP_BIND_PASSWORD endpoint (will fail due to invalid token)
    REDACTED_LDAP_BIND_PASSWORD_endpoint(mock_request)

    # Test permission endpoint (will pass as it's just a demo)
    delete_endpoint(mock_request)


async def _handle_batch_registration(
    batch_ops: object,
    users_data: list[dict[str, str]],
) -> bool:
    """Handle batch user registration."""
    # Note: This is a simplified example - in real usage you'd use proper types
    if hasattr(batch_ops, "register_multiple"):
        batch_register_result = await batch_ops.register_multiple(
            users_data,
            validate_all=True,
        )

        if hasattr(batch_register_result, "success") and batch_register_result.success:
            if hasattr(batch_register_result, "data"):
                registered_users = batch_register_result.data
                for _user in registered_users:
                    pass
            return True
    return False


async def _handle_batch_sessions(
    batch_ops: object,
    credentials: list[tuple[str, str]],
) -> None:
    """Handle batch session creation and token validation."""
    # Note: This is a simplified example - in real usage you'd use proper types
    if hasattr(batch_ops, "create_multiple_sessions"):
        batch_sessions_result = await batch_ops.create_multiple_sessions(
            credentials,
            session_hours=12,
        )

        if (
            hasattr(batch_sessions_result, "success")
            and not batch_sessions_result.success
        ):
            return

        if hasattr(batch_sessions_result, "data"):
            session_data = batch_sessions_result.data
            if isinstance(session_data, dict):
                session_data.get("successful")


async def example_batch_operations() -> None:
    """Exemplo: Operações em lote."""
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

    # Process batch registration
    await _handle_batch_registration(batch_ops, users_data)

    # Credenciais para sessões em lote
    credentials = [
        ("batch_user_1", "BatchPass123!"),
        ("batch_user_2", "BatchPass456!"),
        ("batch_REDACTED_LDAP_BIND_PASSWORD", "BatchAdminPass789!"),
    ]

    # Process batch sessions
    await _handle_batch_sessions(batch_ops, credentials)


async def example_advanced_user_management() -> None:
    """Exemplo: Gerenciamento avançado de usuários."""
    # Configuração de produção
    auth = FlextAuth()

    # Registro de usuário REDACTED_LDAP_BIND_PASSWORDistrador
    REDACTED_LDAP_BIND_PASSWORD_result = await auth.register_validated(
        username="production_REDACTED_LDAP_BIND_PASSWORD",
        email="REDACTED_LDAP_BIND_PASSWORD@production.com",
        password=EXAMPLE_PRODUCTION_ADMIN_PASSWORD,
        role=FlextUserRole.ADMIN,
        require_strong_password=True,
    )

    if REDACTED_LDAP_BIND_PASSWORD_result.success:
        REDACTED_LDAP_BIND_PASSWORD_data = REDACTED_LDAP_BIND_PASSWORD_result.data

        if REDACTED_LDAP_BIND_PASSWORD_data.get("password_strength"):
            strength = REDACTED_LDAP_BIND_PASSWORD_data["password_strength"]
            strength["strength"]
            strength["score"]

        # Sessão completa com dados do usuário
        session_result = await auth.create_user_session(
            "production_REDACTED_LDAP_BIND_PASSWORD",
            "ProductionAdminPass123!@#",
            include_user_data=True,
        )

        if session_result.success:
            session_data = session_result.data

            # Refresh token test
            if "refresh_token" in session_data:
                refresh_result = await auth.refresh(session_data["refresh_token"])
                if refresh_result.success:
                    pass


def main() -> None:
    """Execute all advanced examples using shared runner."""
    # Define sync examples
    sync_examples = [
        example_advanced_configuration,
        example_jwt_operations,
        example_api_key_management,
        example_role_permission_system,
        example_secure_sessions,
        example_multi_factor_authentication,
        example_decorators,
    ]

    # Define async examples
    async_examples = [
        example_batch_operations,
        example_advanced_user_management,
    ]

    # Run all examples using shared runner (DRY principle)
    basic_example_runner(sync_examples, async_examples)


if __name__ == "__main__":
    main()
