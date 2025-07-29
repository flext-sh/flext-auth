"""Exemplo avançado: Sistema completo com RBAC e sessões.

Demonstra recursos avançados com redução massiva de código.
"""

import asyncio

from flext_auth import (
    FlextAuth,
    flext_auth_create_secure_session,
    flext_auth_decode_jwt,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_middleware_creator,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
)


async def exemplo_sistema_completo() -> None:
    """Sistema completo de autenticação com RBAC."""
    # Configuração customizada
    config = {
        "jwt": {
            "secret_key": "minha-chave-super-secreta-de-producao-123456789",
            "access_token_expire_minutes": 15,
            "refresh_token_expire_days": 30,
        },
        "security": {
            "password_rounds": 14,  # Produção
            "max_failed_attempts": 3,
            "lockout_duration_minutes": 60,
        },
    }

    auth = FlextAuth(config)

    # 1. REGISTRO DE MÚLTIPLOS USUÁRIOS
    usuarios = [
        ("REDACTED_LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD@empresa.com", "SuperSecure123!", "REDACTED_LDAP_BIND_PASSWORD"),
        ("manager", "manager@empresa.com", "Manager456!", "manager"),
        ("user", "user@empresa.com", "User789!", "user"),
    ]

    for username, email, password, role in usuarios:
        # Validação de email (helper)
        if not flext_auth_validate_email(email):
            continue

        # Análise de força da senha (helper)
        strength = flext_auth_validate_password_strength(password)
        if not strength["valid"]:
            continue

        # Registro
        result = await auth.register(username, email, password, role)
        if result.is_success:
            pass

    # 2. SISTEMA DE LOGIN COM CONTROLE DE SESSÕES

    # Login do REDACTED_LDAP_BIND_PASSWORD
    login_result = await auth.login(
        "REDACTED_LDAP_BIND_PASSWORD", "SuperSecure123!", "192.168.1.100", "Mozilla/5.0",
    )
    if login_result.is_success:
        REDACTED_LDAP_BIND_PASSWORD_data = login_result.data
        REDACTED_LDAP_BIND_PASSWORD_token = REDACTED_LDAP_BIND_PASSWORD_data["tokens"]["access_token"]
        REDACTED_LDAP_BIND_PASSWORD_user = REDACTED_LDAP_BIND_PASSWORD_data["user"]

        # 3. VALIDAÇÃO E AUTORIZAÇÃO
        validation = await auth.validate(REDACTED_LDAP_BIND_PASSWORD_token)
        if validation.is_success:
            pass

        # 4. GESTÃO DE SESSÕES
        user_sessions = await auth.get_user_sessions(REDACTED_LDAP_BIND_PASSWORD_user["id"])
        if user_sessions.is_success:
            pass

        # 5. OPERAÇÕES AVANÇADAS

        # Mudança de senha
        password_change = await auth.change_password(
            REDACTED_LDAP_BIND_PASSWORD_user["id"],
            "SuperSecure123!",
            "NovaPasswordMuitoSegura456!",
        )
        if password_change.is_success:
            pass

        # Refresh de token
        refresh_result = await auth.refresh(REDACTED_LDAP_BIND_PASSWORD_data["tokens"]["refresh_token"])
        if refresh_result.is_success:
            pass

        # Logout
        await auth.logout(REDACTED_LDAP_BIND_PASSWORD_token)

    # 6. LIMPEZA DE SESSÕES EXPIRADAS
    cleaned = await auth.cleanup_sessions()
    if cleaned.is_success:
        pass


def exemplo_helpers_utilitarios() -> None:
    """Demonstra helpers utilitários para redução massiva de código."""
    # Hash de senha seguro em 1 linha
    senha_hash = flext_auth_hash_password("MinhaPassword123!", rounds=12)

    # Verificação de senha em 1 linha
    flext_auth_verify_password("MinhaPassword123!", senha_hash)

    # JWT customizado em 1 linha
    payload = {"user_id": "123", "username": "teste", "role": "REDACTED_LDAP_BIND_PASSWORD"}
    token = flext_auth_generate_jwt(payload, expires_minutes=60)

    # Decodificação JWT em 1 linha
    decoded = flext_auth_decode_jwt(token, "chave-secreta")
    if decoded:
        pass

    # Sessão segura em 1 linha
    flext_auth_create_secure_session("user123", "joao", "manager", 48)

    # Validação de email robusta
    emails_teste = ["valido@exemplo.com", "invalido", "outro@test", "ok@dom.co"]
    for email in emails_teste:
        flext_auth_validate_email(email)


def exemplo_middleware_web() -> None:
    """Demonstra criação de middleware para frameworks web."""
    auth = FlextAuth()

    # Cria middleware em 1 linha
    flext_auth_middleware_creator(auth)


async def main() -> None:
    """Executa todos os exemplos."""
    await exemplo_sistema_completo()
    exemplo_helpers_utilitarios()
    exemplo_middleware_web()


if __name__ == "__main__":
    asyncio.run(main())
