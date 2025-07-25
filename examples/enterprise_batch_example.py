"""Exemplo enterprise demonstrando batch operations e funcionalidades avançadas.

Mostra como usar flext-auth para operações em lote, API keys,
e cenários enterprise complexos com redução massiva de código.
"""

import asyncio
from datetime import datetime
from typing import Any

# FLEXT: Import único para operações enterprise
from flext_auth import (
    FlextAuth,
    flext_auth_batch_operations,
    flext_auth_create_api_key,
    flext_auth_create_secure_session,
    flext_auth_validate_api_key,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
)

# =============================================================================
# CONFIGURAÇÃO ENTERPRISE
# =============================================================================

def setup_enterprise_auth() -> FlextAuth:
    """Setup enterprise com configuração otimizada."""
    config = {
        "security": {
            "password_rounds": 12,  # Produção
            "max_failed_attempts": 3,
            "lockout_duration_minutes": 15,
            "session_expire_hours": 8,  # Jornada trabalho
            "max_concurrent_sessions": 3,
        },
        "jwt": {
            "access_token_expire_minutes": 60,  # 1 hora
            "refresh_token_expire_days": 30,    # 30 dias
        },
    }

    return FlextAuth(config)

# =============================================================================
# OPERAÇÕES BATCH ENTERPRISE
# =============================================================================

async def bulk_user_import(auth: FlextAuth, users_data: list[dict[str, str]]) -> dict[str, Any]:
    """Importa usuários em lote com validação completa."""
    # FLEXT: Batch operations em 1 linha!
    batch_ops = flext_auth_batch_operations(auth)

    # Validação prévia dos dados
    validated_users = []
    validation_errors = []

    for i, user_data in enumerate(users_data):
        # Validações rápidas com helpers FLEXT
        email_valid = flext_auth_validate_email(user_data.get("email", ""))
        password_strength = flext_auth_validate_password_strength(user_data.get("password", ""))

        if not email_valid:
            validation_errors.append(f"Usuário {i+1}: Email inválido")
            continue

        if not password_strength["valid"]:
            validation_errors.append(f"Usuário {i+1}: Senha fraca - {password_strength['feedback'][0]}")
            continue

        validated_users.append(user_data)


    if validation_errors:
        for _error in validation_errors[:5]:  # Mostra apenas os primeiros 5
            pass

    if not validated_users:
        return {"success": False, "error": "Nenhum usuário válido para importar"}

    # FLEXT: Registro em lote com validação automática
    result = await batch_ops.register_multiple(validated_users, validate_all=True)

    if result.is_success:
        return {
            "success": True,
            "imported": len(result.data),
            "skipped": len(validation_errors),
            "users": result.data,
        }
    return {"success": False, "error": result.error}

# =============================================================================
# SISTEMA DE API KEYS ENTERPRISE
# =============================================================================

def create_service_api_keys(user_ids: list[str]) -> dict[str, str]:
    """Cria API keys para serviços enterprise."""
    api_keys = {}
    "enterprise-secret-key-super-secure-" + "x" * 50

    for user_id in user_ids:
        # FLEXT: API key em 1 linha vs 25+ tradicional
        api_key = flext_auth_create_api_key(
            user_id=user_id,
            scope="api",
            expires_days=365,  # 1 ano para serviços
        )
        api_keys[user_id] = api_key

    return api_keys

def validate_service_requests(api_keys: dict[str, str], secret: str) -> None:
    """Valida requisições de serviços usando API keys."""
    for api_key in api_keys.values():
        # FLEXT: Validação de API key em 1 linha vs 20+ tradicional
        key_data = flext_auth_validate_api_key(api_key, secret)

        if key_data:
            pass
        else:
            pass

# =============================================================================
# SESSÕES ENTERPRISE COM PERMISSÕES
# =============================================================================

def create_role_based_sessions() -> list[dict[str, Any]]:
    """Cria sessões baseadas em roles enterprise."""
    users = [
        {"id": "ceo001", "username": "ceo", "role": "REDACTED_LDAP_BIND_PASSWORD"},
        {"id": "manager001", "username": "manager", "role": "moderator"},
        {"id": "dev001", "username": "developer", "role": "user"},
        {"id": "intern001", "username": "intern", "role": "user"},
    ]

    sessions = []
    for user in users:
        # FLEXT: Sessão com permissões em 1 linha vs 30+ tradicional
        session = flext_auth_create_secure_session(
            user_id=user["id"],
            username=user["username"],
            role=user["role"],
            expires_hours=8,  # Jornada de trabalho
            include_permissions=True,
        )

        sessions.append(session)

    return sessions

# =============================================================================
# DASHBOARD ENTERPRISE
# =============================================================================

async def enterprise_dashboard(auth: FlextAuth) -> dict[str, Any]:
    """Dashboard com métricas enterprise."""
    # Simula dados enterprise
    return {
        "timestamp": datetime.now().isoformat(),
        "system_status": "operational",
        "metrics": {
            "total_users": 1500,
            "active_sessions": 234,
            "api_requests_today": 15000,
            "failed_logins_today": 12,
        },
        "security": {
            "password_policy": "strong",
            "mfa_enabled": True,
            "session_timeout": "8 hours",
            "concurrent_sessions": 3,
        },
    }



# =============================================================================
# DEMONSTRAÇÃO PRINCIPAL
# =============================================================================

async def main_enterprise_demo():
    """Demonstração completa enterprise."""
    # 1. Setup enterprise
    auth = setup_enterprise_auth()

    # 2. Dados de exemplo para import
    users_data = [
        {
            "username": "alice.manager",
            "email": "alice@company.com",
            "password": "StrongPassword123!",
            "role": "moderator",
        },
        {
            "username": "bob.developer",
            "email": "bob@company.com",
            "password": "DevPassword456!",
            "role": "user",
        },
        {
            "username": "carol.REDACTED_LDAP_BIND_PASSWORD",
            "email": "carol@company.com",
            "password": "AdminPassword789!",
            "role": "REDACTED_LDAP_BIND_PASSWORD",
        },
        {
            "username": "invalid.user",
            "email": "invalid-email",
            "password": "weak",
            "role": "user",
        },
    ]

    # 3. Bulk import
    import_result = await bulk_user_import(auth, users_data)

    # 4. API Keys para serviços
    service_ids = ["service-auth", "service-api", "service-webhook"]
    api_keys = create_service_api_keys(service_ids)

    # 5. Validação de API keys
    secret = "enterprise-secret-validation-key-" + "x" * 40
    validate_service_requests(api_keys, secret)

    # 6. Sessões enterprise
    sessions = create_role_based_sessions()

    # 7. Dashboard
    dashboard = await enterprise_dashboard(auth)

    # 8. Resumo final

    return {
        "import_result": import_result,
        "api_keys": len(api_keys),
        "sessions": len(sessions),
        "dashboard": dashboard,
    }

# =============================================================================
# COMPARAÇÃO TRADICIONAL VS FLEXT
# =============================================================================

def show_code_comparison() -> None:
    """Mostra comparação de código tradicional vs FLEXT."""
    comparisons = [
        ("Bulk User Import", "80+ linhas", "5 linhas", "94%"),
        ("API Key System", "60+ linhas", "3 linhas", "95%"),
        ("Role Sessions", "40+ linhas", "2 linhas", "95%"),
        ("Permission System", "50+ linhas", "1 linha", "98%"),
        ("Enterprise Config", "30+ linhas", "1 linha", "97%"),
        ("Validation Pipeline", "45+ linhas", "3 linhas", "93%"),
    ]


    total_tradicional = 0
    total_flext = 0

    for _func, trad, flext, _reducao in comparisons:
        trad_num = int(trad.replace("+ linhas", ""))
        flext_num = int(flext.replace(" linha", "").replace(" linhas", ""))

        total_tradicional += trad_num
        total_flext += flext_num


    round((1 - total_flext/total_tradicional) * 100, 1)



if __name__ == "__main__":
    # Executar demonstração
    result = asyncio.run(main_enterprise_demo())

    # Mostrar comparação
    show_code_comparison()

