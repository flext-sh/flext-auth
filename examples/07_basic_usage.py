"""Exemplo básico: Autenticação usando API atual do flext-auth.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_auth import FlextAuth


def exemplo_flext_auth() -> None:
    """Exemplo de uso da API atual FlextAuth."""
    print("🚀 FlextAuth - Exemplo Básico")

    # Setup usando classe diretamente (sem helpers)
    auth: FlextAuth[object] = FlextAuth()
    print("✅ FlextAuth inicializado")

    # Registrar um usuário novo
    register_result = auth.register_user(
        "usuario_teste", "usuario@example.com", "MinhaSenh@123!"
    )

    if register_result.is_success:
        print("✅ Usuário registrado com sucesso")
        user_data = register_result.value  # This is a User object, not a dict
        print(f"   ID: {user_data.id}")
        print(f"   Username: {user_data.username}")
        print(f"   Email: {user_data.email_str}")
        print(f"   Role: {user_data.role}")
    else:
        print(f"❌ Falha no registro: {register_result.error}")
        return

    # Autenticação em 1 linha (retorna FlextResult)
    auth_result = auth.authenticate_user("usuario_teste", "MinhaSenh@123!")

    if auth_result.is_success:
        print("✅ Autenticação bem-sucedida")
        auth_data = auth_result.value

        # Extract authentication data with proper typing
        tokens_data = cast("dict[str, object]", auth_data.get("tokens", {}))
        session_data = cast("dict[str, object]", auth_data.get("session", {}))

        access_token = str(tokens_data.get("access_token", ""))
        session_id = str(session_data.get("session_id", ""))

        print(f"   Token: {access_token[:20]}...")
        print(f"   Session: {session_id}")

        # Validação de token em 1 linha
        validation_result = auth.validate_token(access_token)
        if validation_result.is_success:
            print("✅ Token válido")
            claims = validation_result.value
            print(f"   User ID: {claims.get('user_id')}")
            print(f"   Username: {claims.get('username')}")
            print(f"   Role: {claims.get('role')}")
        else:
            print(f"❌ Token inválido: {validation_result.error}")

        # Logout em 1 linha
        logout_result = auth.logout_user(session_id)
        if logout_result.is_success:
            print("✅ Logout realizado com sucesso")
        else:
            print(f"❌ Falha no logout: {logout_result.error}")
    else:
        print(f"❌ Falha na autenticação: {auth_result.error}")


if __name__ == "__main__":
    exemplo_flext_auth()
