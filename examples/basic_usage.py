"""Exemplo básico: Autenticação usando API atual do flext-auth.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuth


def exemplo_flext_auth() -> None:
    """Exemplo de uso da API atual FlextAuth."""
    print("🚀 FlextAuth - Exemplo Básico")

    # Setup usando classe diretamente (sem helpers)
    auth = FlextAuth()
    print("✅ FlextAuth inicializado")

    # Registrar um usuário novo
    register_result = auth.register_user(
        "usuario_teste",
        "usuario@example.com",
        "MinhaSenh@123!"
    )

    if register_result.success:
        print("✅ Usuário registrado com sucesso")
        user_data = register_result.value
        print(f"   ID: {user_data['user']['id']}")
        print(f"   Username: {user_data['user']['username']}")
        print(f"   Role: {user_data['user']['role']}")
    else:
        print(f"❌ Falha no registro: {register_result.error}")
        return

    # Autenticação em 1 linha (retorna FlextResult)
    auth_result = auth.authenticate_user("usuario_teste", "MinhaSenh@123!")

    if auth_result.success:
        print("✅ Autenticação bem-sucedida")
        auth_data = auth_result.value
        access_token = auth_data["tokens"]["access_token"]
        session_id = auth_data["session"]["session_id"]

        print(f"   Token: {access_token[:20]}...")
        print(f"   Session: {session_id}")

        # Validação de token em 1 linha
        validation_result = auth.validate_token(access_token)
        if validation_result.success:
            print("✅ Token válido")
            claims = validation_result.value
            print(f"   Username: {claims['username']}")
            print(f"   Role: {claims['role']}")
        else:
            print(f"❌ Token inválido: {validation_result.error}")

        # Logout em 1 linha
        logout_result = auth.logout_user(session_id)
        if logout_result.success:
            print("✅ Logout realizado com sucesso")
        else:
            print(f"❌ Falha no logout: {logout_result.error}")
    else:
        print(f"❌ Falha na autenticação: {auth_result.error}")


if __name__ == "__main__":
    exemplo_flext_auth()
