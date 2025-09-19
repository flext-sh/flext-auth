"""Exemplo básico: Autenticação usando API atual do flext-auth.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_auth import FlextAuth
from flext_core import FlextTypes


def exemplo_flext_auth() -> None:
    """Exemplo de uso da API atual FlextAuth."""
    # Setup usando classe diretamente (sem helpers)
    auth: FlextAuth = FlextAuth()

    # Registrar um usuário novo
    register_result = auth.register_user(
        "usuario_teste", "usuario@example.com", "MinhaSenh@123!",
    )

    if register_result.is_success:
        pass  # This is a User object, not a dict
    else:
        return

    # Autenticação em 1 linha (retorna FlextResult)
    auth_result = auth.authenticate_user("usuario_teste", "MinhaSenh@123!")

    if auth_result.is_success:
        auth_data = auth_result.value

        # Extract authentication data with proper typing
        tokens_data = auth_data.get("tokens", {})
        session_data = cast("FlextTypes.Core.Dict", auth_data.get("session", {}))

        access_token = str(tokens_data.get("access_token", ""))
        session_id = str(session_data.get("session_id", ""))

        # Validação de token em 1 linha
        validation_result = auth.validate_token(access_token)
        if validation_result.is_success:
            pass

        # Logout em 1 linha
        logout_result = auth.logout_user(session_id)
        if logout_result.is_success:
            pass


if __name__ == "__main__":
    exemplo_flext_auth()
