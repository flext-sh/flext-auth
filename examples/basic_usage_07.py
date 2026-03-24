"""Exemplo básico: Autenticação usando API atual do flext-auth.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuth


def exemplo_flext_auth() -> None:
    """Exemplo de uso da API atual FlextAuth."""
    auth: FlextAuth = FlextAuth()
    register_result = auth.register_user(
        "usuario_teste",
        "usuario@example.com",
        "MinhaSenh@123!",
    )
    if register_result.is_success:
        pass
    else:
        return
    auth_result = auth.authenticate_user("usuario_teste", "MinhaSenh@123!")
    if auth_result.is_success:
        auth_data = auth_result.value
        access_token = str(auth_data.token) if auth_data.token else ""
        session_id = str(auth_data.session_id) if auth_data.session_id else ""
        validation_result = auth.validate_token(access_token)
        if validation_result.is_success:
            pass
        logout_result = auth.logout_user(session_id)
        if logout_result.is_success:
            pass


if __name__ == "__main__":
    exemplo_flext_auth()
