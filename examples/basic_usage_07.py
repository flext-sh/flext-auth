"""Exemplo básico: Autenticação usando API atual do flext-auth.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuth, p, r


class FlextAuthBasicUsagePortugueseExample:
    """Single owner for the Portuguese basic usage example."""

    @staticmethod
    def exemplo_flext_auth() -> p.Result[None]:
        """Exemplo de uso da API atual FlextAuth."""
        auth: FlextAuth = FlextAuth()
        register_result = auth.register_user(
            "usuario_teste", "usuario@example.com", "MinhaSenh@123!"
        )
        if register_result.failure:
            return r[None].from_failure(register_result)
        auth_result = auth.authenticate_user("usuario_teste", "MinhaSenh@123!")
        if auth_result.success:
            auth_data = auth_result.value
            access_token = auth_data.token or ""
            session_id = auth_data.session_id or ""
            auth.token_service.validate_token(access_token)
            auth.session_service.session_manager.end_session_by_id(session_id)
        return r[None].ok(None)


if __name__ == "__main__":
    FlextAuthBasicUsagePortugueseExample.exemplo_flext_auth()
