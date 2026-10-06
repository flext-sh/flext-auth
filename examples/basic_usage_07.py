"""Exemplo básico: Autenticação usando API atual do flext-auth.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuth, p, r


class FlextAuthBasicUsagePortugueseExample:
    """Single owner for the Portuguese basic usage example."""

    @staticmethod
    def exemplo_flext_auth() -> p.Result[bool]:
        """Exemplo de uso da API atual FlextAuth.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        auth = FlextAuth()
        register_result = auth.register_user(
            "usuario_teste",
            "usuario@example.com",
            "MinhaSenh@123!",
        )
        if register_result.failure:
            return r[bool].from_failure(register_result)
        auth_result = auth.authenticate_user("usuario_teste", "MinhaSenh@123!")
        if auth_result.failure:
            return r[bool].from_failure(auth_result)
        auth_data = auth_result.value
        validation = auth.session_service.validate_token(auth_data.token)
        if validation.failure:
            return validation
        return auth.session_service.session_manager.end_session_by_id(
            auth_data.session_id,
        )


if __name__ == "__main__":
    FlextAuthBasicUsagePortugueseExample.exemplo_flext_auth().unwrap()
