"""Exemplo básico: Setup instantâneo com redução massiva de código.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio

from flext_auth import flext_auth_quick_start


async def exemplo_tradicional_vs_flext() -> None:
    """Comparação: método tradicional vs flext-auth."""  # REDUÇÃO MASSIVA: Setup completo em 1 linha
    auth_result = flext_auth_quick_start()

    if not auth_result.success or not auth_result.data:
        return

    auth = auth_result.data

    # Login em 1 linha (retorna FlextResult)
    login_result = await auth.login("REDACTED_LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD123")

    if login_result.success:
        login_data = login_result.data
        access_token = login_data.get("access_token")
        if access_token and isinstance(access_token, str):
            # Validação em 1 linha
            validation = await auth.validate(access_token)
            if validation.success:
                pass

            # Logout em 1 linha
            await auth.logout(access_token)


if __name__ == "__main__":
    asyncio.run(exemplo_tradicional_vs_flext())
