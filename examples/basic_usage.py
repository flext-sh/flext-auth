"""Exemplo básico: Setup instantâneo com redução massiva de código.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio

from flext_auth import flext_auth_quick_start


async def exemplo_tradicional_vs_flext() -> None:
    """Comparação: método tradicional vs flext-auth."""  # REDUÇÃO MASSIVA: Setup completo em 1 linha
    auth = flext_auth_quick_start()

    # Login em 1 linha (retorna FlextResult)
    login_result = await auth.login("REDACTED_LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD123")

    if login_result.success:
        access_token = login_result.data["access_token"]

        # Validação em 1 linha
        validation = await auth.validate(access_token)
        if validation.success:
            pass

        # Logout em 1 linha
        await auth.logout(access_token)


if __name__ == "__main__":
    asyncio.run(exemplo_tradicional_vs_flext())
