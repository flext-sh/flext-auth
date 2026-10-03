"""FLEXT Auth LDAP Provider - LDAP/Active Directory authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth import p, t
from flext_auth.providers.mixin import FlextAuthProviderMixin


class FlextAuthLdapProvider(FlextAuthProviderMixin, p.Auth.FlextAuthBaseProvider):
    """LDAP/Active Directory authentication provider.

    This provider authenticates users against LDAP or Active Directory servers.
    It validates credentials and issues tokens upon successful authentication.

    Example:
        >>> provider = FlextAuthLdapProvider()
        >>> result = provider.authenticate({"username": "user", "password": "password"})
        >>> if result.success:
        ...     token = result.value
        ...     u.Cli.print(f"Authenticated with token: {token.token}")

    """

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"ldap", "validate"})

        """
        return {"ldap", "validate"}


__all__: t.MutableSequenceOf[str] = ["FlextAuthLdapProvider"]
