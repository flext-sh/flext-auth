"""FLEXT Auth LDAP Provider - LDAP/Active Directory authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth import FlextAuthProviderMixin, p, r, t


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
    def authenticate(self, credentials: t.JsonMapping) -> p.Result[p.Auth.Token]:
        """Authenticate using LDAP credentials.

        Args:
            credentials: Dictionary containing "username" and "password" keys

        Returns:
            r[Token]: Authentication token on success, error on failure

        """
        _ = credentials
        return r[p.Auth.Token].fail("Not implemented")

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"ldap", "validate"})

        """
        return {"ldap", "validate"}

    @override
    def validate(self, token: str | p.Auth.Token) -> p.Result[bool]:
        """Validate authentication token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        _ = token
        return r[bool].fail("Not implemented")


__all__: t.MutableSequenceOf[str] = ["FlextAuthLdapProvider"]
