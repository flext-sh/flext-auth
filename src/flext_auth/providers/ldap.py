"""FLEXT Auth LDAP Provider - LDAP/Active Directory authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import r

from flext_auth import m, p
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin


class FlextAuthLdapProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    """LDAP/Active Directory authentication provider.

    This provider authenticates users against LDAP or Active Directory servers.
    It validates credentials and issues tokens upon successful authentication.

    Example:
        >>> provider = FlextAuthLdapProvider()
        >>> result = provider.authenticate({"username": "user", "password": "password"})
        >>> if result.is_success:
        ...     token = result.value
        ...     print(f"Authenticated with token: {token.token}")

    """

    @override
    def authenticate(self, credentials: m.Auth.CredentialValidation) -> r[p.Auth.Token]:
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
    def validate(self, token: str | p.Auth.Token) -> r[bool]:
        """Validate authentication token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        _ = token
        return r[bool].fail("Not implemented")


__all__ = ["FlextAuthLdapProvider"]
