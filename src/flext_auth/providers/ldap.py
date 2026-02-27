"""FLEXT Auth LDAP Provider - LDAP/Active Directory authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations


from flext_auth.models import FlextAuthModels as m
from flext_auth.protocols import FlextAuthProtocols

# Forward reference to avoid circular import
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin
from flext_core import r


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

    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider-ldap"

    def authenticate(
        self,
        credentials: m.CredentialValidation,
    ) -> r[FlextAuthProtocols.Auth.TokenProtocol]:
        """Authenticate using LDAP credentials.

        Args:
            credentials: Dictionary containing "username" and "password" keys

        Returns:
            r[TokenProtocol]: Authentication token on success, error on failure

        """
        _ = credentials
        return r[FlextAuthProtocols.Auth.TokenProtocol].fail("Not implemented")

    def validate(
        self,
        token: str | FlextAuthProtocols.Auth.TokenProtocol,
    ) -> r[bool]:
        """Validate authentication token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        _ = token
        return r[bool].fail("Not implemented")

    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"ldap", "validate"})

        """
        return {"ldap", "validate"}


__all__ = ["FlextAuthLdapProvider"]
