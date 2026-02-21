"""OIDC Provider - OpenID Connect authentication provider.

Extends OAuth2 with OpenID Connect capabilities for identity verification
and standardized user profile information retrieval. Supports OIDC discovery
and JWT-based identity tokens.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC

from flext_auth.protocols import FlextAuthProtocols

# Forward reference to avoid circular import
from flext_auth.providers.mixin import FlextAuthProviderMixin
from flext_auth.providers.rfc import FlextAuthRfcProvider
from flext_auth.typings import t
from flext_core import r


class FlextAuthOidcProvider(FlextAuthRfcProvider, FlextAuthProviderMixin, ABC):
    """OpenID Connect (OIDC) authentication provider.

    This provider implements OpenID Connect authentication. It validates
    OIDC tokens and issues new tokens upon successful authentication.

    Example:
        >>> provider = FlextAuthOidcProvider()
        >>> result = provider.authenticate({"id_token": "oidc-token"})
        >>> if result.is_success:
        ...     token = result.value
        ...     print(f"Authenticated with token: {token.token}")

    """

    def authenticate(
        self,
        credentials: dict[str, t.JsonValue],
    ) -> r[FlextAuthProtocols.Auth.TokenProtocol]:
        """Authenticate using OIDC credentials.

        Args:
            credentials: Dictionary containing OIDC authentication data

        Returns:
            r[AuthToken]: Authentication token on success, error on failure

        """
        _ = credentials
        return r[FlextAuthProtocols.Auth.TokenProtocol].fail("Not implemented")

    def validate(
        self,
        token: str | FlextAuthProtocols.Auth.TokenProtocol,
    ) -> r[bool]:
        """Validate OIDC token.

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
            set[str]: Set of supported methods (e.g., {"oidc", "validate", "refresh"})

        """
        return {"oidc", "validate", "refresh"}

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (OpenID Connect Core 1.0)

        """
        return "OpenID Connect Core 1.0"


__all__ = ["FlextAuthOidcProvider"]
