"""FLEXT Auth Basic Provider - HTTP Basic authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC

from flext_core import r

from flext_auth.providers.mixin import FlextAuthProviderMixin
from flext_auth.providers.rfc import FlextAuthRfcProvider

# Forward reference to avoid circular import


class FlextAuthBasicProvider(FlextAuthRfcProvider, FlextAuthProviderMixin, ABC):
    """HTTP Basic authentication provider (RFC 7617).

    This provider implements HTTP Basic Authentication as defined in RFC 7617.
    It validates username/password credentials and issues tokens upon
    successful validation.

    Example:
        >>> provider = FlextAuthBasicProvider()
        >>> result = provider.authenticate({"username": "user", "password": "password"})
        >>> if result.is_success:
        ...     token = result.value
        ...     print(f"Authenticated with token: {token.token}")

    """

    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> r[p.Auth.TokenProtocol]:
        """Authenticate using HTTP Basic credentials.

        Args:
            credentials: Dictionary containing "username" and "password" keys

        Returns:
            r[AuthToken]: Authentication token on success, error on failure

        """
        _ = credentials
        return r[p.Auth.TokenProtocol].fail("Not implemented")

    def validate(
        self,
        token: str | p.Auth.TokenProtocol,
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
            set[str]: Set of supported methods (e.g., {"basic", "validate"})

        """
        return {"basic", "validate"}

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (RFC 7617 for Basic Auth)

        """
        return "RFC 7617"


__all__ = ["FlextAuthBasicProvider"]
