"""Base authentication provider protocol for FLEXT Auth.

This module defines the abstract base class that all authentication providers
must inherit from, providing a consistent interface for authentication operations
such as login, token refresh, validation, and revocation.

The protocol ensures railway-oriented programming patterns with FlextResult returns
and supports various authentication methods (JWT, API keys, OAuth, etc.).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from flext_core import FlextResult as r

from flext_auth.protocols import FlextAuthProtocols as p


class FlextAuthBaseProvider(ABC):
    """Base protocol for all authentication providers.

    All authentication providers must implement this interface to ensure
    consistent behavior across different authentication technologies (JWT,
    OAuth2, SAML, etc.).
    """

    @abstractmethod
    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> r[p.Auth.TokenProtocol]:
        """Authenticate user with provided credentials.

        This is the primary authentication method. It should validate the
        provided credentials and, if valid, return an authentication token.

        Args:
            credentials: Dictionary containing authentication credentials.
                        The exact structure depends on the provider type.

        Returns:
            r[p.Auth.TokenProtocol]: Authentication token on success,
                                   error message on failure

        """

    @abstractmethod
    def validate(
        self,
        token: str | p.Auth.TokenProtocol,
    ) -> r[bool]:
        """Validate authentication token.

        Check if the provided token is valid and has not expired.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """

    def refresh(
        self,
        token: str | p.Auth.TokenProtocol,
    ) -> r[p.Auth.TokenProtocol]:
        """Refresh authentication token.

        Generate a new token based on an existing valid token. This operation
        is optional and should return an error if the provider doesn't support
        token refresh.

        Args:
            token: Existing token to refresh

        Returns:
            r[p.Auth.TokenProtocol]: New token on success,
                                   error if refresh not supported or failed

        """
        msg = "Token refresh not implemented in base provider"
        raise NotImplementedError(msg)

    def revoke(
        self,
        _token: str | p.Auth.TokenProtocol,
    ) -> r[bool]:
        """Revoke authentication token.

        Invalidate the provided token, preventing further use. This operation
        is optional and should return an error if the provider doesn't support
        token revocation.

        Args:
            _token: Token to revoke

        Returns:
            r[bool]: True if revoked successfully,
                   False if revocation not supported or failed,
                   error message on failure

        """
        return r[bool].fail("Token revocation not supported")

    def supports(self) -> set[str]:
        """Return set of capabilities supported by this provider.

        Capabilities help consumers understand what operations are available
        for this provider. This allows graceful degradation when using providers
        with different feature sets.

        Returns:
            set[str]: Set of supported operations

        """
        return {"authenticate", "validate"}


__all__ = ["FlextAuthBaseProvider"]
