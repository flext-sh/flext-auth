"""FLEXT Auth JWT Provider - JSON Web Token authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC

from flext_core import r

from flext_auth.models import FlextAuthModels

# Forward reference to avoid circular import
from flext_auth.providers.mixin import FlextAuthProviderMixin
from flext_auth.providers.rfc import FlextAuthRfcProvider


class FlextAuthJwtProvider(FlextAuthRfcProvider, FlextAuthProviderMixin, ABC):
    """JSON Web Token (JWT) authentication provider (RFC 7519).

    This provider implements JWT authentication as defined in RFC 7519.
    It validates JWT tokens and issues new tokens upon successful authentication.

    Example:
        >>> provider = FlextAuthJwtProvider()
        >>> result = provider.authenticate({"username": "user", "password": "password"})
        >>> if result.is_success:
        ...     token = result.unwrap()
        ...     print(f"Authenticated with token: {token.token}")

    """

    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> r[FlextAuthModels.AuthToken]:
        """Authenticate using JWT credentials.

        Args:
            credentials: Dictionary containing authentication credentials

        Returns:
            r[AuthToken]: Authentication token on success, error on failure

        """
        _ = credentials
        return r["FlextAuthModels.AuthToken"].fail("Not implemented")

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> r[bool]:
        """Validate JWT token.

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
            set[str]: Set of supported methods (e.g., {"jwt", "validate", "refresh"})

        """
        return {"jwt", "validate", "refresh"}

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (RFC 7519 for JWT)

        """
        return "RFC 7519"


__all__ = ["FlextAuthJwtProvider"]
