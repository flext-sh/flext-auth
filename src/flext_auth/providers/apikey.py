"""FLEXT Auth API Key Provider - Generic API key authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC

from flext_core import r

from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.mixin import FlextAuthProviderMixin

# Forward reference to avoid circular import
# Import FlextAuthModels locally in method bodies where needed


class FlextAuthApiKeyProvider(FlextAuthBaseProvider, FlextAuthProviderMixin, ABC):
    """API Key authentication provider.

    This provider authenticates users using API keys. It validates
    API keys against a configured key store and issues tokens upon
    successful validation.

    Example:
        >>> provider = FlextAuthApiKeyProvider()
        >>> result = provider.authenticate({"api_key": "my-api-key"})
        >>> if result.is_success:
        ...     token = result.unwrap()
        ...     print(f"Authenticated with token: {token.token}")

    """

    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> r[FlextAuthModels.AuthToken]:
        """Authenticate using API key.

        Args:
            credentials: Dictionary containing "api_key" key

        Returns:
            r[AuthToken]: Authentication token on success, error on failure

        """
        _ = credentials
        return r["FlextAuthModels.AuthToken"].fail("Not implemented")

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
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
            set[str]: Set of supported methods (e.g., {"api_key", "validate"})

        """
        return {"api_key", "validate"}


__all__ = ["FlextAuthApiKeyProvider"]
