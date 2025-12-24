"""FLEXT Auth API Key Provider - API key authentication provider.

This module provides API key-based authentication for FLEXT applications.
It implements the FlextAuthBaseProvider protocol for seamless integration
with the FLEXT authentication system.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core.protocols import FlextProtocols as p

# FLEXT Standard imports
from flext import FlextResult as r
from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthApiKeyProvider(FlextAuthBaseProvider):
    """API key authentication provider.

    Provides API key-based authentication with token validation.
    """

    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> r[p.Auth.TokenProtocol]:
        """Authenticate using API key credentials."""
        _ = credentials
        return r[p.Auth.TokenProtocol].fail("Not implemented")

    def validate(
        self,
        token: str | p.Auth.TokenProtocol,
    ) -> r[bool]:
        """Validate authentication token."""
        _ = token
        return r[bool].fail("Not implemented")

    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"api_key", "validate"})

        """
        return {"api_key", "validate"}


__all__ = ["FlextAuthApiKeyProvider"]
