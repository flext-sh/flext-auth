"""FLEXT Auth API Key Provider - API key authentication provider.

This module provides API key-based authentication for FLEXT applications.
It implements the FlextAuthBaseProvider protocol for seamless integration
with the FLEXT authentication system.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth import FlextAuthProviderMixin, p, t
from flext_core import r


class FlextAuthApiKeyProvider(FlextAuthProviderMixin, p.Auth.FlextAuthBaseProvider):
    """API key authentication provider.

    Provides API key-based authentication with token validation.
    """

    def __init__(self, config: t.ConfigurationMapping | None = None) -> None:
        """Initialize provider with configuration."""
        super().__init__(config)

    @override
    def authenticate(self, credentials: t.ContainerValueMapping) -> r[p.Auth.Token]:
        """Authenticate using API key credentials."""
        _ = credentials
        return r[p.Auth.Token].fail("Not implemented")

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"api_key", "validate"})

        """
        return {"api_key", "validate"}

    @override
    def validate(self, token: str | p.Auth.Token) -> r[bool]:
        """Validate authentication token."""
        _ = token
        return r[bool].fail("Not implemented")


__all__ = ["FlextAuthApiKeyProvider"]
