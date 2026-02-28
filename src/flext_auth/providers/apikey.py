"""FLEXT Auth API Key Provider - API key authentication provider.

This module provides API key-based authentication for FLEXT applications.
It implements the FlextAuthBaseProvider protocol for seamless integration
with the FLEXT authentication system.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import override

from flext_auth import m, p
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_core import r


class FlextAuthApiKeyProvider(FlextAuthBaseProvider):
    """API key authentication provider.

    Provides API key-based authentication with token validation.
    """

    def __init__(self, config: Mapping[str, str | int | bool] | None = None) -> None:
        """Initialize provider with configuration."""
        super().__init__(config)

    @override
    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider-apikey"

    @override
    def authenticate(
        self,
        credentials: m.Auth.CredentialValidation,
    ) -> r[p.Auth.TokenProtocol]:
        """Authenticate using API key credentials."""
        _ = credentials
        return r[p.Auth.TokenProtocol].fail("Not implemented")

    @override
    def validate(
        self,
        token: str | p.Auth.TokenProtocol,
    ) -> r[bool]:
        """Validate authentication token."""
        _ = token
        return r[bool].fail("Not implemented")

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"api_key", "validate"})

        """
        return {"api_key", "validate"}


__all__ = ["FlextAuthApiKeyProvider"]
