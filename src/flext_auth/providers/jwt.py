"""JWT authentication provider for FLEXT.

This module provides JWT-based authentication for FLEXT applications.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth import FlextAuthProviderMixin, p, t
from flext_core import p, r


class FlextAuthJwtProvider(FlextAuthProviderMixin, p.Auth.FlextAuthBaseProvider):
    """JWT-based authentication provider."""

    def __init__(self, settings: t.ConfigurationMapping | None = None) -> None:
        """Initialize provider with configuration."""
        super().__init__(settings)

    @override
    def authenticate(
        self, credentials: t.ContainerValueMapping
    ) -> p.Result[p.Auth.Token]:
        """Authenticate using JWT credentials."""
        _ = credentials
        return r[p.Auth.Token].fail("Not implemented")

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (RFC 7519 for JWT)

        """
        return "RFC 7519"

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"jwt", "validate", "refresh"})

        """
        return {"jwt", "validate", "refresh"}

    @override
    def validate(self, token: str) -> p.Result[bool]:
        """Validate JWT token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        return self.validate_token(token)

    def validate_token(self, token: str) -> p.Result[bool]:
        """Validate JWT token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        _ = token
        return r[bool].fail("Not implemented")


__all__: list[str] = ["FlextAuthJwtProvider"]
