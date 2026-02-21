"""JWT authentication provider for FLEXT.

This module provides JWT-based authentication for FLEXT applications.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.protocols import FlextAuthProtocols as p
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_core import r, t


class FlextAuthJwtProvider(FlextAuthBaseProvider):
    """JWT-based authentication provider."""

    def __init__(self, config: dict[str, t.JsonValue] | None = None) -> None:
        """Initialize provider with configuration."""
        super().__init__(config)

    def authenticate(
        self,
        credentials: dict[str, t.JsonValue],
    ) -> r[p.Auth.TokenProtocol]:
        """Authenticate using JWT credentials."""
        _ = credentials
        return r[p.Auth.TokenProtocol].fail("Not implemented")

    def validate(
        self,
        token: str | p.Auth.TokenProtocol,
    ) -> r[bool]:
        """Validate JWT token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        token_str = token if isinstance(token, str) else str(token)
        return self.validate_token(token_str)

    def validate_token(self, token: str) -> r[bool]:
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
