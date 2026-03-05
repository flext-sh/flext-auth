"""JWT authentication provider for FLEXT.

This module provides JWT-based authentication for FLEXT applications.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import override

from flext_core import r

from flext_auth import m, p
from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthJwtProvider(FlextAuthBaseProvider):
    """JWT-based authentication provider."""

    def __init__(self, config: Mapping[str, str | int | bool] | None = None) -> None:
        """Initialize provider with configuration."""
        super().__init__(config)

    @override
    def authenticate(
        self,
        credentials: m.Auth.CredentialValidation,
    ) -> r[p.Auth.TokenProtocol]:
        """Authenticate using JWT credentials."""
        _ = credentials
        return r[p.Auth.TokenProtocol].fail("Not implemented")

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
    def validate(
        self,
        token: str,
    ) -> r[bool]:
        """Validate JWT token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        return self.validate_token(token)

    def validate_token(self, token: str) -> r[bool]:
        """Validate JWT token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        _ = token
        return r[bool].fail("Not implemented")

    @override
    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider-jwt"


__all__ = ["FlextAuthJwtProvider"]
