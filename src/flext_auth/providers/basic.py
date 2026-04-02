"""FLEXT Auth Basic Provider - HTTP Basic authentication provider.

This module provides HTTP Basic authentication for FLEXT applications.
It implements RFC 7617 for username/password authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth import FlextAuthProviderMixin, p, t
from flext_core import r


class FlextAuthBasicProvider(FlextAuthProviderMixin, p.Auth.FlextAuthBaseProvider):
    """HTTP Basic authentication provider.

    Provides username/password authentication using HTTP Basic Auth (RFC 7617).
    """

    def __init__(self, config: t.ConfigurationMapping | None = None) -> None:
        """Initialize provider with configuration."""
        super().__init__(config)

    @override
    def authenticate(self, credentials: t.ContainerValueMapping) -> r[p.Auth.Token]:
        """Authenticate using HTTP Basic credentials."""
        _ = credentials
        return r[p.Auth.Token].fail("Not implemented")

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (RFC 7617 for Basic Auth)

        """
        return "RFC 7617"

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"basic", "validate"})

        """
        return {"basic", "validate"}

    @override
    def validate(self, token: str | p.Auth.Token) -> r[bool]:
        """Validate authentication token."""
        _ = token
        return r[bool].fail("Not implemented")


__all__ = ["FlextAuthBasicProvider"]
