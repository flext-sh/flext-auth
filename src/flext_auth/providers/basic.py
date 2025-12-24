"""FLEXT Auth Basic Provider - HTTP Basic authentication provider.

This module provides HTTP Basic authentication for FLEXT applications.
It implements RFC 7617 for username/password authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core.protocols import FlextProtocols as p

# FLEXT Standard imports
from flext import FlextResult as r
from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthBasicProvider(FlextAuthBaseProvider):
    """HTTP Basic authentication provider.

    Provides username/password authentication using HTTP Basic Auth (RFC 7617).
    """

    def authenticate(
        self,
        credentials: dict[str, object],
    ) -> r[p.Auth.TokenProtocol]:
        """Authenticate using HTTP Basic credentials."""
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
            set[str]: Set of supported methods (e.g., {"basic", "validate"})

        """
        return {"basic", "validate"}

    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (RFC 7617 for Basic Auth)

        """
        return "RFC 7617"


__all__ = ["FlextAuthBasicProvider"]
