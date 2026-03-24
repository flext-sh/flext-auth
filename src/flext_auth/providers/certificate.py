"""Certificate authentication provider for FLEXT.

This module provides certificate-based authentication for FLEXT applications.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import r

from flext_auth import m, p, t


class FlextAuthCertificateProvider(p.Auth.FlextAuthBaseProvider):
    """Certificate-based authentication provider."""

    def __init__(self, config: t.ConfigurationMapping | None = None) -> None:
        """Initialize provider with configuration."""
        super().__init__(config)

    @override
    def authenticate(self, credentials: m.Auth.CredentialValidation) -> r[p.Auth.Token]:
        """Authenticate using certificate credentials."""
        _ = credentials
        return r[p.Auth.Token].fail("Not implemented")

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"certificate", "validate"})

        """
        return {"certificate", "validate"}

    @override
    def validate(self, token: str | p.Auth.Token) -> r[bool]:
        """Validate certificate token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        if isinstance(token, str):
            token_value = token
        else:
            token_protocol: p.Auth.Token = token
            token_value = token_protocol.token
        return self.validate_token(str(token_value))

    def validate_token(self, token: str) -> r[bool]:
        """Validate authentication token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        _ = token
        return r[bool].fail("Not implemented")


__all__ = ["FlextAuthCertificateProvider"]
