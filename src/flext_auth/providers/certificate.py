"""Certificate authentication provider for FLEXT.

This module provides certificate-based authentication for FLEXT applications.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth import p, r, t
from flext_auth.providers import FlextAuthProviderMixin


class FlextAuthCertificateProvider(
    FlextAuthProviderMixin,
    p.Auth.FlextAuthBaseProvider,
):
    """Certificate-based authentication provider."""

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"certificate", "validate"})

        """
        return {"certificate", "validate"}

    @override
    def validate(self, token: str | p.Auth.Token) -> p.Result[bool]:
        """Validate certificate token.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        _ = token
        return self.validate_token()

    @staticmethod
    def validate_token() -> p.Result[bool]:
        """Validate authentication token.

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        return r[bool].fail("Not implemented")


__all__: t.MutableSequenceOf[str] = ["FlextAuthCertificateProvider"]
