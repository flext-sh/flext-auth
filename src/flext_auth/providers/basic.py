"""FLEXT Auth Basic Provider - HTTP Basic authentication provider.

This module provides HTTP Basic authentication for FLEXT applications.
It implements RFC 7617 for username/password authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth import p, t
from flext_auth.providers.mixin import FlextAuthProviderMixin


class FlextAuthBasicProvider(FlextAuthProviderMixin, p.Auth.FlextAuthBaseProvider):
    """HTTP Basic authentication provider.

    Provides username/password authentication using HTTP Basic Auth (RFC 7617).
    """

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


__all__: t.MutableSequenceOf[str] = ["FlextAuthBasicProvider"]
