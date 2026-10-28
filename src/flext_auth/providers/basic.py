"""FLEXT Auth Basic Provider - HTTP Basic authentication provider.

This module provides HTTP Basic authentication for FLEXT applications.
It implements RFC 7617 for username/password authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableSequence
from typing import override

from flext_auth import p
from flext_auth.providers import FlextAuthProvider


class FlextAuthBasicProvider(FlextAuthProvider, p.Auth.FlextAuthBaseProvider):
    """HTTP Basic authentication provider.

    Provides username/password authentication using HTTP Basic Auth (RFC 7617).
    """

    @property
    def rfc_version(self) -> str:
        """RFC version this provider implements (RFC 7617 for Basic Auth)."""
        return "RFC 7617"

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"basic", "validate"})

        """
        return {"basic", "validate"}


__all__: MutableSequence[str] = ["FlextAuthBasicProvider"]
