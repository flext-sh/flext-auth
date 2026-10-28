"""FLEXT Auth API Key Provider - API key authentication provider.

This module provides API key-based authentication for FLEXT applications.
It implements the FlextAuthBaseProvider protocol for seamless integration
with the FLEXT authentication system.

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


class FlextAuthApiKeyProvider(FlextAuthProvider, p.Auth.FlextAuthBaseProvider):
    """API key authentication provider.

    Provides API key-based authentication with token validation.
    """

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            set[str]: Set of supported methods (e.g., {"api_key", "validate"})

        """
        return {"api_key", "validate"}


__all__: MutableSequence[str] = ["FlextAuthApiKeyProvider"]
