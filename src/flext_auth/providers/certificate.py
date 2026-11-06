"""Certificate authentication provider for FLEXT.

This module provides certificate-based authentication for FLEXT applications.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import override

from flext_auth import p
from flext_auth.providers import FlextAuthProvider


class FlextAuthCertificateProvider(
    FlextAuthProvider,
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


__all__: MutableSequence[str] = ["FlextAuthCertificateProvider"]
