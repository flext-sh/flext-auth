# AUTO-GENERATED FILE — Regenerate with: make gen
"""FLEXT Auth models facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_api import FlextApiModels

from flext_auth._models import FlextAuthModelsAuth, FlextAuthModelsBase


class FlextAuthModels(FlextApiModels):
    """Authentication models extending the API model namespace."""

    class Auth(
        FlextAuthModelsAuth,
        FlextAuthModelsBase,
    ):
        """Authentication model namespace."""


m = FlextAuthModels
__all__: list[str] = ["FlextAuthModels", "m"]
