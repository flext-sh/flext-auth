# AUTO-GENERATED FILE — Regenerate with: make gen
"""FlextAuth utilities facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_api import FlextApiUtilities

from flext_auth import t
from flext_auth._utilities import (
    FlextAuthUtilitiesAuth,
    FlextAuthUtilitiesAuthResponse,
    FlextAuthUtilitiesAuthSession,
    FlextAuthUtilitiesAuthValidation,
    FlextAuthUtilitiesBase,
    FlextAuthUtilitiesManagers,
)
from flext_auth._utilities._managers.user_create import FlextAuthUserManagerCreate


class FlextAuthUtilities(FlextApiUtilities):
    """FlextAuth advanced utilities extending the API utility namespace."""

    class Auth(
        FlextAuthUtilitiesAuth,
        FlextAuthUtilitiesAuthValidation,
        FlextAuthUtilitiesAuthResponse,
        FlextAuthUtilitiesAuthSession,
        FlextAuthUtilitiesManagers,
        FlextAuthUtilitiesBase,
        FlextAuthUserManagerCreate,
    ):
        """Auth-specific utility namespace."""


u = FlextAuthUtilities

__all__: t.MutableSequenceOf[str] = ["FlextAuthUtilities", "u"]
