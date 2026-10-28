# AUTO-GENERATED FILE — Regenerate with: make gen
"""FlextAuth utilities facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
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

from flext_api import u

from flext_auth._utilities import (
    FlextAuthUtilitiesAuth,
    FlextAuthUtilitiesAuthResponse,
    FlextAuthUtilitiesAuthSession,
    FlextAuthUtilitiesAuthValidation,
    FlextAuthUtilitiesBase,
    FlextAuthUtilitiesManagers,
)


class FlextAuthUtilities(u):
    """FlextAuth advanced utilities extending the API utility namespace."""

    class Auth(
        FlextAuthUtilitiesAuth,
        FlextAuthUtilitiesAuthValidation,
        FlextAuthUtilitiesAuthResponse,
        FlextAuthUtilitiesAuthSession,
        FlextAuthUtilitiesManagers,
        FlextAuthUtilitiesBase,
    ):
        """Auth-specific utility namespace."""


u = FlextAuthUtilities
__all__: list[str] = ["FlextAuthUtilities", "u"]
