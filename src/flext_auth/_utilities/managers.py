"""FLEXT Auth manager namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence

from flext_auth._utilities import FlextAuthUtilitiesBase
from flext_auth._utilities._managers import (
    FlextAuthRateLimiterManagers,
    FlextAuthSessionManagers,
    FlextAuthUserManagers,
)


class FlextAuthUtilitiesManagers(
    FlextAuthUtilitiesBase,
    FlextAuthSessionManagers,
    FlextAuthRateLimiterManagers,
    FlextAuthUserManagers,
):
    """Namespace class for all authentication managers following FLEXT patterns."""


__all__: MutableSequence[str] = ["FlextAuthUtilitiesManagers"]
