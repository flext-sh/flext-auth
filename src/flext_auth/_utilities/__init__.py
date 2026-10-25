# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._utilities._managers import (
        FlextAuthRateLimiterManagers,
        FlextAuthSessionManagers,
        FlextAuthUserManagerCreate,
        FlextAuthUserManagerRead,
        FlextAuthUserManagers,
        FlextAuthUserManagerWrite,
    )
    from flext_auth._utilities.auth import FlextAuthUtilitiesAuth
    from flext_auth._utilities.auth_response import FlextAuthUtilitiesAuthResponse
    from flext_auth._utilities.auth_session import FlextAuthUtilitiesAuthSession
    from flext_auth._utilities.auth_validation import FlextAuthUtilitiesAuthValidation
    from flext_auth._utilities.base import FlextAuthUtilitiesBase
    from flext_auth._utilities.managers import FlextAuthUtilitiesManagers


__all__: tuple[str, ...] = (
    "FlextAuthRateLimiterManagers",
    "FlextAuthSessionManagers",
    "FlextAuthUserManagerCreate",
    "FlextAuthUserManagerRead",
    "FlextAuthUserManagerWrite",
    "FlextAuthUserManagers",
    "FlextAuthUtilitiesAuth",
    "FlextAuthUtilitiesAuthResponse",
    "FlextAuthUtilitiesAuthSession",
    "FlextAuthUtilitiesAuthValidation",
    "FlextAuthUtilitiesBase",
    "FlextAuthUtilitiesManagers",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthRateLimiterManagers": "._managers.rate_limiter",
        "FlextAuthSessionManagers": "._managers.auth_managers_session",
        "FlextAuthUserManagerCreate": "._managers.user_create",
        "FlextAuthUserManagerRead": "._managers.user_read",
        "FlextAuthUserManagerWrite": "._managers.user_write",
        "FlextAuthUserManagers": "._managers.user",
        "FlextAuthUtilitiesAuth": ".auth",
        "FlextAuthUtilitiesAuthResponse": ".auth_response",
        "FlextAuthUtilitiesAuthSession": ".auth_session",
        "FlextAuthUtilitiesAuthValidation": ".auth_validation",
        "FlextAuthUtilitiesBase": ".base",
        "FlextAuthUtilitiesManagers": ".managers",
    }),
    public_exports=__all__,
)
