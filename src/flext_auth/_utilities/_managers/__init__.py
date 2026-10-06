# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Utilities. Managers package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._utilities._managers.auth_managers_session import (
        FlextAuthSessionManagers,
    )
    from flext_auth._utilities._managers.rate_limiter import (
        FlextAuthRateLimiterManagers,
    )
    from flext_auth._utilities._managers.user import FlextAuthUserManagers
    from flext_auth._utilities._managers.user_create import FlextAuthUserManagerCreate
    from flext_auth._utilities._managers.user_read import FlextAuthUserManagerRead
    from flext_auth._utilities._managers.user_write import FlextAuthUserManagerWrite


__all__: tuple[str, ...] = (
    "FlextAuthRateLimiterManagers",
    "FlextAuthSessionManagers",
    "FlextAuthUserManagerCreate",
    "FlextAuthUserManagerRead",
    "FlextAuthUserManagerWrite",
    "FlextAuthUserManagers",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthRateLimiterManagers": ".rate_limiter",
        "FlextAuthSessionManagers": ".auth_managers_session",
        "FlextAuthUserManagerCreate": ".user_create",
        "FlextAuthUserManagerRead": ".user_read",
        "FlextAuthUserManagerWrite": ".user_write",
        "FlextAuthUserManagers": ".user",
    }),
    public_exports=__all__,
)
