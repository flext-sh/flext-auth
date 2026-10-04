# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._utilities import _managers
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
    from flext_auth._utilities.auth import FlextAuthUtilitiesAuth
    from flext_auth._utilities.auth_response import FlextAuthUtilitiesAuthResponse
    from flext_auth._utilities.auth_token import FlextAuthUtilitiesAuthToken
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
    "FlextAuthUtilitiesAuthToken",
    "FlextAuthUtilitiesAuthValidation",
    "FlextAuthUtilitiesBase",
    "FlextAuthUtilitiesManagers",
    "_managers",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            "._managers": ("_managers",),
            "._managers.auth_managers_session": ("FlextAuthSessionManagers",),
            "._managers.rate_limiter": ("FlextAuthRateLimiterManagers",),
            "._managers.user": ("FlextAuthUserManagers",),
            "._managers.user_create": ("FlextAuthUserManagerCreate",),
            "._managers.user_read": ("FlextAuthUserManagerRead",),
            "._managers.user_write": ("FlextAuthUserManagerWrite",),
            ".auth": ("FlextAuthUtilitiesAuth",),
            ".auth_response": ("FlextAuthUtilitiesAuthResponse",),
            ".auth_token": ("FlextAuthUtilitiesAuthToken",),
            ".auth_validation": ("FlextAuthUtilitiesAuthValidation",),
            ".base": ("FlextAuthUtilitiesBase",),
            ".managers": ("FlextAuthUtilitiesManagers",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
