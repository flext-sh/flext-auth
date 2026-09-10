# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Utilities. Managers package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth_managers_session import FlextAuthSessionManagers
    from .rate_limiter import FlextAuthRateLimiterManagers
    from .user import FlextAuthUserManagers
    from .user_create import FlextAuthUserManagerCreate
    from .user_read import FlextAuthUserManagerRead
    from .user_write import FlextAuthUserManagerWrite
__all__: tuple[str, ...] = (
    "FlextAuthRateLimiterManagers",
    "FlextAuthSessionManagers",
    "FlextAuthUserManagerCreate",
    "FlextAuthUserManagerRead",
    "FlextAuthUserManagerWrite",
    "FlextAuthUserManagers",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".auth_managers_session": ("FlextAuthSessionManagers",),
            ".rate_limiter": ("FlextAuthRateLimiterManagers",),
            ".user": ("FlextAuthUserManagers",),
            ".user_create": ("FlextAuthUserManagerCreate",),
            ".user_read": ("FlextAuthUserManagerRead",),
            ".user_write": ("FlextAuthUserManagerWrite",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
