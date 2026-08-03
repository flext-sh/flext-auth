# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Utilities. Managers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth_managers_session import (
        FlextAuthSessionManagers as FlextAuthSessionManagers,
    )
    from .rate_limiter import (
        FlextAuthRateLimiterManagers as FlextAuthRateLimiterManagers,
    )
    from .user import FlextAuthUserManagers as FlextAuthUserManagers
    from .user_create import FlextAuthUserManagerCreate as FlextAuthUserManagerCreate
    from .user_read import FlextAuthUserManagerRead as FlextAuthUserManagerRead
    from .user_write import FlextAuthUserManagerWrite as FlextAuthUserManagerWrite

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    ".auth_managers_session": ("FlextAuthSessionManagers",),
    ".rate_limiter": ("FlextAuthRateLimiterManagers",),
    ".user": ("FlextAuthUserManagers",),
    ".user_create": ("FlextAuthUserManagerCreate",),
    ".user_read": ("FlextAuthUserManagerRead",),
    ".user_write": ("FlextAuthUserManagerWrite",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextAuthRateLimiterManagers",
    "FlextAuthSessionManagers",
    "FlextAuthUserManagerCreate",
    "FlextAuthUserManagerRead",
    "FlextAuthUserManagerWrite",
    "FlextAuthUserManagers",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
