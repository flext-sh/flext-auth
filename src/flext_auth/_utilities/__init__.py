# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import _managers as _managers
    from ._managers.auth_managers_session import (
        FlextAuthSessionManagers as FlextAuthSessionManagers,
    )
    from ._managers.rate_limiter import (
        FlextAuthRateLimiterManagers as FlextAuthRateLimiterManagers,
    )
    from ._managers.user import FlextAuthUserManagers as FlextAuthUserManagers
    from ._managers.user_create import (
        FlextAuthUserManagerCreate as FlextAuthUserManagerCreate,
    )
    from ._managers.user_read import (
        FlextAuthUserManagerRead as FlextAuthUserManagerRead,
    )
    from ._managers.user_write import (
        FlextAuthUserManagerWrite as FlextAuthUserManagerWrite,
    )
    from .auth import FlextAuthUtilitiesAuth as FlextAuthUtilitiesAuth
    from .auth_response import (
        FlextAuthUtilitiesAuthResponse as FlextAuthUtilitiesAuthResponse,
    )
    from .auth_token import FlextAuthUtilitiesAuthToken as FlextAuthUtilitiesAuthToken
    from .auth_validation import (
        FlextAuthUtilitiesAuthValidation as FlextAuthUtilitiesAuthValidation,
    )
    from .identity_audit import FlextAuthIdentityAudit as FlextAuthIdentityAudit
    from .managers import FlextAuthUtilitiesManagers as FlextAuthUtilitiesManagers

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
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
    ".identity_audit": ("FlextAuthIdentityAudit",),
    ".managers": ("FlextAuthUtilitiesManagers",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextAuthIdentityAudit",
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
    "FlextAuthUtilitiesManagers",
    "_managers",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
