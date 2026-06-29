# AUTO-GENERATED FILE — Regenerate with: make gen
"""Managers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._utilities._managers.auth_managers_session import (
        FlextAuthSessionManagers as FlextAuthSessionManagers,
    )
    from flext_auth._utilities._managers.rate_limiter import (
        FlextAuthRateLimiterManagers as FlextAuthRateLimiterManagers,
    )
    from flext_auth._utilities._managers.user import (
        FlextAuthUserManagers as FlextAuthUserManagers,
    )
    from flext_auth._utilities._managers.user_create import (
        FlextAuthUserManagerCreate as FlextAuthUserManagerCreate,
    )
    from flext_auth._utilities._managers.user_extras import (
        FlextAuthUserIdentityExtras as FlextAuthUserIdentityExtras,
    )
    from flext_auth._utilities._managers.user_read import (
        FlextAuthUserManagerRead as FlextAuthUserManagerRead,
    )
    from flext_auth._utilities._managers.user_write import (
        FlextAuthUserManagerWrite as FlextAuthUserManagerWrite,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".auth_managers_session": ("FlextAuthSessionManagers",),
        ".rate_limiter": ("FlextAuthRateLimiterManagers",),
        ".user": ("FlextAuthUserManagers",),
        ".user_create": ("FlextAuthUserManagerCreate",),
        ".user_extras": ("FlextAuthUserIdentityExtras",),
        ".user_read": ("FlextAuthUserManagerRead",),
        ".user_write": ("FlextAuthUserManagerWrite",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
