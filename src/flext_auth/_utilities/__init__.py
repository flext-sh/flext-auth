# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import _managers as _managers
    from ._managers.auth_managers_session import FlextAuthSessionManagers
    from ._managers.rate_limiter import FlextAuthRateLimiterManagers
    from ._managers.user import FlextAuthUserManagers
    from ._managers.user_create import FlextAuthUserManagerCreate
    from ._managers.user_read import FlextAuthUserManagerRead
    from ._managers.user_write import FlextAuthUserManagerWrite
    from .auth import FlextAuthUtilitiesAuth
    from .auth_response import FlextAuthUtilitiesAuthResponse
    from .auth_token import FlextAuthUtilitiesAuthToken
    from .auth_validation import FlextAuthUtilitiesAuthValidation
    from .identity_audit import FlextAuthIdentityAudit
    from .managers import FlextAuthUtilitiesManagers
__all__: tuple[str, ...] = (
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
            ".identity_audit": ("FlextAuthIdentityAudit",),
            ".managers": ("FlextAuthUtilitiesManagers",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
