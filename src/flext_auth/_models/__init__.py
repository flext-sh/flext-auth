# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Models package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth import FlextAuthModelsAuth as FlextAuthModelsAuth
    from .auth_identity import (
        FlextAuthModelsAuthIdentity as FlextAuthModelsAuthIdentity,
    )
    from .auth_identity_request import (
        FlextAuthModelsAuthIdentityRequest as FlextAuthModelsAuthIdentityRequest,
    )
    from .auth_password import (
        FlextAuthModelsAuthPassword as FlextAuthModelsAuthPassword,
    )
    from .auth_provider_config import (
        FlextAuthModelsAuthProviderConfig as FlextAuthModelsAuthProviderConfig,
    )
    from .auth_response import (
        FlextAuthModelsAuthResponse as FlextAuthModelsAuthResponse,
    )
    from .auth_session import FlextAuthModelsAuthSession as FlextAuthModelsAuthSession
    from .auth_token import FlextAuthModelsAuthToken as FlextAuthModelsAuthToken
    from .auth_user_identity_extras import (
        FlextAuthModelsAuthUserIdentityExtras as FlextAuthModelsAuthUserIdentityExtras,
    )

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    ".auth": ("FlextAuthModelsAuth",),
    ".auth_identity": ("FlextAuthModelsAuthIdentity",),
    ".auth_identity_request": ("FlextAuthModelsAuthIdentityRequest",),
    ".auth_password": ("FlextAuthModelsAuthPassword",),
    ".auth_provider_config": ("FlextAuthModelsAuthProviderConfig",),
    ".auth_response": ("FlextAuthModelsAuthResponse",),
    ".auth_session": ("FlextAuthModelsAuthSession",),
    ".auth_token": ("FlextAuthModelsAuthToken",),
    ".auth_user_identity_extras": ("FlextAuthModelsAuthUserIdentityExtras",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextAuthModelsAuth",
    "FlextAuthModelsAuthIdentity",
    "FlextAuthModelsAuthIdentityRequest",
    "FlextAuthModelsAuthPassword",
    "FlextAuthModelsAuthProviderConfig",
    "FlextAuthModelsAuthResponse",
    "FlextAuthModelsAuthSession",
    "FlextAuthModelsAuthToken",
    "FlextAuthModelsAuthUserIdentityExtras",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
