# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Models package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth import FlextAuthModelsAuth
    from .auth_identity import FlextAuthModelsAuthIdentity
    from .auth_identity_request import FlextAuthModelsAuthIdentityRequest
    from .auth_password import FlextAuthModelsAuthPassword
    from .auth_provider_config import FlextAuthModelsAuthProviderConfig
    from .auth_response import FlextAuthModelsAuthResponse
    from .auth_session import FlextAuthModelsAuthSession
    from .auth_token import FlextAuthModelsAuthToken
    from .auth_user_identity_extras import FlextAuthModelsAuthUserIdentityExtras
__all__: tuple[str, ...] = (
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

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".auth": ("FlextAuthModelsAuth",),
            ".auth_identity": ("FlextAuthModelsAuthIdentity",),
            ".auth_identity_request": ("FlextAuthModelsAuthIdentityRequest",),
            ".auth_password": ("FlextAuthModelsAuthPassword",),
            ".auth_provider_config": ("FlextAuthModelsAuthProviderConfig",),
            ".auth_response": ("FlextAuthModelsAuthResponse",),
            ".auth_session": ("FlextAuthModelsAuthSession",),
            ".auth_token": ("FlextAuthModelsAuthToken",),
            ".auth_user_identity_extras": ("FlextAuthModelsAuthUserIdentityExtras",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
