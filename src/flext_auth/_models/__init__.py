# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Models package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._models.auth import FlextAuthModelsAuth
    from flext_auth._models.auth_identity import FlextAuthModelsAuthIdentity
    from flext_auth._models.auth_identity_request import (
        FlextAuthModelsAuthIdentityRequest,
    )
    from flext_auth._models.auth_password import FlextAuthModelsAuthPassword
    from flext_auth._models.auth_provider_config import (
        FlextAuthModelsAuthProviderConfig,
    )
    from flext_auth._models.auth_response import FlextAuthModelsAuthResponse
    from flext_auth._models.auth_session import FlextAuthModelsAuthSession
    from flext_auth._models.auth_token import FlextAuthModelsAuthToken
    from flext_auth._models.auth_user_identity_extras import (
        FlextAuthModelsAuthUserIdentityExtras,
    )
    from flext_auth._models.base import FlextAuthModelsBase
    from flext_auth._models.config import FlextAuthConfigModels


__all__: tuple[str, ...] = (
    "FlextAuthConfigModels",
    "FlextAuthModelsAuth",
    "FlextAuthModelsAuthIdentity",
    "FlextAuthModelsAuthIdentityRequest",
    "FlextAuthModelsAuthPassword",
    "FlextAuthModelsAuthProviderConfig",
    "FlextAuthModelsAuthResponse",
    "FlextAuthModelsAuthSession",
    "FlextAuthModelsAuthToken",
    "FlextAuthModelsAuthUserIdentityExtras",
    "FlextAuthModelsBase",
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
            ".base": ("FlextAuthModelsBase",),
            ".config": ("FlextAuthConfigModels",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
