# AUTO-GENERATED FILE — Regenerate with: make gen
"""Models package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._models.auth import FlextAuthModelsAuth as FlextAuthModelsAuth
    from flext_auth._models.auth_identity import (
        FlextAuthModelsAuthIdentity as FlextAuthModelsAuthIdentity,
    )
    from flext_auth._models.auth_identity_request import (
        FlextAuthModelsAuthIdentityRequest as FlextAuthModelsAuthIdentityRequest,
    )
    from flext_auth._models.auth_password import (
        FlextAuthModelsAuthPassword as FlextAuthModelsAuthPassword,
    )
    from flext_auth._models.auth_provider_config import (
        FlextAuthModelsAuthProviderConfig as FlextAuthModelsAuthProviderConfig,
    )
    from flext_auth._models.auth_response import (
        FlextAuthModelsAuthResponse as FlextAuthModelsAuthResponse,
    )
    from flext_auth._models.auth_session import (
        FlextAuthModelsAuthSession as FlextAuthModelsAuthSession,
    )
    from flext_auth._models.auth_token import (
        FlextAuthModelsAuthToken as FlextAuthModelsAuthToken,
    )
    from flext_auth._models.auth_user_identity_extras import (
        FlextAuthModelsAuthUserIdentityExtras as FlextAuthModelsAuthUserIdentityExtras,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".auth": ("FlextAuthModelsAuth",),
        ".auth_identity": ("FlextAuthModelsAuthIdentity",),
        ".auth_identity_request": ("FlextAuthModelsAuthIdentityRequest",),
        ".auth_password": ("FlextAuthModelsAuthPassword",),
        ".auth_provider_config": ("FlextAuthModelsAuthProviderConfig",),
        ".auth_response": ("FlextAuthModelsAuthResponse",),
        ".auth_session": ("FlextAuthModelsAuthSession",),
        ".auth_token": ("FlextAuthModelsAuthToken",),
        ".auth_user_identity_extras": ("FlextAuthModelsAuthUserIdentityExtras",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
