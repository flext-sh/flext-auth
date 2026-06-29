# AUTO-GENERATED FILE — Regenerate with: make gen
"""Models package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

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
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
