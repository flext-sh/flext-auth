# AUTO-GENERATED FILE — Regenerate with: make gen
"""Protocols package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".auth": ("FlextAuthProtocolsAuth",),
        ".auth_identity": ("FlextAuthProtocolsAuthIdentity",),
        ".auth_provider": ("FlextAuthProtocolsAuthProvider",),
        ".auth_service": ("FlextAuthProtocolsAuthService",),
        ".auth_session": ("FlextAuthProtocolsAuthSession",),
        ".auth_token": ("FlextAuthProtocolsAuthToken",),
        ".auth_transport": ("FlextAuthProtocolsAuthTransport",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
